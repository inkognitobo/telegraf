//go:generate ../../../tools/readme_config_includer/generator
package pcap

import (
	"bytes"
	_ "embed"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
)

//go:embed sample.conf
var sampleCfg string

type PCAP struct {
	Files []string `toml:"files"`

	CSVColumnNames     []string `toml:"csv_column_names"`
	CSVColumnTypes     []string `toml:"csv_column_types"`
	CSVTagColumns      []string `toml:"csv_tag_columns"`
	CSVTimestampColumn string   `toml:"csv_timestamp_column"`
	CSVTimestampFormat string   `toml:"csv_timestamp_format"`
	CSVMeasurementName string   `toml:"csv_measurement_name"`

	TsharkPath string   `toml:"tshark_path"`
	TsharkArgs []string `toml:"tshark_args"`

	TmpDir string `toml:"tmp_dir"`
}

// SampleConfig returns the default configuration of the Input.
func (*PCAP) SampleConfig() string {
	return sampleCfg
}

// Description returns a one-sentence description on the Input.
func (p *PCAP) Description() string {
	return "A Telegraf input plugin to process PCAP files using `tshark`."
}

// Gather takes in an accumulator and adds the metrics that the Input gathers.
// This is called every "interval".
func (p *PCAP) Gather(acc telegraf.Accumulator) error {
	if p.TsharkPath == "" {
		return fmt.Errorf("`tshark_path` is not configured")
	}

	tmpDir := p.TmpDir
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}

	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to created temporary directory %s: %w", tmpDir, err)
	}

	for _, originalFilepath := range p.Files {
		tmpFilename := fmt.Sprintf("%s.pcap.processing", filepath.Base(originalFilepath))
		tmpFilepath := filepath.Join(tmpDir, tmpFilename)

		err := os.Rename(originalFilepath, tmpFilepath)
		if err != nil {
			if os.IsNotExist(err) {
				acc.AddError(fmt.Errorf("original PCAP file %s does not exist, skipping. It might have been rotated or cleand up.",
					originalFilepath))
			} else {
				acc.AddError(fmt.Errorf("failed to rename original PCAP file %s to %s: %w",
					originalFilepath, tmpFilepath, err))
			}
			continue
		}

		newFile, err := os.Create(originalFilepath)
		if err != nil {
			acc.AddError(fmt.Errorf("failed to create new empty PCAP file %s after renaming: %w. "+
				"Processing will continue on %s but original file might be missing.",
				originalFilepath, err, tmpFilepath))
		} else {
			newFile.Close()
		}

		tsharkCmdArgs := append(p.TsharkArgs, "-r", tmpFilepath)
		cmd := exec.Command(p.TsharkPath, tsharkCmdArgs...)

		output, err := cmd.Output()
		if err != nil {
			os.Remove(tmpFilepath)
			acc.AddError(fmt.Errorf("failed to execute `tshark` for %s: %w\nOutput: %s",
				tmpFilepath, err, output))
			continue
		}

		reader := bytes.NewReader(output)
		csvReader := csv.NewReader(reader)
		csvReader.Comma = ','

		// Cache which column names are tags
		numExpectedEntries := len(p.CSVColumnNames)
		tagMap := make([]bool, numExpectedEntries)
		for i, name := range p.CSVColumnNames {
			tagMap[i] = slices.Contains(p.CSVTagColumns, name)
		}

		for lno := 0; ; lno++ {
			record, err := csvReader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				acc.AddError(fmt.Errorf("failed to read CSV record from `tshark` output for %s at line %d: %w",
					tmpFilepath, lno, err))
				continue
			}

			// Verify that the record has the expected number of entries
			numGotEntries := len(record)
			if numGotEntries != numExpectedEntries {
				acc.AddError(fmt.Errorf("CSV record at line %d has %d entries, but expected %d based on columns for %s. Skipping...",
					numGotEntries, numExpectedEntries, tmpFilepath))
				continue
			}

			tags := make(map[string]string)
			fields := make(map[string]interface{})
			var timestamp time.Time = time.Now()

			for i, col := range p.CSVColumnNames {
				val := record[i]

				// Check if it is a tag column
				isTag := tagMap[i]
				if isTag {
					tags[col] = val
					continue
				}

				// Check if it is a timestamp column
				if col == p.CSVTimestampColumn {
					parsedTime, err := time.Parse(p.CSVTimestampFormat, val)
					if err != nil {
						acc.AddError(fmt.Errorf("failed to parse timestap '%s' with format '%s' for column '%s': %w",
							val, p.CSVTimestampFormat, col, err))
					} else {
						timestamp = parsedTime
					}
					continue
				}

				// Otherwise, it is a field; parse by type
				colType := p.CSVColumnTypes[i]
				switch strings.ToLower(colType) {
				case "int":
					if parsedVal, err := strconv.Atoi(val); err != nil {
						acc.AddError(fmt.Errorf("failed to parse int for column '%s' value '%s': %w",
							col, val, err))
					} else {
						fields[col] = parsedVal
					}
				case "float":
					if parsedVal, err := strconv.ParseFloat(val, 64); err != nil {
						acc.AddError(fmt.Errorf("failed to parse float64 for column '%s' value '%s': %w",
							col, val, err))
					} else {
						fields[col] = parsedVal
					}
				case "bool":
					if parsedVal, err := strconv.ParseBool(val); err != nil {
						acc.AddError(fmt.Errorf("failed to parse bool for column '%s' value '%s': %w",
							col, val, err))
					} else {
						fields[col] = parsedVal
					}
				default: // "string" or unknown type
					fields[col] = val
				}
			}
			acc.AddFields(p.CSVMeasurementName, fields, tags, timestamp)
		}

		if err := os.Remove(tmpFilepath); err != nil {
			acc.AddError(fmt.Errorf("failed to remove processing PCAP file %s: %w",
				tmpFilepath, err))
		}
	}

	return nil
}

// Registers the plugin with Telegraf.
// This function is automatically called when the package is initialised.
func init() {
	inputs.Add("pcap", func() telegraf.Input {
		return &PCAP{}
	})
}

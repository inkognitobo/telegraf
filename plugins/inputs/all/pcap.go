//go:build !custom || inputs || inputs.pcap

package all

import _ "github.com/inkognitobo/telegraf/plugins/inputs/pcap" // register plugin

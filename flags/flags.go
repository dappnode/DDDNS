package flags

import (
	"os"

	"github.com/urfave/cli"
)

var (
	// BootstrapNode node (optional)
	BootstrapNode = cli.StringFlag{
		Name:  "bootstrap-node",
		Usage: "The address a of bootstrap node. DDDNS will connect for peer discovery via DHT. Will use IPFS ones by default",
		Value: "",
	}
	// Port defines the port used to communicate
	Port = cli.Int64Flag{
		Name:  "port",
		Usage: "Port used to listening and respond requests.",
		Value: 44453,
	}
	// ProtocolID is a string to define the protocol identifier
	ProtocolID = cli.StringFlag{
		Name:  "protid",
		Usage: "The ID of the protocol.",
		Value: "/dddns/1.0.0",
	}
	// DataDir is the path where we store keys (and config)
	DataDir = cli.StringFlag{
		Name:  "datadir",
		Usage: "Path to store the data.",
		Value: getHomePath() + "/.dddns",
	}
)

// Client flags
var (
	// PublicKey defines the key of the node we want to resolve
	PublicKey = cli.StringFlag{
		Name:     "pubkey",
		Usage:    "The address (public key) of the node to resolve.",
		Value:    "",
		Required: true,
	}
)

// Daemon flags
var (
	// DNSPort ...
	DNSEnable = cli.BoolFlag{
		Name:  "dnsenable",
		Usage: "Enable DNS server.",
	}
	// DNSPort ...
	DNSPort = cli.IntFlag{
		Name:  "dnsport",
		Usage: "The port to listen for DNS requests.",
		Value: 53,
	}
	// DNSHost ...
	DNSHost = cli.StringFlag{
		Name:  "dnshost",
		Usage: "The host to listen for DNS requests.",
		Value: "127.0.0.1",
	}
)

func getHomePath() string {
	homepath, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return homepath
}

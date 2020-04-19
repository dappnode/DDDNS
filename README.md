# DDDNS

A dynamic DNS system using libp2p. Uses a rendezvous point in the DHT to find the target peer.

The public IP of the node is obtained from the multiaddress array provided from libp2p, or from third party services as a fallback.

Each node in the network has an ID in the base32 form of it's public key, such as:

`baareie5g66lu3ney2e4qfs2x3webynbaeoojkjxnd6dm36daas5k73vba`

When running as a daemon, it can act as a DNS proxy, resolving domains with the "dddns" TLD, with the form:

`baareie5g66lu3ney2e4qfs2x3webynbaeoojkjxnd6dm36daas5k73vba.dddns`

and forwarding the rest to an upstream DNS server.

To build:

`$ go build -o dddnscli ./cli/cli.go`

To run as a daemon:

`$ ./dddnscli daemon [--dnsenable]`

To run as client:

`$ ./dddnscli client --pubkey baareie5g66lu3ney2e4qfs2x3webynbaeoojkjxnd6dm36daas5k73vba`

TODO:

- [ ] IPv6
- [ ] Use a PubSub system

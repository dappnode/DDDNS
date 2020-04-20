# DDDNS

A dynamic DNS system using libp2p. Uses a rendezvous point in the DHT to find the target peer.

The public IP of the node is obtained from the multiaddress array provided from libp2p, or from third party services as a fallback.

Each node in the network has an ID in the base32 form of it's public key, such as:

`baareie5g66lu3ney2e4qfs2x3webynbaeoojkjxnd6dm36daas5k73vba`

When running as a daemon, it can act as a DNS proxy, resolving domains with the "dddns" TLD, with the form:

`baareie5g66lu3ney2e4qfs2x3webynbaeoojkjxnd6dm36daas5k73vba.dddns`

and forwarding the rest to an upstream DNS server.

## Usage

To build:

`$ go build ./cmd/dddns/dddns.go`

To run as a daemon:

`$ ./dddns daemon [--dnsenable]`

To run as client:

`$ ./dddns client --pubkey baareie5g66lu3ney2e4qfs2x3webynbaeoojkjxnd6dm36daas5k73vba`

If you are running the deamon locally, it can act as a proxy adding the following line at the top of `/etc/resolv.conf` :

`nameserver 127.0.0.1`

then, you should be able to resolve .dddns hosts like the example:

```
$ dig @localhost baareie5g66lu3ney2e4qfs2x3webynbaeoojkjxnd6dm36daas5k73vba.dddns +short
108.61.209.8
```

## To-Do

- [ ] Tests!
- [ ] IPv6 support
- [ ] Use channels
- [ ] Improve forwarding (only A now)
- [ ] Use a simple PubSub system, like [subpub](https://gitlab.com/vocdoni/go-dvote/-/blob/master/subpub/subpub.go)
- [ ] Add [cache](https://github.com/patrickmn/go-cache) for faster resolution
- [ ] Add a wrapper script to use alternative resolution [(bubblewrap)](https://wiki.archlinux.org/index.php/Bubblewrap)

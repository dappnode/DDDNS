# DDDNS

A dynamic DNS system using libp2p. Uses a rendezvous point in the DHT to find the target peer.

The public IP of the node is obtained from the multiaddress array provided from libp2p, or from third party services as a fallback.

Each node in the network has an ID in the base32 form of it's public key, such as:

`baareie5g66lu3ney2e4qfs2x3webynbaeoojkjxnd6dm36daas5k73vba`

When running as a daemon, it can act as a DNS proxy, resolving domains with the "dddns" TLD, with the form:

`baareie5g66lu3ney2e4qfs2x3webynbaeoojkjxnd6dm36daas5k73vba.dddns`

and forwarding the rest to an upstream DNS server.

## Build

To build:

`go build ./cmd/dddns/dddns.go`

With docker compose:

`docker-compose build`

## Usage

```
NAME:
   dddns - A dynamic and distributed DNS system.

USAGE:
   dddns [global options] command [command options] [arguments...]

VERSION:
   0.1

COMMANDS:
   help, h  Shows a list of commands or help for one command

   client:
     client  Starts DDDNS in client mode

   daemon:
     daemon  Starts DDDNS in daemon mode

GLOBAL OPTIONS:
   --bootstrap-node value  The address a of bootstrap node. DDDNS will connect for peer discovery via DHT. Will use IPFS ones by default
   --datadir value         Path to store the data. (default: "/home/vdo/.dddns")
   --port value            Port used to listening and respond requests. (default: 44453)
   --protid value          The ID of the protocol. (default: "/dddns/1.0.0")
   --loglevel value        Log level of the output [debug,info,warn,error] (default: "info")
   --help, -h              show help
   --version, -v           print the version

```

To run as a daemon:

`./dddns daemon [--dnsenable]`

To run as client:

`./dddns client --pubkey baareie5g66lu3ney2e4qfs2x3webynbaeoojkjxnd6dm36daas5k73vba`

If you are running the deamon locally, it can act as a proxy adding the following line at the top of `/etc/resolv.conf` :

`nameserver 127.0.0.1`

then, you should be able to resolve .dddns hosts like the example:

```
$ dig @localhost baareie5g66lu3ney2e4qfs2x3webynbaeoojkjxnd6dm36daas5k73vba.dddns +short
108.61.209.8
```

## Notes

In order to run the nameserver daemon a normal user, you need to add capabilities to bind the DNS port (53):

`sudo setcap CAP_NET_BIND_SERVICE=+eip dddns`

## To-Do

- [ ] Tests!
- [ ] IPv6 support
- [ ] Use channels
- [ ] Improve forwarding (only A now)
- [ ] Use a simple PubSub system, like [subpub](https://gitlab.com/vocdoni/go-dvote/-/blob/master/subpub/subpub.go)
- [ ] Add [cache](https://github.com/patrickmn/go-cache) for faster resolution
- [ ] Add a wrapper script to use alternative resolution [(bubblewrap)](https://wiki.archlinux.org/index.php/Bubblewrap)

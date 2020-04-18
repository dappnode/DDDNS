package dddns

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/dappnode/dddns/flags"
	"github.com/dappnode/dddns/log"

	externalip "github.com/glendc/go-external-ip"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	discovery "github.com/libp2p/go-libp2p-discovery"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	multiaddr "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
	"github.com/urfave/cli"
)

const (
	// VERSION of the app
	VERSION = "0.1"
	// RendezvousRefresh in minutes
	RendezvousRefresh = 4
)

// Message ...
// Should include a signature to validate it's the right answer
type Message struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Data      string `json:"data"`
	Signature string `json:"signature"`
}

// DDDNS type
type DDDNS struct {
	// Address to listen on
	Addr string

	// libp2p Host
	host             host.Host
	clictx           *cli.Context
	ctx              context.Context
	dht              *dht.IpfsDHT
	routingDiscovery *discovery.RoutingDiscovery
	privkey          crypto.PrivKey
	Pubkey           crypto.PubKey
	// Public IP if not nil
	PubIP  *string
	client bool
	Port   int64
}

// NewDDDNS creates a new DDDNS node
func NewDDDNS(clictx *cli.Context) (dddns *DDDNS) {
	port := clictx.GlobalInt64(flags.Port.Name)
	dddns = &DDDNS{
		clictx: clictx,
		Port:   port,
	}
	return
}

func (dddns *DDDNS) handleStream(stream network.Stream) {
	log.Info("Got a new stream!")
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))

	go dddns.reader(rw)
	// go inputLoop(rw)

}

func (dddns *DDDNS) reader(rw *bufio.ReadWriter) {
	for {
		message, err := rw.ReadString('\n')
		if message == "" {
			return
		}
		if err != nil {
			fmt.Println("Error reading from buffer: ", err)
		}

		decoded, err := base64.StdEncoding.DecodeString(message)
		if err != nil {
			fmt.Println("Error decoding: ", err)
		}
		if message != "\n" {
			// Green console colour:        \x1b[32m
			// Reset console colour:        \x1b[0m
			log.Info(fmt.Sprintf("Receiving msg: \x1b[34m%s\x1b[0m", message))

		}
		log.Info(fmt.Sprintf("Message received: \x1b[34m%s\x1b[0m", decoded))

		res := &Message{}
		err = json.Unmarshal(decoded, res)
		if err != nil {
			log.Error(err)
		}

		ip := dddns.getPublicIP()
		if err != nil {
			log.Error("cmd.Run() failed with %s\n", err)
		}

		m := Message{
			Type:      "IP",
			Timestamp: res.Timestamp,
			Data:      ip,
			//Signature: nil,
		}

		msg, err := json.Marshal(m)
		if err != nil {
			panic(err)
		}

		_, err = rw.WriteString(fmt.Sprintf("%s\n", base64.StdEncoding.EncodeToString(msg)))
		if err != nil {
			fmt.Println("Error writing to buffer")
			panic(err)
		}
		err = rw.Flush()
		if err != nil {
			fmt.Println("Error flushing buffer")
			panic(err)
		}
	}
}

func (dddns *DDDNS) clientReader(rw *bufio.ReadWriter) string {

	message, err := rw.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading from buffer: ", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		fmt.Println("Error decoding: ", err)
	}
	res := &Message{}
	err = json.Unmarshal(decoded, res)

	if message == "" {
		return message
	}
	if message != "\n" {
		// Green console colour:        \x1b[32m
		// Reset console colour:        \x1b[0m
		log.Info(fmt.Sprintf("Receiving msg: \x1b[34m%s\x1b[0m", message))

	}
	log.Info(fmt.Sprintf("Message received: \x1b[32m%s\x1b[0m", decoded))
	return res.Data
}

func inputLoop(rw *bufio.ReadWriter) {
	stdReader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		sendData, err := stdReader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading from stdin")
			panic(err)
		}

		_, err = rw.WriteString(fmt.Sprintf("%s\n", sendData))
		if err != nil {
			fmt.Println("Error writing to buffer")
			panic(err)
		}
		err = rw.Flush()
		if err != nil {
			fmt.Println("Error flushing buffer")
			panic(err)
		}
	}
}

// Start initializes the DDNS with all required functions
func (dddns *DDDNS) Start() {
	dddns.initCtx()
	err := dddns.genKeys()
	if err != nil {
		panic(err)
	}
	dddns.initHost()
	dddns.bootstrap()
}

// Function to announce ourselves
func (dddns *DDDNS) announceLoop(rendezvous string) {
	for {
		if dddns.dht != nil {
			routingDiscovery := discovery.NewRoutingDiscovery(dddns.dht)
			log.Info("Announcing ourselves...")
			discovery.Advertise(dddns.ctx, routingDiscovery, rendezvous)
			log.Infof("Successfully announced! at: %s", rendezvous)
		}
		time.Sleep(RendezvousRefresh * time.Minute)
	}
}

// TODO, add Options
func (dddns *DDDNS) initHost() {
	// Use config port here
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", 44453))
	var err error
	dddns.host, err = libp2p.New(dddns.ctx,
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(dddns.privkey),
		libp2p.DefaultEnableRelay,
		libp2p.NATPortMap(),
		libp2p.DefaultSecurity,
	)
	if err != nil {
		panic(err)
	}
	log.Infof("Host created. Our libp2p PeerID is: \x1b[32m%s\x1b[0m", dddns.host.ID())

}

// Review method to get IP, it can change in order:
// getting IP from Addrs: [/ip4/127.0.0.1/tcp/44453 /ip4/173.249.54.25/tcp/44453 /ip4/172.17.0.1/tcp/44453 /ip4/172.33.0.1/tcp/44453 /ip4/172.18.0.1/tcp/44453]
func (dddns *DDDNS) getPublicIP() string {

	// To avoid an special internal docker subnet
	dnSubnet := "172.33.0.0/16"
	_, ipnetDn, _ := net.ParseCIDR(dnSubnet)

	addrs := dddns.host.Addrs()
	log.Infof("getting IP from Addrs: %v", addrs)
	var ip string = ""
	for _, addr := range addrs {
		netaddr, _ := manet.ToNetAddr(addr)
		if manet.IsPublicAddr(addr) && !ipnetDn.Contains(netaddr.(*net.TCPAddr).IP) {
			ip = netaddr.(*net.TCPAddr).IP.String()
			continue
		}
	}
	// If we fail to get the IP from the libp2p, try fallback from third party, centralized service
	if ip == "" {
		consensus := externalip.DefaultConsensus(nil, nil)
		netIP, err := consensus.ExternalIP()
		if err != nil {
			panic(err)
		}
		ip = netIP.String()
	}
	return ip
}

func (dddns *DDDNS) initCtx() {
	dddns.ctx = context.Background()
}

func (dddns *DDDNS) setHandler() {

	pid := dddns.clictx.GlobalString(flags.ProtocolID.Name)
	dddns.host.SetStreamHandler(protocol.ID(pid), dddns.handleStream)
}

func (dddns *DDDNS) Close() {
	err := dddns.host.Close()
	if err != nil {
		log.Error("Error closing p2p host.")
	}
}

func (dddns *DDDNS) genKeys() error {
	// Try to get key from fs
	keyfile := filepath.Join(dddns.clictx.GlobalString(flags.DataDir.Name), "nodekey")
	//If we don't have a nodekey we must to create a new one
	if _, err := os.Stat(keyfile); os.IsNotExist(err) {
		dddns.privkey, dddns.Pubkey, err = crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			panic(err)
		}
		privateKeyBytes, err := crypto.MarshalPrivateKey(dddns.privkey)
		if err != nil {
			panic(err)
		}
		kex := hex.EncodeToString(privateKeyBytes)

		// Dir must exist
		err = os.MkdirAll(dddns.clictx.GlobalString(flags.DataDir.Name), os.ModePerm)
		if err != nil {
			panic(err)
		}
		ioutil.WriteFile(keyfile, []byte(kex), 0600)
	} else {
		kex, _ := ioutil.ReadFile(keyfile)
		if err != nil {
			panic(err)
		}
		privateKeyBytes, err := hex.DecodeString(string(kex))
		if err != nil {
			panic(err)
		}
		dddns.privkey, err = crypto.UnmarshalPrivateKey(privateKeyBytes)
		if err != nil {
			panic(err)
		}
		dddns.Pubkey = dddns.privkey.GetPublic()
	}
	return nil
}

func (dddns *DDDNS) bootstrap() {
	var err error
	dddns.dht, err = dht.New(dddns.ctx, dddns.host)
	if err != nil {
		panic(err)
	}

	// Bootstrap the DHT. In the default configuration, this spawns a Background
	// thread that will refresh the peer table every five minutes.
	log.Debug("Bootstrapping the DHT")
	if err = dddns.dht.Bootstrap(dddns.ctx); err != nil {
		log.Error(err)
	}
	var peers []multiaddr.Multiaddr
	bootstrapNodeFlag := dddns.clictx.GlobalString(flags.BootstrapNode.Name)
	if len(bootstrapNodeFlag) == 0 {
		peers = dht.DefaultBootstrapPeers
	} else {
		addr, err := multiaddr.NewMultiaddr(bootstrapNodeFlag)
		if err != nil {
			log.Error(err)
		}
		peers = append(peers, addr)
	}

	log.Debug("Connecting to bootstrap nodes...")
	var wg sync.WaitGroup
	for _, peerAddr := range peers {
		peerinfo, _ := peer.AddrInfoFromP2pAddr(peerAddr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := dddns.host.Connect(dddns.ctx, *peerinfo); err != nil {
				log.Warn(err)
			} else {
				log.Info("Connection established with bootstrap node:", *peerinfo)
			}
		}()
	}
	wg.Wait()
}

// Resolve as client the IP of a peer
func (dddns *DDDNS) Resolve(id string) {
	target := dddns.clictx.GlobalString(flags.PublicKey.Name)
	routingDiscovery := discovery.NewRoutingDiscovery(dddns.dht)
	log.Info(fmt.Sprintf("Searching for peer identity \x1b[34m%s\x1b[0m", target))
	peerChan, err := routingDiscovery.FindPeers(dddns.ctx, id)
	if err != nil {
		panic(err)
	}

	for peer := range peerChan {
		if peer.ID == dddns.host.ID() {
			continue
		}
		log.Info(fmt.Sprintf("Found peer: \x1b[34m%s\x1b[0m", peer.ID))

		pid := dddns.clictx.GlobalString(flags.ProtocolID.Name)
		stream, err := dddns.host.NewStream(dddns.ctx, peer.ID, protocol.ID(pid))

		if err != nil {
			log.Warn("Connection failed:", err)
			continue
		} else {
			rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))

			m := Message{
				Type:      "GET",
				Timestamp: strconv.FormatInt(time.Now().Unix(), 10),
				Data:      "",
			}
			message, err := json.Marshal(m)
			if err != nil {
				panic(err)
			}
			log.Info(fmt.Sprintf("Sending msg: \x1b[95m%s\x1b[0m", message))

			_, err = rw.WriteString(fmt.Sprintf("%s\n", base64.StdEncoding.EncodeToString(message)))
			if err != nil {
				fmt.Println("Error writing to buffer")
				panic(err)
			}

			err = rw.Flush()
			if err != nil {
				fmt.Println("Error flushing buffer")
				panic(err)
			}
			ip := dddns.clientReader(rw)
			fmt.Println(ip)
			dddns.host.RemoveStreamHandler(protocol.ID(pid))
			return
		}
	}
}

// StartDaemon endless loop
func (dddns *DDDNS) StartDaemon() {
	go dddns.announceLoop(dddns.host.ID().String())
	dddns.setHandler()

	// This keeps the daemon running
	select {}
}

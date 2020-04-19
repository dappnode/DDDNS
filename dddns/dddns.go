package dddns

import (
	"bufio"
	"context"
	crypto_rand "crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	//"math"
	math_rand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

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
	dhtopts "github.com/libp2p/go-libp2p-kad-dht/opts"
	multiaddr "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
)

const (
	// VERSION of the app
	VERSION = "0.1"
	// RendezvousRefresh in minutes
	RendezvousRefresh = 30
)

// Feed random seed with 32 bytes
func init() {
	var b [32]byte
	_, err := crypto_rand.Read(b[:])
	if err != nil {
		panic("cannot seed math/rand package with cryptographically secure random number generator")
	}
	math_rand.Seed(int64(binary.LittleEndian.Uint64(b[:])))
}

// Message ...
// Should include a signature to validate it's the right answer
type Message struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Data      string `json:"data"`
	Signature []byte `json:"signature"`
	Nonce     uint32 `json:"nonce"`
}

// DDDNS type
// TODO: Use a config struct
type DDDNS struct {
	// Address to listen on
	Addr string

	// libp2p Host
	host             host.Host
	ctx              context.Context
	dht              *dht.IpfsDHT
	routingDiscovery *discovery.RoutingDiscovery
	privkey          crypto.PrivKey
	Pubkey           crypto.PubKey
	datadir          string
	// TODO: Should be array
	bootstrapNode string
	ProtID        string
	ID            string
	Port          int
}

// NewDDDNS creates a new DDDNS node
func NewDDDNS(port int, datadir string, bnode string, protid string) (dddns *DDDNS) {
	dddns = &DDDNS{
		ctx:           context.TODO(),
		Port:          port,
		datadir:       datadir,
		bootstrapNode: bnode,
		ProtID:        protid,
	}
	return
}

func (dddns *DDDNS) handleStream(stream network.Stream) {
	log.Debug("Got a new stream!")
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))

	go dddns.reader(rw)
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
			log.Error("Failed to get public IP: %s\n", err)
		}

		// Sign the received nonce
		noncebytes := make([]byte, 32)
		binary.LittleEndian.PutUint32(noncebytes, res.Nonce)
		signature, err := dddns.privkey.Sign(noncebytes)

		m := Message{
			Type:      "A",
			Timestamp: res.Timestamp,
			Data:      ip,
			Signature: signature,
			Nonce:     res.Nonce,
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

func (dddns *DDDNS) clientReader(rw *bufio.ReadWriter, id string, nonce uint32) string {

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
		log.Info(fmt.Sprintf("Receiving msg: \x1b[32m%s\x1b[0m", message))

	}

	// TODO: Check signature
	log.Debug(fmt.Sprintf("Message received: \x1b[32m%s\x1b[0m", decoded))

	pubkey := getPubKeyFromBase32(id)
	noncebytes := make([]byte, 32)
	binary.LittleEndian.PutUint32(noncebytes, res.Nonce)
	v, err := pubkey.Verify(noncebytes, res.Signature)
	if err != nil {
		log.Error("Error verifying signature: %s", err)
		// TODO: Better return
		return ""
	}
	if !v {
		log.Error("Error: Signature not valid!")
		return ""
	}

	return res.Data
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

func (dddns *DDDNS) initHost() {
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", dddns.Port))
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
	// If we fail to get the IP from the libp2p, try fallback from third party (centralized services)
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

	protid := dddns.ProtID
	dddns.host.SetStreamHandler(protocol.ID(protid), dddns.handleStream)
}

func (dddns *DDDNS) Close() {
	err := dddns.host.Close()
	if err != nil {
		log.Error("Error closing p2p host.")
	}
}

func (dddns *DDDNS) genKeys() error {
	// Try to get key from fs
	keyfile := filepath.Join(dddns.datadir, "nodekey")
	//If we don't have a nodekey we must to create a new one
	if _, err := os.Stat(keyfile); os.IsNotExist(err) {
		dddns.privkey, dddns.Pubkey, err = crypto.GenerateEd25519Key(crypto_rand.Reader)
		if err != nil {
			panic(err)
		}
		privateKeyBytes, err := crypto.MarshalPrivateKey(dddns.privkey)
		if err != nil {
			panic(err)
		}
		kex := hex.EncodeToString(privateKeyBytes)
		dddns.ID = getBase32FromPubKey(dddns.Pubkey)
		// Dir must exist

		err = os.MkdirAll(dddns.datadir, os.ModePerm)
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
		dddns.ID = getBase32FromPubKey(dddns.Pubkey)
	}
	return nil
}

func (dddns *DDDNS) bootstrap() {
	var err error

	opts := []dhtopts.Option{
		dhtopts.RoutingTableLatencyTolerance(time.Second * 5),
		dhtopts.MaxRecordAge(1 * time.Hour),
	}

	dddns.dht, err = dht.New(dddns.ctx, dddns.host, opts...)
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
	bootstrapNodeFlag := dddns.bootstrapNode
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
func (dddns *DDDNS) Resolve(id string) string {
	var ip string
	routingDiscovery := discovery.NewRoutingDiscovery(dddns.dht)
	log.Info(fmt.Sprintf("Searching for peer identity \x1b[34m%s\x1b[0m", id))
	peerChan, err := routingDiscovery.FindPeers(dddns.ctx, id)
	if err != nil {
		panic(err)
	}

	for peer := range peerChan {
		if peer.ID == dddns.host.ID() {
			continue
		}
		log.Info(fmt.Sprintf("Found peer: \x1b[34m%s\x1b[0m", peer.ID))

		protid := dddns.ProtID
		stream, err := dddns.host.NewStream(dddns.ctx, peer.ID, protocol.ID(protid))

		if err != nil {
			log.Warn("Connection failed:", err)
			continue
		} else {
			rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
			nonce := math_rand.Uint32()
			m := Message{
				Type:      "GET",
				Timestamp: strconv.FormatInt(time.Now().Unix(), 10),
				Data:      "",
				Nonce:     nonce,
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
			ip = dddns.clientReader(rw, id, nonce)
			// fmt.Println(ip)
			dddns.host.RemoveStreamHandler(protocol.ID(protid))
			return ip
		}
	}
	return ""
}

// StartDaemon endless loop
func (dddns *DDDNS) StartDaemon() {
	go dddns.announceLoop(dddns.ID)
	dddns.setHandler()

	// This keeps the daemon running
	select {}
}

func getBase32FromPubKey(key crypto.PubKey) string {
	keyBytes, err := crypto.MarshalPublicKey(key)
	if err != nil {
		panic(err)
	}
	// Return removing the padding (======)
	return strings.ToLower(base32.StdEncoding.EncodeToString(keyBytes))[0:58]
}

func getPubKeyFromBase32(id string) crypto.PubKey {
	// Add the removed padding
	if i := len(id) % 8; i != 0 {
		id += strings.Repeat("=", 8-i)
	}
	// ... and convert back to upper case
	keyBytes, err := base32.StdEncoding.DecodeString(strings.ToUpper(id))
	if err != nil {
		panic(err)
	}
	key, _ := crypto.UnmarshalPublicKey(keyBytes)
	if err != nil {
		panic(err)
	}
	return key
}

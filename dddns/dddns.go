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
	// VERSION ...
	VERSION = "0.1"
	// RendezvousRefresh time in minutes
	// With larger values node may not be reachable
	RendezvousRefresh = 4
)

// Feed random seed with 32 bytes
func init() {
	var b [32]byte
	_, err := crypto_rand.Read(b[:])
	if err != nil {
		panic("Cannot seed with cryptographically secure random generator.")
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
			log.Errorf("Error reading from buffer: ", err)
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(message)
		if err != nil {
			log.Errorf("Error decoding: ", err)
			return
		}
		log.Debug(fmt.Sprintf("Receiving msg: \x1b[34m%s\x1b[0m", message))
		log.Debug(fmt.Sprintf("Message received: \x1b[34m%s\x1b[0m", decoded))

		res := &Message{}
		err = json.Unmarshal(decoded, res)
		if err != nil {
			log.Errorf("Error decoding: ", err)
			return
		}

		ip, err := dddns.getPublicIP()
		if err != nil {
			log.Errorf("Failed to get public IP: %s\n", err)
			return
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
			log.Errorf("Error encoding message: %s\n", err)
			return
		}
		_, err = rw.WriteString(fmt.Sprintf("%s\n", base64.StdEncoding.EncodeToString(msg)))
		if err != nil {
			log.Errorf("Error writing to buffer")
		}
		err = rw.Flush()
		if err != nil {
			log.Errorf("Error flushing buffer")
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
	log.Debug(fmt.Sprintf("Receiving msg: \x1b[32m%s\x1b[0m", message))
	log.Debug(fmt.Sprintf("Message received: \x1b[32m%s\x1b[0m", decoded))

	pubkey := getPubKeyFromBase32(id)
	noncebytes := make([]byte, 32)
	binary.LittleEndian.PutUint32(noncebytes, res.Nonce)
	v, err := pubkey.Verify(noncebytes, res.Signature)
	if err != nil {
		log.Errorf("Error verifying signature: %s", err)
		// TODO: Better return / error handling
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
	dddns.ctx = context.Background()
	err := dddns.genKeys()
	if err != nil {
		log.Errorf("Error generating keys: %s", err)
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
			discovery.Advertise(dddns.ctx, routingDiscovery, rendezvous)
			log.Debugf("Announced to rendezvous at: %s", rendezvous)
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
		log.Errorf("Error initalizing libp2p host: %s", err)
		return
	}
	log.Infof("Host created. Our libp2p PeerID is: %s", dddns.host.ID())

}

func (dddns *DDDNS) getPublicIP() (string, error) {

	// To avoid an internal docker subnet
	dnSubnet := "172.33.0.0/16"
	_, ipnetDn, _ := net.ParseCIDR(dnSubnet)

	addrs := dddns.host.Addrs()
	log.Debugf("getting IP from Addrs: %v", addrs)
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
			log.Errorf("Error getting getting IP from external source: %s", err)
			return "", err
		}
		ip = netIP.String()
	}
	return ip, nil
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
			log.Errorf("Error generating key: %s", err)
			return err
		}
		privateKeyBytes, err := crypto.MarshalPrivateKey(dddns.privkey)
		if err != nil {
			log.Errorf("Error marshalling key: %s", err)
			return err
		}
		kex := hex.EncodeToString(privateKeyBytes)
		dddns.ID = getBase32FromPubKey(dddns.Pubkey)
		// Dir must exist

		err = os.MkdirAll(dddns.datadir, os.ModePerm)
		if err != nil {
			log.Errorf("Error creating data directory: %s", err)
			return err
		}
		ioutil.WriteFile(keyfile, []byte(kex), 0600)
	} else {
		kex, _ := ioutil.ReadFile(keyfile)
		if err != nil {
			log.Errorf("Error reading key: %s", err)
			return err
		}
		privateKeyBytes, err := hex.DecodeString(string(kex))
		if err != nil {
			log.Errorf("Error decoding key: %s", err)
			return err
		}
		dddns.privkey, err = crypto.UnmarshalPrivateKey(privateKeyBytes)
		if err != nil {
			log.Errorf("Error unmarshalling key: %s", err)
			return err
		}
		dddns.Pubkey = dddns.privkey.GetPublic()
		dddns.ID = getBase32FromPubKey(dddns.Pubkey)
	}
	log.Infof("Our node ID is: \x1b[32m%s\x1b[0m", dddns.ID)
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
		log.Fatalf("Error creating DHT: %s", err)
		return
	}

	// Bootstrap the DHT. In the default configuration, this spawns a Background
	// thread that will refresh the peer table every five minutes.
	log.Debug("Bootstrapping the DHT")
	if err = dddns.dht.Bootstrap(dddns.ctx); err != nil {
		log.Fatalf("Error bootstrapping DHT: %s", err)
		return
	}
	var peers []multiaddr.Multiaddr
	if len(dddns.bootstrapNode) == 0 {
		peers = dht.DefaultBootstrapPeers
	} else {
		addr, err := multiaddr.NewMultiaddr(dddns.bootstrapNode)
		if err != nil {
			log.Errorf("Error getting multiaddr from %s: %s", dddns.bootstrapNode, err)
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
				log.Warnf("Error connecting to peer: %s", err)
			} else {
				log.Debug("Connection established with bootstrap node:", *peerinfo)
			}
		}()
	}
	wg.Wait()
}

// Resolve as client the IP of a peer
func (dddns *DDDNS) Resolve(id string) string {
	var ip string
	routingDiscovery := discovery.NewRoutingDiscovery(dddns.dht)
	log.Debug(fmt.Sprintf("Searching for peer identity \x1b[34m%s\x1b[0m", id))
	peerChan, err := routingDiscovery.FindPeers(dddns.ctx, id)
	if err != nil {
		log.Error("Error finding peers: %s", err)
		panic(err)
	}

	for peer := range peerChan {
		if peer.ID == dddns.host.ID() {
			continue
		}
		log.Debug(fmt.Sprintf("Found peer: \x1b[34m%s\x1b[0m", peer.ID))

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
				log.Errorf("Error encoding message: %s\n", err)
				return ""
			}

			log.Debugf(fmt.Sprintf("Sending msg: \x1b[95m%s\x1b[0m", message))

			_, err = rw.WriteString(fmt.Sprintf("%s\n", base64.StdEncoding.EncodeToString(message)))
			if err != nil {
				log.Errorf("Error writing to buffer: %s", err)
				return ""
			}
			err = rw.Flush()
			if err != nil {
				log.Errorf("Error flushing buffer: %s", err)
				return ""
			}
			ip = dddns.clientReader(rw, id, nonce)
			dddns.host.RemoveStreamHandler(protocol.ID(protid))
			return ip
		}
	}
	return ""
}

// StartDaemon endless loop
func (dddns *DDDNS) StartDaemon() {

	dddns.host.SetStreamHandler(protocol.ID(dddns.ProtID), dddns.handleStream)
	go dddns.announceLoop(dddns.ID)

	// This keeps the daemon running
	select {}
}

func getBase32FromPubKey(key crypto.PubKey) string {
	keyBytes, err := crypto.MarshalPublicKey(key)
	if err != nil {
		panic(err)
	}
	// Return trimming the padding (======)
	return strings.Trim(strings.ToLower(base32.StdEncoding.EncodeToString(keyBytes)), "=")
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

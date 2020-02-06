package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/ecies"

	"github.com/dappnode/dddns/log"
	eth "github.com/ethereum/go-ethereum/crypto"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"

	// Deprecated!
	crypto "github.com/libp2p/go-libp2p-crypto"
	discovery "github.com/libp2p/go-libp2p-discovery"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	multiaddr "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr-net"
)

var client *bool
var config Config

// Message ...
type Message struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Data      string `json:"data"`
}

// DDDNS type
type DDDNS struct {
	// Address to listen on
	Addr string

	// libp2p Host
	host             host.Host
	ctx              context.Context
	dht              *dht.IpfsDHT
	routingDiscovery *discovery.RoutingDiscovery
	// Public IP if not nil
	PubIP  *string
	client bool
	Config Config
}

func handleStream(stream network.Stream) {
	log.Info("Got a new stream!")

	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))

	go readData(rw)
	//go writeData(rw)

	// 'stream' will stay open until you close it (or the other side closes it).
}

func readData(rw *bufio.ReadWriter) {

	for {
		message, err := rw.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading from buffer: ", err)
		}

		decoded, err := base64.StdEncoding.DecodeString(message)

		if message == "" {
			return
		}
		if message != "\n" {
			// Green console colour:        \x1b[32m
			// Reset console colour:        \x1b[0m
			log.Info(fmt.Sprintf("Receiving encrypted msg: \x1b[34m%s\x1b[0m", message))

		}
		keyfile := filepath.Join(config.DataDir, "nodekey")

		key, err := eth.LoadECDSA(keyfile)
		if err != nil {
			panic(err)
		}
		cpk := eth.CompressPubkey(&key.PublicKey)
		address := hexutil.Encode(cpk)
		pk := ecies.ImportECDSA(key)

		decryptMessage, err := pk.Decrypt(decoded, nil, nil)
		if err != nil {
			log.Error(err)
		}
		log.Info(fmt.Sprintf("Decrypted message received: \x1b[34m%s\x1b[0m", decryptMessage))

		if !*client {

			// New Message
			res := &Message{}
			err = json.Unmarshal(decryptMessage, res)
			if err != nil {
				log.Error(err)
			}

			decodeAddress, err := hexutil.Decode(res.PublicKey)
			if err != nil {
				panic(err)
			}
			desPuBKey, err := eth.DecompressPubkey(decodeAddress)
			if err != nil {
				log.Error(err)
				panic(err)
			}
			responsePubKey := ecies.ImportECDSAPublic(desPuBKey)

			cmd := exec.Command("ip", "route", "get", "1")
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.Error("cmd.Run() failed with %s\n", err)
			}

			reg := regexp.MustCompile(`src (.*) uid`)

			ipTmp := reg.FindString(string(out))
			reg2 := regexp.MustCompile(` (.*) `)
			ip := strings.TrimSpace(reg2.FindString(string(ipTmp)))
			if err != nil {
				log.Error("cmd.Run() failed with %s\n", err)
			}

			m := Message{
				Type:      "IP",
				Timestamp: res.Timestamp,
				Random:    res.Random,
				PublicKey: address,
				Data:      ip,
			}

			message, err := json.Marshal(m)
			if err != nil {
				panic(err)
			}

			ct, err := ecies.Encrypt(rand.Reader, responsePubKey, message, nil, nil)
			if err != nil {
				log.Fatal(err)
			}

			_, err = rw.WriteString(fmt.Sprintf("%s\n", base64.StdEncoding.EncodeToString(ct)))
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
}

func (dddns *DDDNS) reader(rw *bufio.ReadWriter) {
	for {
		message, err := rw.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading from buffer: ", err)
		}

		decoded, err := base64.StdEncoding.DecodeString(message)
		if err != nil {
			fmt.Println("Error decoding: ", err)
		}

		if message == "" {
			return
		}
		if message != "\n" {
			// Green console colour:        \x1b[32m
			// Reset console colour:        \x1b[0m
			log.Info(fmt.Sprintf("Receiving msg: \x1b[34m%s\x1b[0m", message))

		}
		log.Info(fmt.Sprintf("Message received: \x1b[34m%s\x1b[0m", decoded))

		// New Message if server
		if !dddns.client {
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
			}

			message, err := json.Marshal(m)
			if err != nil {
				panic(err)
			}

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
		}
	}
}

// func writeData(rw *bufio.ReadWriter) {
// 	stdReader := bufio.NewReader(os.Stdin)

// 	for {
// 		fmt.Print("> ")
// 		sendData, err := stdReader.ReadString('\n')
// 		if err != nil {
// 			fmt.Println("Error reading from stdin")
// 			panic(err)
// 		}

// 		_, err = rw.WriteString(fmt.Sprintf("%s\n", sendData))
// 		if err != nil {
// 			fmt.Println("Error writing to buffer")
// 			panic(err)
// 		}
// 		err = rw.Flush()
// 		if err != nil {
// 			fmt.Println("Error flushing buffer")
// 			panic(err)
// 		}
// 	}
// }

func main() {
	// log.SetAllLoggers(logging.ERROR)
	// log.SetLogLevel("dddns", "info")

	var err error
	help := flag.Bool("h", false, "Display Help")
	client = flag.Bool("client", false, "Client mode")
	config, err = parseFlags()
	if err != nil {
		panic(err)
	}

	if *help {
		fmt.Println("DDDNS (Decentralized Dynamic Domain Name Service")
		fmt.Println()
		fmt.Println("Usage: Run './dddns ...")
		flag.PrintDefaults()
		return
	}

	if *client {
		log.Info(fmt.Sprintf("\x1b[32m%s\x1b[0m", "Running client mode!"))
	}

	// // Get the address
	// //address := eth.PubkeyToAddress(key.PublicKey).Hex()
	// cpk := eth.CompressPubkey(&key.PublicKey)
	// address := hexutil.Encode(cpk)

	// log.Info(fmt.Sprintf("Public Address: \x1b[32m%s\x1b[0m", address))

	// // Get the private key
	// privateKey := hex.EncodeToString(key.D.Bytes())

	// // 0.0.0.0 will listen on any interface device.
	// sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", 45678))
	// prvKey, _, err := crypto.GenerateKeyPairWithReader(crypto.ECDSA, 2048, strings.NewReader(privateKey))

	// Set a function as stream handler. This function is called when a peer
	// initiates a connection and starts a stream with this peer.

}

// NewDDNS creator
func NewDDNS(config Config) (dddns *DDDNS) {
	dddns = &DDDNS{
		Config: config,
	}
	return
}

// Start initializes the DDNS with all functions
func (dddns *DDDNS) Start() {
	dddns.initCtx()
	prvKey, _, err := dddns.getKeys()
	if err != nil {
		panic(err)
	}
	dddns.initHost(prvKey)
	dddns.bootstrap()
	if !dddns.client {
		dddns.announce(dddns.host.ID().String())
		dddns.setHandler()
	} else {
		dddns.resolve('someaddr')
	}
}

// Function to announce ourselves
func (dddns *DDDNS) announce(rendezvous string) {
	if dddns.dht != nil {
		routingDiscovery := discovery.NewRoutingDiscovery(dddns.dht)
		log.Info("Announcing ourselves...")
		discovery.Advertise(dddns.ctx, routingDiscovery, rendezvous)
		log.Info("Successfully announced!", rendezvous)
	}
}

// TODO, add Options
func (dddns *DDDNS) initHost(prvKey crypto.PrivKey) {
	// Use config port here
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", 45678))
	var err error
	dddns.host, err = libp2p.New(dddns.ctx,
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(prvKey),
		libp2p.DefaultEnableRelay,
		libp2p.NATPortMap(),
	)
	log.Info(fmt.Sprintf("Host created. Our libp2p PeerID is: \x1b[32m%s\x1b[0m", dddns.host.ID()))
	if err != nil {
		panic(err)
	}
}

func (dddns *DDDNS) getPublicIP() string {
	addrs := dddns.host.Addrs()
	var ip string
	if (len(addrs) > 0) && manet.IsPublicAddr(addrs[len(addrs)-1]) {
		addr, _ := manet.ToNetAddr(addrs[len(addrs)-1])
		ip = strings.Split(addr.String(), ":")[0]

	} else {
		// try fallback from third party service
		return ""
	}
	return ip
}

func (dddns *DDDNS) initCtx() {
	dddns.ctx = context.Background()
}

func (dddns *DDDNS) setHandler() {
	dddns.host.SetStreamHandler(protocol.ID(config.ProtocolID), handleStream)
}

func (dddns *DDDNS) getKeys() (crypto.PrivKey, crypto.PubKey, error) {
	// Try to get key from fs
	keyfile := filepath.Join(dddns.Config.DataDir, "nodekey")
	var privateKey crypto.PrivKey
	var publicKey crypto.PubKey
	//If we don't have a nodekey we must to create a new one
	if _, err := os.Stat(keyfile); os.IsNotExist(err) {
		privateKey, publicKey, err = crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			panic(err)
		}
		privateKeyBytes, err := crypto.MarshalPrivateKey(privateKey)
		if err != nil {
			panic(err)
		}
		kex := hex.EncodeToString(privateKeyBytes)
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
		privateKey, err := crypto.UnmarshalEd25519PrivateKey(privateKeyBytes)
		if err != nil {
			panic(err)
		}
		publicKey = privateKey.GetPublic()
	}
	return privateKey, publicKey, nil
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

	log.Debug("Connecting to bootstrap nodes...")
	var wg sync.WaitGroup
	for _, peerAddr := range config.BootstrapPeers {
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
func (dddns *DDDNS) resolve(id string) {
	routingDiscovery := discovery.NewRoutingDiscovery(dddns.dht)
	log.Info(fmt.Sprintf("Searching for peer identity \x1b[34m%s\x1b[0m", config.ServerPublicKey))
	peerChan, err := routingDiscovery.FindPeers(dddns.ctx, id)
	if err != nil {
		panic(err)
	}

	for peer := range peerChan {
		if peer.ID == dddns.host.ID() {
			continue
		}
		log.Info(fmt.Sprintf("Found peer: \x1b[34m%s\x1b[0m", peer.ID))
		stream, err := dddns.host.NewStream(dddns.ctx, peer.ID, protocol.ID(config.ProtocolID))

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
			go dddns.reader(rw)
		}
	}
}

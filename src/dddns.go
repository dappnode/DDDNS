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
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"os/exec"
	"regexp"

	"github.com/ethereum/go-ethereum/common/hexutil"

	eth "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ipfs/go-log"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	crypto "github.com/libp2p/go-libp2p-crypto"
	discovery "github.com/libp2p/go-libp2p-discovery"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	multiaddr "github.com/multiformats/go-multiaddr"
	logging "github.com/whyrusleeping/go-logging"
)

var logger = log.Logger("dddns")

var client *bool
var config Config

// Message ...
type Message struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Random    string `json:"random"`
	PublicKey string `json:"publickey"`
	Data      string `json:"data"`
}

func handleStream(stream network.Stream) {
	logger.Info("Got a new stream!")

	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))

	go readData(rw)
	go writeData(rw)

	// 'stream' will stay open until you close it (or the other side closes it).
}

func readData(rw *bufio.ReadWriter) {

	for {
		message, err := rw.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading from buffer: ",err)
		}

		decoded, err := base64.StdEncoding.DecodeString(message)

		if message == "" {
			return
		}
		if message != "\n" {
			// Green console colour:        \x1b[32m
			// Reset console colour:        \x1b[0m
			logger.Info(fmt.Sprintf("Receiving encrypted msg: \x1b[34m%s\x1b[0m",message))
			
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
			logger.Error(err)
		}
		logger.Info(fmt.Sprintf("decrypted message received: \x1b[34m%s\x1b[0m",decryptMessage))


		if !*client {

			// New Message
			res := &Message{}
			err = json.Unmarshal(decryptMessage, res)
			if err != nil {
				logger.Error(err)
			}

			decodeAddress, err := hexutil.Decode(res.PublicKey)
			if err != nil {
				panic(err)
			}
			desPuBKey, err := eth.DecompressPubkey(decodeAddress)
			if err != nil {
				logger.Error(err)
				panic(err)
			}
			responsePubKey := ecies.ImportECDSAPublic(desPuBKey)

			cmd := exec.Command("ip", "route", "get","1")
			out, err := cmd.CombinedOutput()
			if err != nil {
				logger.Error("cmd.Run() failed with %s\n", err)
			}

			reg := regexp.MustCompile(`src (.*) uid`) 
  
			ipTmp:= reg.FindString(string(out))
			reg2 := regexp.MustCompile(` (.*) `) 
			ip := strings.TrimSpace(reg2.FindString(string(ipTmp)))
			if err != nil {
                                logger.Error("cmd.Run() failed with %s\n", err)
                        }

			m := Message{
				Type:      "IP",
				Timestamp: res.Timestamp,
				Random:    res.Random,
				PublicKey: address,
				Data:      ip,
			}

			b, err := json.Marshal(m)
			if err != nil {
				panic(err)
			}


			message := b

			ct, err := ecies.Encrypt(rand.Reader, responsePubKey, message, nil, nil)
			if err != nil {
				logger.Fatal(err)
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

func writeData(rw *bufio.ReadWriter) {
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

func main() {
	log.SetAllLoggers(logging.ERROR)
	log.SetLogLevel("dddns", "info")

	var err error
	help := flag.Bool("h", false, "Display Help")
	client = flag.Bool("client", false, "Client mode")
	config, err = ParseFlags()
	if err != nil {
		panic(err)
	}

	if *help {
		fmt.Println("DDDNS (Decentralized Dynamic Domain Name Service")
		fmt.Println()
		fmt.Println("Usage: Run './dddns.go ...")
		flag.PrintDefaults()
		return
	}

	if *client {
		logger.Info(fmt.Sprintf("\x1b[32m%s\x1b[0m", "Running client mode!"))
	}

	ctx := context.Background()
	var key *ecdsa.PrivateKey

	keyfile := filepath.Join(config.DataDir, "nodekey")

	//If we don't have a nodekey we must to create a new one
	if _, err := os.Stat(keyfile); os.IsNotExist(err) {
		// Create an account
		key, err = eth.GenerateKey()
		if err != nil {
			panic(err)
		}
		eth.SaveECDSA(keyfile, key)
	} else {
		key, err = eth.LoadECDSA(keyfile)
		if err != nil {
			panic(err)
		}
	}
	// Get the address
	//address := eth.PubkeyToAddress(key.PublicKey).Hex()
	cpk := eth.CompressPubkey(&key.PublicKey)
	address := hexutil.Encode(cpk)
	
	logger.Info(fmt.Sprintf("Public Address: \x1b[32m%s\x1b[0m",address))

	// Get the private key
	privateKey := hex.EncodeToString(key.D.Bytes())

	// 0.0.0.0 will listen on any interface device.
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", 45678))
	prvKey, _, err := crypto.GenerateKeyPairWithReader(crypto.ECDSA, 2048, strings.NewReader(privateKey))

	// libp2p.New constructs a new libp2p Host.
	host, err := libp2p.New(ctx,
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(prvKey),
	)
	if err != nil {
		panic(err)
	}

	logger.Info(fmt.Sprintf("Host created. Our libp2p PeerID is: \x1b[32m%s\x1b[0m",host.ID()))

	// Set a function as stream handler. This function is called when a peer
	// initiates a connection and starts a stream with this peer.
	host.SetStreamHandler(protocol.ID(config.ProtocolID), handleStream)

	// Start a DHT, for use in peer discovery. We can't just make a new DHT
	// client because we want each peer to maintain its own local copy of the
	// DHT, so that the bootstrapping node of the DHT can go down without
	// inhibiting future peer discovery.
	kademliaDHT, err := dht.New(ctx, host)
	if err != nil {
		panic(err)
	}

	// Bootstrap the DHT. In the default configuration, this spawns a Background
	// thread that will refresh the peer table every five minutes.
	logger.Debug("Bootstrapping the DHT")
	if err = kademliaDHT.Bootstrap(ctx); err != nil {
		panic(err)
	}

	// Let's connect to the bootstrap nodes first. They will tell us about the
	// other nodes in the network.
	logger.Info("Connecting to bootstrap nodes...")
	var wg sync.WaitGroup
	for _, peerAddr := range config.BootstrapPeers {
		peerinfo, _ := peer.AddrInfoFromP2pAddr(peerAddr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := host.Connect(ctx, *peerinfo); err != nil {
				logger.Warning(err)
			} else {
				logger.Info("Connection established with bootstrap node:", *peerinfo)
			}
		}()
	}
	wg.Wait()


	// We use a rendezvous point "meet me here" to announce our location.
	// This is like telling your friends to meet you at the Eiffel Tower.
	routingDiscovery := discovery.NewRoutingDiscovery(kademliaDHT)
	if !*client {
		logger.Info("Announcing ourselves...")
		discovery.Advertise(ctx, routingDiscovery, address)
		logger.Info("Successfully announced!", address)
	}

	// Now, look for others who have announced
	// This is like your friend telling you the location to meet you.
	if *client {
		logger.Info(fmt.Sprintf("Searching for peer identity \x1b[34m%s\x1b[0m",config.ServerPublicKey))
		peerChan, err := routingDiscovery.FindPeers(ctx, config.ServerPublicKey)
		if err != nil {
			panic(err)
		}

		for peer := range peerChan {
			if peer.ID == host.ID() {
				continue
			}
			logger.Info(fmt.Sprintf("Found peer: \x1b[34m%s\x1b[0m",peer.ID))
			stream, err := host.NewStream(ctx, peer.ID, protocol.ID(config.ProtocolID))

			if err != nil {
				logger.Warning("Connection failed:", err)
				continue
			} else {
				rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))

				randomNonce, err := rand.Int(rand.Reader, big.NewInt(1000000))
				if err != nil {
					panic(err)
				}
				m := Message{
					Type:      "GET",
					Timestamp: strconv.FormatInt(time.Now().Unix(), 10),
					Random:    randomNonce.String(),
					PublicKey: hexutil.Encode(eth.CompressPubkey(&key.PublicKey)),
					Data:      "",
				}
				message, err := json.Marshal(m)
				if err != nil {
					panic(err)
				}
				logger.Info(fmt.Sprintf("Sending msg: \x1b[95m%s\x1b[0m",message))

				decodeAddress, err := hexutil.Decode(config.ServerPublicKey)
				if err != nil {
					panic(err)
				}
				desPuBKey, err := eth.DecompressPubkey(decodeAddress)
				if err != nil {
					logger.Error(err)
					panic(err)
				}
				serverPK := ecies.ImportECDSAPublic(desPuBKey)

				ct, err := ecies.Encrypt(rand.Reader, serverPK, message, nil, nil)
				if err != nil {
					logger.Fatal(err)
				}
				logger.Info(fmt.Sprintf("Sending encrypted msg: \x1b[95m%s\x1b[0m",base64.StdEncoding.EncodeToString(ct)))

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
				go readData(rw)

			}
		}
	} else {
		logger.Info("Waiting for clients")
	}

	select {}

}

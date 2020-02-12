package nameserver

import (
	"github.com/dappnode/dddns/log"

	"github.com/miekg/dns"
)

// This (optional) DNS compatible nameserver will resolve addresses with the base32 encoding of the pubkey.
// Example: baareidiv6frlwaqewpu7mweupqvahyuoikki5uqpfk3awlke4baf6juqu.dddns

const DDNSZone = "dddns."

type NameServer struct {
	//log        *log.Logger
	zoneConfig map[string][]dns.RR
	dnsClient  *dns.Client
	dnsServer  *dns.Server
	started    bool
}

func (s *NameServer) Start(config *config.NodeState, log *log.Logger, options interface{}) error {
	s.log = log
	s.started = false
	s.zoneConfig = make(map[string][]dns.RR)
	if s.dnsClient == nil {
		s.dnsClient = new(dns.Client)
		s.dnsClient.Timeout = 60000000000 // 60 seconds timeout
	}
	return nil
}

func (s *NameServer) Stop() error {
	if s.started {
		s.dnsServer.Shutdown()
		s.started = false
	}
	return nil
}

func (s *NameServer) Start() error {
	current := s.config.GetCurrent()
	if current.DNSServer.Enable == false {
		return nil
	}
	s.LoadConfig(current)
	s.dnsServer = &dns.Server{Addr: current.DNSServer.Listen, Net: "udp"}
	dns.HandleFunc(DDNSZone, s.handleRequest)
	s.started = true
	go s.dnsServer.ListenAndServe()
	log.Debugln("Started nameserver on:", current.DNSServer.Listen)
	return nil
}

func (s *NameServer) handleRequest(w dns.ResponseWriter, r *dns.Msg) {}

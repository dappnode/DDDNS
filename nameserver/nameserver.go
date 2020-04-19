package nameserver

import (
	//"errors"
	"github.com/dappnode/dddns/dddns"
	"github.com/dappnode/dddns/log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// This (optional) DNS compatible nameserver will resolve addresses with the base32 encoding of the pubkey.
// Example: baareidiv6frlwaqewpu7mweupqvahyuoikki5uqpfk3awlke4baf6juqu.dddns

const DDNSZone = "dddns."

type NameServer struct {
	//log        *log.Logger
	dddns     *dddns.DDDNS
	dnsServer *dns.Server
	port      int
	host      string
	started   bool
}

func NewNameServer(port int, host string, dddns *dddns.DDDNS) *NameServer {
	return &NameServer{port: port, host: host, dddns: dddns, started: false}
}

func (s *NameServer) Start() error {
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(s.port))
	s.dnsServer = &dns.Server{Addr: addr,
		Net:          "udp",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	dns.HandleFunc(".", s.handleRequest)
	s.started = true
	go s.dnsServer.ListenAndServe()
	log.Infof("Started nameserver on: %s", addr)
	return nil
}

func (s *NameServer) Stop() error {
	if s.started {
		s.dnsServer.Shutdown()
		s.started = false
	}
	return nil
}
func (s *NameServer) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	domain := r.Question[0].Name
	log.Infof("Domain request: %s", domain)
	if strings.HasSuffix(domain, DDNSZone) {
		log.Infof("Has suffix: %s", DDNSZone)
		s.resolveRequest(w, r)
	} else {
		s.forwardRequest(w, r)
	}
}

func (s *NameServer) resolveRequest(w dns.ResponseWriter, r *dns.Msg) error {
	var (
		rr dns.RR
		a  net.IP
	)
	m := new(dns.Msg)
	m.SetReply(r)
	defer w.WriteMsg(m)

	domain := r.Question[0].Name

	target := strings.TrimSuffix(domain, "."+DDNSZone)
	ip := s.dddns.Resolve(target)
	a = net.ParseIP(ip)
	rr = &dns.A{
		Hdr: dns.RR_Header{Name: DDNSZone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
		A:   a.To4(),
	}
	m.Answer = append(m.Answer, rr)
	return nil
}

func (s *NameServer) forwardRequest(w dns.ResponseWriter, r *dns.Msg) {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)

	r.RecursionDesired = true
	server := config.Servers[0]

	if (config.Servers[0] == "127.0.0.1") && (len(config.Servers[1]) > 1) {
		server = config.Servers[1]
	} else {
		server = "1.1.1.1"
	}
	log.Infof("Querying %s!\n", server)
	r, _, err := c.Exchange(r, net.JoinHostPort(server, config.Port))
	if r == nil {
		log.Infof("*** error: %s\n", err.Error())
	} else if r.Rcode != dns.RcodeSuccess {
		log.Infof("*** invalid answer for name: %s\n", r.Question[0].Name)
	} else {
		// Print answer
		for _, a := range r.Answer {
			log.Infof("%v\n", a)
		}
		w.WriteMsg(r)
	}
	return
}

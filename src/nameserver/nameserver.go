package nameserver

import (
	//"errors"
	"github.com/dappnode/dddns/src/dddns"
	"github.com/dappnode/dddns/src/log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	DDNSZone         = "dddns."
	ResolvConfigFile = "/etc/resolv.conf"
	ForwardServer    = "1.1.1.1"
)

type NameServer struct {
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
	log.Infof("Started UDP nameserver on: %s", addr)
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
	m.RecursionDesired = true

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
	config, err := dns.ClientConfigFromFile(ResolvConfigFile)
	if err != nil {
		log.Errorf("Error loading config file: %s", ResolvConfigFile)
		return
	}
	c := new(dns.Client)

	r.RecursionDesired = true
	server := config.Servers[0]

	if (config.Servers[0] == "127.0.0.1") && (len(config.Servers[1]) > 1) {
		server = config.Servers[1]
	} else {
		server = ForwardServer
	}
	log.Infof("Forwarding query to: %s", server)
	r, _, err = c.Exchange(r, net.JoinHostPort(server, config.Port))
	if r == nil {
		log.Debugf("Error querying: %s", err.Error())
	} else if r.Rcode != dns.RcodeSuccess {
		log.Debugf("Invalid answer for name: %s", r.Question[0].Name)
	} else {
		// Print answer
		for _, a := range r.Answer {
			log.Debugf("%v\n", a)
		}
		w.WriteMsg(r)
	}
	return
}

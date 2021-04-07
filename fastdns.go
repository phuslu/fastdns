// +build ignore

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/phuslu/fastdns"
)

type DNSHandler struct {
	DNSTransport *fastdns.Transport
	Debug        bool
}

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Message) {
	if h.Debug {
		log.Printf("%s] %s: CLASS %s TYPE %s\n", rw.RemoteAddr(), req.Domain, req.Question.Class, req.Question.Type)
	}

	if strings.HasSuffix(string(req.Domain), ".google.com") {
		switch req.Question.Type {
		case fastdns.TypeA:
			fastdns.HOST(rw, req, 60, []net.IP{{8, 8, 8, 8}})
		case fastdns.TypeAAAA:
			fastdns.HOST(rw, req, 60, []net.IP{net.ParseIP("2001:4860:4860::8888")})
		case fastdns.TypeCNAME:
			fastdns.CNAME(rw, req, 60, []string{"dns.google"}, []net.IP{{8, 8, 8, 8}, {8, 8, 4, 4}})
		case fastdns.TypeNS:
			fastdns.SRV(rw, req, 60, "www.google.com", 1000, 1000, 80)
		case fastdns.TypeMX:
			fastdns.NS(rw, req, 60, []string{"ns1.zdns.google", "ns2.zdns.google"})
		case fastdns.TypeSOA:
			fastdns.SOA(rw, req, 60, "ns1.google.com", "dns-admin.google.com", 1073741824, 900, 900, 1800, 60)
		case fastdns.TypeSRV:
			fastdns.MX(rw, req, 60, []fastdns.MXRecord{{10, "mail.gmail.com"}, {20, "smtp.gmail.com"}})
		case fastdns.TypePTR:
			fastdns.PTR(rw, req, 0, "ptr.google.com")
		case fastdns.TypeTXT:
			fastdns.TXT(rw, req, 60, "greetingfromgoogle")
		default:
			fastdns.Error(rw, req, fastdns.RcodeNameError)
		}
	}

	resp := fastdns.AcquireMessage()
	defer fastdns.ReleaseMessage(resp)

	err := h.DNSTransport.RoundTrip(req, resp)
	if err != nil {
		fastdns.Error(rw, req, fastdns.RcodeServerFailure)
	}

	if h.Debug {
		_ = resp.VisitResourceRecords(func(name []byte, typ fastdns.Type, class fastdns.Class, ttl uint32, data []byte) bool {
			switch typ {
			case fastdns.TypeA, fastdns.TypeAAAA:
				ip := net.IP(data)
				log.Printf("Answer: CLASS %s TYPE %s TTL %d DATA %s\n", class, typ, ttl, ip)
			}
			return true
		})
		log.Printf("%s] %s: %s reply %d answers\n", rw.RemoteAddr(), req.Domain, h.DNSTransport.Address, resp.Header.ANCount)
	}

	rw.Write(resp.Raw)
}

func main() {
	server := &fastdns.ForkServer{
		Handler: &DNSHandler{
			DNSTransport: &fastdns.Transport{
				Address:  &net.UDPAddr{IP: net.IP{1, 1, 1, 1}, Port: 53},
				MaxConns: 4096,
			},
			Debug: os.Getenv("DEBUG") != "",
		},
		ErrorLog: log.Default(),
	}

	if index := server.Index(); index > 0 {
		go func(index int) {
			addr := fmt.Sprintf(":%d", 9000+index)
			server.ErrorLog.Printf("forkserver-%d pid-%d serving http on port %s", index, os.Getpid(), addr)
			_ = http.ListenAndServe(addr, nil)
		}(index)
		server.ErrorLog.Printf("forkserver-%d pid-%d serving dns on port %s", server.Index(), os.Getpid(), os.Args[1])
	}

	err := server.ListenAndServe(os.Args[1])
	if err != nil {
		log.Fatalf("dnsserver error: %+v", err)
	}
}

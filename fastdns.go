// +build ignore

package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/phuslu/fastdns"
)

type DNSHandler struct {
	Debug bool
}

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Message) {
	if h.Debug {
		log.Printf("%s] %s: CLASS %s TYPE %s\n", rw.RemoteAddr(), req.Domain, req.Question.Class, req.Question.Type)
	}

	switch req.Question.Type {
	case fastdns.TypeA:
		fastdns.HOST(rw, req, []net.IP{{10, 0, 0, 1}}, 300)
	case fastdns.TypeAAAA:
		fastdns.HOST(rw, req, []net.IP{net.ParseIP("2001:4860:4860::8888")}, 300)
	case fastdns.TypeCNAME:
		fastdns.CNAME(rw, req, []string{"dns.google"}, []net.IP{{8, 8, 8, 8}, {8, 8, 4, 4}}, 300)
	case fastdns.TypeNS:
		fastdns.SRV(rw, req, "www.google.com", 1000, 1000, 80, 300)
	case fastdns.TypeMX:
		fastdns.NS(rw, req, []string{"ns1.zdns.google", "ns2.zdns.google"}, 60)
	case fastdns.TypeSOA:
		fastdns.SOA(rw, req, "ns1.google.com", "dns-admin.google.com", 1073741824, 900, 900, 1800, 60, 60)
	case fastdns.TypeSRV:
		fastdns.MX(rw, req, []fastdns.MXRecord{{10, "mail.gmail.com"}, {20, "smtp.gmail.com"}}, 60)
	case fastdns.TypePTR:
		fastdns.PTR(rw, req, "ptr.example.com", 0)
	case fastdns.TypeTXT:
		fastdns.TXT(rw, req, "helloworld", 300)
	default:
		fastdns.Error(rw, req, fastdns.RcodeNameError)
	}
}

func main() {
	server := &fastdns.ForkServer{
		Handler: &DNSHandler{
			Debug: os.Getenv("DEBUG") != "",
		},
		Logger: log.Default(),
	}

	if index := server.Index(); index > 0 {
		go func(index int) {
			addr := fmt.Sprintf(":%d", 9000+index)
			server.Logger.Printf("forkserver-%d pid-%d serving http on port %s", index, os.Getpid(), addr)
			_ = http.ListenAndServe(addr, nil)
		}(index)
	}

	err := server.ListenAndServe(os.Args[1])
	if err != nil {
		log.Fatalf("dnsserver error: %+v", err)
	}
}

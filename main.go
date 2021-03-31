// +build ignore

package main

import (
	"log"
	"net"
	_ "net/http/pprof"
	"os"

	"github.com/phuslu/fastdns"
)

type DNSHandler struct {
	Debug bool
}

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Request) {
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
	case fastdns.TypeSRV:
		fastdns.SRV(rw, req, "www.google.com", 1000, 1000, 80, 300)
	case fastdns.TypeMX:
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
		Logger:       log.Default(),
		HTTPPortBase: 9000,
	}

	err := server.ListenAndServe(os.Args[1])
	if err != nil {
		log.Fatalf("dnsserver error: %+v", err)
	}
}

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

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, msg *fastdns.Message) {
	if h.Debug {
		log.Printf("%s] %s: CLASS %s TYPE %s\n", rw.RemoteAddr(), msg.Domain, msg.Question.Class, msg.Question.Type)
	}

	switch msg.Question.Type {
	case fastdns.TypeA:
		fastdns.HOST(rw, msg, []net.IP{{10, 0, 0, 1}}, 300)
	case fastdns.TypeAAAA:
		fastdns.HOST(rw, msg, []net.IP{net.ParseIP("2001:4860:4860::8888")}, 300)
	case fastdns.TypeCNAME:
		fastdns.CNAME(rw, msg, []string{"dns.google"}, []net.IP{{8, 8, 8, 8}, {8, 8, 4, 4}}, 300)
	case fastdns.TypeSRV:
		fastdns.SRV(rw, msg, "www.google.com", 1000, 1000, 80, 300)
	case fastdns.TypeMX:
		fastdns.MX(rw, msg, []fastdns.MXRecord{{10, "mail.gmail.com"}, {20, "smtp.gmail.com"}}, 60)
	case fastdns.TypePTR:
		fastdns.PTR(rw, msg, "ptr.example.com", 0)
	case fastdns.TypeTXT:
		fastdns.TXT(rw, msg, "helloworld", 300)
	default:
		fastdns.Error(rw, msg, fastdns.RcodeNameError)
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

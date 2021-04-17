## Getting Started

### A fastdoh server example
```go
package main

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/fastdns/fastdoh"
	"github.com/valyala/fasthttp"
)

type DNSHandler struct {
	DNSClient *fastdns.Client
	Debug     bool
}

// ServeDNS implements fastdns.Handler
func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Message) {
	if h.Debug {
		log.Printf("%s] %s: CLASS %s TYPE %s\n", rw.RemoteAddr(), req.Domain, req.Question.Class, req.Question.Type)
	}

	resp := fastdns.AcquireMessage()
	defer fastdns.ReleaseMessage(resp)

	err := h.DNSClient.Exchange(req, resp)
	if err == fastdns.ErrMaxConns {
		time.Sleep(10 * time.Millisecond)
		err = h.DNSClient.Exchange(req, resp)
	}
	if err != nil {
		fastdns.Error(rw, req, fastdns.RcodeServFail)
	}

	if h.Debug {
		_ = resp.VisitResourceRecords(func(name []byte, typ fastdns.Type, class fastdns.Class, ttl uint32, data []byte) bool {
			switch typ {
			case fastdns.TypeCNAME:
				log.Printf("%s.\t%d\t%s\t%s\t%s.\n", resp.DecodeName(nil, name), ttl, class, typ, resp.DecodeName(nil, data))
			case fastdns.TypeA, fastdns.TypeAAAA:
				log.Printf("%s.\t%d\t%s\t%s\t%s\n", resp.DecodeName(nil, name), ttl, class, typ, net.IP(data))
			}
			return true
		})
		log.Printf("%s] %s: %s reply %d answers\n", rw.RemoteAddr(), req.Domain, h.DNSClient.ServerAddr, resp.Header.ANCount)
	}

	_, _ = rw.Write(resp.Raw)
}

func main() {
	addr := os.Args[1]

	handler := (&fastdoh.DoHHandler{
		DNSQuery:   "/dns-query",
		DNSHandler: &DNSHandler{
			DNSClient: &fastdns.Client{
				ServerAddr: &net.UDPAddr{IP: net.IP{1, 1, 1, 1}, Port: 53},
				MaxConns:   8192,
			},
			Debug: os.Getenv("DEBUG") != "",
		},
		DoHStats: &fastdns.CoreStats{
			Prefix: "coredns_",
			Family: "1",
			Proto:  "http",
			Server: "doh://" + addr,
			Zone:   ".",
		},
	}).Handler

	log.Printf("start fast DoH server on %s", addr)
	err := fasthttp.ListenAndServe(addr, handler)
	if err != nil {
		log.Fatalf("listen and serve DNS/DoH error: %+v", err)
	}
}
```

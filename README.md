## Usage

```go
package main

import (
	"log"
	"net"
	"os"

	"github.com/phuslu/fastdns"
)

type DNSHandler struct {
	Debug bool
}

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Request) {
	addr, name := rw.RemoteAddr(), req.GetDomainName()
	if h.Debug {
		log.Printf("%s] %s: CLASS %s TYPE %s\n", addr, name, req.Question.Class, req.Question.Type)
	}

	if req.Question.Type != fastdns.QTypeA {
		fastdns.Error(rw, req, fastdns.NXDOMAIN)
		return
	}

	fastdns.Host(rw, req, []net.IP{net.IP{8, 8, 8, 8}}, 300)
}

func main() {
	server := &fastdns.ForkServer{
		Handler: &DNSHandler{
			Debug: os.Getenv("DEBUG") != "",
		},
		Logger:       log.New(os.Stderr, "", 0),
		HTTPPortBase: 9000,
	}

	err := server.ListenAndServe(":53")
	if err != nil {
		log.Fatalf("dnsserver error: %+v", err)
	}
}
```

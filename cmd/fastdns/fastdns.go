package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/valyala/fasthttp"
)

// DNSHandler is a fastdns Handler
type DNSHandler struct {
	DNSClient *fastdns.Client
	Debug     bool
}

// ServeDNS implements fastdns.Handler
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
		case fastdns.TypeSRV:
			fastdns.SRV(rw, req, 60, []net.SRV{{"www.google.com", 443, 1000, 1000}})
		case fastdns.TypeNS:
			fastdns.NS(rw, req, 60, []net.NS{{"ns1.zdns.google"}, {"ns2.zdns.google"}})
		case fastdns.TypeMX:
			fastdns.MX(rw, req, 60, []net.MX{{"mail.gmail.com", 10}, {"smtp.gmail.com", 10}}) // nolint
		case fastdns.TypeSOA:
			fastdns.SOA(rw, req, 60, net.NS{"ns1.google.com"}, net.NS{"dns-admin.google.com"}, 180, 900, 900, 1800, 60)
		case fastdns.TypePTR:
			fastdns.PTR(rw, req, 0, "ptr.google.com")
		case fastdns.TypeTXT:
			fastdns.TXT(rw, req, 60, "greetingfromgoogle")
		default:
			fastdns.Error(rw, req, fastdns.RcodeNameError)
		}
		return
	}

	resp := fastdns.AcquireMessage()
	defer fastdns.ReleaseMessage(resp)

	err := h.DNSClient.Exchange(req, resp)
	if err == fastdns.ErrMaxConns {
		time.Sleep(10 * time.Millisecond)
		err = h.DNSClient.Exchange(req, resp)
	}
	if err != nil {
		fastdns.Error(rw, req, fastdns.RcodeServerFailure)
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
	addr, addr2 := os.Args[1], ""
	if host, portStr, err := net.SplitHostPort(addr); err == nil {
		port, _ := strconv.Atoi(portStr)
		addr2 = fmt.Sprintf("%s:%d", host, port+1)
	}

	handler := &DNSHandler{
		DNSClient: &fastdns.Client{
			ServerAddr: &net.UDPAddr{IP: net.IP{1, 1, 1, 1}, Port: 53},
			MaxConns:   4096,
		},
		Debug: os.Getenv("DEBUG") != "",
	}

	stats := &fastdns.CoreStats{
		Family: "1",
		Proto:  "udp",
		Server: "dns://" + addr,
		Zone:   ".",
	}

	c := make(chan error)
	go func() {
		log.Printf("start fast DNS server on %s", addr)
		server := &fastdns.Server{
			Handler:  handler,
			Stats:    stats,
			ErrorLog: log.Default(),
		}
		c <- server.ListenAndServe(addr)
	}()

	go func() {
		log.Printf("start fast DoH server on %s", addr2)
		adapter := &fasthttpAdapter{
			FastdnsHandler: handler,
			FastdnsStats:   stats,
		}
		c <- fasthttp.ListenAndServe(addr2, adapter.Handler)
	}()

	log.Fatalf("listen and serve DNS/DoH error: %+v", <-c)
}

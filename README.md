# Fast DNS implementation for Go

[![godoc][godoc-img]][godoc]
[![release][release-img]][release]
[![goreport][goreport-img]][goreport]


## Features

* 0 Dependency
* Similar Interface with net/http
* Fast DoH Server Co-create with fasthttp
* Fast DNS Client with rich features
* Fast eDNS options
* Compatible metrics with coredns
* High Performance
    - 0-allocs dns request parser
    - 0-allocs dns records marshaller
    - worker pool + message pool
    - prefork + reuse_port + set_affinity


## Getting Started

### DNS Server
```go
package main

import (
	"log/slog"
	"net"
	"net/netip"
	"os"

	"github.com/phuslu/fastdns"
)

type DNSHandler struct {
	Debug bool
}

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Message) {
	if h.Debug {
		slog.Info("serve dns request", "domain", req.Domain, "class", req.Question.Class, "type", req.Question.Type)
	}

	switch req.Question.Type {
	case fastdns.TypeA:
		req.SetResponseHeader(fastdns.RcodeNoError, 1)
		req.AppendHOST1(600, netip.AddrFrom4([4]byte{8, 8, 8, 8}))
	case fastdns.TypeAAAA:
		ips := []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")}
		req.SetResponseHeader(fastdns.RcodeNoError, uint16(len(ips)))
		req.AppendHOST(600, ips)
	case fastdns.TypeCNAME:
		cnames, ips := []string{"dns.google"}, []netip.Addr{netip.MustParseAddr("8.8.8.8")}
		req.SetResponseHeader(fastdns.RcodeNoError, uint16(len(cnames)+len(ips)))
		req.AppendCNAME(600, cnames, ips)
	case fastdns.TypeSRV:
		srvs := []net.SRV{{"www.google.com", 443, 1000, 1000}}
		req.SetResponseHeader(fastdns.RcodeNoError, uint16(len(srvs)))
		req.AppendSRV(600, srvs)
	case fastdns.TypeNS:
		nameservers := []net.NS{{"ns1.google.com"}, {"ns2.google.com"}}
		req.SetResponseHeader(fastdns.RcodeNoError, uint16(len(nameservers)))
		req.AppendNS(600, nameservers)
	case fastdns.TypeSOA:
		mname := net.NS{Host: "ns1.google.com"}
		rname := net.NS{Host: "dns-admin.google.com"}
		req.SetResponseHeader(fastdns.RcodeNoError, 1)
		req.AppendSOA(600, mname, rname, 42, 900, 900, 1800, 60)
	case fastdns.TypeMX:
		mxs := []net.MX{{"mail.gmail.com", 10}, {"smtp.gmail.com", 10}}
		req.SetResponseHeader(fastdns.RcodeNoError, uint16(len(mxs)))
		req.AppendMX(600, mxs)
	case fastdns.TypePTR:
		ptr := "ptr.google.com"
		req.SetResponseHeader(fastdns.RcodeNoError, 1)
		req.AppendPTR(600, ptr)
	case fastdns.TypeTXT:
		txt := "iamatxtrecord"
		req.SetResponseHeader(fastdns.RcodeNoError, 1)
		req.AppendTXT(600, txt)
	default:
		req.SetResponseHeader(fastdns.RcodeFormErr, 0)
	}

	_, _ = rw.Write(req.Raw)
}

func main() {
	addr := ":53"

	server := &fastdns.ForkServer{
		Handler: &DNSHandler{
			Debug: os.Getenv("DEBUG") != "",
		},
		Stats: &fastdns.CoreStats{
			Prefix: "coredns_",
			Family: "1",
			Proto:  "udp",
			Server: "dns://" + addr,
			Zone:   ".",
		},
		ErrorLog: slog.Default(),
	}

	err := server.ListenAndServe(addr)
	if err != nil {
		slog.Error("dnsserver serve failed", "error", err)
	}
}
```

### DoH Client
```go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/phuslu/fastdns"
)

func main() {
	endpoint, _ := url.Parse("https://1.1.1.1/dns-query")

	client := &fastdns.Client{
		Addr: endpoint.String(),
		Dialer: &fastdns.HTTPDialer{
			Endpoint:  endpoint,
			Header: http.Header{
				"content-type": {"application/dns-message"},
				"user-agent":   {"fastdns/1.0"},
			},
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				TLSClientConfig: &tls.Config{
					NextProtos:         []string{"h2"},
					InsecureSkipVerify: false,
					ServerName:         endpoint.Hostname(),
					ClientSessionCache: tls.NewLRUClientSessionCache(1024),
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	fmt.Println(client.LookupHTTPS(ctx, "cloud.phus.lu"))
}
```

### DNS/eDNS Client Tool
```bash
$ go install github.com/phuslu/fastdns/cmd/fastdig@master
$ fastdig www.google.com @https://8.8.8.8/dns-query +subnet=1.2.3.0/24

; <<>> DiG 0.0.1-fastdns-go1.25.0 <<>> www.google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 589
;; flags: qr rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;www.google.com.                IN      A

;; ANSWER SECTION:
www.google.com. 300     IN      A       142.250.9.147
www.google.com. 300     IN      A       142.250.9.104
www.google.com. 300     IN      A       142.250.9.99
www.google.com. 300     IN      A       142.250.9.105
www.google.com. 300     IN      A       142.250.9.106
www.google.com. 300     IN      A       142.250.9.103

;; Query time: 30 msec
;; SERVER: https://8.8.8.8/dns-query#53(https://8.8.8.8/dns-query)
;; WHEN: Sat Oct 11 00:44:09 +08 2025
;; MSG SIZE  rcvd: 150
```

### DoH Server Example
```bash
$ go install github.com/phuslu/fastdns/cmd/fastdoh@master
$ fastdoh :8080
```

## High Performance

A Performance result as below, for daily benchmark results see [github actions][benchmark]
```
# go test -v -run=none -benchmem -bench=.
goos: linux
goarch: amd64
pkg: github.com/phuslu/fastdns
cpu: AMD EPYC 7763 64-Core Processor

BenchmarkMessageParseMessage-4        	80922766	        14.68 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageEncodeDomain-4       	100000000	        12.78 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageSetQuestion-4         	40993672	        30.27 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageSetResponseHeader-4   	320204428	         3.606 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageDecodeName-4          	52074597	        23.07 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageAppendHOST-4          	183561132	         6.544 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageAppendCNAME-4         	42692521	        27.77 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageAppendSRV-4           	50555230	        23.85 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageAppendNS-4            	32065906	        36.33 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageAppendSOA-4           	26630746	        45.05 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageAppendPTR-4           	54242904	        22.74 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageAppendMX-4            	61512556	        19.59 ns/op	       0 B/op	       0 allocs/op
BenchmarkMessageAppendTXT-4           	166240762	         7.213 ns/op	       0 B/op	       0 allocs/op
BenchmarkServerHandlerHOST1-4         	152072834	         7.914 ns/op	       0 B/op	       0 allocs/op
BenchmarkServerHandlerHOST-4          	130878036	         8.404 ns/op	       0 B/op	       0 allocs/op
BenchmarkServerHandlerCNAME-4         	36238018	        33.11 ns/op	       0 B/op	       0 allocs/op
BenchmarkServerHandlerSRV-4           	47581225	        25.69 ns/op	       0 B/op	       0 allocs/op
BenchmarkServerHandlerNS-4            	30977643	        39.82 ns/op	       0 B/op	       0 allocs/op
BenchmarkServerHandlerSOA-4           	22182384	        54.29 ns/op	       0 B/op	       0 allocs/op
BenchmarkServerHandlerMX-4            	42502989	        28.91 ns/op	       0 B/op	       0 allocs/op
BenchmarkServerHandlerPTR-4           	40598533	        28.77 ns/op	       0 B/op	       0 allocs/op
BenchmarkServerHandlerTXT-4           	100000000	        14.72 ns/op	       0 B/op	       0 allocs/op
BenchmarkServerUpdateStats-4          	39958220	        30.05 ns/op	       0 B/op	       0 allocs/op
BenchmarkServerAppendOpenMetrics-4    	  465868	      2662 ns/op	       0 B/op	       0 allocs/op

PASS
ok  	github.com/phuslu/fastdns
```

Here is the real-world flamegraph [![flamegraph][flamegraph]][flamegraph] when fastdns server reaches **1.4M QPS** on a single machine with Xeon 4216 and Intel X710.

## Acknowledgment
This dns server is inspired by [fasthttp][fasthttp], [rawdns][rawdns] and [miekg/dns][miekg/dns].

[godoc-img]: http://img.shields.io/badge/godoc-reference-blue.svg
[godoc]: https://godoc.org/github.com/phuslu/fastdns
[release-img]: https://img.shields.io/github/v/tag/phuslu/fastdns?label=release
[release]: https://github.com/phuslu/fastdns/releases
[goreport-img]: https://goreportcard.com/badge/github.com/phuslu/fastdns
[goreport]: https://goreportcard.com/report/github.com/phuslu/fastdns
[benchmark]: https://github.com/phuslu/fastdns/actions?query=workflow%3Abenchmark
[flamegraph]: https://cdn.jsdelivr.net/gh/phuslu/fastdns/torch.svg
[fasthttp]: https://github.com/valyala/fasthttp
[rawdns]: https://github.com/cirocosta/rawdns
[miekg/dns]: https://github.com/miekg/dns

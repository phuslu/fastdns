# Fast DNS implementation for Go

[![godoc][godoc-img]][godoc]
[![release][release-img]][release]
[![goreport][goreport-img]][goreport]


## Features

* 0 Dependency
* Similar Interface with net/http
* Fast DoH Server Co-create with fasthttp
* Fast DNS Client with rich features
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
		fastdns.HOST1(rw, req, 60, netip.AddrFrom4([4]byte{8, 8, 8, 8}))
	case fastdns.TypeAAAA:
		fastdns.HOST(rw, req, 60, []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")})
	case fastdns.TypeCNAME:
		fastdns.CNAME(rw, req, 60, []string{"dns.google"}, []netip.Addr{netip.MustParseAddr("8.8.8.8")})
	case fastdns.TypeSRV:
		fastdns.SRV(rw, req, 60, []net.SRV{{"www.google.com", 443, 1000, 1000}})
	case fastdns.TypeNS:
		fastdns.NS(rw, req, 60, []net.NS{{"ns1.google.com"}, {"ns2.google.com"}})
	case fastdns.TypeMX:
		fastdns.MX(rw, req, 60, []net.MX{{"mail.gmail.com", 10}, {"smtp.gmail.com", 10}})
	case fastdns.TypeSOA:
		fastdns.SOA(rw, req, 60, net.NS{"ns1.google"}, net.NS{"ns2.google"}, 60, 90, 90, 180, 60)
	case fastdns.TypePTR:
		fastdns.PTR(rw, req, 0, "ptr.google.com")
	case fastdns.TypeTXT:
		fastdns.TXT(rw, req, 60, "greetingfromgoogle")
	default:
		fastdns.Error(rw, req, fastdns.RcodeNXDomain)
	}
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
	"fmt"
	"net/url"
	"time"

	"github.com/phuslu/fastdns"
)

func main() {
	doh := "https://1.1.1.1/dns-query"

	client := &fastdns.Client{
		Addr: doh,
		Dialer: &fastdns.HTTPDialer{
			Endpoint:  func() (u *url.URL) { u, _ = url.Parse(doh); return }(),
			UserAgent: "fastdns/0.9",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	fmt.Println(client.LookupHTTPS(ctx, "cloud.phus.lu"))
}
```

### DoQ Client
```go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/phuslu/fastdns"
)

func main() {
	doq := "https://1.1.1.1/dns-query"

	client := &fastdns.Client{
		Addr: doq,
		Dialer: &fastdns.HTTPDialer{
			Endpoint:  func() (u *url.URL) { u, _ = url.Parse(doq); return }(),
			UserAgent: "fastdns/0.9",
			Transport: &http3.RoundTripper{
				DisableCompression: false,
				EnableDatagrams:    true,
				TLSClientConfig: &tls.Config{
					NextProtos:         []string{"h3"},
					InsecureSkipVerify: true,
					ServerName:         "1.1.1.1",
					ClientSessionCache: tls.NewLRUClientSessionCache(128),
				},
				QUICConfig: &quic.Config{
					DisablePathMTUDiscovery: false,
					EnableDatagrams:         true,
					MaxIncomingUniStreams:   200,
					MaxIncomingStreams:      200,
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	fmt.Println(client.LookupHTTPS(ctx, "cloud.phus.lu"))
}
```

### DNS Client Tool
```bash
$ go install github.com/phuslu/fastdns/cmd/fastdig@master
$ fastdig ip.phus.lu @https://1.1.1.1/dns-query

; <<>> DiG 0.0.1-Fastdns <<>> ip.phus.lu
;; global options: +cmd +noedns
;; Got answer:
;; ->>HEADER<<- opcode: Query, status: Success, id: 2775
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;ip.phus.lu.            IN      A

;; ANSWER SECTION:
ip.phus.lu.     299     IN      CNAME   phus.lu.
phus.lu.        299     IN      A       101.32.116.118

;; Query time: 15 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Mon Apr 12 22:07:16 +08 2021
;; MSG SIZE  rcvd: 58
```

### DoH Server Example
```bash
$ go install github.com/phuslu/fastdns/cmd/fastdoh@master
$ fastdoh :8080
```

## High Performance

A Performance result as below, for daily benchmark results see [github actions][benchmark]
```
# go test -v -cpu=1 -run=none -benchmem -bench=.
goos: linux
goarch: amd64
pkg: github.com/phuslu/fastdns
cpu: AMD EPYC 7763 64-Core Processor

BenchmarkHOST1-4               	56613120	        21.09 ns/op	       0 B/op	       0 allocs/op
BenchmarkHOST-4                	57722778	        20.82 ns/op	       0 B/op	       0 allocs/op
BenchmarkCNAME-4               	40001464	        30.00 ns/op	       0 B/op	       0 allocs/op
BenchmarkSRV-4                 	26439794	        44.84 ns/op	       0 B/op	       0 allocs/op
BenchmarkNS-4                  	22967035	        52.28 ns/op	       0 B/op	       0 allocs/op
BenchmarkSOA-4                 	19650216	        61.16 ns/op	       0 B/op	       0 allocs/op
BenchmarkPTR-4                 	50205879	        30.12 ns/op	       0 B/op	       0 allocs/op
BenchmarkMX-4                  	39453458	        29.81 ns/op	       0 B/op	       0 allocs/op
BenchmarkTXT-4                 	62278441	        19.15 ns/op	       0 B/op	       0 allocs/op
BenchmarkParseMessage-4        	83152729	        14.84 ns/op	       0 B/op	       0 allocs/op
BenchmarkSetQuestion-4         	37922407	        31.28 ns/op	       0 B/op	       0 allocs/op
BenchmarkSetResponseHeader-4   	336013587	         3.583 ns/op	       0 B/op	       0 allocs/op
BenchmarkDecodeName-4          	52855680	        22.86 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendHOSTRecord-4    	71025451	        16.81 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendCNAMERecord-4   	52953403	        23.92 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendSRVRecord-4     	30775414	        36.37 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendNSRecord-4      	27102512	        43.92 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendSOARecord-4     	21295884	        56.13 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendPTRRecord-4     	62573373	        24.38 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendMXRecord-4      	43072573	        28.30 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendTXTRecord-4     	100000000	        11.15 ns/op	       0 B/op	       0 allocs/op
BenchmarkUpdateStats-4         	40084848	        29.85 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendOpenMetrics-4   	  110046	     10824 ns/op	       0 B/op	       0 allocs/op
BenchmarkEncodeDomain-4        	100000000	        11.54 ns/op	       0 B/op	       0 allocs/op

PASS
ok  	github.com/phuslu/fastdns	30.430s
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

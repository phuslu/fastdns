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
# go test -v -cpu=1 -run=none -benchmem -bench=.
goos: linux
goarch: amd64
pkg: github.com/phuslu/fastdns
cpu: AMD EPYC 7763 64-Core Processor

BenchmarkHOST1-4                      	90622921	        13.13 ns/op	       0 B/op	       0 allocs/op
BenchmarkHOST-4                       	86702996	        13.97 ns/op	       0 B/op	       0 allocs/op
BenchmarkCNAME-4                      	40921741	        29.58 ns/op	       0 B/op	       0 allocs/op
BenchmarkSRV-4                        	41724364	        29.30 ns/op	       0 B/op	       0 allocs/op
BenchmarkNS-4                         	25308493	        46.98 ns/op	       0 B/op	       0 allocs/op
BenchmarkSOA-4                        	24272625	        50.31 ns/op	       0 B/op	       0 allocs/op
BenchmarkPTR-4                        	41139378	        26.34 ns/op	       0 B/op	       0 allocs/op
BenchmarkMX-4                         	42688246	        28.16 ns/op	       0 B/op	       0 allocs/op
BenchmarkTXT-4                        	88897778	        12.49 ns/op	       0 B/op	       0 allocs/op
BenchmarkParseMessage-4               	81886836	        14.72 ns/op	       0 B/op	       0 allocs/op
BenchmarkSetQuestion-4                	39833023	        29.96 ns/op	       0 B/op	       0 allocs/op
BenchmarkSetResponseHeader-4          	332957912	         3.608 ns/op	       0 B/op	       0 allocs/op
BenchmarkDecodeName-4                 	52066440	        23.08 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendHOSTRecord-4           	240075102	         4.993 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendCNAMERecord-4          	53928686	        22.39 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendSRVRecord-4            	53588487	        22.48 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendNSRecord-4             	28367340	        42.24 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendSOARecord-4            	27182631	        44.29 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendPTRRecord-4            	59003535	        20.30 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendMXRecord-4             	51977874	        23.10 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendTXTRecord-4            	192769546	         6.234 ns/op	       0 B/op	       0 allocs/op
BenchmarkUpdateStats-4                	39903940	        30.03 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendOpenMetrics-4          	  468852	      2552 ns/op	       0 B/op	       0 allocs/op
BenchmarkEncodeDomain-4               	100000000	        10.85 ns/op	       0 B/op	       0 allocs/op

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

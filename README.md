# Fast DNS implementation for Go

[![godoc][godoc-img]][godoc]
[![release][release-img]][release]
[![goreport][goreport-img]][goreport]
[![coverage][coverage-img]][coverage]


## Features

* 0 Dependency
* Similar Interface with net/http
* Fast DoH Server Co-manufactured with fasthttp
* Compatible metrics with coredns
* High Performance
    - 0-allocs dns request parser
    - 0-allocs dns records marshaller
    - worker pool + message pool
    - prefork + reuse_port + set_affinity


## Getting Started

### A fastdns server example
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

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Message) {
	if h.Debug {
		log.Printf("%s: CLASS %s TYPE %s\n", req.Domain, req.Question.Class, req.Question.Type)
	}

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
		fastdns.Error(rw, req, fastdns.RcodeNameError)
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
		}
		Logger: log.Default(),
	}

	err := server.ListenAndServe(addr)
	if err != nil {
		log.Fatalf("dnsserver error: %+v", err)
	}
}
```

### DoH Server
see https://github.com/phuslu/fastdns/tree/master/cmd/fastdns

### Command Tool
```bash
$ go get github.com/phuslu/fastdns/cmd/fastdig
$ fastdig ip.phus.lu @8.8.8.8

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

## High Performance

A Performance result as below, for daily benchmark results see [github actions][benchmark]
```
# go test -v -cpu=1 -run=none -benchmem -bench=.
goos: linux
goarch: amd64
pkg: github.com/phuslu/fastdns
cpu: Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz
BenchmarkHOST              	33714019	        35.50 ns/op	       0 B/op	       0 allocs/op
BenchmarkCNAME             	19525077	        61.67 ns/op	       0 B/op	       0 allocs/op
BenchmarkSRV               	18085641	        66.18 ns/op	       0 B/op	       0 allocs/op
BenchmarkNS                	14765006	        81.39 ns/op	       0 B/op	       0 allocs/op
BenchmarkSOA               	13095116	        90.40 ns/op	       0 B/op	       0 allocs/op
BenchmarkPTR               	25070546	        47.98 ns/op	       0 B/op	       0 allocs/op
BenchmarkMX                	22039374	        55.53 ns/op	       0 B/op	       0 allocs/op
BenchmarkTXT               	35151956	        34.15 ns/op	       0 B/op	       0 allocs/op
BenchmarkParseMessage      	44680574	        27.02 ns/op	       0 B/op	       0 allocs/op
BenchmarkSetQuestion       	24864686	        48.89 ns/op	       0 B/op	       0 allocs/op
BenchmarkSetRcode          	129398640	         9.38 ns/op	       0 B/op	       0 allocs/op
BenchmarkDecodeName        	30526934	        39.30 ns/op	       0 B/op	       0 allocs/op
BenchmarkEncodeDomain      	62231484	        19.30 ns/op	       0 B/op	       0 allocs/op

PASS
ok  	github.com/phuslu/fastdns	19.026s
```

Here is the real-world flamegraph [![flamegraph][flamegraph]][flamegraph] when fastdns reaches **1.2M QPS** on a single machine with Xeon 4216 and Intel X710.

## Acknowledgment
This dns server is inspired by [fasthttp][fasthttp], [rawdns][rawdns] and [miekg/dns][miekg/dns].

[godoc-img]: http://img.shields.io/badge/godoc-reference-blue.svg
[godoc]: https://godoc.org/github.com/phuslu/fastdns
[release-img]: https://img.shields.io/github/v/tag/phuslu/fastdns?label=release
[release]: https://github.com/phuslu/fastdns/releases
[goreport-img]: https://goreportcard.com/badge/github.com/phuslu/fastdns
[goreport]: https://goreportcard.com/report/github.com/phuslu/fastdns
[coverage-img]: http://gocover.io/_badge/github.com/phuslu/fastdns
[coverage]: https://gocover.io/github.com/phuslu/fastdns
[benchmark]: https://github.com/phuslu/fastdns/actions?query=workflow%3Abenchmark
[flamegraph]: https://cdn.jsdelivr.net/gh/phuslu/fastdns@0.2.1/torch.svg
[fasthttp]: https://github.com/valyala/fasthttp
[rawdns]: https://github.com/cirocosta/rawdns
[miekg/dns]: https://github.com/miekg/dns

# Fast DNS implementation for Go

[![godoc][godoc-img]][godoc]
[![release][release-img]][release]
[![goreport][goreport-img]][goreport]
[![coverage][coverage-img]][coverage]


## Features

* 0 Dependency
* Similar Interface with net/http
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
	server := &fastdns.ForkServer{
		Handler: &DNSHandler{
			Debug: os.Getenv("DEBUG") != "",
		},
		Logger: log.Default(),
	}

	err := server.ListenAndServe(":53")
	if err != nil {
		log.Fatalf("dnsserver error: %+v", err)
	}
}
```

### Command Tool
```bash
$ go get github.com/phuslu/fastdns/cmd/fastdig
$ fastdig www.microsoft.com @8.8.8.8

; <<>> DiG 0.0.1-Fastdns <<>> www.microsoft.com +noedns
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: Query, status: Success, id: 54012
;; flags: qr rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.microsoft.com.		IN	A

;; ANSWER SECTION:
www.microsoft.com.	2690	IN	CNAME	www.microsoft.com-c-3.edgekey.net
www.microsoft.com-c-3.edgekey.net.	408	IN	CNAME	www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net
www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.	330	IN	CNAME	e13678.dscb.akamaiedge.net
e13678.dscb.akamaiedge.net.	11	IN	A	23.195.153.175

;; Query time: 6 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Sun Apr 11 03:34:51 +08 2021
;; MSG SIZE  rcvd: 202
```

## High Performance

A Performance result as below, for daily benchmark results see [github actions][benchmark]
```
# go test -v -cpu=1 -run=none -benchmem -bench=.
goos: linux
goarch: amd64
pkg: github.com/phuslu/fastdns
cpu: Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz
BenchmarkHOST              	24803638	        48.38 ns/op	       0 B/op	       0 allocs/op
BenchmarkCNAME             	18300250	        65.59 ns/op	       0 B/op	       0 allocs/op
BenchmarkSRV               	16979125	        70.74 ns/op	       0 B/op	       0 allocs/op
BenchmarkNS                	13861065	        86.52 ns/op	       0 B/op	       0 allocs/op
BenchmarkSOA               	12355112	        97.15 ns/op	       0 B/op	       0 allocs/op
BenchmarkPTR               	21184699	        56.66 ns/op	       0 B/op	       0 allocs/op
BenchmarkMX                	19056997	        63.02 ns/op	       0 B/op	       0 allocs/op
BenchmarkTXT               	27121401	        44.27 ns/op	       0 B/op	       0 allocs/op
BenchmarkParseMessage      	48858211	        24.44 ns/op	       0 B/op	       0 allocs/op
BenchmarkSetQuestion       	26983996	        44.55 ns/op	       0 B/op	       0 allocs/op
BenchmarkEncodeDomain      	60727620	        19.34 ns/op	       0 B/op	       0 allocs/op

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

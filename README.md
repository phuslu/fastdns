# fastdns - fast dns server for go

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
		fastdns.HOST(rw, req, 300, []net.IP{{10, 0, 0, 1}})
	case fastdns.TypeAAAA:
		fastdns.HOST(rw, req, 300, []net.IP{net.ParseIP("2001:4860:4860::8888")})
	case fastdns.TypeCNAME:
		fastdns.CNAME(rw, req, 300, []string{"dns.google"}, []net.IP{{8, 8, 8, 8}, {8, 8, 4, 4}})
	case fastdns.TypeNS:
		fastdns.SRV(rw, req, 300, "www.google.com", 1000, 1000, 80)
	case fastdns.TypeMX:
		fastdns.NS(rw, req, 60, []string{"ns1.zdns.google", "ns2.zdns.google"})
	case fastdns.TypeSOA:
		fastdns.SOA(rw, req, 60, "ns1.google.com", "dns-admin.google.com", 42, 900, 900, 1800, 60)
	case fastdns.TypeSRV:
		fastdns.MX(rw, req, 60, []fastdns.MXRecord{{10, "mail.gmail.com"}, {20, "smtp.gmail.com"}})
	case fastdns.TypePTR:
		fastdns.PTR(rw, req, 0, "ptr.example.com")
	case fastdns.TypeTXT:
		fastdns.TXT(rw, req, 300, "helloworld")
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

## High Performance

A Performance result as below, for daily benchmark results see [github actions][benchmark]
```
# go test -v -cpu=1 -run=none -benchmem -bench=.
goos: linux
goarch: amd64
pkg: github.com/phuslu/fastdns
cpu: Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz
BenchmarkHOST              	24969481	        48.02 ns/op	       0 B/op	       0 allocs/op
BenchmarkCNAME             	18388495	        65.18 ns/op	       0 B/op	       0 allocs/op
BenchmarkSRV               	18291327	        65.63 ns/op	       0 B/op	       0 allocs/op
BenchmarkPTR               	21368215	        56.14 ns/op	       0 B/op	       0 allocs/op
BenchmarkMX                	19648399	        61.09 ns/op	       0 B/op	       0 allocs/op
BenchmarkTXT               	27348226	        43.87 ns/op	       0 B/op	       0 allocs/op
BenchmarkParseRequest      	45153006	        26.63 ns/op	       0 B/op	       0 allocs/op
BenchmarkEncodeDomain      	70016161	        17.11 ns/op	       0 B/op	       0 allocs/op
PASS
ok  	github.com/phuslu/fastdns	19.026s
```

Here is the real-world flamegraph [![flamegraph][flamegraph]][flamegraph] when fastdns reaches **1.2M QPS** in a single machine with Xeon 4216 and Intel X710.

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

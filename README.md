# fastdns - fast dns server for go

[![godoc][godoc-img]][godoc] [![release][release-img]][release] [![goreport][goreport-img]][goreport] [![coverage][coverage-img]][coverage]


## Features

* Dependency Free
* Simple Interface, similar with net/http
* High Performance
    - prefork + reuse_port + set_affinity
    - worker pool + memory pool
    - 0-allocs dns request parser
    - 0-allocs dns records marshaller


## Getting Started

```go
package main

import (
	"log"
	"net"
	_ "net/http/pprof"
	"os"

	"github.com/phuslu/fastdns"
)

type DNSHandler struct {
	Debug bool
}

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Request) {
	if h.Debug {
		log.Printf("%s: CLASS %s TYPE %s\n", req.Domain, req.Question.Class, req.Question.Type)
	}

	switch req.Question.Type {
	case fastdns.TypeA:
		fastdns.HOST(rw, req, []net.IP{{10, 0, 0, 1}}, 300)
	case fastdns.TypeAAAA:
		fastdns.HOST(rw, req, []net.IP{net.ParseIP("2001:4860:4860::8888")}, 300)
	case fastdns.TypeCNAME:
		fastdns.CNAME(rw, req, []string{"dns.google"}, []net.IP{{8, 8, 8, 8}, {8, 8, 4, 4}}, 300)
	case fastdns.TypeSRV:
		fastdns.SRV(rw, req, "www.google.com", 1000, 1000, 80, 300)
	case fastdns.TypeMX:
		fastdns.MX(rw, req, []fastdns.MXRecord{{10, "mail.gmail.com"}, {20, "smtp.gmail.com"}}, 60)
	case fastdns.TypePTR:
		fastdns.PTR(rw, req, "ptr.example.com", 0)
	case fastdns.TypeTXT:
		fastdns.TXT(rw, req, "helloworld", 300)
	default:
		fastdns.Error(rw, req, fastdns.RcodeNameError)
	}
}

func main() {
	server := &fastdns.ForkServer{
		Handler: &DNSHandler{
			Debug: os.Getenv("DEBUG") != "",
		},
		Logger:       log.Default(),
		HTTPPortBase: 9000,
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
BenchmarkHOST              	17677506	        67.69 ns/op	       0 B/op	       0 allocs/op
BenchmarkCNAME             	13310619	        89.37 ns/op	       0 B/op	       0 allocs/op
BenchmarkSRV               	13235827	        90.61 ns/op	       0 B/op	       0 allocs/op
BenchmarkPTR               	14475850	        83.27 ns/op	       0 B/op	       0 allocs/op
BenchmarkMX                	13991402	        85.74 ns/op	       0 B/op	       0 allocs/op
BenchmarkTXT               	18690344	        64.56 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendHostRecord  	57637756	        20.81 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendCNameRecord 	30262444	        39.51 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendSRVRecord   	27443810	        43.77 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendPTRRecord   	37948849	        31.66 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendMXRecord    	35865289	        33.83 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendTXTRecord   	67243420	        17.87 ns/op	       0 B/op	       0 allocs/op
BenchmarkParseRequest      	33742836	        35.73 ns/op	       0 B/op	       0 allocs/op
BenchmarkDecodeQName       	402798675	         2.978 ns/op	       0 B/op	       0 allocs/op
BenchmarkEncodeDomain      	60813676	        19.36 ns/op	       0 B/op	       0 allocs/op
PASS
ok  	github.com/phuslu/fastdns	19.064s
```

Here is the flamegraph [![flamegraph][flamegraph]][flamegraph] when fastdns reaches 1M QPS in a single machine with Xeon 4216 and Intel X710.

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
[flamegraph]: https://cdn.jsdelivr.net/gh/phuslu/fastdns/torch.svg
[fasthttp]: https://github.com/valyala/fasthttp
[rawdns]: https://github.com/cirocosta/rawdns
[miekg/dns]: https://github.com/miekg/dns

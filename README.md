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

	switch req.Question.Type {
	case fastdns.TypeA:
		fastdns.CNAME(rw, req, []string{"a.example.com"}, []net.IP{{8, 8, 8, 8}}, 300)
	case fastdns.TypeAAAA:
		fastdns.HOST(rw, req, []net.IP{net.ParseIP("::1")}, 300)
	case fastdns.TypeSRV:
		fastdns.SRV(rw, req, "service1.example.com", 1000, 1000, 80, 300)
	case fastdns.TypeMX:
		fastdns.MX(rw, req, []fastdns.MXRecord{{10, "mail.gmail.com"}, {20, "smtp.gmail.com"}}, 60)
	case fastdns.TypePTR:
		fastdns.PTR(rw, req, "ptr.example.com", 0)
	case fastdns.TypeTXT:
		fastdns.TXT(rw, req, "iamatxtrecord", 300)
	default:
		fastdns.Error(rw, req, fastdns.RcodeNotImplemented)
	}
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

## High Performance

A Performance result as below, for daily benchmark results see [github actions][benchmark]
```
BenchmarkHOST                   18412334            64.17 ns/op          0 B/op        0 allocs/op
BenchmarkCNAME                  13569256            88.55 ns/op          0 B/op        0 allocs/op
BenchmarkSRV                    13565667            86.18 ns/op          0 B/op        0 allocs/op
BenchmarkPTR                    14394494            80.65 ns/op          0 B/op        0 allocs/op
BenchmarkMX                     14018642            82.41 ns/op          0 B/op        0 allocs/op
BenchmarkTXT                    19182474            62.08 ns/op          0 B/op        0 allocs/op
BenchmarkAppendHostRecord       59952037            19.19 ns/op          0 B/op        0 allocs/op
BenchmarkAppendCNameRecord      32140732            36.30 ns/op          0 B/op        0 allocs/op
BenchmarkAppendSRVRecord        34749872            34.69 ns/op          0 B/op        0 allocs/op
BenchmarkAppendPTRRecord        44071792            27.68 ns/op          0 B/op        0 allocs/op
BenchmarkAppendMXRecord         38512765            31.53 ns/op          0 B/op        0 allocs/op
BenchmarkAppendTXTRecord        70415923            16.72 ns/op          0 B/op        0 allocs/op
BenchmarkParseRequest           54310437            21.96 ns/op          0 B/op        0 allocs/op
BenchmarkGetDomainName          59479258            18.86 ns/op          0 B/op        0 allocs/op
BenchmarkDecodeQName            485569677            2.47 ns/op          0 B/op        0 allocs/op
BenchmarkEncodeDomain           79780868            14.46 ns/op          0 B/op        0 allocs/op
```

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
[fasthttp]: https://github.com/valyala/fasthttp
[rawdns]: https://github.com/cirocosta/rawdns
[miekg/dns]: https://github.com/miekg/dns

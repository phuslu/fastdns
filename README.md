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

### High Performance

A Performance result as below, for daily benchmark results see [github actions][benchmark]
```
BenchmarkAppendHostRecord-2     	51252039	        27.0 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendCNameRecord-2      	29154194	        41.7 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendSRVRecord-2        	26954487	        43.5 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendPTRRecord-2        	34947418	        35.3 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendMXRecord-2         	33740932	        36.5 ns/op	       0 B/op	       0 allocs/op
BenchmarkAppendTXTRecord-2        	66549254	        18.3 ns/op	       0 B/op	       0 allocs/op
BenchmarkParseRequest-2           	51268648	        23.4 ns/op	       0 B/op	       0 allocs/op
BenchmarkGetDomainName-2          	45560821	        26.7 ns/op	       0 B/op	       0 allocs/op
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

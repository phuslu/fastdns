// +build ignore

package main

import (
	"log"
	"net"
	"os"
	"sync"

	"github.com/phuslu/fastdns"
	"github.com/valyala/fasthttp"
)

type memCtx struct {
	rw  *fastdns.MemoryResponseWriter
	req *fastdns.Message
}

var memPool = sync.Pool{
	New: func() interface{} {
		mem := new(memCtx)
		mem.rw = new(fastdns.MemoryResponseWriter)
		mem.rw.Data = make([]byte, 0, 1024)
		mem.req = new(fastdns.Message)
		mem.req.Raw = make([]byte, 0, 1024)
		mem.req.Domain = make([]byte, 0, 256)
		return mem
	},
}

type FasthttpAdapter struct {
	FastdnsHandler fastdns.Handler
}

func (h *FasthttpAdapter) Handler(ctx *fasthttp.RequestCtx) {
	mem := memPool.Get().(*memCtx)

	rw, req := mem.rw, mem.req
	rw.Data = rw.Data[:0]
	rw.Raddr = ctx.RemoteAddr()
	rw.Laddr = ctx.LocalAddr()

	err := fastdns.ParseMessage(req, ctx.PostBody(), true)
	if err != nil {
		fastdns.Error(rw, req, fastdns.RcodeFormatError)
	} else {
		h.FastdnsHandler.ServeDNS(rw, req)
	}

	ctx.SetContentType("application/dns-message")
	_, _ = ctx.Write(rw.Data)

	memPool.Put(mem)
}

type DNSHandler struct{}

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Message) {
	log.Printf("%s] %s: CLASS %s TYPE %s\n", rw.RemoteAddr(), req.Domain, req.Question.Class, req.Question.Type)
	if req.Question.Type == fastdns.TypeA {
		fastdns.HOST(rw, req, 300, []net.IP{{10, 0, 0, 1}})
	} else {
		fastdns.Error(rw, req, fastdns.RcodeNameError)
	}
}

func main() {
	fasthttp.ListenAndServe(os.Args[1], (&FasthttpAdapter{&DNSHandler{}}).Handler)
}

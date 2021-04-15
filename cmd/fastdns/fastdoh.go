package main

import (
	"sync"

	"github.com/phuslu/fastdns"
	"github.com/valyala/bytebufferpool"
	"github.com/valyala/fasthttp"
)

type memCtx struct {
	rw  *fastdns.MemResponseWriter
	req *fastdns.Message
}

var memPool = sync.Pool{
	New: func() interface{} {
		mem := new(memCtx)
		mem.rw = new(fastdns.MemResponseWriter)
		mem.rw.Data = make([]byte, 0, 1024)
		mem.req = new(fastdns.Message)
		mem.req.Raw = make([]byte, 0, 1024)
		mem.req.Domain = make([]byte, 0, 256)
		return mem
	},
}

type fasthttpAdapter struct {
	FastdnsHandler fastdns.Handler
	FastdnsStats   fastdns.Stats
}

func (h *fasthttpAdapter) Handler(ctx *fasthttp.RequestCtx) {
	switch string(ctx.Path()) {
	case "/dns-query":
		h.HandlerDoH(ctx)
	case "/metrics":
		h.HandlerMetrics(ctx)
	default:
		ctx.NotFound()
	}
}

func (h *fasthttpAdapter) HandlerMetrics(ctx *fasthttp.RequestCtx) {
	b := bytebufferpool.Get()
	defer bytebufferpool.Put(b)

	b.B = h.FastdnsStats.AppendOpenMetrics(b.B[:0])

	ctx.Success("text/plain; charset=utf-8", b.B)
}

func (h *fasthttpAdapter) HandlerDoH(ctx *fasthttp.RequestCtx) {
	mem := memPool.Get().(*memCtx)

	rw, req := mem.rw, mem.req
	rw.Data = rw.Data[:0]
	rw.Raddr = ctx.RemoteAddr()
	rw.Laddr = ctx.LocalAddr()

	err := fastdns.ParseMessage(req, ctx.PostBody(), true)
	if err != nil {
		fastdns.Error(rw, req, fastdns.RcodeFormErr)
	} else {
		h.FastdnsHandler.ServeDNS(rw, req)
	}

	ctx.SetContentType("application/dns-message")
	_, _ = ctx.Write(rw.Data)

	memPool.Put(mem)
}

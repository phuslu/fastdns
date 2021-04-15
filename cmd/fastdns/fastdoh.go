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

var memCtxPool = sync.Pool{
	New: func() interface{} {
		ctx := new(memCtx)
		ctx.rw = new(fastdns.MemResponseWriter)
		ctx.rw.Data = make([]byte, 0, 1024)
		ctx.req = new(fastdns.Message)
		ctx.req.Raw = make([]byte, 0, 1024)
		ctx.req.Domain = make([]byte, 0, 256)
		return ctx
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
	memCtx := memCtxPool.Get().(*memCtx)

	rw, req := memCtx.rw, memCtx.req
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

	memCtxPool.Put(memCtx)
}

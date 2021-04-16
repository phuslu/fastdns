package main

import (
	"sync"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/valyala/bytebufferpool"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/pprofhandler"
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
	FastdohStats   fastdns.Stats
}

func (h *fasthttpAdapter) Handler(ctx *fasthttp.RequestCtx) {
	switch string(ctx.Path()) {
	case "/dns-query":
		h.HandlerDoH(ctx)
	case "/metrics":
		h.HandlerMetrics(ctx)
	case "/debug/pprof/",
		"/debug/pprof/cmdline",
		"/debug/pprof/heap",
		"/debug/pprof/profile",
		"/debug/pprof/symbol",
		"/debug/pprof/trace":
		/*
			git clone https://github.com/brendangregg/FlameGraph.git /opt/FlameGraph
			go get -v -u github.com/uber-archive/go-torch
			env PATH=/opt/FlameGraph/:$PATH go-torch http://127.0.0.1:9001/debug/pprof/profile -f mem.svg
			env PATH=/opt/FlameGraph/:$PATH go-torch -alloc_space -cum http://127.0.0.1:9001/debug/pprof/heap --colors mem -f mem.svg
		*/
		pprofhandler.PprofHandler(ctx)
	default:
		ctx.NotFound()
	}
}

func (h *fasthttpAdapter) HandlerMetrics(ctx *fasthttp.RequestCtx) {
	b := bytebufferpool.Get()
	defer bytebufferpool.Put(b)

	b.Reset()

	if h.FastdnsStats != nil {
		b.B = h.FastdnsStats.AppendOpenMetrics(b.B)
	}

	if h.FastdohStats != nil {
		b.B = h.FastdohStats.AppendOpenMetrics(b.B)
	}

	ctx.Success("text/plain; charset=utf-8", b.B)
}

func (h *fasthttpAdapter) HandlerDoH(ctx *fasthttp.RequestCtx) {
	var start time.Time
	if h.FastdohStats != nil {
		start = time.Now()
	}

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
		if h.FastdohStats != nil {
			h.FastdohStats.UpdateStats(rw.Raddr, req, time.Since(start))
		}
	}

	ctx.SetContentType("application/dns-message")
	_, _ = ctx.Write(rw.Data)

	memCtxPool.Put(memCtx)
}

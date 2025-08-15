package main

import (
	"net"
	"net/netip"
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

type DoHHandler struct {
	DNSQuery   string
	DNSHandler fastdns.Handler
	DNSStats   fastdns.Stats
	DoHStats   fastdns.Stats
}

func (h *DoHHandler) Handler(ctx *fasthttp.RequestCtx) {
	switch string(ctx.Path()) {
	case h.DNSQuery:
		h.HandlerDoH(ctx)
	case "/metrics":
		h.HandlerMetrics(ctx)
	case "/debug/pprof/",
		"/debug/pprof/cmdline",
		"/debug/pprof/heap",
		"/debug/pprof/profile",
		"/debug/pprof/symbol",
		"/debug/pprof/trace":
		pprofhandler.PprofHandler(ctx)
	default:
		ctx.NotFound()
	}
}

func (h *DoHHandler) HandlerMetrics(ctx *fasthttp.RequestCtx) {
	b := bytebufferpool.Get()
	defer bytebufferpool.Put(b)

	b.Reset()

	if h.DNSStats != nil {
		b.B = h.DNSStats.AppendOpenMetrics(b.B)
	}

	if h.DoHStats != nil {
		b.B = h.DoHStats.AppendOpenMetrics(b.B)
	}

	ctx.Success("text/plain; charset=utf-8", b.B)
}

func (h *DoHHandler) HandlerDoH(ctx *fasthttp.RequestCtx) {
	var start time.Time
	if h.DoHStats != nil {
		start = time.Now()
	}

	memCtx := memCtxPool.Get().(*memCtx)
	defer memCtxPool.Put(memCtx)

	rw, req := memCtx.rw, memCtx.req
	rw.Data = rw.Data[:0]

	switch v := ctx.RemoteAddr().(type) {
	case *net.TCPAddr:
		rw.Raddr = v.AddrPort()
	case *net.UDPAddr:
		rw.Raddr = v.AddrPort()
	default:
		rw.Raddr, _ = netip.ParseAddrPort(v.String())
	}

	switch v := ctx.LocalAddr().(type) {
	case *net.TCPAddr:
		rw.Laddr = v.AddrPort()
	case *net.UDPAddr:
		rw.Laddr = v.AddrPort()
	default:
		rw.Laddr, _ = netip.ParseAddrPort(v.String())
	}

	err := fastdns.ParseMessage(req, ctx.PostBody(), true)
	if err != nil {
		fastdns.Error(rw, req, fastdns.RcodeFormErr)
	} else {
		h.DNSHandler.ServeDNS(rw, req)
		if h.DoHStats != nil {
			h.DoHStats.UpdateStats(rw.Raddr, req, time.Since(start))
		}
	}

	ctx.SetContentType("application/dns-message")
	_, _ = ctx.Write(rw.Data)
}

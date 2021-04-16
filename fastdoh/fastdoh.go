package fastdoh

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

type Adapter struct {
	DNSHandler fastdns.Handler
	DNSStats   fastdns.Stats
	DoHStats   fastdns.Stats
}

func (adapter *Adapter) Handler(ctx *fasthttp.RequestCtx) {
	switch string(ctx.Path()) {
	case "/dns-query":
		adapter.HandlerDoH(ctx)
	case "/metrics":
		adapter.HandlerMetrics(ctx)
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

func (adapter *Adapter) HandlerMetrics(ctx *fasthttp.RequestCtx) {
	b := bytebufferpool.Get()
	defer bytebufferpool.Put(b)

	b.Reset()

	if adapter.DNSStats != nil {
		b.B = adapter.DNSStats.AppendOpenMetrics(b.B)
	}

	if adapter.DoHStats != nil {
		b.B = adapter.DoHStats.AppendOpenMetrics(b.B)
	}

	ctx.Success("text/plain; charset=utf-8", b.B)
}

func (adapter *Adapter) HandlerDoH(ctx *fasthttp.RequestCtx) {
	var start time.Time
	if adapter.DoHStats != nil {
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
		adapter.DNSHandler.ServeDNS(rw, req)
		if adapter.DoHStats != nil {
			adapter.DoHStats.UpdateStats(rw.Raddr, req, time.Since(start))
		}
	}

	ctx.SetContentType("application/dns-message")
	_, _ = ctx.Write(rw.Data)

	memCtxPool.Put(memCtx)
}

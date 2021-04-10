package main

import (
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

// +build ignore

package main

import (
	"log"
	"net"
	"os"

	"github.com/phuslu/fastdns"
	"github.com/valyala/fasthttp"
)

type memResponseWriter struct {
	data  []byte
	raddr net.Addr
	laddr net.Addr
}

func (rw *memResponseWriter) RemoteAddr() net.Addr {
	return rw.raddr
}

func (rw *memResponseWriter) LocalAddr() net.Addr {
	return rw.laddr
}

func (rw *memResponseWriter) Write(p []byte) (n int, err error) {
	rw.data = append(rw.data, p...)
	n = len(p)
	return
}

func HandlerFunc(handler fastdns.Handler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		req := fastdns.AcquireRequest()
		defer fastdns.ReleaseRequest(req)

		err := fastdns.ParseRequest(req, ctx.PostBody())
		if err != nil {
			ctx.Error("bad request", fasthttp.StatusBadRequest)
			return
		}

		rw := &memResponseWriter{
			raddr: ctx.RemoteAddr(),
			laddr: ctx.LocalAddr(),
		}

		handler.ServeDNS(rw, req)

		ctx.SetContentType("application/dns-message")
		_, _ = ctx.Write(rw.data)
	}
}

type DNSHandler struct{}

func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Request) {
	log.Printf("%s] %s: CLASS %s TYPE %s\n", rw.RemoteAddr(), req.Domain, req.Question.Class, req.Question.Type)
	if req.Question.Type == fastdns.TypeA {
		fastdns.HOST(rw, req, []net.IP{{10, 0, 0, 1}}, 300)
	} else {
		fastdns.Error(rw, req, fastdns.RcodeNameError)
	}
}

func main() {
	fasthttp.ListenAndServe(os.Args[1], HandlerFunc(&DNSHandler{}))
}

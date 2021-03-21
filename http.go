package fastdns

import (
	"net"
	"net/http"
	"strconv"
)

// HTTPHandlerFunc converts fastdns.Handler to a http.Hander for DoH servers
func HTTPHandlerFunc(h Handler) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		b := AcquireByteBuffer()
		defer ReleaseByteBuffer(b)

		b.B = b.B[:cap(b.B)]
		n, err := req.Body.Read(b.B)
		if err != nil {
			return
		}
		b.B = b.B[:n]

		r := AcquireRequest()
		defer ReleaseRequest(r)

		err = ParseRequest(b.B, r)
		if err != nil {
			return
		}

		ip, port, _ := net.SplitHostPort(req.RemoteAddr)
		addr := &net.TCPAddr{IP: net.ParseIP(ip)}
		addr.Port, _ = strconv.Atoi(port)

		h.ServeDNS(&httpResponseWriter{rw, addr}, r)
	}
}

type httpResponseWriter struct {
	rw   http.ResponseWriter
	addr net.Addr
}

func (rw *httpResponseWriter) RemoteAddr() net.Addr {
	return rw.addr
}

func (rw *httpResponseWriter) Write(p []byte) (n int, err error) {
	return rw.rw.Write(p)
}

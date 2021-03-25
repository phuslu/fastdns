package fastdns

import (
	"io"
	"net"
	"net/http"
	"strconv"
)

// HTTPHandlerFunc converts fastdns.Handler to a http.Hander for DoH servers
func HTTPHandlerFunc(h Handler) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		b := AcquireByteBuffer()
		defer ReleaseByteBuffer(b)

		b.B = b.B[:0]
		_, err := io.Copy(b, req.Body)
		if err != nil {
			http.Error(rw, "bad request", http.StatusBadRequest)
			return
		}

		r := AcquireRequest()
		defer ReleaseRequest(r)

		err = ParseRequest(r, b.B)
		if err != nil {
			http.Error(rw, "bad request", http.StatusBadRequest)
			return
		}

		// remote addr
		ip, port, _ := net.SplitHostPort(req.RemoteAddr)
		raddr := &net.TCPAddr{IP: net.ParseIP(ip)}
		raddr.Port, _ = strconv.Atoi(port)
		// local addr
		laddr := req.Context().Value(http.LocalAddrContextKey).(net.Addr)
		// in-memory response writer
		mem := &memResponseWriter{raddr: raddr, laddr: laddr}

		h.ServeDNS(mem, r)

		rw.Header().Set("content-type", "application/dns-message")
		rw.Header().Set("content-length", strconv.Itoa(len(mem.data)))
		_, _ = rw.Write(mem.data)
	}
}

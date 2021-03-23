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

		err = ParseRequest(b.B, r)
		if err != nil {
			http.Error(rw, "bad request", http.StatusBadRequest)
			return
		}

		ip, port, _ := net.SplitHostPort(req.RemoteAddr)
		addr := &net.TCPAddr{IP: net.ParseIP(ip)}
		addr.Port, _ = strconv.Atoi(port)
		mem := &memResponseWriter{addr: addr}

		h.ServeDNS(mem, r)

		rw.Header().Set("content-type", "application/dns-message")
		rw.Header().Set("content-length", strconv.Itoa(len(mem.data)))
		rw.Write(mem.data)
	}
}

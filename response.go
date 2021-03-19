package fastdns

import (
	"net"
)

type ResponseWriter interface {
	RemoteAddr() net.Addr
	Write([]byte) (int, error)
}

type responseWriter struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func (rw *responseWriter) RemoteAddr() net.Addr {
	return rw.addr
}

func (rw *responseWriter) Write(p []byte) (n int, err error) {
	n, _, err = rw.conn.WriteMsgUDP(p, nil, rw.addr)
	return
}

package fastdns

import (
	"net"
)

// A ResponseWriter interface is used by an DNS handler to construct an DNS response.
type ResponseWriter interface {
	// LocalAddr returns the net.Addr of the server
	LocalAddr() net.Addr

	// RemoteAddr returns the net.Addr of the client that sent the current request.
	RemoteAddr() net.Addr

	// Write writes a raw buffer back to the client.
	Write([]byte) (int, error)
}

type udpResponseWriter struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func (rw *udpResponseWriter) RemoteAddr() net.Addr {
	return rw.addr
}

func (rw *udpResponseWriter) LocalAddr() net.Addr {
	return rw.conn.LocalAddr()
}

func (rw *udpResponseWriter) Write(p []byte) (n int, err error) {
	n, _, err = rw.conn.WriteMsgUDP(p, nil, rw.addr)
	return
}

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

type nilResponseWriter struct{}

func (rw *nilResponseWriter) RemoteAddr() net.Addr {
	return nil
}

func (rw *nilResponseWriter) LocalAddr() net.Addr {
	return nil
}

func (rw *nilResponseWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

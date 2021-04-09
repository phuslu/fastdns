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

// MemoryResponseWriter is an implementation of ResponseWriter that supports write response to memory.
type MemoryResponseWriter struct {
	Data  []byte
	Raddr net.Addr
	Laddr net.Addr
}

// RemoteAddr returns the net.Addr of the client that sent the current request.
func (rw *MemoryResponseWriter) RemoteAddr() net.Addr {
	return rw.Raddr
}

// LocalAddr returns the net.Addr of the server
func (rw *MemoryResponseWriter) LocalAddr() net.Addr {
	return rw.Laddr
}

// Write writes a raw buffer back to the memory buffer.
func (rw *MemoryResponseWriter) Write(p []byte) (n int, err error) {
	rw.Data = append(rw.Data, p...)
	n = len(p)
	return
}

type udpResponseWriter struct {
	Conn *net.UDPConn
	Addr *net.UDPAddr
}

func (rw *udpResponseWriter) RemoteAddr() net.Addr {
	return rw.Addr
}

func (rw *udpResponseWriter) LocalAddr() net.Addr {
	return rw.Conn.LocalAddr()
}

func (rw *udpResponseWriter) Write(p []byte) (n int, err error) {
	n, _, err = rw.Conn.WriteMsgUDP(p, nil, rw.Addr)
	return
}

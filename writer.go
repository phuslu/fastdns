package fastdns

import (
	"net"
	"net/netip"
)

// A ResponseWriter interface is used by an DNS handler to construct an DNS response.
type ResponseWriter interface {
	// LocalAddr returns the netip.AddrPort of the server
	LocalAddr() netip.AddrPort

	// RemoteAddr returns the netip.AddrPort of the client that sent the current request.
	RemoteAddr() netip.AddrPort

	// Write writes a raw buffer back to the client.
	Write([]byte) (int, error)
}

// MemResponseWriter is an implementation of ResponseWriter that supports write response to memory.
type MemResponseWriter struct {
	Data  []byte
	Raddr netip.AddrPort
	Laddr netip.AddrPort
}

// RemoteAddr returns the netip.AddrPort of the client that sent the current request.
func (rw *MemResponseWriter) RemoteAddr() netip.AddrPort {
	return rw.Raddr
}

// LocalAddr returns the netip.AddrPort of the server
func (rw *MemResponseWriter) LocalAddr() netip.AddrPort {
	return rw.Laddr
}

// Write writes a raw buffer back to the memory buffer.
func (rw *MemResponseWriter) Write(p []byte) (n int, err error) {
	rw.Data = append(rw.Data, p...)
	n = len(p)
	return
}

type udpResponseWriter struct {
	Conn     *net.UDPConn
	AddrPort netip.AddrPort
}

func (rw *udpResponseWriter) RemoteAddr() netip.AddrPort {
	return rw.AddrPort
}

func (rw *udpResponseWriter) LocalAddr() netip.AddrPort {
	return rw.Conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (rw *udpResponseWriter) Write(p []byte) (n int, err error) {
	n, _, err = rw.Conn.WriteMsgUDPAddrPort(p, nil, rw.AddrPort)
	return
}

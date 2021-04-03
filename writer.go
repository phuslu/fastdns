package fastdns

import (
	"net"
	"sync"
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

type MemoryResponseWriter struct {
	Data  []byte
	Raddr net.Addr
	Laddr net.Addr
}

func (rw *MemoryResponseWriter) RemoteAddr() net.Addr {
	return rw.Raddr
}

func (rw *MemoryResponseWriter) LocalAddr() net.Addr {
	return rw.Laddr
}

func (rw *MemoryResponseWriter) Write(p []byte) (n int, err error) {
	rw.Data = append(rw.Data, p...)
	n = len(p)
	return
}

var memoryResponseWriterPool = sync.Pool{
	New: func() interface{} {
		return &MemoryResponseWriter{
			Data: make([]byte, 0, 1024),
		}
	},
}

// AcquireMemoryResponseWriter returns new dns memory response writer.
func AcquireMemoryResponseWriter() *MemoryResponseWriter {
	return memoryResponseWriterPool.Get().(*MemoryResponseWriter)
}

// ReleaseMemoryResponseWriter returnes the dns memory response writer to the pool.
func ReleaseMemoryResponseWriter(rw *MemoryResponseWriter) {
	memoryResponseWriterPool.Put(rw)
}

type UDPResponseWriter struct {
	Conn *net.UDPConn
	Addr *net.UDPAddr
}

func (rw *UDPResponseWriter) RemoteAddr() net.Addr {
	return rw.Addr
}

func (rw *UDPResponseWriter) LocalAddr() net.Addr {
	return rw.Conn.LocalAddr()
}

func (rw *UDPResponseWriter) Write(p []byte) (n int, err error) {
	n, _, err = rw.Conn.WriteMsgUDP(p, nil, rw.Addr)
	return
}

var udpResponseWriterPool = sync.Pool{
	New: func() interface{} {
		return new(UDPResponseWriter)
	},
}

// AcquireUDPResponseWriter returns new dns udp response writer.
func AcquireUDPResponseWriter() *UDPResponseWriter {
	return udpResponseWriterPool.Get().(*UDPResponseWriter)
}

// ReleaseUDPResponseWriter returnes the dns udp response writer to the pool.
func ReleaseUDPResponseWriter(rw *UDPResponseWriter) {
	udpResponseWriterPool.Put(rw)
}

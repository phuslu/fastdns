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

var memResponseWriterPool = sync.Pool{
	New: func() interface{} {
		return &MemoryResponseWriter{
			Data: make([]byte, 0, 1024),
		}
	},
}

// AcquireMemoryResponseWriter returns new dns memory response writer.
func AcquireMemoryResponseWriter() *MemoryResponseWriter {
	return memResponseWriterPool.Get().(*MemoryResponseWriter)
}

// ReleaseMemoryResponseWriter returnes the dns memory response writer to the pool.
func ReleaseMemoryResponseWriter(req *MemoryResponseWriter) {
	memResponseWriterPool.Put(req)
}

type udpResponseWriter struct {
	rbuf []byte
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

var udpResponseWriterPool = sync.Pool{
	New: func() interface{} {
		return &udpResponseWriter{
			rbuf: make([]byte, 0, 1024),
		}
	},
}

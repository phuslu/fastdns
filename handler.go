package fastdns

import (
	"fmt"
	"net"
)

var _ = fmt.Printf

type Handler interface {
	ServeDNS(rw ResponseWriter, req *Request)
}

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

type memResponseWriter struct {
	data []byte
	addr net.Addr
}

func (rw *memResponseWriter) RemoteAddr() net.Addr {
	return rw.addr
}

func (rw *memResponseWriter) Write(p []byte) (n int, err error) {
	rw.data = append(rw.data, p...)
	n = len(p)
	return
}

func Error(rw ResponseWriter, req *Request, code RCODE) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = AppendHeaderQuestion(b.B[:0], req, code, 0, 0, 0, 0)

	_, _ = rw.Write(b.B)
}

func Host(rw ResponseWriter, req *Request, ips []net.IP, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, NOERROR, 1, uint16(len(ips)), 0, 0)
	b.B = AppendHostRecord(b.B, req, ips, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

func CNAME(rw ResponseWriter, req *Request, cnames []string, ips []net.IP, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, NOERROR, 1, uint16(len(cnames)+len(ips)), 0, 0)
	b.B = AppendCNameRecord(b.B, req, cnames, ips, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

func SRV(rw ResponseWriter, req *Request, srv string, priovrity, weight, port uint16, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, NOERROR, 1, 1, 0, 0)
	b.B = AppendSRVRecord(b.B, req, srv, priovrity, weight, port, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

func PTR(rw ResponseWriter, req *Request, ptr string, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, NOERROR, 1, 1, 0, 0)
	b.B = AppendPTRRecord(b.B, req, ptr, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

func TXT(rw ResponseWriter, req *Request, txt string, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, NOERROR, 1, 1, 0, 0)
	b.B = AppendTXTRecord(b.B, req, txt, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

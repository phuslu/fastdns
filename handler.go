package fastdns

import (
	"fmt"
	"net"
)

var _ = fmt.Printf

type Handler interface {
	ServeDNS(rw ResponseWriter, req *Request)
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

func TXT(rw ResponseWriter, req *Request, txt string, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, NOERROR, 1, 1, 0, 0)
	b.B = AppendTXTRecord(b.B, req, txt, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

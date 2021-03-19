package fastdns

import (
	"net"
)

type Handler interface {
	ServeDNS(rw ResponseWriter, req *Request)
}

func Error(rw ResponseWriter, req *Request, code RCODE) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = AppendHeaderQuestionToResponse(b.B[:0], req, code, 0, 0, 0, 0)

	_, _ = rw.Write(b.B)
}

func Host(rw ResponseWriter, req *Request, ips []net.IP, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestionToResponse(b.B, req, NOERROR, 1, Count(len(ips)), 0, 0)
	b.B = AppendHostToResponse(b.B, req, ips, ttl)

	_, _ = rw.Write(b.B)
}

func CNAME(rw ResponseWriter, req *Request, cnames []string, ips []net.IP, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestionToResponse(b.B, req, NOERROR, 1, Count(len(cnames)+len(ips)), 0, 0)
	b.B = AppendCNameToResponse(b.B, req, cnames, ips, ttl)

	_, _ = rw.Write(b.B)
}

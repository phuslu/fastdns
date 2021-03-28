package fastdns

import (
	"fmt"
	"net"
)

var _ = fmt.Printf

// Handler is implemented by any value that implements ServeDNS.
type Handler interface {
	ServeDNS(rw ResponseWriter, req *Request)
}

// Error replies to the request with the specified Rcode.
func Error(rw ResponseWriter, req *Request, code Rcode) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = AppendHeaderQuestion(b.B[:0], req, code, 0, 0, 0, 0)

	_, _ = rw.Write(b.B)
}

// HOST replies to the request with the specified Host records.
func HOST(rw ResponseWriter, req *Request, ips []net.IP, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, RcodeSuccess, 1, uint16(len(ips)), 0, 0)
	b.B = AppendHostRecord(b.B, req, ips, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

// CNAME replies to the request with the specified CName and Host records.
func CNAME(rw ResponseWriter, req *Request, cnames []string, ips []net.IP, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, RcodeSuccess, 1, uint16(len(cnames)+len(ips)), 0, 0)
	b.B = AppendCNameRecord(b.B, req, cnames, ips, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

// SRV replies to the request with the specified SRV records.
func SRV(rw ResponseWriter, req *Request, srv string, priovrity, weight, port uint16, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, RcodeSuccess, 1, 1, 0, 0)
	b.B = AppendSRVRecord(b.B, req, srv, priovrity, weight, port, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

// MX replies to the request with the specified MX records.
func MX(rw ResponseWriter, req *Request, mx []MXRecord, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, RcodeSuccess, 1, uint16(len(mx)), 0, 0)
	b.B = AppendMXRecord(b.B, req, mx, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

// PTR replies to the request with the specified PTR records.
func PTR(rw ResponseWriter, req *Request, ptr string, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, RcodeSuccess, 1, 1, 0, 0)
	b.B = AppendPTRRecord(b.B, req, ptr, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

// TXT replies to the request with the specified TXT records.
func TXT(rw ResponseWriter, req *Request, txt string, ttl uint32) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = b.B[:0]
	b.B = AppendHeaderQuestion(b.B, req, RcodeSuccess, 1, 1, 0, 0)
	b.B = AppendTXTRecord(b.B, req, txt, ttl)

	// fmt.Printf("%x\n", b.B)

	_, _ = rw.Write(b.B)
}

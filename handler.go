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
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, code, 0, 0, 0, 0)
	_, _ = rw.Write(req.Raw)
}

// HOST replies to the request with the specified Host records.
func HOST(rw ResponseWriter, req *Request, ips []net.IP, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, uint16(len(ips)), 0, 0)
	req.Raw = AppendHostRecord(req.Raw, req, ips, ttl)
	// fmt.Printf("%x\n", req.Raw)
	_, _ = rw.Write(req.Raw)

}

// CNAME replies to the request with the specified CName and Host records.
func CNAME(rw ResponseWriter, req *Request, cnames []string, ips []net.IP, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, uint16(len(cnames)+len(ips)), 0, 0)
	req.Raw = AppendCNameRecord(req.Raw, req, cnames, ips, ttl)
	// fmt.Printf("%x\n", req.Raw)
	_, _ = rw.Write(req.Raw)

}

// SRV replies to the request with the specified SRV records.
func SRV(rw ResponseWriter, req *Request, srv string, priovrity, weight, port uint16, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, 1, 0, 0)
	req.Raw = AppendSRVRecord(req.Raw, req, srv, priovrity, weight, port, ttl)
	// fmt.Printf("%x\n", req.Raw)
	_, _ = rw.Write(req.Raw)
}

// MX replies to the request with the specified MX records.
func MX(rw ResponseWriter, req *Request, mx []MXRecord, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, uint16(len(mx)), 0, 0)
	req.Raw = AppendMXRecord(req.Raw, req, mx, ttl)
	// fmt.Printf("%x\n", req.Raw)
	_, _ = rw.Write(req.Raw)
}

// PTR replies to the request with the specified PTR records.
func PTR(rw ResponseWriter, req *Request, ptr string, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, 1, 0, 0)
	req.Raw = AppendPTRRecord(req.Raw, req, ptr, ttl)
	// fmt.Printf("%x\n", req.Raw)
	_, _ = rw.Write(req.Raw)
}

// TXT replies to the request with the specified TXT records.
func TXT(rw ResponseWriter, req *Request, txt string, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, 1, 0, 0)
	req.Raw = AppendTXTRecord(req.Raw, req, txt, ttl)
	// fmt.Printf("%x\n", req.Raw)
	_, _ = rw.Write(req.Raw)
}

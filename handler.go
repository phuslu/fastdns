package fastdns

import (
	"net"
)

// Handler is implemented by any value that implements ServeDNS.
type Handler interface {
	ServeDNS(rw ResponseWriter, req *Message)
}

// Error replies to the request with the specified Rcode.
func Error(rw ResponseWriter, req *Message, code Rcode) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, code, 0, 0, 0, 0)
	_, _ = rw.Write(req.Raw)
}

// HOST replies to the request with the specified Host records.
func HOST(rw ResponseWriter, req *Message, ips []net.IP, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, uint16(len(ips)), 0, 0)
	req.Raw = AppendHostRecord(req.Raw, req, ips, ttl)
	_, _ = rw.Write(req.Raw)
}

// CNAME replies to the request with the specified CName and Host records.
func CNAME(rw ResponseWriter, req *Message, cnames []string, ips []net.IP, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, uint16(len(cnames)+len(ips)), 0, 0)
	req.Raw = AppendCNameRecord(req.Raw, req, cnames, ips, ttl)
	_, _ = rw.Write(req.Raw)
}

// SRV replies to the request with the specified SRV records.
func SRV(rw ResponseWriter, req *Message, srv string, priovrity, weight, port uint16, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, 1, 0, 0)
	req.Raw = AppendSRVRecord(req.Raw, req, srv, priovrity, weight, port, ttl)
	_, _ = rw.Write(req.Raw)
}

// MX replies to the request with the specified MX records.
func MX(rw ResponseWriter, req *Message, mx []MXRecord, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, uint16(len(mx)), 0, 0)
	req.Raw = AppendMXRecord(req.Raw, req, mx, ttl)
	_, _ = rw.Write(req.Raw)
}

// PTR replies to the request with the specified PTR records.
func PTR(rw ResponseWriter, req *Message, ptr string, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, 1, 0, 0)
	req.Raw = AppendPTRRecord(req.Raw, req, ptr, ttl)
	_, _ = rw.Write(req.Raw)
}

// TXT replies to the request with the specified TXT records.
func TXT(rw ResponseWriter, req *Message, txt string, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, 1, 0, 0)
	req.Raw = AppendTXTRecord(req.Raw, req, txt, ttl)
	_, _ = rw.Write(req.Raw)
}

// SOA replies to the request with the specified SOA records.
func SOA(rw ResponseWriter, req *Message, mname, rname string, serial, refresh, retry, expire, minimum uint32, ttl uint32) {
	req.Raw = AppendHeaderQuestion(req.Raw[:0], req, RcodeSuccess, 1, 1, 0, 0)
	req.Raw = AppendSOARecord(req.Raw, req, mname, rname, serial, refresh, retry, expire, minimum, ttl)
	_, _ = rw.Write(req.Raw)
}

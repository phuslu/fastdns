package fastdns

import (
	"net"
)

// Handler is implemented by any value that implements ServeDNS.
type Handler interface {
	ServeDNS(rw ResponseWriter, msg *Message)
}

// Error replies to the request with the specified Rcode.
func Error(rw ResponseWriter, msg *Message, code Rcode) {
	msg.Raw = AppendHeaderQuestion(msg.Raw[:0], msg, code, 0, 0, 0, 0)
	_, _ = rw.Write(msg.Raw)
}

// HOST replies to the request with the specified Host records.
func HOST(rw ResponseWriter, msg *Message, ips []net.IP, ttl uint32) {
	msg.Raw = AppendHeaderQuestion(msg.Raw[:0], msg, RcodeSuccess, 1, uint16(len(ips)), 0, 0)
	msg.Raw = AppendHostRecord(msg.Raw, msg, ips, ttl)
	_, _ = rw.Write(msg.Raw)
}

// CNAME replies to the request with the specified CName and Host records.
func CNAME(rw ResponseWriter, msg *Message, cnames []string, ips []net.IP, ttl uint32) {
	msg.Raw = AppendHeaderQuestion(msg.Raw[:0], msg, RcodeSuccess, 1, uint16(len(cnames)+len(ips)), 0, 0)
	msg.Raw = AppendCNameRecord(msg.Raw, msg, cnames, ips, ttl)
	_, _ = rw.Write(msg.Raw)
}

// SRV replies to the request with the specified SRV records.
func SRV(rw ResponseWriter, msg *Message, srv string, priovrity, weight, port uint16, ttl uint32) {
	msg.Raw = AppendHeaderQuestion(msg.Raw[:0], msg, RcodeSuccess, 1, 1, 0, 0)
	msg.Raw = AppendSRVRecord(msg.Raw, msg, srv, priovrity, weight, port, ttl)
	_, _ = rw.Write(msg.Raw)
}

// MX replies to the request with the specified MX records.
func MX(rw ResponseWriter, msg *Message, mx []MXRecord, ttl uint32) {
	msg.Raw = AppendHeaderQuestion(msg.Raw[:0], msg, RcodeSuccess, 1, uint16(len(mx)), 0, 0)
	msg.Raw = AppendMXRecord(msg.Raw, msg, mx, ttl)
	_, _ = rw.Write(msg.Raw)
}

// PTR replies to the request with the specified PTR records.
func PTR(rw ResponseWriter, msg *Message, ptr string, ttl uint32) {
	msg.Raw = AppendHeaderQuestion(msg.Raw[:0], msg, RcodeSuccess, 1, 1, 0, 0)
	msg.Raw = AppendPTRRecord(msg.Raw, msg, ptr, ttl)
	_, _ = rw.Write(msg.Raw)
}

// TXT replies to the request with the specified TXT records.
func TXT(rw ResponseWriter, msg *Message, txt string, ttl uint32) {
	msg.Raw = AppendHeaderQuestion(msg.Raw[:0], msg, RcodeSuccess, 1, 1, 0, 0)
	msg.Raw = AppendTXTRecord(msg.Raw, msg, txt, ttl)
	_, _ = rw.Write(msg.Raw)
}

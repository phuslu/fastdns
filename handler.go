package fastdns

import (
	"net"
	"net/netip"
)

// Handler is implemented by any value that implements ServeDNS.
type Handler interface {
	ServeDNS(rw ResponseWriter, req *Message)
}

// Error replies to the request with the specified Rcode.
func Error(rw ResponseWriter, req *Message, rcode Rcode) {
	req.SetResponseHeader(rcode, 0)
	_, _ = rw.Write(req.Raw)
}

// HOST1 replies to the request with the specified Host record.
func HOST1(rw ResponseWriter, req *Message, ttl uint32, ip netip.Addr) {
	req.SetResponseHeader(RcodeNoError, 1)
	req.AppendHOST1Record(ttl, ip)
	_, _ = rw.Write(req.Raw)
}

// HOST replies to the request with the specified Host records.
func HOST(rw ResponseWriter, req *Message, ttl uint32, ips []netip.Addr) {
	req.SetResponseHeader(RcodeNoError, uint16(len(ips)))
	req.AppendHOSTRecord(ttl, ips)
	_, _ = rw.Write(req.Raw)
}

// CNAME replies to the request with the specified CName and Host records.
func CNAME(rw ResponseWriter, req *Message, ttl uint32, cnames []string, ips []netip.Addr) {
	req.SetResponseHeader(RcodeNoError, uint16(len(cnames)+len(ips)))
	req.AppendCNAMERecord(ttl, cnames, ips)
	_, _ = rw.Write(req.Raw)
}

// SRV replies to the request with the specified SRV records.
func SRV(rw ResponseWriter, req *Message, ttl uint32, srvs []net.SRV) {
	req.SetResponseHeader(RcodeNoError, uint16(len(srvs)))
	req.AppendSRVRecord(ttl, srvs)
	_, _ = rw.Write(req.Raw)
}

// NS replies to the request with the specified CName and Host records.
func NS(rw ResponseWriter, req *Message, ttl uint32, nameservers []net.NS) {
	req.SetResponseHeader(RcodeNoError, uint16(len(nameservers)))
	req.AppendNSRecord(ttl, nameservers)
	_, _ = rw.Write(req.Raw)
}

// SOA replies to the request with the specified SOA records.
func SOA(rw ResponseWriter, req *Message, ttl uint32, mname, rname net.NS, serial, refresh, retry, expire, minimum uint32) {
	req.SetResponseHeader(RcodeNoError, 1)
	req.AppendSOARecord(ttl, mname, rname, serial, refresh, retry, expire, minimum)
	_, _ = rw.Write(req.Raw)
}

// MX replies to the request with the specified MX records.
func MX(rw ResponseWriter, req *Message, ttl uint32, mxs []net.MX) {
	req.SetResponseHeader(RcodeNoError, uint16(len(mxs)))
	req.AppendMXRecord(ttl, mxs)
	_, _ = rw.Write(req.Raw)
}

// PTR replies to the request with the specified PTR records.
func PTR(rw ResponseWriter, req *Message, ttl uint32, ptr string) {
	req.SetResponseHeader(RcodeNoError, 1)
	req.AppendPTRRecord(ttl, ptr)
	_, _ = rw.Write(req.Raw)
}

// TXT replies to the request with the specified TXT records.
func TXT(rw ResponseWriter, req *Message, ttl uint32, txt string) {
	req.SetResponseHeader(RcodeNoError, 1)
	req.AppendTXTRecord(ttl, txt)
	_, _ = rw.Write(req.Raw)
}

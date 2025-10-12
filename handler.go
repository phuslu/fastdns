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
	req.Raw = req.AppendHOST1Record(req.Raw, ttl, ip)
	_, _ = rw.Write(req.Raw)
}

// HOST replies to the request with the specified Host records.
func HOST(rw ResponseWriter, req *Message, ttl uint32, ips []netip.Addr) {
	req.SetResponseHeader(RcodeNoError, uint16(len(ips)))
	req.Raw = req.AppendHOSTRecord(req.Raw, ttl, ips)
	_, _ = rw.Write(req.Raw)
}

// CNAME replies to the request with the specified CName and Host records.
func CNAME(rw ResponseWriter, req *Message, ttl uint32, cnames []string, ips []netip.Addr) {
	req.SetResponseHeader(RcodeNoError, uint16(len(cnames)+len(ips)))
	req.Raw = req.AppendCNAMERecord(req.Raw, ttl, cnames, ips)
	_, _ = rw.Write(req.Raw)
}

// SRV replies to the request with the specified SRV records.
func SRV(rw ResponseWriter, req *Message, ttl uint32, srvs []net.SRV) {
	req.SetResponseHeader(RcodeNoError, uint16(len(srvs)))
	req.Raw = req.AppendSRVRecord(req.Raw, ttl, srvs)
	_, _ = rw.Write(req.Raw)
}

// NS replies to the request with the specified CName and Host records.
func NS(rw ResponseWriter, req *Message, ttl uint32, nameservers []net.NS) {
	req.SetResponseHeader(RcodeNoError, uint16(len(nameservers)))
	req.Raw = req.AppendNSRecord(req.Raw, ttl, nameservers)
	_, _ = rw.Write(req.Raw)
}

// SOA replies to the request with the specified SOA records.
func SOA(rw ResponseWriter, req *Message, ttl uint32, mname, rname net.NS, serial, refresh, retry, expire, minimum uint32) {
	req.SetResponseHeader(RcodeNoError, 1)
	req.Raw = req.AppendSOARecord(req.Raw, ttl, mname, rname, serial, refresh, retry, expire, minimum)
	_, _ = rw.Write(req.Raw)
}

// MX replies to the request with the specified MX records.
func MX(rw ResponseWriter, req *Message, ttl uint32, mxs []net.MX) {
	req.SetResponseHeader(RcodeNoError, uint16(len(mxs)))
	req.Raw = req.AppendMXRecord(req.Raw, ttl, mxs)
	_, _ = rw.Write(req.Raw)
}

// PTR replies to the request with the specified PTR records.
func PTR(rw ResponseWriter, req *Message, ttl uint32, ptr string) {
	req.SetResponseHeader(RcodeNoError, 1)
	req.Raw = req.AppendPTRRecord(req.Raw, ttl, ptr)
	_, _ = rw.Write(req.Raw)
}

// TXT replies to the request with the specified TXT records.
func TXT(rw ResponseWriter, req *Message, ttl uint32, txt string) {
	req.SetResponseHeader(RcodeNoError, 1)
	req.Raw = req.AppendTXTRecord(req.Raw, ttl, txt)
	_, _ = rw.Write(req.Raw)
}

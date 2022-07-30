package fastdns

import (
	"net"
	"net/netip"
)

// AppendHOSTRecord appends the Host records to dst and returns the resulting dst.
func AppendHOSTRecord(dst []byte, req *Message, ttl uint32, ips []netip.Addr) []byte {
	for _, ip := range ips {
		if ip.Is4() {
			v4 := ip.As4()
			answer := [...]byte{
				// NAME
				0xc0, 0x0c,
				// TYPE
				0x00, byte(TypeA),
				// CLASS
				byte(req.Question.Class >> 8), byte(req.Question.Class),
				// TTL
				byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
				// RDLENGTH
				0x00, 0x04,
				// RDATA
				v4[0], v4[1], v4[2], v4[3],
			}
			dst = append(dst, answer[:]...)
		} else {
			v6 := ip.As16()
			answer := [...]byte{
				// NAME
				0xc0, 0x0c,
				// TYPE
				0x00, byte(TypeAAAA),
				// CLASS
				byte(req.Question.Class >> 8), byte(req.Question.Class),
				// TTL
				byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
				// RDLENGTH
				0x00, 0x10,
				// RDATA
				v6[0], v6[1], v6[2], v6[3],
				v6[4], v6[5], v6[6], v6[7],
				v6[8], v6[9], v6[10], v6[11],
				v6[12], v6[13], v6[14], v6[15],
			}
			dst = append(dst, answer[:]...)
		}
	}

	return dst
}

// AppendCNAMERecord appends the CNAME and Host records to dst and returns the resulting dst.
func AppendCNAMERecord(dst []byte, req *Message, ttl uint32, cnames []string, ips []netip.Addr) []byte {
	offset := 0x0c
	// CName Records
	for i, cname := range cnames {
		// fixed size array for avoid bounds check
		answer := [...]byte{
			// NAME
			0xc0 | byte(offset>>8), byte(offset),
			// TYPE
			0x00, byte(TypeCNAME),
			// CLASS
			byte(req.Question.Class >> 8), byte(req.Question.Class),
			// TTL
			byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
			// RDLENGTH
			0x00, byte(len(cname) + 2),
		}
		dst = append(dst, answer[:]...)
		// set offset
		if i == 0 {
			offset += len(req.Question.Name) + 2 + 2
		} else {
			offset += len(cname) + 2
		}
		offset += len(answer)
		// RDATA
		dst = EncodeDomain(dst, cname)
	}
	// Host Records
	for _, ip := range ips {
		if ip.Is4() {
			v4 := ip.As4()
			answer := [...]byte{
				// NAME
				0xc0 | byte(offset>>8), byte(offset),
				// TYPE
				0x00, byte(TypeA),
				// CLASS
				byte(req.Question.Class >> 8), byte(req.Question.Class),
				// TTL
				byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
				// RDLENGTH
				0x00, 0x04,
				// RDATA
				v4[0], v4[1], v4[2], v4[3],
			}
			dst = append(dst, answer[:]...)
		} else {
			v6 := ip.As16()
			answer := [...]byte{
				// NAME
				0xc0 | byte(offset>>8), byte(offset),
				// TYPE
				0x00, byte(TypeAAAA),
				// CLASS
				byte(req.Question.Class >> 8), byte(req.Question.Class),
				// TTL
				byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
				// RDLENGTH
				0x00, 0x10,
				// RDATA
				v6[0], v6[1], v6[2], v6[3],
				v6[4], v6[5], v6[6], v6[7],
				v6[8], v6[9], v6[10], v6[11],
				v6[12], v6[13], v6[14], v6[15],
			}
			dst = append(dst, answer[:]...)
		}
	}

	return dst
}

// AppendSRVRecord appends the SRV records to dst and returns the resulting dst.
func AppendSRVRecord(dst []byte, req *Message, ttl uint32, srvs []net.SRV) []byte {
	// SRV Records
	for _, srv := range srvs {
		length := 8 + len(srv.Target)
		// fixed size array for avoid bounds check
		answer := [...]byte{
			// NAME
			0xc0, 0x0c,
			// TYPE
			0x00, byte(TypeSRV),
			// CLASS
			byte(req.Question.Class >> 8), byte(req.Question.Class),
			// TTL
			byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
			// RDLENGTH
			byte(length >> 8), byte(length),
			// PRIOVRITY
			byte(srv.Priority >> 8), byte(srv.Priority),
			// WEIGHT
			byte(srv.Weight >> 8), byte(srv.Weight),
			// PORT
			byte(srv.Port >> 8), byte(srv.Port),
		}
		dst = append(dst, answer[:]...)
		// RDATA
		dst = EncodeDomain(dst, srv.Target)
	}

	return dst
}

// AppendNSRecord appends the NS records to dst and returns the resulting dst.
func AppendNSRecord(dst []byte, req *Message, ttl uint32, nameservers []net.NS) []byte {
	// NS Records
	for _, ns := range nameservers {
		// fixed size array for avoid bounds check
		answer := [...]byte{
			// NAME
			0xc0, 0x0c,
			// TYPE
			0x00, byte(TypeNS),
			// CLASS
			byte(req.Question.Class >> 8), byte(req.Question.Class),
			// TTL
			byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
			// RDLENGTH
			0x00, byte(len(ns.Host) + 2),
		}
		dst = append(dst, answer[:]...)
		// RDATA
		dst = EncodeDomain(dst, ns.Host)
	}

	return dst
}

// AppendSOARecord appends the SOA records to dst and returns the resulting dst.
func AppendSOARecord(dst []byte, req *Message, ttl uint32, mname, rname net.NS, serial, refresh, retry, expire, minimum uint32) []byte {
	length := 2 + len(mname.Host) + 2 + len(rname.Host) + 4 + 4 + 4 + 4 + 4
	// fixed size array for avoid bounds check
	answer := [...]byte{
		// NAME
		0xc0, 0x0c,
		// TYPE
		0x00, byte(TypeSOA),
		// CLASS
		byte(req.Question.Class >> 8), byte(req.Question.Class),
		// TTL
		byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
		// RDLENGTH
		byte(length >> 8), byte(length),
	}
	dst = append(dst, answer[:]...)

	// MNAME
	dst = EncodeDomain(dst, mname.Host)
	// RNAME
	dst = EncodeDomain(dst, rname.Host)

	section := [...]byte{
		// SERIAL
		byte(serial >> 24), byte(serial >> 16), byte(serial >> 8), byte(serial),
		// REFRESH
		byte(refresh >> 24), byte(refresh >> 16), byte(refresh >> 8), byte(refresh),
		// RETRY
		byte(retry >> 24), byte(retry >> 16), byte(retry >> 8), byte(retry),
		// EXPIRE
		byte(expire >> 24), byte(expire >> 16), byte(expire >> 8), byte(expire),
		// MINIMUM
		byte(minimum >> 24), byte(minimum >> 16), byte(minimum >> 8), byte(minimum),
	}
	dst = append(dst, section[:]...)

	return dst
}

// AppendMXRecord appends the MX records to dst and returns the resulting dst.
func AppendMXRecord(dst []byte, req *Message, ttl uint32, mxs []net.MX) []byte {
	// MX Records
	for _, mx := range mxs {
		length := 4 + len(mx.Host)
		// fixed size array for avoid bounds check
		answer := [...]byte{
			// NAME
			0xc0, 0x0c,
			// TYPE
			0x00, byte(TypeMX),
			// CLASS
			byte(req.Question.Class >> 8), byte(req.Question.Class),
			// TTL
			byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
			// RDLENGTH
			byte(length >> 8), byte(length),
			// PRIOVRITY
			byte(mx.Pref >> 8), byte(mx.Pref),
		}
		dst = append(dst, answer[:]...)
		// RDATA
		dst = EncodeDomain(dst, mx.Host)
	}

	return dst
}

// AppendPTRRecord appends the PTR records to dst and returns the resulting dst.
func AppendPTRRecord(dst []byte, req *Message, ttl uint32, ptr string) []byte {
	// fixed size array for avoid bounds check
	answer := [...]byte{
		// NAME
		0xc0, 0x0c,
		// TYPE
		0x00, byte(TypePTR),
		// CLASS
		byte(req.Question.Class >> 8), byte(req.Question.Class),
		// TTL
		byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
		// RDLENGTH
		00, byte(2 + len(ptr)),
	}
	dst = append(dst, answer[:]...)
	// PTR
	dst = EncodeDomain(dst, ptr)

	return dst
}

// AppendTXTRecord appends the TXT records to dst and returns the resulting dst.
func AppendTXTRecord(dst []byte, req *Message, ttl uint32, txt string) []byte {
	length := len(txt) + (len(txt)+0xff)/0x100
	// fixed size array for avoid bounds check
	answer := [...]byte{
		// NAME
		0xc0, 0x0c,
		// TYPE
		0x00, byte(TypeTXT),
		// CLASS
		byte(req.Question.Class >> 8), byte(req.Question.Class),
		// TTL
		byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
		// RDLENGTH
		byte(length >> 8), byte(length),
	}
	dst = append(dst, answer[:]...)

	for len(txt) > 0xff {
		// TXT Length
		dst = append(dst, 0xff)
		// TXT
		dst = append(dst, txt[:0xff]...)
		txt = txt[0xff:]
	}

	// TXT Length
	dst = append(dst, byte(len(txt)))
	// TXT
	dst = append(dst, txt...)

	return dst
}

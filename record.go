package fastdns

import (
	"net"
)

// AppendSRVRecord appends the SRV records to msg.
func (msg *Message) AppendSRVRecord(ttl uint32, srvs []net.SRV) {
	// SRV Records
	for _, srv := range srvs {
		length := 8 + len(srv.Target)
		msg.Raw = EncodeDomain(append(msg.Raw,
			// NAME
			0xc0, 0x0c,
			// TYPE
			0x00, byte(TypeSRV),
			// CLASS
			byte(msg.Question.Class>>8), byte(msg.Question.Class),
			// TTL
			byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
			// RDLENGTH
			byte(length>>8), byte(length),
			// PRIOVRITY
			byte(srv.Priority>>8), byte(srv.Priority),
			// WEIGHT
			byte(srv.Weight>>8), byte(srv.Weight),
			// PORT
			byte(srv.Port>>8), byte(srv.Port),
			// RDATA
		), srv.Target)
	}
}

// AppendNSRecord appends the NS records to msg.
func (msg *Message) AppendNSRecord(ttl uint32, nameservers []net.NS) {
	// NS Records
	for _, ns := range nameservers {
		msg.Raw = EncodeDomain(append(msg.Raw,
			// NAME
			0xc0, 0x0c,
			// TYPE
			0x00, byte(TypeNS),
			// CLASS
			byte(msg.Question.Class>>8), byte(msg.Question.Class),
			// TTL
			byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
			// RDLENGTH
			0x00, byte(len(ns.Host)+2),
			// RDATA
		), ns.Host)
	}
}

// AppendSOARecord appends the SOA records to msg.
func (msg *Message) AppendSOARecord(ttl uint32, mname, rname net.NS, serial, refresh, retry, expire, minimum uint32) {
	length := 2 + len(mname.Host) + 2 + len(rname.Host) + 4 + 4 + 4 + 4 + 4
	msg.Raw = append(msg.Raw,
		// NAME
		0xc0, 0x0c,
		// TYPE
		0x00, byte(TypeSOA),
		// CLASS
		byte(msg.Question.Class>>8), byte(msg.Question.Class),
		// TTL
		byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
		// RDLENGTH
		byte(length>>8), byte(length),
	)

	// MNAME
	msg.Raw = EncodeDomain(msg.Raw, mname.Host)
	// RNAME
	msg.Raw = EncodeDomain(msg.Raw, rname.Host)

	msg.Raw = append(msg.Raw,
		// SERIAL
		byte(serial>>24), byte(serial>>16), byte(serial>>8), byte(serial),
		// REFRESH
		byte(refresh>>24), byte(refresh>>16), byte(refresh>>8), byte(refresh),
		// RETRY
		byte(retry>>24), byte(retry>>16), byte(retry>>8), byte(retry),
		// EXPIRE
		byte(expire>>24), byte(expire>>16), byte(expire>>8), byte(expire),
		// MINIMUM
		byte(minimum>>24), byte(minimum>>16), byte(minimum>>8), byte(minimum),
	)
}

// AppendMXRecord appends the MX records to msg.
func (msg *Message) AppendMXRecord(ttl uint32, mxs []net.MX) {
	// MX Records
	for _, mx := range mxs {
		length := 4 + len(mx.Host)
		msg.Raw = EncodeDomain(append(msg.Raw,
			// NAME
			0xc0, 0x0c,
			// TYPE
			0x00, byte(TypeMX),
			// CLASS
			byte(msg.Question.Class>>8), byte(msg.Question.Class),
			// TTL
			byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
			// RDLENGTH
			byte(length>>8), byte(length),
			// PRIOVRITY
			byte(mx.Pref>>8), byte(mx.Pref),
			// RDATA
		), mx.Host)
	}
}

// AppendPTRRecord appends the PTR records to msg.
func (msg *Message) AppendPTRRecord(ttl uint32, ptr string) {
	msg.Raw = EncodeDomain(append(msg.Raw,
		// NAME
		0xc0, 0x0c,
		// TYPE
		0x00, byte(TypePTR),
		// CLASS
		byte(msg.Question.Class>>8), byte(msg.Question.Class),
		// TTL
		byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
		// RDLENGTH
		00, byte(2+len(ptr)),
		// PTR
	), ptr)
}

// AppendTXTRecord appends the TXT records to msg.
func (msg *Message) AppendTXTRecord(ttl uint32, txt string) {
	length := len(txt) + (len(txt)+0xff)/0x100
	msg.Raw = append(msg.Raw,
		// NAME
		0xc0, 0x0c,
		// TYPE
		0x00, byte(TypeTXT),
		// CLASS
		byte(msg.Question.Class>>8), byte(msg.Question.Class),
		// TTL
		byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
		// RDLENGTH
		byte(length>>8), byte(length),
	)

	for len(txt) > 0xff {
		// TXT Length
		msg.Raw = append(msg.Raw, 0xff)
		// TXT
		msg.Raw = append(msg.Raw, txt[:0xff]...)
		txt = txt[0xff:]
	}

	// TXT Length
	msg.Raw = append(msg.Raw, byte(len(txt)))
	// TXT
	msg.Raw = append(msg.Raw, txt...)
}

//go:build 386 || amd64 || arm || amd64p32 || arm64 || ppc64le || mipsle || mips64le || mips64p32le
// +build 386 amd64 arm amd64p32 arm64 ppc64le mipsle mips64le mips64p32le

package fastdns

import (
	"net/netip"
	"unsafe"
)

// AppendHOST1Record appends a Host records to dst and returns the resulting dst.
func (req *Message) AppendHOST1Record(dst []byte, ttl uint32, ip netip.Addr) []byte {
	b := (*[16]byte)(unsafe.Pointer(&ip))
	if ip.Is4() {
		dst = append(dst,
			// NAME
			0xc0, 0x0c,
			// TYPE
			0x00, byte(TypeA),
			// CLASS
			byte(req.Question.Class>>8), byte(req.Question.Class),
			// TTL
			byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
			// RDLENGTH
			0x00, 0x04,
			// RDATA
			b[11], b[10], b[9], b[8],
		)
	} else {
		dst = append(dst,
			// NAME
			0xc0, 0x0c,
			// TYPE
			0x00, byte(TypeAAAA),
			// CLASS
			byte(req.Question.Class>>8), byte(req.Question.Class),
			// TTL
			byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
			// RDLENGTH
			0x00, 0x10,
			// RDATA
			b[7], b[6], b[5], b[4],
			b[3], b[2], b[1], b[0],
			b[15], b[14], b[13], b[12],
			b[11], b[10], b[9], b[8],
		)
	}

	return dst
}

// AppendHOSTRecord appends the Host records to dst and returns the resulting dst.
func (req *Message) AppendHOSTRecord(dst []byte, ttl uint32, ips []netip.Addr) []byte {
	for _, ip := range ips {
		b := (*[16]byte)(unsafe.Pointer(&ip))
		if ip.Is4() {
			dst = append(dst,
				// NAME
				0xc0, 0x0c,
				// TYPE
				0x00, byte(TypeA),
				// CLASS
				byte(req.Question.Class>>8), byte(req.Question.Class),
				// TTL
				byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
				// RDLENGTH
				0x00, 0x04,
				// RDATA
				b[11], b[10], b[9], b[8],
			)
		} else {
			dst = append(dst,
				// NAME
				0xc0, 0x0c,
				// TYPE
				0x00, byte(TypeAAAA),
				// CLASS
				byte(req.Question.Class>>8), byte(req.Question.Class),
				// TTL
				byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
				// RDLENGTH
				0x00, 0x10,
				// RDATA
				b[7], b[6], b[5], b[4],
				b[3], b[2], b[1], b[0],
				b[15], b[14], b[13], b[12],
				b[11], b[10], b[9], b[8],
			)
		}
	}

	return dst
}

// AppendCNAMERecord appends the CNAME and Host records to dst and returns the resulting dst.
func (req *Message) AppendCNAMERecord(dst []byte, ttl uint32, cnames []string, ips []netip.Addr) []byte {
	offset := 0x0c
	// CName Records
	for i, cname := range cnames {
		dst = append(dst,
			// NAME
			0xc0|byte(offset>>8), byte(offset),
			// TYPE
			0x00, byte(TypeCNAME),
			// CLASS
			byte(req.Question.Class>>8), byte(req.Question.Class),
			// TTL
			byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
			// RDLENGTH
			0x00, byte(len(cname)+2),
		)
		// set offset
		if i == 0 {
			offset += len(req.Question.Name) + 2 + 2 + 12
		} else {
			offset += len(cname) + 2 + 12
		}
		// RDATA
		dst = EncodeDomain(dst, cname)
	}
	// Host Records
	for _, ip := range ips {
		b := (*[16]byte)(unsafe.Pointer(&ip))
		if ip.Is4() {
			dst = append(dst,
				// NAME
				0xc0|byte(offset>>8), byte(offset),
				// TYPE
				0x00, byte(TypeA),
				// CLASS
				byte(req.Question.Class>>8), byte(req.Question.Class),
				// TTL
				byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
				// RDLENGTH
				0x00, 0x04,
				// RDATA
				b[11], b[10], b[9], b[8],
			)
		} else {
			dst = append(dst,
				// NAME
				0xc0|byte(offset>>8), byte(offset),
				// TYPE
				0x00, byte(TypeAAAA),
				// CLASS
				byte(req.Question.Class>>8), byte(req.Question.Class),
				// TTL
				byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
				// RDLENGTH
				0x00, 0x10,
				// RDATA
				b[7], b[6], b[5], b[4],
				b[3], b[2], b[1], b[0],
				b[15], b[14], b[13], b[12],
				b[11], b[10], b[9], b[8],
			)
		}
	}

	return dst
}

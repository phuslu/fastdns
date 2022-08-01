//go:build ppc64be || mipsbe || mips64be || mips64p32be
// +build ppc64be mipsbe mips64be mips64p32be

package fastdns

import (
	"net/netip"
	"unsafe"
)

// AppendHOSTRecord appends the Host records to dst and returns the resulting dst.
func AppendHOSTRecord(dst []byte, req *Message, ttl uint32, ips []netip.Addr) []byte {
	for _, ip := range ips {
		b := (*[16]byte)(unsafe.Pointer(&ip))
		if ip.Is4() {
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
				b[8], b[9], b[10], b[11],
			}
			dst = append(dst, answer[:]...)
		} else {
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
				b[8], b[9], b[10], b[11],
				b[12], b[13], b[14], b[15],
				b[0], b[1], b[2], b[3],
				b[4], b[5], b[6], b[7],
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
		b := (*[16]byte)(unsafe.Pointer(&ip))
		if ip.Is4() {
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
				b[8], b[9], b[10], b[11],
			}
			dst = append(dst, answer[:]...)
		} else {
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
				b[8], b[9], b[10], b[11],
				b[12], b[13], b[14], b[15],
				b[0], b[1], b[2], b[3],
				b[4], b[5], b[6], b[7],
			}
			dst = append(dst, answer[:]...)
		}
	}

	return dst
}

package fastdns

import (
	"net"
)

type ResponseWriter interface {
	RemoteAddr() net.Addr
	Write([]byte) (int, error)
}

type responseWriter struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func (rw *responseWriter) RemoteAddr() net.Addr {
	return rw.addr
}

func (rw *responseWriter) Write(p []byte) (n int, err error) {
	n, _, err = rw.conn.WriteMsgUDP(p, nil, rw.addr)
	return
}

func AppendHeaderQuestionToResponse(dst []byte, req *Request, rcode RCODE, qd, an, ns, ar uint16) []byte {
	var header [12]byte

	// ID
	header[0] = byte(req.Header.ID >> 8)
	header[1] = byte(req.Header.ID & 0xff)

	// QR :		0
	// OpCode:	1 2 3 4
	// AA:		5
	// TC:		6
	// RD:		7
	b := byte(1) << (7 - 0)
	b |= byte(req.Header.OpCode) << (7 - (1 + 3))
	b |= req.Header.AA << (7 - 5)
	b |= req.Header.TC << (7 - 6)
	b |= req.Header.RD
	header[2] = b

	// second 8bit part of the second row
	// RA:		0
	// Z:		1 2 3
	// RCODE:	4 5 6 7
	b = req.Header.RA << (7 - 0)
	b |= req.Header.Z << (7 - 1)
	b |= byte(rcode) << (7 - (4 + 3))
	header[3] = b

	// QDCOUNT
	header[4] = byte(qd >> 8)
	header[5] = byte(qd & 0xff)
	// ANCOUNT
	header[6] = byte(an >> 8)
	header[7] = byte(an & 0xff)
	// NSCOUNT
	header[8] = byte(ns >> 8)
	header[9] = byte(ns & 0xff)
	// ARCOUNT
	header[10] = byte(ar >> 8)
	header[11] = byte(ar & 0xff)

	dst = append(dst, header[:]...)

	// question
	if qd != 0 {
		// QNAME
		dst = append(dst, req.Question.Name...)
		// QTYPE
		dst = append(dst, byte(req.Question.Type>>8), byte(req.Question.Type&0xff))
		// QCLASS
		dst = append(dst, byte(req.Question.Class>>8), byte(req.Question.Class&0xff))
	}

	return dst
}

func AppendHostToResponse(dst []byte, req *Request, ips []net.IP, ttl uint32) []byte {
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			_ = ip4[3]
			answer := [...]byte{
				// NAME
				0xc0, 0x0c,
				// TYPE
				0x00, byte(QTypeA),
				// CLASS
				byte(req.Question.Class >> 8), byte(req.Question.Class),
				// TTL
				byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
				// RDLENGTH
				0x00, 0x04,
				// RDATA
				ip4[0], ip4[1], ip4[2], ip4[3],
			}
			dst = append(dst, answer[:]...)
		} else {
			_ = ip[15]
			answer := [...]byte{
				// NAME
				0xc0, 0x0c,
				// TYPE
				0x00, byte(QTypeAAAA),
				// CLASS
				byte(req.Question.Class >> 8), byte(req.Question.Class),
				// TTL
				byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
				// RDLENGTH
				0x00, 0x10,
				// RDATA
				ip[0], ip[1], ip[2], ip[3],
				ip[4], ip[5], ip[6], ip[7],
				ip[8], ip[9], ip[10], ip[11],
				ip[12], ip[13], ip[14], ip[15],
			}
			dst = append(dst, answer[:]...)
		}
	}

	return dst
}

func AppendCNameToResponse(dst []byte, req *Request, cnames []string, ips []net.IP, ttl uint32) []byte {
	offset := 0x0c
	// CName Records
	for i, cname := range cnames {
		answer := [...]byte{
			// NAME
			0xc0 | byte(offset>>8), byte(offset),
			// TYPE
			0x00, byte(QTypeCNAME),
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
		dst = encodeDomain(dst, cname)
	}
	// Host Records
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			_ = ip4[3]
			answer := [...]byte{
				// NAME
				0xc0 | byte(offset>>8), byte(offset),
				// TYPE
				0x00, byte(QTypeA),
				// CLASS
				byte(req.Question.Class >> 8), byte(req.Question.Class),
				// TTL
				byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
				// RDLENGTH
				0x00, 0x04,
				// RDATA
				ip4[0], ip4[1], ip4[2], ip4[3],
			}
			dst = append(dst, answer[:]...)
		} else {
			_ = ip[15]
			answer := [...]byte{
				// NAME
				0xc0 | byte(offset>>8), byte(offset),
				// TYPE
				0x00, byte(QTypeAAAA),
				// CLASS
				byte(req.Question.Class >> 8), byte(req.Question.Class),
				// TTL
				byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
				// RDLENGTH
				0x00, 0x10,
				// RDATA
				ip[0], ip[1], ip[2], ip[3],
				ip[4], ip[5], ip[6], ip[7],
				ip[8], ip[9], ip[10], ip[11],
				ip[12], ip[13], ip[14], ip[15],
			}
			dst = append(dst, answer[:]...)
		}
	}

	return dst
}

func AppendSRVToResponse(dst []byte, req *Request, srv string, priovrity, weight, port uint16, ttl uint32) []byte {
	// SRV Records
	answer := [...]byte{
		// NAME
		0xc0, 0x0c,
		// TYPE
		0x00, byte(QTypeSRV),
		// CLASS
		byte(req.Question.Class >> 8), byte(req.Question.Class),
		// TTL
		byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl),
		// RDLENGTH
		byte((8 + len(srv)) >> 8), byte(8 + len(srv)),
		// PRIOVRITY
		byte(priovrity >> 8), byte(priovrity),
		// WEIGHT
		byte(weight >> 8), byte(weight),
		// PORT
		byte(port >> 8), byte(port),
	}
	dst = append(dst, answer[:]...)
	// RDATA
	dst = encodeDomain(dst, srv)

	return dst
}

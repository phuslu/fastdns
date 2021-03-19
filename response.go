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

func AppendRequestToResponse(dst []byte, req *Request, rcode RCODE, qd, an, ns, ar Count) []byte {
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
		dst = append(dst, req.Question.QName...)
		// QTYPE
		dst = append(dst, byte(req.Question.QType>>8), byte(req.Question.QType&0xff))
		// QCLASS
		dst = append(dst, byte(req.Question.QClass>>8), byte(req.Question.QClass&0xff))
	}

	return dst
}

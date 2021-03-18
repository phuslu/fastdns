package fastdns

import (
	"net"
)

type Handler interface {
	ServeDNS(rw ResponseWriter, req *Request)
}

func Error(rw ResponseWriter, req *Request, code RCODE) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	req.Header.QR = 1
	req.Header.RCODE = code
	req.Header.QDCount = 0
	b.B = AppendRequest(b.B[:0], req)

	rw.Write(b.B)
}

func HostRecord(rw ResponseWriter, req *Request, ips []net.IP, ttl uint16) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	req.Header.QR = 1
	req.Header.ANCount = uint16(len(ips))
	req.Header.ARCount = 0
	b.B = AppendRequest(b.B[:0], req)

	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			_ = ip4[3]
			var answer = [16]byte{
				// NAME
				0xc0, 0x0c,
				// TYPE
				0x00, byte(QTypeA),
				// CLASS
				0x00, byte(req.Question.QClass),
				// TTL
				0x00, 0x00, byte(ttl >> 8), byte(ttl),
				// RDLENGTH
				0x00, 0x04,
				// RDATA
				ip4[0], ip4[1], ip4[2], ip4[3],
			}
			b.B = append(b.B, answer[:]...)
		} else {
			_ = ip[15]
			var answer = [28]byte{
				// NAME
				0xc0, 0x0c,
				// TYPE
				0x00, byte(QTypeA),
				// CLASS
				0x00, byte(req.Question.QClass),
				// TTL
				0x00, 0x00, byte(ttl >> 8), byte(ttl),
				// RDLENGTH
				0x00, 0x10,
				// RDATA
				ip[0], ip[1], ip[2], ip[3],
				ip[4], ip[5], ip[6], ip[7],
				ip[8], ip[9], ip[10], ip[11],
				ip[12], ip[13], ip[14], ip[15],
			}
			b.B = append(b.B, answer[:]...)
		}
	}

	rw.Write(b.B)
}

func CNAMERecord(rw ResponseWriter, req *Request, cname []string, ips []net.IP, ttl uint16) {
}

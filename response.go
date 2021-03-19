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

type RR struct {

	// Name is the Domain name to which this resource record pertains.
	// It might either come in the compressed format or not, depending
	// on the server.
	// Typically this should come compressed (indicated by the first two
	// bits).
	Name [2]byte

	// Type is the type of the RR. It specifies the meaning of the
	// data that RDATA contains.
	QType QType

	// CLASS identifies the class of the data holded on RDATA.
	QClass QClass

	// TTL indicates the time interval in seconds that the resource
	// recorded may be cached before it should be discarded.
	TTL uint32

	// RDLength specifies the length in octets of the RDATA field.
	// ps.: if there's a pointer in the RDATA, this length
	// will not count the final result (expanded), but the
	// actual amount in transfer.
	RDLength uint16

	// RDATA is the generic data from the record.
	// The format of the information contained here varies
	// according to the tupple {TYPE, CLASS} of the RR.
	RData []byte
}

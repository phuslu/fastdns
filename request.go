package fastdns

import (
	"errors"
	"sync"
)

type Request struct {
	/*
		Header encapsulates the construct of the header part of the DNS
		query message.
		It follows the conventions stated at RFC1035 section 4.1.1.


		The header contains the following fields:

						0  1  2  3  4  5  6  7
		      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |                      ID                       |
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |QR|   OpCode  |AA|TC|RD|RA|   Z    |   RCODE   |
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |                    QDCOUNT                    |
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |                    ANCOUNT                    |
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |                    NSCOUNT                    |
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		    |                    ARCOUNT                    |
		    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	*/
	Header struct {

		// ID is an arbitrary 16bit request identifier that is
		// forwarded back in the response so that we can match them up.
		ID uint16

		// QR is an 1bit flag specifying whether this message is a query (0)
		// of a response (1)
		// 1bit
		QR byte

		// OpCode is a 4bit field that specifies the query type.
		// Possible values are:
		// 0		- standard query		(QUERY)
		// 1		- inverse query			(IQUERY)
		// 2		- server status request		(STATUS)
		// 3 to 15	- reserved for future use
		OpCode OpCode

		// AA indicates whether this is an (A)nswer from an (A)uthoritative
		// server.
		// Valid in responses only.
		// 1bit.
		AA byte

		// TC indicates whether the message was (T)run(C)ated due to the length
		// being grater than the permitted on the transmission channel.
		// 1bit.
		TC byte

		// RD indicates whether (R)ecursion is (D)esired or not.
		// 1bit.
		RD byte

		// RA indidicates whether (R)ecursion is (A)vailable or not.
		// 1bit.
		RA byte

		// Z is reserved for future use
		Z byte

		// RCODE contains the (R)esponse (CODE) - it's a 4bit field that is
		// set as part of responses.
		RCODE RCODE

		// QDCOUNT specifies the number of entries in the question section
		QDCount uint16

		// ANCount specifies the number of resource records (RR) in the answer
		// section
		ANCount uint16

		// NSCount specifies the number of name server resource records in the
		// authority section
		NSCount uint16

		// ARCount specifies the number of resource records in the additional
		// records section
		ARCount uint16
	}

	/*
	     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   |                                               |
	   /                     QNAME                     /
	   /                                               /
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   |                     QTYPE                     |
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	   |                     QCLASS                    |
	   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	*/
	Question struct {
		// QName refers to the raw query name to be resolved in the query.
		Name QName

		// QTYPE specifies the type of the query to perform.
		Type QType

		// QCLASS
		Class QClass
	}
}

func (req *Request) GetDomainName() string {
	return string(decodeQName(make([]byte, 0, 256), req.Question.Name))
}

func (req *Request) AppendDomainName(dst []byte) []byte {
	return decodeQName(dst, req.Question.Name)
}

var (
	ErrInvalidHeader   = errors.New("dns message does not have the expected header size")
	ErrInvalidQuestion = errors.New("dns message does not have the expected question size")
)

func ParseRequest(payload []byte, req *Request) error {
	if len(payload) < 12 {
		return ErrInvalidHeader
	}

	_ = payload[11]

	// ID
	req.Header.ID = uint16(payload[1]) | uint16(payload[0])<<8

	// RD, TC, AA, OpCode, QR
	b := payload[2]
	req.Header.RD = b & 0b00000001
	req.Header.TC = (b >> 1) & 0b00000001
	req.Header.AA = (b >> 2) & 0b00000001
	req.Header.OpCode = OpCode((b >> 3) & 0b00001111)
	req.Header.QR = (b >> 7) & 0b00000001

	// RA, Z, RCODE
	b = payload[3]
	req.Header.RCODE = RCODE(b & 0b00001111)
	req.Header.Z = (b >> 4) & 0b00000111
	req.Header.RA = (b >> 7) & 0b00000001

	// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
	req.Header.QDCount = uint16(payload[4])<<8 | uint16(payload[5])
	req.Header.ANCount = uint16(payload[6])<<8 | uint16(payload[7])
	req.Header.NSCount = uint16(payload[8])<<8 | uint16(payload[9])
	req.Header.ARCount = uint16(payload[10])<<8 | uint16(payload[11])

	if req.Header.QDCount != 1 {
		return ErrInvalidHeader
	}

	// QNAME
	payload = payload[12:]
	var i int
	for i, b = range payload {
		if b == 0 {
			break
		}
	}
	if i+5 > len(payload) {
		return ErrInvalidQuestion
	}
	req.Question.Name = append(req.Question.Name[:0], payload[:i+1]...)

	// QTYPE, QCLASS
	payload = payload[i:]
	req.Question.Class = QClass(uint16(payload[4]) | uint16(payload[3])<<8)
	req.Question.Type = QType(uint16(payload[2]) | uint16(payload[1])<<8)

	return nil
}

func AppendRequest(dst []byte, req *Request) []byte {
	var header [12]byte

	// ID
	header[0] = byte(req.Header.ID >> 8)
	header[1] = byte(req.Header.ID & 0xff)

	// QR :		0
	// OpCode:	1 2 3 4
	// AA:		5
	// TC:		6
	// RD:		7
	b := req.Header.QR << (7 - 0)
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
	b |= byte(req.Header.RCODE) << (7 - (4 + 3))
	header[3] = b

	// QDCOUNT
	header[4] = byte(req.Header.QDCount >> 8)
	header[5] = byte(req.Header.QDCount & 0xff)
	// ANCOUNT
	header[6] = byte(req.Header.ANCount >> 8)
	header[7] = byte(req.Header.ANCount & 0xff)
	// NSCOUNT
	header[8] = byte(req.Header.NSCount >> 8)
	header[9] = byte(req.Header.NSCount & 0xff)
	// ARCOUNT
	header[10] = byte(req.Header.ARCount >> 8)
	header[11] = byte(req.Header.ARCount & 0xff)

	dst = append(dst, header[:]...)

	// question
	if req.Header.QDCount != 0 {
		// QNAME
		dst = append(dst, req.Question.Name...)
		// QTYPE
		dst = append(dst, byte(req.Question.Type>>8), byte(req.Question.Type&0xff))
		// QCLASS
		dst = append(dst, byte(req.Question.Class>>8), byte(req.Question.Class&0xff))
	}

	return dst
}

var reqPool = sync.Pool{
	New: func() interface{} {
		req := new(Request)
		req.Question.Name = make([]byte, 0, 256)
		return req
	},
}

func AcquireRequest() *Request {
	return reqPool.Get().(*Request)
}

func ReleaseRequest(req *Request) {
	reqPool.Put(req)
}

package fastdns

import (
	"errors"
	"sync"
)

// Message represents an DNS request received by a server or to be sent by a client.
type Message struct {
	// Raw refers to the raw query packet.
	Raw []byte

	// Domain represents to the parsed query domain in the query.
	Domain []byte

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
		    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
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

		// Opcode is a 4bit field that specifies the query type.
		// Possible values are:
		// 0		- standard query		(QUERY)
		// 1		- inverse query			(IQUERY)
		// 2		- server status request		(STATUS)
		// 3 to 15	- reserved for future use
		Opcode Opcode

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
		RCODE Rcode

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
		// Name refers to the raw query name to be resolved in the query.
		Name []byte

		// Type specifies the type of the query to perform.
		Type Type

		// Class specifies the class of the query to perform.
		Class Class
	}
}

var (
	// ErrInvalidHeader is returned when dns message does not have the expected header size.
	ErrInvalidHeader = errors.New("dns message does not have the expected header size")
	// ErrInvalidQuestion is returned when dns message does not have the expected question size.
	ErrInvalidQuestion = errors.New("dns message does not have the expected question size")
	// ErrInvalidAnswer is returned when dns message does not have the expected answer size.
	ErrInvalidAnswer = errors.New("dns message does not have the expected answer size")
)

// ParseMessage parses dns request from payload into dst and returns the error.
func ParseMessage(dst *Message, payload []byte, copying bool) error {
	if copying {
		dst.Raw = append(dst.Raw[:0], payload...)
		payload = dst.Raw
	}

	if len(payload) < 12 {
		return ErrInvalidHeader
	}

	// hint golang compiler remove ip bounds check
	_ = payload[11]

	// ID
	dst.Header.ID = uint16(payload[1]) | uint16(payload[0])<<8

	// RD, TC, AA, Opcode, QR
	b := payload[2]
	dst.Header.RD = b & 0b00000001
	dst.Header.TC = (b >> 1) & 0b00000001
	dst.Header.AA = (b >> 2) & 0b00000001
	dst.Header.Opcode = Opcode((b >> 3) & 0b00001111)
	dst.Header.QR = (b >> 7) & 0b00000001

	// RA, Z, RCODE
	b = payload[3]
	dst.Header.RCODE = Rcode(b & 0b00001111)
	dst.Header.Z = (b >> 4) & 0b00000111
	dst.Header.RA = (b >> 7) & 0b00000001

	// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
	dst.Header.QDCount = uint16(payload[4])<<8 | uint16(payload[5])
	dst.Header.ANCount = uint16(payload[6])<<8 | uint16(payload[7])
	dst.Header.NSCount = uint16(payload[8])<<8 | uint16(payload[9])
	dst.Header.ARCount = uint16(payload[10])<<8 | uint16(payload[11])

	if dst.Header.QDCount != 1 {
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
	if i == 0 || i+5 > len(payload) {
		return ErrInvalidQuestion
	}
	dst.Question.Name = payload[:i+1]

	// QTYPE, QCLASS
	payload = payload[i:]
	dst.Question.Class = Class(uint16(payload[4]) | uint16(payload[3])<<8)
	dst.Question.Type = Type(uint16(payload[2]) | uint16(payload[1])<<8)

	// Domain
	i = int(dst.Question.Name[0])
	payload = append(dst.Domain[:0], dst.Question.Name[1:]...)
	for payload[i] != 0 {
		j := int(payload[i])
		payload[i] = '.'
		i += j + 1
	}
	dst.Domain = payload[:len(payload)-1]

	return nil
}

// VisitResourceRecords calls f for each item in the msg in the original order of the parsed RR.
func (msg *Message) VisitResourceRecords(f func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool) error {
	if msg.Header.ANCount == 0 {
		return ErrInvalidAnswer
	}

	payload := msg.Raw[16+len(msg.Question.Name):]

	for {
		var name []byte
		if payload[0]&0b11000000 == 0b11000000 {
			name = payload[:2]
		} else {
			for i := 0; i < len(payload); i++ {
				if payload[i] == 0 {
					name = payload[:i]
					break
				}
			}
		}
		payload = payload[len(name):]
		typ := Type(payload[1])<<8 | Type(payload[2])
		class := Class(payload[3])<<8 | Class(payload[4])
		ttl := uint32(payload[5])<<24 | uint32(payload[6])<<16 | uint32(payload[7])<<8 | uint32(payload[8])
		length := uint16(payload[9])<<8 | uint16(payload[10])
		data := payload[10 : 10+length]
		payload = payload[10+length:]
		ok := f(name, typ, class, ttl, data)
		if !ok || len(payload) == 0 {
			break
		}
	}

	return nil
}

// VisitAdditionalRecords calls f for each item in the msg in the original order of the parsed AR.
func (msg *Message) VisitAdditionalRecords(f func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool) error {
	if msg.Header.ANCount == 0 {
		return ErrInvalidAnswer
	}

	payload := msg.Raw[16+len(msg.Question.Name):]

	for {
		var name []byte
		if payload[0]&0b11000000 == 0b11000000 {
			name = payload[:2]
		} else {
			for i := 0; i < len(payload); i++ {
				if payload[i] == 0 {
					name = payload[:i]
					break
				}
			}
		}
		payload = payload[len(name):]
		typ := Type(payload[1])<<8 | Type(payload[2])
		class := Class(payload[3])<<8 | Class(payload[4])
		ttl := uint32(payload[5])<<24 | uint32(payload[6])<<16 | uint32(payload[7])<<8 | uint32(payload[8])
		length := uint16(payload[9])<<8 | uint16(payload[10])
		data := payload[10 : 10+length]
		payload = payload[10+length:]
		ok := f(name, typ, class, ttl, data)
		if !ok || len(payload) == 0 {
			break
		}
	}

	return nil
}

// AppendMessage appends the dns request to dst and returns the resulting dst.
func AppendMessage(dst []byte, msg *Message) []byte {
	// fixed size array for avoid bounds check
	var header [12]byte

	// ID
	header[0] = byte(msg.Header.ID >> 8)
	header[1] = byte(msg.Header.ID & 0xff)

	// QR :		0
	// Opcode:	1 2 3 4
	// AA:		5
	// TC:		6
	// RD:		7
	b := msg.Header.QR << (7 - 0)
	b |= byte(msg.Header.Opcode) << (7 - (1 + 3))
	b |= msg.Header.AA << (7 - 5)
	b |= msg.Header.TC << (7 - 6)
	b |= msg.Header.RD
	header[2] = b

	// second 8bit part of the second row
	// RA:		0
	// Z:		1 2 3
	// RCODE:	4 5 6 7
	b = msg.Header.RA << (7 - 0)
	b |= msg.Header.Z << (7 - 1)
	b |= byte(msg.Header.RCODE) << (7 - (4 + 3))
	header[3] = b

	// QDCOUNT
	header[4] = byte(msg.Header.QDCount >> 8)
	header[5] = byte(msg.Header.QDCount & 0xff)
	// ANCOUNT
	header[6] = byte(msg.Header.ANCount >> 8)
	header[7] = byte(msg.Header.ANCount & 0xff)
	// NSCOUNT
	header[8] = byte(msg.Header.NSCount >> 8)
	header[9] = byte(msg.Header.NSCount & 0xff)
	// ARCOUNT
	header[10] = byte(msg.Header.ARCount >> 8)
	header[11] = byte(msg.Header.ARCount & 0xff)

	dst = append(dst, header[:]...)

	// question
	if msg.Header.QDCount != 0 {
		// QNAME
		dst = append(dst, msg.Question.Name...)
		// QTYPE
		dst = append(dst, byte(msg.Question.Type>>8), byte(msg.Question.Type&0xff))
		// QCLASS
		dst = append(dst, byte(msg.Question.Class>>8), byte(msg.Question.Class&0xff))
	}

	return dst
}

var msgPool = sync.Pool{
	New: func() interface{} {
		msg := new(Message)
		msg.Raw = make([]byte, 0, 1024)
		msg.Domain = make([]byte, 0, 256)
		return msg
	},
}

// AcquireMessage returns new dns request.
func AcquireMessage() *Message {
	return msgPool.Get().(*Message)
}

// ReleaseMessage returnes the dns request to the pool.
func ReleaseMessage(msg *Message) {
	msgPool.Put(msg)
}

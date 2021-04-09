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

		// 0  1  2  3  4  5  6  7  8
		// +--+--+--+--+--+--+--+--+
		// |QR|   Opcode  |AA|TC|RD|
		// +--+--+--+--+--+--+--+--+
		// |RA|   Z    |   RCODE   |
		// +--+--+--+--+--+--+--+--+
		Bits uint16

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
	dst.Header.ID = uint16(payload[0])<<8 | uint16(payload[1])

	// RD, TC, AA, Opcode, QR, RA, Z, RCODE
	dst.Header.Bits = uint16(payload[2])<<8 | uint16(payload[3])

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
	var b byte
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

// DecodeName decodes dns labels to dst.
func (msg *Message) DecodeName(dst []byte, name []byte) []byte {
	switch len(name) {
	case 2:
		if name[1] == 12 && name[0] == 0b11000000 {
			dst = append(dst, msg.Domain...)
			return dst
		}
	case 0, 1:
		return dst
	}

	var offset int
	if name[0]&0b11000000 == 0b11000000 {
		offset := int(name[0]&0b00111111)<<8 + int(name[1])
		for i, b := range msg.Raw[offset:] {
			if b == 0 {
				name = msg.Raw[offset : offset+i+1]
				break
			} else if b&0b11000000 == 0b11000000 {
				name = msg.Raw[offset : offset+i+2]
				break
			}
		}
	}

	var p int
	n := len(dst) + int(name[0])
	dst = append(dst, name[1:]...)
	for {
		if dst[n]&0b11000000 == 0b11000000 {
			p = int(dst[n]&0b00111111)<<8 + int(dst[n+1])
			break
		} else if dst[n] == 0 {
			break
		} else {
			offset = int(dst[n])
			dst[n] = '.'
			n += offset + 1
		}
	}

	dst = dst[:len(dst)-1]
	if p != 0 {
		dst[len(dst)-1] = '.'
		for i := p; i < len(msg.Raw); i++ {
			b := msg.Raw[i]
			if b&0b11000000 == 0b11000000 {
				// QQQ: support pointer to pointer
				return dst
			} else if b == 0 {
				name = msg.Raw[p : i+1]
				break
			}
		}
		n = len(dst) + int(name[0])
		dst = append(dst, name[1:]...)
		for {
			if dst[n] == 0 {
				break
			} else {
				offset = int(dst[n])
				dst[n] = '.'
				n += offset + 1
			}
		}
		dst = dst[:len(dst)-1]
	}

	return dst
}

// VisitResourceRecords calls f for each item in the msg in the original order of the parsed RR.
func (msg *Message) VisitResourceRecords(f func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool) error {
	if msg.Header.ANCount == 0 {
		return ErrInvalidAnswer
	}

	payload := msg.Raw[16+len(msg.Question.Name):]

	for i := uint16(0); i < msg.Header.ANCount; i++ {
		var name []byte
		for j, b := range payload {
			if b&0b11000000 == 0b11000000 {
				name = payload[:j+2]
				payload = payload[j+2:]
				break
			} else if b == 0 {
				name = payload[:j+1]
				payload = payload[j+1:]
				break
			}
		}
		if name == nil {
			return ErrInvalidAnswer
		}
		typ := Type(payload[0])<<8 | Type(payload[1])
		class := Class(payload[2])<<8 | Class(payload[3])
		ttl := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
		length := uint16(payload[8])<<8 | uint16(payload[9])
		data := payload[10 : 10+length]
		payload = payload[10+length:]
		ok := f(name, typ, class, ttl, data)
		if !ok {
			break
		}
	}

	return nil
}

// VisitAdditionalRecords calls f for each item in the msg in the original order of the parsed AR.
func (msg *Message) VisitAdditionalRecords(f func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool) error {
	panic("not implemented")
}

// SetQustion calls f for each item in the msg in the original order of the parsed AR.
func (msg *Message) SetQustion(domain string, typ Type, class Class) {
	// QR = 0, RCODE=0, RD = 1
	msg.Header.Bits &= 0b0111111111110000
	msg.Header.Bits |= 0b0000000100000000
	msg.Header.QDCount = 1
	msg.Header.ANCount = 0
	msg.Header.NSCount = 0
	msg.Header.ARCount = 0

	header := [...]byte{
		// ID
		byte(msg.Header.ID >> 8), byte(msg.Header.ID & 0xff),
		// 0  1  2  3  4  5  6  7  8
		// +--+--+--+--+--+--+--+--+
		// |QR|   Opcode  |AA|TC|RD|
		// +--+--+--+--+--+--+--+--+
		// |RA|   Z    |   RCODE   |
		// +--+--+--+--+--+--+--+--+
		byte(msg.Header.Bits >> 8), byte(msg.Header.Bits & 0xff),
		// QDCOUNT
		0, 1,
		// ANCOUNT
		0, 0,
		// NSCOUNT
		0, 0,
		// ARCOUNT
		0, 0,
	}

	msg.Raw = append(msg.Raw[:0], header[:]...)

	// QNAME
	msg.Raw = EncodeDomain(msg.Raw, domain)
	// QTYPE
	msg.Raw = append(msg.Raw, byte(typ>>8), byte(typ&0xff))
	// QCLASS
	msg.Raw = append(msg.Raw, byte(class>>8), byte(class&0xff))
}

// AppendMessage appends the dns request to dst and returns the resulting dst.
func AppendMessage(dst []byte, msg *Message) []byte {
	// fixed size array for avoid bounds check
	var header [12]byte

	// ID
	header[0] = byte(msg.Header.ID >> 8)
	header[1] = byte(msg.Header.ID & 0xff)

	// first 8bit part of the first row
	// QR :		0
	// Opcode:	1 2 3 4
	// AA:		5
	// TC:		6
	// RD:		7
	// second 8bit part of the second row
	// RA:		0
	// Z:		1 2 3
	// RCODE:	4 5 6 7
	header[2] = byte(msg.Header.Bits >> 8)
	header[3] = byte(msg.Header.Bits & 0xff)

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
		if msg.Question.Name != nil {
			dst = append(dst, msg.Question.Name...)
		} else {
			i := len(dst)
			j := i + len(msg.Domain)
			dst = append(dst, '.')
			dst = append(dst, msg.Domain...)
			var n byte = 0
			for k := j; k >= i; k-- {
				if dst[k] == '.' {
					dst[k] = n
					n = 0
				} else {
					n++
				}
			}
			dst = append(dst, 0)
		}
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

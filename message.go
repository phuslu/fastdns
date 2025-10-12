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

	// Header encapsulates the construct of the header part of the DNS query message.
	// It follows the conventions stated at RFC1035 section 4.1.1.
	Header struct {
		// ID is an arbitrary 16bit request identifier that is
		// forwarded back in the response so that we can match them up.
		//
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		// |                      ID                       |
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		ID uint16

		// Flags is an arbitrary 16bit represents QR, Opcode, AA, TC, RD, RA, Z and RCODE.
		//
		//   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		Flags Flags

		// QDCOUNT specifies the number of entries in the question section
		//
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		// |                    QDCOUNT                    |
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		QDCount uint16

		// ANCount specifies the number of resource records (RR) in the answer section
		//
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		// |                    ANCOUNT                    |
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		ANCount uint16

		// NSCount specifies the number of name server resource records in the authority section
		//
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		// |                    NSCOUNT                    |
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		NSCount uint16

		// ARCount specifies the number of resource records in the additional records section
		//
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		// |                    ARCOUNT                    |
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		ARCount uint16
	}

	// Question encapsulates the construct of the question part of the DNS query message.
	// It follows the conventions stated at RFC1035 section 4.1.2.
	Question struct {
		// Name refers to the raw query name to be resolved in the query.
		//
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		// |                                               |
		// /                     QNAME                     /
		// /                                               /
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		Name []byte

		// Type specifies the type of the query to perform.
		//
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		// |                     QTYPE                     |
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		Type Type

		// Class specifies the class of the query to perform.
		//
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		// |                     QCLASS                    |
		// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
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
	dst.Header.Flags = Flags(payload[2])<<8 | Flags(payload[3])

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
	for i < len(payload) && payload[i] != 0 {
		j := int(payload[i])
		payload[i] = '.'
		i += j + 1
	}
	dst.Domain = payload[:len(payload)-1]

	return nil
}

// DecodeName decodes dns labels to dst.
func (msg *Message) DecodeName(dst []byte, name []byte) []byte {
	if len(name) < 2 {
		return dst
	}

	// fast path for domain pointer
	if name[1] == 12 && name[0] == 0b11000000 {
		return append(dst, msg.Domain...)
	}

	pos := len(dst)
	var offset int
	if name[len(name)-1] == 0 {
		dst = append(dst, name...)
	} else {
		dst = append(dst, name[:len(name)-2]...)
		offset = int(name[len(name)-2]&0b00111111)<<8 + int(name[len(name)-1])
	}

	for offset != 0 {
		for i := offset; i < len(msg.Raw); {
			b := int(msg.Raw[i])
			if b == 0 {
				offset = 0
				dst = append(dst, 0)
				break
			} else if b&0b11000000 == 0b11000000 {
				offset = int(b&0b00111111)<<8 + int(msg.Raw[i+1])
				break
			} else {
				dst = append(dst, msg.Raw[i:i+b+1]...)
				i += b + 1
			}
		}
	}

	n := pos
	for dst[pos] != 0 {
		i := int(dst[pos])
		dst[pos] = '.'
		pos += i + 1
	}

	if n == 0 {
		dst = dst[1 : len(dst)-1]
	} else {
		dst = append(dst[:n], dst[n+1:len(dst)-1]...)
	}

	return dst
}

type MessageRecord struct {
	Name  []byte
	Type  Type
	Class Class
	TTL   uint32
	Data  []byte
}

type MessageRecords struct {
	count   uint16
	payload []byte
	error   error
	record  MessageRecord
}

func (r *MessageRecords) Next() bool {
	if r.error != nil || r.count == 0 {
		return false
	}
	r.count--
	for j, b := range r.payload {
		if b&0b11000000 == 0b11000000 {
			r.record.Name = r.payload[:j+2]
			r.payload = r.payload[j+2:]
			break
		} else if b == 0 {
			r.record.Name = r.payload[:j+1]
			r.payload = r.payload[j+1:]
			break
		}
	}
	if r.record.Name == nil {
		r.error = ErrInvalidAnswer
		return false
	}
	_ = r.payload[9] // hint compiler to remove bounds check
	r.record.Type = Type(r.payload[0])<<8 | Type(r.payload[1])
	r.record.Class = Class(r.payload[2])<<8 | Class(r.payload[3])
	r.record.TTL = uint32(r.payload[4])<<24 | uint32(r.payload[5])<<16 | uint32(r.payload[6])<<8 | uint32(r.payload[7])
	length := uint16(r.payload[8])<<8 | uint16(r.payload[9])
	r.record.Data = r.payload[10 : 10+length]
	r.payload = r.payload[10+length:]

	return true
}

func (r *MessageRecords) Item() MessageRecord {
	return r.record
}

func (r *MessageRecords) Err() error {
	return r.error
}

// Records return items in the msg in the original order of the parsed RR.
func (msg *Message) Records() (records MessageRecords) {
	records.count = msg.Header.ANCount + msg.Header.NSCount + msg.Header.ARCount
	if n := 16 + len(msg.Question.Name); n <= len(msg.Raw) {
		records.payload = msg.Raw[n:]
	} else {
		records.error = ErrInvalidAnswer
	}
	return
}

// EncodeDomain encodes domain to dst.
func EncodeDomain(dst []byte, domain string) []byte {
	i := len(dst)
	j := i + len(domain)

	dst = append(dst, '.')
	dst = append(dst, domain...)

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

	return dst
}

// SetRequestQuestion set question for DNS request.
func (msg *Message) SetRequestQuestion(domain string, typ Type, class Class) {
	// random head id
	msg.Header.ID = uint16(cheaprandn(65536))

	// QR = 0, RCODE = 0, RD = 1
	//
	//   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	msg.Header.Flags &= 0b0111111111110000
	msg.Header.Flags |= 0b0000000100000000

	msg.Header.QDCount = 1
	msg.Header.ANCount = 0
	msg.Header.NSCount = 0
	msg.Header.ARCount = 0

	header := [...]byte{
		// ID
		byte(msg.Header.ID >> 8), byte(msg.Header.ID),
		// Flags
		byte(msg.Header.Flags >> 8), byte(msg.Header.Flags),
		// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
		0, 1, 0, 0, 0, 0, 0, 0,
	}

	msg.Raw = append(msg.Raw[:0], header[:]...)

	// QNAME
	msg.Raw = EncodeDomain(msg.Raw, domain)
	msg.Question.Name = msg.Raw[len(header) : len(header)+len(domain)+2]
	// QTYPE
	msg.Raw = append(msg.Raw, byte(typ>>8), byte(typ))
	msg.Question.Type = typ
	// QCLASS
	msg.Raw = append(msg.Raw, byte(class>>8), byte(class))
	msg.Question.Class = class

	// Domain
	msg.Domain = append(msg.Domain[:0], domain...)
}

// SetResponseHeader sets QR=1, RCODE=rcode, ANCount=ancount then updates Raw.
func (msg *Message) SetResponseHeader(rcode Rcode, ancount uint16) {
	// QR = 1, RCODE = rcode
	//
	//   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	msg.Header.Flags &= 0b1111111111110000
	msg.Header.Flags |= 0b1000000000000000 | Flags(rcode)

	// Error
	if rcode != RcodeNoError {
		msg.Header.QDCount = 0
		msg.Header.ANCount = 0
		msg.Header.NSCount = 0
		msg.Header.ARCount = 0

		msg.Raw = msg.Raw[:12]

		// Flags
		msg.Raw[2] = byte(msg.Header.Flags >> 8)
		msg.Raw[3] = byte(msg.Header.Flags)

		// QDCount
		msg.Raw[4] = 0
		msg.Raw[5] = 0

		// ANCOUNT
		msg.Raw[6] = 0
		msg.Raw[7] = 0

		// NSCOUNT
		msg.Raw[8] = 0
		msg.Raw[9] = 0

		// ARCOUNT
		msg.Raw[10] = 0
		msg.Raw[11] = 0

		return
	}

	msg.Header.QDCount = 1
	msg.Header.ANCount = ancount
	msg.Header.NSCount = 0
	msg.Header.ARCount = 0

	msg.Raw = msg.Raw[:12+len(msg.Question.Name)+4]
	header := msg.Raw[:12]

	// Flags
	header[2] = byte(msg.Header.Flags >> 8)
	header[3] = byte(msg.Header.Flags)

	// QDCount
	header[4] = 0
	header[5] = 1

	// ANCOUNT
	header[6] = byte(ancount >> 8)
	header[7] = byte(ancount)

	// NSCOUNT
	header[8] = 0
	header[9] = 0

	// ARCOUNT
	header[10] = 0
	header[11] = 0
}

var MaxUDPSize = 1232

var msgPool = sync.Pool{
	New: func() interface{} {
		msg := new(Message)
		msg.Raw = make([]byte, 0, MaxUDPSize)
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

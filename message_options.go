package fastdns

import (
	"errors"
	"net/netip"
)

var (
	// ErrInvalidOption is returned when dns message does not have the expected option size.
	ErrInvalidOption = errors.New("dns message does not have the expected option size")
)

func (r *MessageRecords) Options() (options MessageOptions, err error) {
	if r.error != nil || r.count != 0 {
		err = errors.New("cannot get dns options before records")
		return
	}
	if len(r.payload) < 12 {
		err = ErrInvalidOption
		return
	}
	_ = r.payload[11] // hint compiler to remove bounds check
	options.count = r.options
	options.payload = r.payload
	options.Type = Type(r.payload[1])<<8 | Type(r.payload[2])
	options.UDPSize = uint16(r.payload[3])<<8 | uint16(r.payload[4])
	options.Rcode = Rcode(r.payload[5])
	options.Version = r.payload[6]
	options.Flags = uint16(r.payload[7])<<8 | uint16(r.payload[8])
	options.RDLength = uint16(r.payload[9])<<8 | uint16(r.payload[10])
	options.payload = options.payload[11:]
	if options.Type != TypeOPT || uint16(len(options.payload)) != options.RDLength {
		err = ErrInvalidOption
	}
	return
}

type OptionCode uint16

const (
	OptionCodeNSID      OptionCode = 3
	OptionCodeDAU       OptionCode = 5
	OptionCodeDHU       OptionCode = 6
	OptionCodeN3U       OptionCode = 7
	OptionCodeECS       OptionCode = 8
	OptionCodeEXPIRE    OptionCode = 9
	OptionCodeCOOKIE    OptionCode = 10
	OptionCodeKeepalive OptionCode = 11
	OptionCodePadding   OptionCode = 12
)

type MessageOptions struct {
	Type     Type
	UDPSize  uint16
	Rcode    Rcode
	Version  byte
	Flags    uint16
	RDLength uint16

	count   uint16
	payload []byte
	error   error
	option  MessageOption
}

func (o *MessageOptions) Next() bool {
	if o.error != nil || o.count == 0 {
		return false
	}
	o.count--
	if len(o.payload) < 4 {
		o.error = ErrInvalidOption
		return false
	}
	o.option.Code = OptionCode(o.payload[0])<<8 | OptionCode(o.payload[1])
	length := uint16(o.payload[2])<<8 | uint16(o.payload[3])
	if uint16(len(o.payload)) < 4+length {
		o.error = ErrInvalidOption
		return false
	}
	o.option.Data = o.payload[4 : 4+length]
	o.payload = o.payload[4+length:]
	return true
}

func (o *MessageOptions) Item() MessageOption {
	return o.option
}

func (o *MessageOptions) Err() error {
	return o.error
}

type MessageOption struct {
	Code OptionCode
	Data []byte
}

func (o MessageOption) AsClientSubnet() (subnet netip.Prefix, err error) {
	if o.Code != OptionCodeECS || len(o.Data) < 4 {
		err = ErrInvalidOption
		return
	}
	family := uint16(o.Data[0])<<8 | uint16(o.Data[1])
	sourceNetmask := o.Data[2]
	// scopeNetmask := o.Data[3]
	switch family {
	case 1:
		var b [4]byte
		copy(b[:], o.Data[4:])
		ip, ok := netip.AddrFromSlice(b[:])
		if !ok {
			err = ErrInvalidOption
			return
		}
		subnet = netip.PrefixFrom(ip, int(sourceNetmask))
	case 2:
		var b [16]byte
		copy(b[:], o.Data[4:])
		ip, ok := netip.AddrFromSlice(b[:])
		if !ok {
			err = ErrInvalidOption
			return
		}
		subnet = netip.PrefixFrom(ip, int(sourceNetmask))
	}
	return
}

// OptionsAppender return an options appender for request message.
func (msg *Message) OptionsAppender() (*MessageOptionsAppender, error) {
	if msg.Header.ARCount != 0 {
		return nil, ErrInvalidHeader
	}
	msg.Raw = append(msg.Raw,
		0x00,       // Name
		0x00, 0x29, // OPT
		0x04, 0xd0, // UDP payload size: 1232
		0x00,       // Extended RCODE
		0x00,       // EDNS0 version
		0x00, 0x00, // Z flags
		0x00, 0x00, // Data Legnth: 0
	)
	msg.Raw[10] = 0
	msg.Raw[11] = 1
	msg.Header.ARCount++
	return &MessageOptionsAppender{
		msg:    msg,
		offset: len(msg.Raw) - 2,
	}, nil
}

type MessageOptionsAppender struct {
	msg    *Message
	offset int
}

func (a *MessageOptionsAppender) AppendClientSubnet(prefix netip.Prefix) {
	length := uint16(a.msg.Raw[a.offset])<<8 | uint16(a.msg.Raw[a.offset+1])
	if prefix.Addr().Is4() {
		ipv4 := prefix.Addr().As4()
		a.msg.Raw = append(a.msg.Raw,
			0x00, 0x08, // Option Code: CSUBNET
			0x00, 0x07, // Option Length: 7
			0x00, 0x01, // Family: IPv4
			0x18, // Source Netmask: 24
			0x00, // Scope Netmask: 0
			ipv4[0], ipv4[1], ipv4[2],
		)
		length += 11
	} else {
		ipv6 := prefix.Addr().As16()
		a.msg.Raw = append(a.msg.Raw,
			0x00, 0x08, // Option Code: CSUBNET
			0x00, 0x0b, // Option Length: 11
			0x00, 0x02, // Family: IPv6
			0x38, // Source Netmask:56
			0x00, // Scope Netmask: 0
			ipv6[0], ipv6[1], ipv6[2], ipv6[3],
			ipv6[4], ipv6[5], ipv6[6],
		)
		length += 15
	}
	a.msg.Raw[a.offset] = byte(length >> 8)
	a.msg.Raw[a.offset+1] = byte(length & 0xff)
}

func (a *MessageOptionsAppender) AppendPadding(padding uint16) {
	length := uint16(a.msg.Raw[a.offset])<<8 | uint16(a.msg.Raw[a.offset+1])
	a.msg.Raw = append(append(a.msg.Raw,
		0x00, 0x0c, // Option Code: PADDING
		byte(padding>>8), byte(padding&0xff), // Option Length
	), make([]byte, padding)...)
	length += 2 + 2 + padding
	a.msg.Raw[a.offset] = byte(length >> 8)
	a.msg.Raw[a.offset+1] = byte(length & 0xff)
}

package fastdns

import (
	"net/netip"
)

// AsOptions converts an OPT record into message options.
func (r *MessageRecord) AsOptions() (options MessageOptions, err error) {
	if r.Type != TypeOPT {
		err = ErrInvalidOption
		return
	}
	options.Type = TypeOPT
	options.UDPSize = uint16(r.Class)
	options.Rcode = Rcode(r.TTL >> 24)
	options.Version = byte(r.TTL >> 16)
	options.Flags = uint16(r.TTL)
	options.data = r.Data
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
	Type    Type
	UDPSize uint16
	Rcode   Rcode
	Version byte
	Flags   uint16

	data   []byte
	error  error
	option MessageOption
}

// Next advances to the next available option.
func (o *MessageOptions) Next() bool {
	if o.error != nil || len(o.data) == 0 {
		return false
	}
	if len(o.data) < 4 {
		o.error = ErrInvalidOption
		return false
	}
	o.option.Code = OptionCode(o.data[0])<<8 | OptionCode(o.data[1])
	length := uint16(o.data[2])<<8 | uint16(o.data[3])
	if uint16(len(o.data)) < 4+length {
		o.error = ErrInvalidOption
		return false
	}
	o.option.Data = o.data[4 : 4+length]
	o.data = o.data[4+length:]
	return true
}

// Item returns the current option.
func (o *MessageOptions) Item() MessageOption {
	return o.option
}

// Err reports the iteration error.
func (o *MessageOptions) Err() error {
	return o.error
}

type MessageOption struct {
	Code OptionCode
	Data []byte
}

// AsSubnet decodes an ECS option into a subnet prefix.
func (o MessageOption) AsSubnet() (netip.Prefix, error) {
	if o.Code != OptionCodeECS || len(o.Data) < 4 {
		return netip.Prefix{}, ErrInvalidOption
	}
	family := uint16(o.Data[0])<<8 | uint16(o.Data[1])
	netmask := o.Data[2]
	length := len(o.Data) - 4
	if expected := int(netmask+8-1) / 8; length < expected {
		return netip.Prefix{}, ErrInvalidOption
	}
	switch family {
	case 0x01:
		if netmask > 32 || length > 4 {
			return netip.Prefix{}, ErrInvalidOption
		}
		var b [4]byte
		copy(b[:], o.Data[4:])
		ip, ok := netip.AddrFromSlice(b[:])
		if !ok {
			return netip.Prefix{}, ErrInvalidOption
		}
		return netip.PrefixFrom(ip, int(netmask)), nil
	case 0x02:
		if netmask > 128 || length > 16 {
			return netip.Prefix{}, ErrInvalidOption
		}
		var b [16]byte
		copy(b[:], o.Data[4:])
		ip, ok := netip.AddrFromSlice(b[:])
		if !ok {
			return netip.Prefix{}, ErrInvalidOption
		}
		return netip.PrefixFrom(ip, int(netmask)), nil
	default:
		return netip.Prefix{}, ErrInvalidOption
	}
}

// AsCookie decodes a COOKIE option payload.
func (o MessageOption) AsCookie(dst []byte) ([]byte, error) {
	if o.Code != OptionCodeCOOKIE {
		return nil, ErrInvalidOption
	}
	if n := len(o.Data); n < 8 || n > 40 {
		return nil, ErrInvalidOption
	}
	return append(dst, o.Data...), nil
}

// AsPadding returns the padding option payload.
func (o MessageOption) AsPadding(dst []byte) ([]byte, error) {
	if o.Code != OptionCodePadding {
		return nil, ErrInvalidOption
	}
	return append(dst, o.Data...), nil
}

// OptionsAppender constructs an EDNS options appender for the message.
func (msg *Message) OptionsAppender() (moa MessageOptionsAppender, err error) {
	return MessageOptionsAppender{msg: msg}, nil
}

type MessageOptionsAppender struct {
	msg    *Message
	offset int
}

// init prepares the message for appending options.
func (a *MessageOptionsAppender) init() {
	a.msg.Header.ARCount++
	a.msg.Raw[10] = byte(a.msg.Header.ARCount >> 8)
	a.msg.Raw[11] = byte(a.msg.Header.ARCount)
	a.msg.Raw = append(a.msg.Raw,
		0x00,       // Name
		0x00, 0x29, // OPT
		0x04, 0xd0, // UDP payload size: 1232
		0x00,       // Extended RCODE
		0x00,       // EDNS0 version
		0x00, 0x00, // Z flags
		0x00, 0x00, // Data Legnth: 0
	)
	a.offset = len(a.msg.Raw) - 2
}

// AppendSubnet adds an ECS option for the given prefix.
func (a *MessageOptionsAppender) AppendSubnet(prefix netip.Prefix) {
	if a.offset == 0 {
		a.init()
	}
	prefix = prefix.Masked()
	if !prefix.IsValid() {
		return
	}
	bits := prefix.Bits()
	count := (bits + 8 - 1) / 8
	var family byte
	if prefix.Addr().Is4() {
		family = 0x01
	} else {
		family = 0x02
	}
	ip := prefix.Addr().AsSlice()
	if n := len(ip); count < n {
		ip = ip[:count]
	}
	a.msg.Raw = append(append(a.msg.Raw,
		0x00, 0x08, // Option Code: CSUBNET
		0x00, byte(4+count), // Option Length: 4+count
		0x00, family, // Family: IPv4/IPv6
		byte(bits), // Source Netmask: bits
		0x00,       // Scope Netmask: 0
		// IP slice
	), ip...)
	length := (uint16(a.msg.Raw[a.offset])<<8 | uint16(a.msg.Raw[a.offset+1])) + 4 + 4 + uint16(count)
	a.msg.Raw[a.offset] = byte(length >> 8)
	a.msg.Raw[a.offset+1] = byte(length)
}

// AppendCookie adds a COOKIE option to the message.
func (a *MessageOptionsAppender) AppendCookie(cookie string) {
	if a.offset == 0 {
		a.init()
	}
	a.msg.Raw = append(append(a.msg.Raw,
		0x00, 0x0a, // Option Code: COOKIE
		byte(len(cookie)>>8), byte(len(cookie)), // Option Length
	), cookie...)
	length := (uint16(a.msg.Raw[a.offset])<<8 | uint16(a.msg.Raw[a.offset+1])) + 2 + 2 + uint16(len(cookie))
	a.msg.Raw[a.offset] = byte(length >> 8)
	a.msg.Raw[a.offset+1] = byte(length)
}

// AppendPadding grows the message with a padding option.
func (a *MessageOptionsAppender) AppendPadding(padding uint16) {
	if a.offset == 0 {
		a.init()
	}
	padding = (uint16(len(a.msg.Raw)) + padding - 1) / padding * padding
	a.msg.Raw = append(append(a.msg.Raw,
		0x00, 0x0c, // Option Code: PADDING
		byte(padding>>8), byte(padding), // Option Length
		// Padding
	), make([]byte, padding)...)
	length := (uint16(a.msg.Raw[a.offset])<<8 | uint16(a.msg.Raw[a.offset+1])) + 2 + 2 + padding
	a.msg.Raw[a.offset] = byte(length >> 8)
	a.msg.Raw[a.offset+1] = byte(length)
}

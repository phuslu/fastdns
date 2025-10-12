package fastdns

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strconv"
	"unsafe"
)

// nolint
func b2s(b []byte) string { return *(*string)(unsafe.Pointer(&b)) }

// cheaprandn returns a pseudorandom uint32 in [0,n).
//
//go:noescape
//go:linkname cheaprandn runtime.cheaprandn
func cheaprandn(x uint32) uint32

/*
	  b := appendablebytes(make([]byte, 0, 1024))
	  b = b.Str("GET ").Str(req.RequestURI).Str(" HTTP/1.1\r\n")
	  for key, values := range req.Header {
		for _, value := range values {
			b = b.Str(key).Str(": ").Str(value).Str("\r\n")
	  	}
	  }
	  b = b.Str("\r\n")
*/
type appendablebytes []byte

func (b appendablebytes) Str(s string) appendablebytes {
	return append(b, s...)
}

func (b appendablebytes) Bytes(s []byte) appendablebytes {
	return append(b, s...)
}

func (b appendablebytes) Byte(c byte) appendablebytes {
	return append(b, c)
}

func (b appendablebytes) Base64(data []byte) appendablebytes {
	return base64.StdEncoding.AppendEncode(b, data)
}

func (b appendablebytes) Hex(data []byte) appendablebytes {
	return hex.AppendEncode(b, data)
}

func (b appendablebytes) NetIPAddr(ip netip.Addr) appendablebytes {
	return ip.AppendTo(b)
}

func (b appendablebytes) NetIPAddrPort(addr netip.AddrPort) appendablebytes {
	return addr.AppendTo(b)
}

func (b appendablebytes) Uint64(i uint64, base int) appendablebytes {
	return strconv.AppendUint(b, i, base)
}

func (b appendablebytes) Float64(f float64) appendablebytes {
	return strconv.AppendFloat(b, f, 'f', -1, 64)
}

func (b appendablebytes) Int64(i int64, base int) appendablebytes {
	return strconv.AppendInt(b, i, base)
}

func (b appendablebytes) Pad(c byte, base int) appendablebytes {
	n := (base - len(b)%base) % base
	if n == 0 {
		return b
	}
	if n <= 32 {
		b = append(b, make([]byte, 32)...)
		b = b[:len(b)+n-32]
	} else {
		b = append(b, make([]byte, n)...)
	}
	if c != 0 {
		m := len(b) - 1
		_ = b[m]
		for i := m - n + 1; i <= m; i++ {
			b[i] = c
		}
	}
	return b
}

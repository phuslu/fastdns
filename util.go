package fastdns

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strconv"
	"unsafe"
)

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

// nolint
func b2s(b []byte) string { return *(*string)(unsafe.Pointer(&b)) }

// cheaprandn returns a pseudorandom uint32 in [0,n).
//
//go:noescape
//go:linkname cheaprandn runtime.cheaprandn
func cheaprandn(x uint32) uint32

/*
	  b := AppendableBytes(make([]byte, 0, 1024))
	  b = b.Str("GET ").Str(req.RequestURI).Str(" HTTP/1.1\r\n")
	  for key, values := range req.Header {
		for _, value := range values {
			b = b.Str(key).Str(": ").Str(value).Str("\r\n")
	  	}
	  }
	  b = b.Str("\r\n")
*/
type AppendableBytes []byte

func (b AppendableBytes) Str(s string) AppendableBytes {
	return append(b, s...)
}

func (b AppendableBytes) Bytes(s []byte) AppendableBytes {
	return append(b, s...)
}

func (b AppendableBytes) Byte(c byte) AppendableBytes {
	return append(b, c)
}

func (b AppendableBytes) Base64(data []byte) AppendableBytes {
	return base64.StdEncoding.AppendEncode(b, data)
}

func (b AppendableBytes) Hex(data []byte) AppendableBytes {
	return hex.AppendEncode(b, data)
}

func (b AppendableBytes) NetIPAddr(ip netip.Addr) AppendableBytes {
	return ip.AppendTo(b)
}

func (b AppendableBytes) NetIPAddrPort(addr netip.AddrPort) AppendableBytes {
	return addr.AppendTo(b)
}

func (b AppendableBytes) Uint64(i uint64, base int) AppendableBytes {
	return strconv.AppendUint(b, i, base)
}

func (b AppendableBytes) Float64(f float64) AppendableBytes {
	return strconv.AppendFloat(b, f, 'f', -1, 64)
}

func (b AppendableBytes) Int64(i int64, base int) AppendableBytes {
	return strconv.AppendInt(b, i, base)
}

func (b AppendableBytes) Pad(c byte, base int) AppendableBytes {
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

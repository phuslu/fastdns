package fastdns

import (
	"fmt"
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

func template(dst []byte, template string, startTag, endTag byte, m map[string]interface{}, stripSpace bool) []byte {
	j := 0
	for i := 0; i < len(template); i++ {
		switch template[i] {
		case startTag:
			dst = append(dst, template[j:i]...)
			j = i
		case endTag:
			v, ok := m[template[j+1:i]]
			if !ok {
				dst = append(dst, template[j:i]...)
				j = i
				continue
			}
			switch v := v.(type) {
			case string:
				dst = append(dst, v...)
			case []byte:
				dst = append(dst, v...)
			case int:
				dst = strconv.AppendInt(dst, int64(v), 10)
			case int8:
				dst = strconv.AppendInt(dst, int64(v), 10)
			case int16:
				dst = strconv.AppendInt(dst, int64(v), 10)
			case int32:
				dst = strconv.AppendInt(dst, int64(v), 10)
			case int64:
				dst = strconv.AppendInt(dst, v, 10)
			case uint:
				dst = strconv.AppendUint(dst, uint64(v), 10)
			case uint8:
				dst = strconv.AppendUint(dst, uint64(v), 10)
			case uint16:
				dst = strconv.AppendUint(dst, uint64(v), 10)
			case uint32:
				dst = strconv.AppendUint(dst, uint64(v), 10)
			case uint64:
				dst = strconv.AppendUint(dst, v, 10)
			case float32:
				dst = strconv.AppendFloat(dst, float64(v), 'f', -1, 64)
			case float64:
				dst = strconv.AppendFloat(dst, v, 'f', -1, 64)
			default:
				dst = append(dst, fmt.Sprint(v)...)
			}
			j = i + 1
		case '\r', '\n':
			if stripSpace {
				dst = append(dst, template[j:i]...)
				for j = i; j < len(template); j++ {
					b := template[j]
					if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
						break
					}
				}
				i = j
			}
		}
	}
	dst = append(dst, template[j:]...)
	return dst
}

// nolint
func b2s(b []byte) string { return *(*string)(unsafe.Pointer(&b)) }

// fastrandn returns a pseudorandom uint32 in [0,n).
//
//go:noescape
//go:linkname fastrandn runtime.fastrandn
func fastrandn(x uint32) uint32

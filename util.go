package fastdns

func decodeQName(dst []byte, qname []byte) []byte {
	var i byte
	for i < 255 {
		n := qname[i]
		if n == 0 {
			break
		}
		if i != 0 {
			dst = append(dst, '.')
		}
		dst = append(dst, qname[i+1:i+n+1]...)
		i += n + 1
	}
	return dst
}

func encodeDomain(dst []byte, domain string) []byte {
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

package fastdns

// DecodeQustionName decodes question name to dst.
func DecodeQustionName(dst []byte, qname []byte) []byte {
	switch len(qname) {
	case 0, 1:
		return dst
	}

	n := len(dst) + int(qname[0])
	// append once for performance
	dst = append(dst, qname[1:]...)
	for dst[n] != 0 {
		offset := int(dst[n])
		dst[n] = '.'
		n += offset + 1
	}
	dst = dst[:len(dst)-1]

	return dst
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

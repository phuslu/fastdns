package fastdns

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

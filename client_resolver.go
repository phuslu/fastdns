package fastdns

import (
	"context"
	"errors"
	"net/netip"
)

// LookupCNAME returns the canonical name for the given host.
func (c *Client) LookupCNAME(ctx context.Context, host string) (cname string, err error) {
	req, resp := AcquireMessage(), AcquireMessage()
	defer ReleaseMessage(resp)
	defer ReleaseMessage(req)

	req.SetRequestQuestion(host, TypeCNAME, ClassINET)

	err = c.Exchange(ctx, req, resp)
	if err != nil {
		return
	}

	_ = resp.Walk(func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool {
		switch typ {
		case TypeCNAME:
			cname = string(resp.DecodeName(nil, data))
			return false
		default:
			err = ErrInvalidAnswer
		}
		return true
	})

	return
}

// LookupTXT returns the DNS TXT records for the given domain name.
func (c *Client) LookupTXT(ctx context.Context, host string) (txt []string, err error) {
	req, resp := AcquireMessage(), AcquireMessage()
	defer ReleaseMessage(resp)
	defer ReleaseMessage(req)

	req.SetRequestQuestion(host, TypeTXT, ClassINET)

	err = c.Exchange(ctx, req, resp)
	if err != nil {
		return
	}

	_ = resp.Walk(func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool {
		switch typ {
		case TypeTXT:
			if len(data) > 1 && int(data[0])+1 == len(data) {
				txt = append(txt, string(data[1:]))
			} else {
				err = ErrInvalidAnswer
			}
		default:
			err = ErrInvalidAnswer
		}
		return true
	})

	return
}

// LookupNetIP looks up host using the local resolver. It returns a slice of that host's IP addresses of the type specified by network. The network must be one of "ip", "ip4" or "ip6".
func (c *Client) LookupNetIP(ctx context.Context, network, host string) (ips []netip.Addr, err error) {
	req, resp := AcquireMessage(), AcquireMessage()
	defer ReleaseMessage(resp)
	defer ReleaseMessage(req)

	var typ Type

	switch network {
	case "ip4":
		typ = TypeA
	case "ip6":
		typ = TypeAAAA
	default:
		ips1, err1 := c.LookupNetIP(ctx, "ip4", host)
		ips2, err2 := c.LookupNetIP(ctx, "ip6", host)
		return append(ips1, ips2...), errors.Join(err1, err2)
	}

	req.SetRequestQuestion(host, typ, ClassINET)

	err = c.Exchange(ctx, req, resp)
	if err != nil {
		return
	}

	var cname []byte

	_ = resp.Walk(func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool {
		switch typ {
		case TypeCNAME:
			cname = resp.DecodeName(nil, data)
		case TypeA:
			ips = append(ips, netip.AddrFrom4(*(*[4]byte)(data)))
		case TypeAAAA:
			ips = append(ips, netip.AddrFrom16(*(*[16]byte)(data)))
		}
		return true
	})

	if cname != nil {
		return c.LookupNetIP(ctx, network, b2s(cname))
	}

	return
}

func (c *Client) LookupHTTPS(ctx context.Context, network, host string) (https []NetHTTPS, err error) {
	req, resp := AcquireMessage(), AcquireMessage()
	defer ReleaseMessage(resp)
	defer ReleaseMessage(req)

	req.SetRequestQuestion(host, TypeHTTPS, ClassINET)

	err = c.Exchange(ctx, req, resp)
	if err != nil {
		return
	}

	_ = resp.Walk(func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool {
		switch typ {
		case TypeHTTPS:
			var h NetHTTPS
			if len(data) < 7 {
				return true
			}
			data = data[3:]
			for len(data) >= 4 {
				key := int(data[0])<<8 | int(data[1])
				length := int(data[2])<<8 | int(data[3])
				value := data[4 : 4+length]
				data = data[4+length:]
				switch key {
				case 1: // alpn
					for len(value) != 0 {
						length := int(value[0])
						h.ALPN = append(h.ALPN, string(value[1:1+length]))
						value = value[1+length:]
					}
				case 4: // ipv4hint
					if len(value) != length {
						continue
					}
					for i := 0; i < length; i += 4 {
						h.IPv4Hint = append(h.IPv4Hint, netip.AddrFrom4(*(*[4]byte)(value[i : i+4])))
					}
				case 5: // ech
					if len(value) < 2 {
						continue
					}
					h.ECH = append(h.ECH[:0], value[2:]...)
				case 6: // ipv6hint
					if len(value) != length {
						continue
					}
					for i := 0; i < length; i += 16 {
						h.IPv6Hint = append(h.IPv6Hint, netip.AddrFrom16(*(*[16]byte)(value[i : i+16])))
					}
				}
			}
			https = append(https, h)
		}
		return true
	})

	return
}

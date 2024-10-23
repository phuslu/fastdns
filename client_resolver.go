package fastdns

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
)

// AppendLookupNetIP looks up host and appends result to dst using the local resolver.
func (c *Client) AppendLookupNetIP(dst []netip.Addr, ctx context.Context, network, host string) (_ []netip.Addr, err error) {
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
		dst, err = c.AppendLookupNetIP(dst, ctx, "ip4", host)
		if err != nil {
			return
		}
		dst, err = c.AppendLookupNetIP(dst, ctx, "ip6", host)
		if err != nil {
			return
		}
		return dst, nil
	}

	req.SetRequestQuestion(host, typ, ClassINET)

	err = c.Exchange(ctx, req, resp)
	if err != nil {
		return nil, err
	}

	cname := make([]byte, 0, 64)

	_ = resp.Walk(func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool {
		switch typ {
		case TypeCNAME:
			cname = resp.DecodeName(cname[:0], data)
		case TypeA:
			dst = append(dst, netip.AddrFrom4(*(*[4]byte)(data)))
		case TypeAAAA:
			dst = append(dst, netip.AddrFrom16(*(*[16]byte)(data)))
		}
		return true
	})

	if cname != nil && len(dst) == 0 {
		dst, err = c.AppendLookupNetIP(dst, ctx, network, b2s(cname))
	}

	return dst, err
}

// LookupNetIP looks up host using the local resolver. It returns a slice of that host's IP addresses of the type specified by network. The network must be one of "ip", "ip4" or "ip6".
func (c *Client) LookupNetIP(ctx context.Context, network, host string) (ips []netip.Addr, err error) {
	return c.AppendLookupNetIP(ips, ctx, network, host)
}

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

// LookupNS returns the DNS NS records for the given domain name.
func (c *Client) LookupNS(ctx context.Context, name string) (ns []*net.NS, err error) {
	req, resp := AcquireMessage(), AcquireMessage()
	defer ReleaseMessage(resp)
	defer ReleaseMessage(req)

	req.SetRequestQuestion(name, TypeNS, ClassINET)

	err = c.Exchange(ctx, req, resp)
	if err != nil {
		return
	}

	_ = resp.Walk(func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool {
		switch typ {
		case TypeNS:
			ns = append(ns, &net.NS{
				Host: string(resp.DecodeName(nil, data)),
			})
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

// LookupMX returns the DNS MX records for the given domain name sorted by preference.
func (c *Client) LookupMX(ctx context.Context, host string) (mx []*net.MX, err error) {
	req, resp := AcquireMessage(), AcquireMessage()
	defer ReleaseMessage(resp)
	defer ReleaseMessage(req)

	req.SetRequestQuestion(host, TypeMX, ClassINET)

	err = c.Exchange(ctx, req, resp)
	if err != nil {
		return
	}

	_ = resp.Walk(func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool {
		switch typ {
		case TypeMX:
			mx = append(mx, &net.MX{
				Host: string(resp.DecodeName(nil, data[2:])),
				Pref: binary.BigEndian.Uint16(data),
			})
		}
		return true
	})

	return
}

// LookupHTTPS returns the DNS HTTPS records for the given domain name.
func (c *Client) LookupHTTPS(ctx context.Context, host string) (https []NetHTTPS, err error) {
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
				case 1: // ALPN
					for len(value) != 0 {
						length := int(value[0])
						h.ALPN = append(h.ALPN, string(value[1:1+length]))
						value = value[1+length:]
					}
				case 2: // NoDefaultALPN
					h.NoDefaultALPN = true
				case 3: // Port
					h.Port = uint32(value[0])<<8 | uint32(value[1])
				case 4: // IPV4Hint
					if len(value) != length {
						continue
					}
					for i := 0; i < length; i += 4 {
						h.IPv4Hint = append(h.IPv4Hint, netip.AddrFrom4(*(*[4]byte)(value[i : i+4])))
					}
				case 5: // ECH
					if len(value) < 2 {
						continue
					}
					h.ECH = append(h.ECH[:0], value...)
				case 6: // IPV6Hint
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

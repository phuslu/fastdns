package fastdns

import (
	"cmp"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
)

// AppendLookupNetIP looks up host and appends result to dst using the local resolver.
func (c *Client) AppendLookupNetIP(dst []netip.Addr, ctx context.Context, network, host string) (_ []netip.Addr, err error) {
	req, resp := AcquireMessage(), AcquireMessage()
	defer ReleaseMessage(resp)
	defer ReleaseMessage(req)

	var typ Type

	switch network {
	case "ip":
		dst, err = c.AppendLookupNetIP(dst, ctx, "ip4", host)
		if err != nil {
			return
		}
		dst, err = c.AppendLookupNetIP(dst, ctx, "ip6", host)
		if err != nil {
			return
		}
		return dst, nil
	case "ip4":
		typ = TypeA
	case "ip6":
		typ = TypeAAAA
	default:
		return nil, ErrInvalidQuestion
	}

	req.SetRequestQuestion(host, typ, ClassINET)

	err = c.Exchange(ctx, req, resp)
	if err != nil {
		return nil, err
	}

	var cname []byte
	records := resp.Records()
	for records.Next() {
		r := records.Item()
		switch r.Type {
		case TypeCNAME:
			cname = r.Data
		case TypeA:
			dst = append(dst, netip.AddrFrom4(*(*[4]byte)(r.Data)))
		case TypeAAAA:
			dst = append(dst, netip.AddrFrom16(*(*[16]byte)(r.Data)))
		}
	}
	if err := records.Err(); err != nil {
		return dst, err
	}

	if cname != nil && len(dst) == 0 {
		b := resp.DecodeName(make([]byte, 0, 64), cname)
		dst, err = c.AppendLookupNetIP(dst, ctx, network, b2s(b))
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

	records := resp.Records()
	for records.Next() {
		r := records.Item()
		switch r.Type {
		case TypeCNAME:
			cname = string(resp.DecodeName(nil, r.Data))
		default:
			err = ErrInvalidAnswer
		}
	}
	if err = records.Err(); err != nil {
		return
	}

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

	soa := make([]byte, 0, 64)

	records := resp.Records()
	for records.Next() {
		r := records.Item()
		switch r.Type {
		case TypeSOA:
			soa = resp.DecodeName(soa[:0], r.Name)
		case TypeNS:
			ns = append(ns, &net.NS{Host: string(resp.DecodeName(nil, r.Data))})
		default:
			err = ErrInvalidAnswer
		}
	}
	if err = records.Err(); err != nil {
		return
	}

	if len(soa) != 0 {
		ns, err = c.LookupNS(ctx, b2s(soa))
	}

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

	records := resp.Records()
	for records.Next() {
		r := records.Item()
		switch r.Type {
		case TypeTXT:
			if len(r.Data) > 1 && int(r.Data[0])+1 == len(r.Data) {
				txt = append(txt, string(r.Data[1:]))
			} else {
				err = ErrInvalidAnswer
			}
		default:
			err = ErrInvalidAnswer
		}
	}
	if err = records.Err(); err != nil {
		return
	}

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

	records := resp.Records()
	for records.Next() {
		r := records.Item()
		if r.Type == TypeMX {
			mx = append(mx, &net.MX{
				Host: string(resp.DecodeName(nil, r.Data[2:])),
				Pref: binary.BigEndian.Uint16(r.Data),
			})
		}
	}
	if err = records.Err(); err != nil {
		return
	}

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

	records := resp.Records()
	for records.Next() {
		r := records.Item()
		if r.Type == TypeHTTPS {
			var h NetHTTPS
			data := r.Data
			if len(data) < 7 {
				return nil, ErrInvalidAnswer
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
	}
	if err = records.Err(); err != nil {
		return
	}

	return
}

// LookupSRV tries to resolve an SRV query of the given service, protocol, and domain name.
// The proto is "tcp" or "udp". The returned records are sorted by priority and randomized by weight within a priority.
func (c *Client) LookupSRV(ctx context.Context, service, proto, name string) (target string, srvs []*net.SRV, err error) {
	if service == "" && proto == "" {
		target = name
	} else {
		target = "_" + service + "._" + proto + "." + name
	}

	req, resp := AcquireMessage(), AcquireMessage()
	defer ReleaseMessage(resp)
	defer ReleaseMessage(req)

	req.SetRequestQuestion(target, TypeSRV, ClassINET)

	err = c.Exchange(ctx, req, resp)
	if err != nil {
		return
	}

	var buf [256]byte
	records := resp.Records()
	for records.Next() {
		r := records.Item()
		switch r.Type {
		case TypeSRV:
			if len(r.Data) < 8 {
				err = ErrInvalidAnswer
				break
			}
			srvs = append(srvs, &net.SRV{
				Target:   string(resp.DecodeName(buf[:0], r.Data[6:])),
				Port:     binary.BigEndian.Uint16(r.Data[4:]),
				Priority: binary.BigEndian.Uint16(r.Data[0:]),
				Weight:   binary.BigEndian.Uint16(r.Data[2:]),
			})
		default:
			err = ErrInvalidAnswer
		}
	}
	if err = records.Err(); err != nil {
		return
	}

	if len(srvs) > 1 {
		byPriorityWeight(srvs).sort()
	}

	return
}

// Copy from https://github.com/golang/go/blob/master/src/net/dnsclient.go
// byPriorityWeight sorts SRV records by ascending priority and weight.
type byPriorityWeight []*net.SRV

// shuffleByWeight shuffles SRV records by weight using the algorithm
// described in RFC 2782.
func (addrs byPriorityWeight) shuffleByWeight() {
	sum := 0
	for _, addr := range addrs {
		sum += int(addr.Weight)
	}
	for sum > 0 && len(addrs) > 1 {
		s := 0
		n := int(cheaprandn(uint32(sum)))
		for i := range addrs {
			s += int(addrs[i].Weight)
			if s > n {
				if i > 0 {
					addrs[0], addrs[i] = addrs[i], addrs[0]
				}
				break
			}
		}
		sum -= int(addrs[0].Weight)
		addrs = addrs[1:]
	}
}

// sort reorders SRV records as specified in RFC 2782.
func (addrs byPriorityWeight) sort() {
	slices.SortFunc(addrs, func(a, b *net.SRV) int {
		if r := cmp.Compare(a.Priority, b.Priority); r != 0 {
			return r
		}
		return cmp.Compare(a.Weight, b.Weight)
	})
	i := 0
	for j := 1; j < len(addrs); j++ {
		if addrs[i].Priority != addrs[j].Priority {
			addrs[i:j].shuffleByWeight()
			i = j
		}
	}
	addrs[i:].shuffleByWeight()
}

package fastdns

import (
	"context"
	"errors"
	"net/netip"
)

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

	err = c.Exchange(req, resp)
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

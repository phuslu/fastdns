package fastdns

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestClientExchange(t *testing.T) {
	var cases = []struct {
		Domain string
		Class  Class
		Type   Type
	}{
		{"hk2cn.phus.lu", ClassINET, TypeA},
	}

	client := &Client{
		AddrPort:    netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53),
		ReadTimeout: 1 * time.Second,
		MaxConns:    1000,
	}

	for _, c := range cases {
		req, resp := AcquireMessage(), AcquireMessage()
		req.SetRequestQuestion(c.Domain, c.Type, c.Class)
		err := client.Exchange(req, resp)
		if err != nil {
			t.Errorf("client=%+v exchange(%v) error: %+v\n", client, c.Domain, err)
		}
		t.Logf("%s: CLASS %s TYPE %s\n", resp.Domain, resp.Question.Class, resp.Question.Type)
		_ = resp.Walk(func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool {
			switch typ {
			case TypeCNAME:
				t.Logf("%s.\t%d\t%s\t%s\t%s.\n", resp.DecodeName(nil, name), ttl, class, typ, resp.DecodeName(nil, data))
			case TypeA:
				t.Logf("%s.\t%d\t%s\t%s\t%s\n", resp.DecodeName(nil, name), ttl, class, typ, netip.AddrFrom4(*(*[4]byte)(data)))
			case TypeAAAA:
				t.Logf("%s.\t%d\t%s\t%s\t%s\n", resp.DecodeName(nil, name), ttl, class, typ, netip.AddrFrom16(*(*[16]byte)(data)))
			}
			return true
		})
	}
}

func TestLookupNetIP(t *testing.T) {
	host := "cloud.phus.lu"

	client := &Client{
		AddrPort:    netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53),
		ReadTimeout: 1 * time.Second,
		MaxConns:    1000,
		DialContext: (&HTTPDialer{
			Endpoint:  "https://1.1.1.1/dns-query",
			UserAgent: "fastdns/0.9",
		}).DialContext,
	}

	ips, err := client.LookupNetIP(context.Background(), "ip", host)

	t.Logf("client.LookupNetIP(%+v) return ips=%s err=%+v\n", host, ips, err)
}

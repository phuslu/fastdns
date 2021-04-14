package fastdns

import (
	"net"
	"testing"
	"time"
)

func TestClientExchange(t *testing.T) {
	var cases = []struct {
		Domain string
		Class  Class
		Type   Type
	}{
		{"hk2cn.flyspace.top", ClassINET, TypeA},
	}

	client := &Client{
		ServerAddr:  &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53},
		ReadTimeout: 1 * time.Second,
		MaxConns:    1000,
	}

	for _, c := range cases {
		req, resp := AcquireMessage(), AcquireMessage()
		req.SetRequestQustion(c.Domain, c.Type, c.Class)
		err := client.Exchange(req, resp)
		if err != nil {
			t.Errorf("client=%+v exchange(%v) error: %+v\n", client, c.Domain, err)
		}
		t.Logf("%s: CLASS %s TYPE %s\n", resp.Domain, resp.Question.Class, resp.Question.Type)
		_ = resp.VisitResourceRecords(func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool {
			switch typ {
			case TypeCNAME:
				t.Logf("%s.\t%d\t%s\t%s\t%s.\n", resp.DecodeName(nil, name), ttl, class, typ, resp.DecodeName(nil, data))
			case TypeA, TypeAAAA:
				t.Logf("%s.\t%d\t%s\t%s\t%s\n", resp.DecodeName(nil, name), ttl, class, typ, net.IP(data))
			}
			return true
		})
	}
}

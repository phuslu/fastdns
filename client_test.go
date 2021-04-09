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
		ServerAddr: &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53},
		ReadTimout: 1 * time.Second,
		MaxConns:   1000,
	}

	for _, c := range cases {
		req, resp := AcquireMessage(), AcquireMessage()
		req.SetQustion(c.Domain, c.Type, c.Class)
		err := client.Exchange(req, resp)
		if err != nil {
			t.Errorf("client=%+v exchange(%v) error: %+v\n", client, c.Domain, err)
		}
		t.Logf("%s: CLASS %s TYPE %s\n", resp.Domain, resp.Question.Class, resp.Question.Type)
		_ = resp.VisitResourceRecords(func(name []byte, typ Type, class Class, ttl uint32, data []byte) bool {
			switch typ {
			case TypeA, TypeAAAA:
				t.Logf("%s: CLASS %s TYPE %s %d %s\n", resp.DecodeName(nil, name), class, typ, ttl, net.IP(data))
			case TypeCNAME:
				t.Logf("%s: CLASS %s TYPE %s %d %s\n", resp.DecodeName(nil, name), class, typ, ttl, resp.DecodeName(nil, data))
			}
			return true
		})
	}
}

package fastdns

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"
	"unsafe"
)

func TestClientContext(t *testing.T) {
	key, value := struct{ key string }{key: "a"}, "b"

	ctx := context.WithValue(context.Background(), key, value)
	req, _ := http.NewRequest(http.MethodGet, "https://1.1.1.1/dns-query", nil)

	*(*context.Context)(unsafe.Pointer(uintptr(unsafe.Pointer(req)) + httpctxoffset)) = ctx

	got, _ := req.Context().Value(key).(string)
	want := value
	if got != want {
		t.Errorf("set http request context inplace failed, got=%s, want=%s", got, want)
	}
}

func TestClientExchange(t *testing.T) {
	var cases = []struct {
		Domain string
		Class  Class
		Type   Type
	}{
		{"hk2cn.phus.lu", ClassINET, TypeA},
	}

	client := &Client{
		Addr:    "1.1.1.1:53",
		Timeout: 1 * time.Second,
	}

	for _, c := range cases {
		req, resp := AcquireMessage(), AcquireMessage()
		req.SetRequestQuestion(c.Domain, c.Type, c.Class)
		err := client.Exchange(context.Background(), req, resp)
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

func TestClientLookup(t *testing.T) {
	var cases = []struct {
		Host string
		Type Type
	}{
		{"cloud.phus.lu", TypeA},
		{"cloud.phus.lu", TypeAAAA},
		{"cloud.phus.lu", TypeANY},
		{"cloud.phus.lu", TypeHTTPS},
		{"abcde.phus.lu", TypeCNAME},
		{"phus.lu", TypeTXT},
	}

	client := &Client{
		Addr: "1.1.1.1:53",
		Dialer: &HTTPDialer{
			Endpoint:  func() (u *url.URL) { u, _ = url.Parse("https://1.1.1.1/dns-query"); return }(),
			UserAgent: "fastdns/0.9",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, c := range cases {
		var result any
		var err error
		switch c.Type {
		case TypeA:
			result, err = client.LookupNetIP(ctx, "ip4", c.Host)
		case TypeAAAA:
			result, err = client.LookupNetIP(ctx, "ip6", c.Host)
		case TypeANY:
			result, err = client.LookupNetIP(ctx, "ip", c.Host)
		case TypeCNAME:
			result, err = client.LookupCNAME(ctx, c.Host)
		case TypeHTTPS:
			result, err = client.LookupHTTPS(ctx, c.Host)
		case TypeTXT:
			result, err = client.LookupTXT(ctx, c.Host)
		default:
			t.Errorf("fastdns client lookup is unsupported type(%s)", c.Type)
		}
		if err != nil {
			t.Errorf("fastdns client lookup %s %s error: %+v", c.Type, c.Host, err)
		}
		t.Logf("Lookup %s %s result=%+v", c.Type, c.Host, result)
	}
}

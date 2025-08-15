package fastdns

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"regexp"
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
		records := resp.Records()
		for records.Next() {
			r := records.Item()
			switch r.Type {
			case TypeCNAME:
				t.Logf("%s.\t%d\t%s\t%s\t%s.\n", resp.DecodeName(nil, r.Name), r.TTL, r.Class, r.Type, resp.DecodeName(nil, r.Data))
			case TypeA:
				t.Logf("%s.\t%d\t%s\t%s\t%s\n", resp.DecodeName(nil, r.Name), r.TTL, r.Class, r.Type, netip.AddrFrom4(*(*[4]byte)(r.Data)))
			case TypeAAAA:
				t.Logf("%s.\t%d\t%s\t%s\t%s\n", resp.DecodeName(nil, r.Name), r.TTL, r.Class, r.Type, netip.AddrFrom16(*(*[16]byte)(r.Data)))
			}
		}
	}
}

func deref(value any) any {
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Slice {
		return v
	}
	result := make([]any, v.Len())
	for i := 0; i < v.Len(); i++ {
		elem := v.Index(i)
		if elem.Kind() == reflect.Ptr {
			result[i] = elem.Elem().Interface()
		} else {
			result[i] = elem.Interface()
		}
	}
	return result
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
		{"cloud.phus.lu", TypeNS},
		{"abcde.phus.lu", TypeCNAME},
		{"phus.lu", TypeHTTPS},
		{"phus.lu", TypeTXT},
		{"phus.lu", TypeNS},
		{"phus.lu", TypeMX},
	}

	clients := []*Client{
		{
			Addr: "1.1.1.1:53",
			Dialer: &UDPDialer{
				Addr:     func() (u *net.UDPAddr) { u, _ = net.ResolveUDPAddr("udp", "1.1.1.1:53"); return }(),
				MaxConns: 16,
			},
		},
		{
			Addr: "1.1.1.1:53",
			Dialer: &TCPDialer{
				Addr:     func() (u *net.TCPAddr) { u, _ = net.ResolveTCPAddr("tcp", "1.1.1.1:53"); return }(),
				MaxConns: 16,
			},
		},
		{
			Addr: "1.1.1.1:853",
			Dialer: &TCPDialer{
				Addr:      func() (u *net.TCPAddr) { u, _ = net.ResolveTCPAddr("tcp", "1.1.1.1:853"); return }(),
				TLSConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "1.1.1.1"},
				MaxConns:  16,
			},
		},
		{
			Addr: "https://1.1.1.1/dns-query",
			Dialer: &HTTPDialer{
				Endpoint: func() (u *url.URL) { u, _ = url.Parse("https://1.1.1.1/dns-query"); return }(),
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, client := range clients {
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
			case TypeNS:
				result, err = client.LookupNS(ctx, c.Host)
			case TypeMX:
				result, err = client.LookupMX(ctx, c.Host)
			default:
				t.Errorf("fastdns client lookup is unsupported type(%s)", c.Type)
			}
			if err != nil {
				t.Errorf("fastdns client lookup %s %s error: %+v", c.Type, c.Host, err)
			}
			t.Logf("%s Lookup %s %s result=%+v", client.Addr, c.Type, c.Host, deref(result))
		}
	}
}

func TestClientLookupNetIP(t *testing.T) {
	host := "ip.phus.lu"

	client := &Client{
		Addr:    "1.1.1.1:53",
		Timeout: 1 * time.Second,
	}

	ips, err := client.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		t.Errorf("dns_server=%+v LookupNetIP(%#v) error: %+v\n", client.Addr, host, err)
	}
	t.Logf("dns_server=%+v LookupNetIP(%#v) return %+v", client.Addr, host, ips)
}

func TestClientLookupSRV(t *testing.T) {
	client := &Client{
		Addr:    "1.1.1.1:53",
		Timeout: 1 * time.Second,
	}

	cname, ips, err := client.LookupSRV(context.Background(), "xmpp-client", "tcp", "jabber.org")
	if err != nil {
		t.Errorf("dns_server=%+v LookupSRV(\"_xmpp-client._tcp.jabber.org\") error: %+v\n", client.Addr, err)
	}
	t.Logf("dns_server=%+v LookupSRV(\"_xmpp-client._tcp.jabber.org\") return %+v %+v", client.Addr, cname, deref(ips))
}

func BenchmarkResolverPureGo(b *testing.B) {
	resolver := net.Resolver{PreferGo: true}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(b *testing.PB) {
		for b.Next() {
			_, _ = resolver.LookupNetIP(context.Background(), "ip4", "www.google.com")
		}
	})
}

func BenchmarkResolverFastdnsDefault(b *testing.B) {
	server := "8.8.8.8:53"
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if m := regexp.MustCompile(`(^|\n)\s*nameserver\s+(\S+)`).FindAllStringSubmatch(string(data), -1); len(m) != 0 {
			server = m[0][2] + ":53"
		}
	}
	// b.Logf("fastdns use dns server: %s", server)

	resolver := &Client{
		Addr: server,
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ips, err := resolver.LookupNetIP(context.Background(), "ip4", "www.google.com")
			if len(ips) == 0 || err != nil {
				b.Errorf("fastdns return ips: %+v error: %+v", ips, err)
			}
		}
	})
}

func BenchmarkResolverFastdnsUDP(b *testing.B) {
	server := "8.8.8.8:53"
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if m := regexp.MustCompile(`(^|\n)\s*nameserver\s+(\S+)`).FindAllStringSubmatch(string(data), -1); len(m) != 0 {
			server = m[0][2] + ":53"
		}
	}
	// b.Logf("fastdns use dns server: %s", server)

	resolver := &Client{
		Addr: server,
		Dialer: &UDPDialer{
			Addr:     func() (u *net.UDPAddr) { u, _ = net.ResolveUDPAddr("udp", server); return }(),
			MaxConns: 1024,
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ips, err := resolver.LookupNetIP(context.Background(), "ip4", "www.google.com")
			if len(ips) == 0 || err != nil {
				b.Errorf("fastdns return ips: %+v error: %+v", ips, err)
			}
		}
	})
}

func BenchmarkResolverFastdnsUDPAppend(b *testing.B) {
	server := "8.8.8.8:53"
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if m := regexp.MustCompile(`(^|\n)\s*nameserver\s+(\S+)`).FindAllStringSubmatch(string(data), -1); len(m) != 0 {
			server = m[0][2] + ":53"
		}
	}
	// b.Logf("fastdns use dns server: %s", server)

	resolver := &Client{
		Addr: server,
		Dialer: &UDPDialer{
			Addr:     func() (u *net.UDPAddr) { u, _ = net.ResolveUDPAddr("udp", server); return }(),
			MaxConns: 1024,
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var ips []netip.Addr
		var err error
		for pb.Next() {
			ips, err = resolver.AppendLookupNetIP(ips[:0], context.Background(), "ip4", "www.google.com")
			if len(ips) == 0 || err != nil {
				b.Errorf("fastdns return ips: %+v error: %+v", ips, err)
			}
		}
	})
}

func BenchmarkResolverFastdnsTCP(b *testing.B) {
	server := "1.1.1.1:53"

	resolver := &Client{
		Addr: server,
		Dialer: &TCPDialer{
			Addr:     func() (u *net.TCPAddr) { u, _ = net.ResolveTCPAddr("tcp", server); return }(),
			MaxConns: 8,
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ips, err := resolver.LookupNetIP(context.Background(), "ip4", "www.google.com")
			if len(ips) == 0 || err != nil {
				b.Errorf("fastdns return ips: %+v error: %+v", ips, err)
			}
		}
	})
}

func BenchmarkResolverFastdnsTLS(b *testing.B) {
	server := "1.1.1.1:853"

	resolver := &Client{
		Addr: server,
		Dialer: &TCPDialer{
			Addr:     func() (u *net.TCPAddr) { u, _ = net.ResolveTCPAddr("tcp", server); return }(),
			MaxConns: 8,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         server,
				ClientSessionCache: tls.NewLRUClientSessionCache(1024),
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ips, err := resolver.LookupNetIP(context.Background(), "ip4", "www.google.com")
			if len(ips) == 0 || err != nil {
				b.Errorf("fastdns return ips: %+v error: %+v", ips, err)
			}
		}
	})
}

func BenchmarkResolverFastdnsHTTP(b *testing.B) {
	server := "1.1.1.1"

	resolver := &Client{
		Addr: server,
		Dialer: &HTTPDialer{
			Endpoint: func() (u *url.URL) { u, _ = url.Parse("https://" + server + "/dns-query"); return }(),
			Header: http.Header{
				"content-type": {"application/dns-message"},
				"user-agent":   {"fastdns/1.0"},
			},
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				TLSClientConfig: &tls.Config{
					NextProtos:         []string{"h2"},
					InsecureSkipVerify: false,
					ServerName:         server,
					ClientSessionCache: tls.NewLRUClientSessionCache(1024),
				},
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ips, err := resolver.LookupNetIP(context.Background(), "ip4", "www.google.com")
			if len(ips) == 0 || err != nil {
				b.Errorf("fastdns return ips: %+v error: %+v", ips, err)
			}
		}
	})
}

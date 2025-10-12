package fastdns

import (
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestMessageAppendHOST(t *testing.T) {
	cases := []struct {
		Hex string
		IPs []netip.Addr
		TTL uint32
	}{
		{
			"c00c000100010000012c000401010101c00c000100010000012c000408080808c00c000100010000012c00047b2d064e",
			[]netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1}), netip.AddrFrom4([4]byte{8, 8, 8, 8}), netip.AddrFrom4([4]byte{123, 45, 6, 78})},
			300,
		},
		{
			"c00c001c00010000012c001000000000000000000000000000000001c00c001c00010000012c001020014860486000000000000000008888",
			[]netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("2001:4860:4860::8888")},
			300,
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Class = ClassINET
		req.AppendHOST(c.TTL, c.IPs)
		if got, want := hex.EncodeToString(req.Raw), c.Hex; got != want {
			t.Errorf("AppendHOST(%v) error got=%#v want=%#v", c.IPs, got, want)
		}
	}

}

func TestMessageAppendCNAME(t *testing.T) {
	cases := []struct {
		Hex    string
		CNAMEs []string
		IPs    []netip.Addr
		TTL    uint32
	}{
		{
			"c00c000500010000012c00090470687573026c7500",
			[]string{"phus.lu"},
			nil,
			300,
		},
		{
			"c00c000500010000012c00090470687573026c7500c028001c00010000012c001020014860486000000000000000008888",
			[]string{"phus.lu"},
			[]netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")},
			300,
		},
		{
			"c00c000500010000012c00090470687573026c7500c028000500010000012c000c02686b0470687573026c7500c040000100010000012c000401010101c040000100010000012c000408080808",
			[]string{"phus.lu", "hk.phus.lu"},
			[]netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1}), netip.AddrFrom4([4]byte{8, 8, 8, 8})},
			300,
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Name = EncodeDomain(nil, "ip.phus.lu")
		req.Question.Class = ClassINET
		req.AppendCNAME(c.TTL, c.CNAMEs, c.IPs)
		if got, want := hex.EncodeToString(req.Raw), c.Hex; got != want {
			t.Errorf("AppendCNAME(%v) error got=%#v want=%#v", c.IPs, got, want)
		}
	}

}

func TestMessageAppendSRV(t *testing.T) {
	cases := []struct {
		Hex string
		TTL uint32
		SRV net.SRV
	}{
		{
			"c00c002100010000012c001203e803e8005002686b0470687573026c7500",
			300,
			net.SRV{Target: "hk.phus.lu", Port: 80, Priority: 1000, Weight: 1000},
		},
		{
			"c00c002100010000012c00120400040001bb0273670470687573026c7500",
			300,
			net.SRV{Target: "sg.phus.lu", Port: 443, Priority: 1024, Weight: 1024},
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Class = ClassINET
		req.AppendSRV(c.TTL, []net.SRV{c.SRV})
		if got, want := hex.EncodeToString(req.Raw), c.Hex; got != want {
			t.Errorf("AppendSRV(%v) error got=%#v want=%#v", c.SRV, got, want)
		}
	}

}

func TestMessageAppendNS(t *testing.T) {
	cases := []struct {
		Hex         string
		TTL         uint32
		Nameservers []net.NS
	}{
		{
			"c00c000200010000012c0010036e733106676f6f676c6503636f6d00",
			300,
			[]net.NS{{Host: "ns1.google.com"}},
		},
		{
			"c00c000200010000012c0010036e733106676f6f676c6503636f6d00c00c000200010000012c0010036e733206676f6f676c6503636f6d00",
			300,
			[]net.NS{{Host: "ns1.google.com"}, {Host: "ns2.google.com"}},
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Name = EncodeDomain(nil, "ip.phus.lu")
		req.Question.Class = ClassINET
		req.AppendNS(c.TTL, c.Nameservers)
		if got, want := hex.EncodeToString(req.Raw), c.Hex; got != want {
			t.Errorf("AppendNS(%v) error got=%#v want=%#v", c.Nameservers, got, want)
		}
	}

}

func TestMessageAppendSOA(t *testing.T) {
	cases := []struct {
		Hex     string
		TTL     uint32
		MName   net.NS
		RName   net.NS
		Serial  uint32
		Refresh uint32
		Retry   uint32
		Expire  uint32
		Minimum uint32
	}{
		{
			"c00c000600010000012c003a036e733106676f6f676c6503636f6d0009646e732d61646d696e06676f6f676c6503636f6d00400000000000038400000384000007080000003c",
			300,
			net.NS{Host: "ns1.google.com"},
			net.NS{Host: "dns-admin.google.com"},
			1073741824,
			900,
			900,
			1800,
			60,
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Name = EncodeDomain(nil, "www.google.com")
		req.Question.Class = ClassINET
		req.AppendSOA(c.TTL, c.MName, c.RName, c.Serial, c.Refresh, c.Retry, c.Expire, c.Minimum)
		if got, want := hex.EncodeToString(req.Raw), c.Hex; got != want {
			t.Errorf("AppendSOA(%v) error got=%#v want=%#v", c.MName, got, want)
		}
	}

}

func TestMessageAppendMX(t *testing.T) {
	cases := []struct {
		Hex string
		TTL uint32
		MX  net.MX
	}{
		{
			"c00c000f00010000012c000e000a02686b0470687573026c7500",
			300,
			net.MX{Host: "hk.phus.lu", Pref: 10},
		},
		{
			"c00c000f00010000012c000e000a0273670470687573026c7500",
			300,
			net.MX{Host: "sg.phus.lu", Pref: 10},
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Class = ClassINET
		req.AppendMX(c.TTL, []net.MX{c.MX})
		if got, want := hex.EncodeToString(req.Raw), c.Hex; got != want {
			t.Errorf("AppendMX(%v) error got=%#v want=%#v", c.MX, got, want)
		}
	}

}

func TestMessageAppendPTR(t *testing.T) {
	cases := []struct {
		Hex string
		PTR string
		TTL uint32
	}{
		{
			"c00c000c00010000012c000c02686b0470687573026c7500",
			"hk.phus.lu",
			300,
		},
		{
			"c00c000c00010000012c000c0273670470687573026c7500",
			"sg.phus.lu",
			300,
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Class = ClassINET
		req.AppendPTR(c.TTL, c.PTR)
		if got, want := hex.EncodeToString(req.Raw), c.Hex; got != want {
			t.Errorf("AppendPTR(%v) error got=%#v want=%#v", c.PTR, got, want)
		}
	}

}

func TestMessageAppendTXT(t *testing.T) {
	cases := []struct {
		Hex string
		TXT string
		TTL uint32
	}{
		{
			"c00c001000010000012c000e0d69616d617478747265636f7264",
			"iamatxtrecord",
			300,
		},
		{
			"c00c001000010000012c010fff3030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300e3069616d617478747265636f7264",
			strings.Repeat("0", 256) + "iamatxtrecord",
			300,
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Class = ClassINET
		req.AppendTXT(c.TTL, c.TXT)
		if got, want := hex.EncodeToString(req.Raw), c.Hex; got != want {
			t.Errorf("AppendTXT(%v) error got=%#v want=%#v", c.TXT, got, want)
		}
	}

}

func BenchmarkMessageAppendHOST(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	size := len(req.Raw)
	ips := []netip.Addr{netip.AddrFrom4([4]byte{8, 8, 8, 8})}
	for i := 0; i < b.N; i++ {
		req.Raw = req.Raw[:size]
		req.AppendHOST(3000, ips)
	}
}

func BenchmarkMessageAppendCNAME(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	size := len(req.Raw)
	cnames := []string{"cname.example.org"}
	for i := 0; i < b.N; i++ {
		req.Raw = req.Raw[:size]
		req.AppendCNAME(3000, cnames, nil)
	}
}

func BenchmarkMessageAppendSRV(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	size := len(req.Raw)
	srv := net.SRV{Target: "service1.example.org", Port: 443, Priority: 100, Weight: 100}
	for i := 0; i < b.N; i++ {
		req.Raw = req.Raw[:size]
		req.AppendSRV(3000, []net.SRV{srv})
	}
}

func BenchmarkMessageAppendNS(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	size := len(req.Raw)
	nameservers := []net.NS{{Host: "ns1.google.com"}, {Host: "ns2.google.com"}}
	for i := 0; i < b.N; i++ {
		req.Raw = req.Raw[:size]
		req.AppendNS(300, nameservers)
	}
}

func BenchmarkMessageAppendSOA(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	size := len(req.Raw)
	for i := 0; i < b.N; i++ {
		req.Raw = req.Raw[:size]
		req.AppendSOA(300, net.NS{Host: "ns1.google.com"}, net.NS{Host: "dns-admin.google.com"}, 1073741824, 900, 900, 1800, 60)
	}
}

func BenchmarkMessageAppendPTR(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	size := len(req.Raw)
	ptr := "ptr.example.org"
	for i := 0; i < b.N; i++ {
		req.Raw = req.Raw[:size]
		req.AppendPTR(3000, ptr)
	}
}

func BenchmarkMessageAppendMX(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	size := len(req.Raw)
	mx := net.MX{Host: "mail.google.com", Pref: 100}
	for i := 0; i < b.N; i++ {
		req.Raw = req.Raw[:size]
		req.AppendMX(3000, []net.MX{mx})
	}
}

func BenchmarkMessageAppendTXT(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	size := len(req.Raw)
	txt := "iamatxtrecord"
	for i := 0; i < b.N; i++ {
		req.Raw = req.Raw[:size]
		req.AppendTXT(3000, txt)
	}
}

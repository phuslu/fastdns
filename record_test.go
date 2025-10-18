package fastdns

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// TestMessageAppendHOST serializes A and AAAA answers into the message buffer.
func TestMessageAppendHOST(t *testing.T) {
	cases := []struct {
		Raw []byte
		IPs []netip.Addr
		TTL uint32
	}{
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x01, // TYPE A
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x04, // RDLENGTH
				0x01, 0x01, 0x01, 0x01, // RDATA 1.1.1.1
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x01, // TYPE A
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x04, // RDLENGTH
				0x08, 0x08, 0x08, 0x08, // RDATA 8.8.8.8
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x01, // TYPE A
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x04, // RDLENGTH
				0x7b, 0x2d, 0x06, 0x4e, // RDATA 123.45.6.78
			},
			IPs: []netip.Addr{
				netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				netip.AddrFrom4([4]byte{8, 8, 8, 8}),
				netip.AddrFrom4([4]byte{123, 45, 6, 78}),
			},
			TTL: 300,
		},
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x1c, // TYPE AAAA
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x10, // RDLENGTH
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // RDATA ::1
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x1c, // TYPE AAAA
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x10, // RDLENGTH
				0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88, // RDATA 2001:4860:4860::8888
			},
			IPs: []netip.Addr{
				netip.MustParseAddr("::1"),
				netip.MustParseAddr("2001:4860:4860::8888"),
			},
			TTL: 300,
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Class = ClassINET
		req.AppendHOST(c.TTL, c.IPs)
		if got, want := req.Raw, c.Raw; !bytes.Equal(got, want) {
			t.Errorf("AppendHOST(%v) error got=%#v want=%#v", c.IPs, got, want)
		}
	}

}

// TestMessageAppendCNAME emits CNAME chains and optional address records.
func TestMessageAppendCNAME(t *testing.T) {
	cases := []struct {
		Raw    []byte
		CNAMEs []string
		IPs    []netip.Addr
		TTL    uint32
	}{
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x05, // TYPE CNAME
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x09, // RDLENGTH
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
			},
			CNAMEs: []string{"phus.lu"},
			IPs:    nil,
			TTL:    300,
		},
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x05, // TYPE CNAME
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x09, // RDLENGTH
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
				0xc0, 0x28, // NAME: pointer to first CNAME (offset 40)
				0x00, 0x1c, // TYPE AAAA
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x10, // RDLENGTH
				0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88, // RDATA 2001:4860:4860::8888
			},
			CNAMEs: []string{"phus.lu"},
			IPs:    []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")},
			TTL:    300,
		},
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x05, // TYPE CNAME
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x09, // RDLENGTH
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
				0xc0, 0x28, // NAME: pointer to first CNAME (offset 40)
				0x00, 0x05, // TYPE CNAME
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x0c, // RDLENGTH
				0x02, 'i', 'p',
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
				0xc0, 0x40, // NAME: pointer to second CNAME (offset 64)
				0x00, 0x01, // TYPE A
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x04, // RDLENGTH
				0x01, 0x01, 0x01, 0x01, // RDATA 1.1.1.1
				0xc0, 0x40, // NAME: pointer to second CNAME (offset 64)
				0x00, 0x01, // TYPE A
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x04, // RDLENGTH
				0x08, 0x08, 0x08, 0x08, // RDATA 8.8.8.8
			},
			CNAMEs: []string{"phus.lu", "ip.phus.lu"},
			IPs: []netip.Addr{
				netip.AddrFrom4([4]byte{1, 1, 1, 1}),
				netip.AddrFrom4([4]byte{8, 8, 8, 8}),
			},
			TTL: 300,
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Name = EncodeDomain(nil, "ip.phus.lu")
		req.Question.Class = ClassINET
		req.AppendCNAME(c.TTL, c.CNAMEs, c.IPs)
		if got, want := req.Raw, c.Raw; !bytes.Equal(got, want) {
			t.Errorf("AppendCNAME(%v) error got=%#v want=%#v", c.IPs, got, want)
		}
	}

}

// TestMessageAppendSRV writes SRV records with varying priorities.
func TestMessageAppendSRV(t *testing.T) {
	cases := []struct {
		Raw []byte
		TTL uint32
		SRV net.SRV
	}{
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x21, // TYPE SRV
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x12, // RDLENGTH
				0x03, 0xe8, // PRIORITY 1000
				0x03, 0xe8, // WEIGHT 1000
				0x00, 0x50, // PORT 80
				0x02, 'i', 'p',
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
			},
			TTL: 300,
			SRV: net.SRV{Target: "ip.phus.lu", Port: 80, Priority: 1000, Weight: 1000},
		},
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x21, // TYPE SRV
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x12, // RDLENGTH
				0x04, 0x00, // PRIORITY 1024
				0x04, 0x00, // WEIGHT 1024
				0x01, 0xbb, // PORT 443
				0x02, 's', 'g',
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
			},
			TTL: 300,
			SRV: net.SRV{Target: "sg.phus.lu", Port: 443, Priority: 1024, Weight: 1024},
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Class = ClassINET
		req.AppendSRV(c.TTL, []net.SRV{c.SRV})
		if got, want := req.Raw, c.Raw; !bytes.Equal(got, want) {
			t.Errorf("AppendSRV(%v) error got=%#v want=%#v", c.SRV, got, want)
		}
	}

}

// TestMessageAppendNS writes NS records for different zones.
func TestMessageAppendNS(t *testing.T) {
	cases := []struct {
		Raw         []byte
		TTL         uint32
		Nameservers []net.NS
	}{
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x02, // TYPE NS
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x10, // RDLENGTH
				0x03, 'n', 's', '1',
				0x06, 'g', 'o', 'o', 'g', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
			},
			TTL:         300,
			Nameservers: []net.NS{{Host: "ns1.google.com"}},
		},
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x02, // TYPE NS
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x10, // RDLENGTH
				0x03, 'n', 's', '1',
				0x06, 'g', 'o', 'o', 'g', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x02, // TYPE NS
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x10, // RDLENGTH
				0x03, 'n', 's', '2',
				0x06, 'g', 'o', 'o', 'g', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
			},
			TTL:         300,
			Nameservers: []net.NS{{Host: "ns1.google.com"}, {Host: "ns2.google.com"}},
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Name = EncodeDomain(nil, "ip.phus.lu")
		req.Question.Class = ClassINET
		req.AppendNS(c.TTL, c.Nameservers)
		if got, want := req.Raw, c.Raw; !bytes.Equal(got, want) {
			t.Errorf("AppendNS(%v) error got=%#v want=%#v", c.Nameservers, got, want)
		}
	}

}

// TestMessageAppendSOA emits an SOA record with expected fields.
func TestMessageAppendSOA(t *testing.T) {
	cases := []struct {
		Raw     []byte
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
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x06, // TYPE SOA
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x3a, // RDLENGTH
				0x03, 'n', 's', '1',
				0x06, 'g', 'o', 'o', 'g', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x09, 'd', 'n', 's', '-', 'a', 'd', 'm', 'i', 'n',
				0x06, 'g', 'o', 'o', 'g', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,
				0x40, 0x00, 0x00, 0x00, // SERIAL 1073741824
				0x00, 0x00, 0x03, 0x84, // REFRESH 900
				0x00, 0x00, 0x03, 0x84, // RETRY 900
				0x00, 0x00, 0x07, 0x08, // EXPIRE 1800
				0x00, 0x00, 0x00, 0x3c, // MINIMUM 60
			},
			TTL:     300,
			MName:   net.NS{Host: "ns1.google.com"},
			RName:   net.NS{Host: "dns-admin.google.com"},
			Serial:  1073741824,
			Refresh: 900,
			Retry:   900,
			Expire:  1800,
			Minimum: 60,
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Name = EncodeDomain(nil, "www.google.com")
		req.Question.Class = ClassINET
		req.AppendSOA(c.TTL, c.MName, c.RName, c.Serial, c.Refresh, c.Retry, c.Expire, c.Minimum)
		if got, want := req.Raw, c.Raw; !bytes.Equal(got, want) {
			t.Errorf("AppendSOA(%v) error got=%#v want=%#v", c.MName, got, want)
		}
	}

}

// TestMessageAppendMX serializes MX answers with priorities.
func TestMessageAppendMX(t *testing.T) {
	cases := []struct {
		Raw []byte
		TTL uint32
		MX  net.MX
	}{
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x0f, // TYPE MX
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x0e, // RDLENGTH
				0x00, 0x0a, // PREF 10
				0x02, 'i', 'p',
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
			},
			TTL: 300,
			MX:  net.MX{Host: "ip.phus.lu", Pref: 10},
		},
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x0f, // TYPE MX
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x0e, // RDLENGTH
				0x00, 0x0a, // PREF 10
				0x02, 's', 'g',
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
			},
			TTL: 300,
			MX:  net.MX{Host: "sg.phus.lu", Pref: 10},
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Class = ClassINET
		req.AppendMX(c.TTL, []net.MX{c.MX})
		if got, want := req.Raw, c.Raw; !bytes.Equal(got, want) {
			t.Errorf("AppendMX(%v) error got=%#v want=%#v", c.MX, got, want)
		}
	}

}

// TestMessageAppendPTR assembles PTR responses for reverse lookups.
func TestMessageAppendPTR(t *testing.T) {
	cases := []struct {
		Raw []byte
		PTR string
		TTL uint32
	}{
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x0c, // TYPE PTR
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x0c, // RDLENGTH
				0x02, 'i', 'p',
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
			},
			PTR: "ip.phus.lu",
			TTL: 300,
		},
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x0c, // TYPE PTR
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x0c, // RDLENGTH
				0x02, 's', 'g',
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
			},
			PTR: "sg.phus.lu",
			TTL: 300,
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Class = ClassINET
		req.AppendPTR(c.TTL, c.PTR)
		if got, want := req.Raw, c.Raw; !bytes.Equal(got, want) {
			t.Errorf("AppendPTR(%v) error got=%#v want=%#v", c.PTR, got, want)
		}
	}

}

// TestMessageAppendTXT builds TXT records including multi-chunk payloads.
func TestMessageAppendTXT(t *testing.T) {
	cases := []struct {
		Raw []byte
		TXT string
		TTL uint32
	}{
		{
			Raw: []byte{
				0xc0, 0x0c, // NAME: pointer to question (offset 12)
				0x00, 0x10, // TYPE TXT
				0x00, 0x01, // CLASS IN
				0x00, 0x00, 0x01, 0x2c, // TTL 300s
				0x00, 0x0e, // RDLENGTH
				0x0d, // TXT length 13
				'i', 'a', 'm', 'a', 't', 'x', 't', 'r', 'e', 'c', 'o', 'r', 'd',
			},
			TXT: "iamatxtrecord",
			TTL: 300,
		},
		{
			Raw: func() []byte {
				payload := []byte{
					0xc0, 0x0c, // NAME: pointer to question (offset 12)
					0x00, 0x10, // TYPE TXT
					0x00, 0x01, // CLASS IN
					0x00, 0x00, 0x01, 0x2c, // TTL 300s
					0x01, 0x0f, // RDLENGTH 271 bytes
					0xff, // chunk length 255
				}
				payload = append(payload, bytes.Repeat([]byte{'0'}, 255)...)
				payload = append(payload,
					0x0e, // remaining chunk length 14
					'0', 'i', 'a', 'm', 'a', 't', 'x', 't', 'r', 'e', 'c', 'o', 'r', 'd',
				)
				return payload
			}(),
			TXT: strings.Repeat("0", 256) + "iamatxtrecord",
			TTL: 300,
		},
	}

	for _, c := range cases {
		req := new(Message)
		req.Question.Class = ClassINET
		req.AppendTXT(c.TTL, c.TXT)
		if got, want := req.Raw, c.Raw; !bytes.Equal(got, want) {
			t.Errorf("AppendTXT(%v) error got=%#v want=%#v", c.TXT, got, want)
		}
	}

}

// BenchmarkMessageAppendHOST measures host record serialization speed.
func BenchmarkMessageAppendHOST(b *testing.B) {
	payload := []byte{
		0x00, 0x02, // Transaction ID
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x02, 'i', 'p',
		0x04, 'p', 'h', 'u', 's',
		0x02, 'l', 'u',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
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

// BenchmarkMessageAppendCNAME measures CNAME serialization speed.
func BenchmarkMessageAppendCNAME(b *testing.B) {
	payload := []byte{
		0x00, 0x02, // Transaction ID
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x02, 'i', 'p',
		0x04, 'p', 'h', 'u', 's',
		0x02, 'l', 'u',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
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

// BenchmarkMessageAppendSRV measures SRV serialization speed.
func BenchmarkMessageAppendSRV(b *testing.B) {
	payload := []byte{
		0x00, 0x02, // Transaction ID
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x02, 'i', 'p',
		0x04, 'p', 'h', 'u', 's',
		0x02, 'l', 'u',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
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

// BenchmarkMessageAppendNS measures NS serialization speed.
func BenchmarkMessageAppendNS(b *testing.B) {
	payload := []byte{
		0x00, 0x02, // Transaction ID
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x02, 'i', 'p',
		0x04, 'p', 'h', 'u', 's',
		0x02, 'l', 'u',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
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

// BenchmarkMessageAppendSOA measures SOA serialization speed.
func BenchmarkMessageAppendSOA(b *testing.B) {
	payload := []byte{
		0x00, 0x02, // Transaction ID
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x02, 'i', 'p',
		0x04, 'p', 'h', 'u', 's',
		0x02, 'l', 'u',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
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

// BenchmarkMessageAppendPTR measures PTR serialization speed.
func BenchmarkMessageAppendPTR(b *testing.B) {
	payload := []byte{
		0x00, 0x02, // Transaction ID
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x02, 'i', 'p',
		0x04, 'p', 'h', 'u', 's',
		0x02, 'l', 'u',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
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

// BenchmarkMessageAppendMX measures MX serialization speed.
func BenchmarkMessageAppendMX(b *testing.B) {
	payload := []byte{
		0x00, 0x02, // Transaction ID
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x02, 'i', 'p',
		0x04, 'p', 'h', 'u', 's',
		0x02, 'l', 'u',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
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

// BenchmarkMessageAppendTXT measures TXT serialization speed.
func BenchmarkMessageAppendTXT(b *testing.B) {
	payload := []byte{
		0x00, 0x02, // Transaction ID
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x02, 'i', 'p',
		0x04, 'p', 'h', 'u', 's',
		0x02, 'l', 'u',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
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

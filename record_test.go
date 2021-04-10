package fastdns

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

//nolint
type Header struct {
	ID      uint16
	Bits    Bits
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

//nolint
type Question struct {
	Name  []byte
	Type  Type
	Class Class
}

func TestAppendHeaderQuestion(t *testing.T) {
	var cases = []struct {
		Message *Message
	}{
		{
			/*
				Domain Name System (query)
				    Transaction ID: 0x0001
				    Flags: 0x0100 Standard query
				        0... .... .... .... = Response: Message is a query
				        .000 0... .... .... = Opcode: Standard query (0)
				        .... ..0. .... .... = Truncated: Message is not truncated
				        .... ...1 .... .... = Recursion desired: Do query recursively
				        .... .... .0.. .... = Z: reserved (0)
				        .... .... ...0 .... = Non-authenticated data: Unacceptable
				    Questions: 1
				    Answer RRs: 0
				    Authority RRs: 0
				    Additional RRs: 0
				    Queries
				        1.50.168.192.in-addr.arpa: type PTR, class IN
				            Name: 1.50.168.192.in-addr.arpa
				            [Name Length: 25]
				            [Label Count: 6]
				            Type: PTR (domain name PoinTeR) (12)
				            Class: IN (0x0001)
			*/
			&Message{
				[]byte("\x00\x01\x81\x00\x00\x01\x00\x01\x00\x00\x00\x00\x01\x31\x02\x35\x30\x03\x31\x36\x38\x03\x31\x39\x32\x07\x69\x6e\x2d\x61\x64\x64\x72\x04\x61\x72\x70\x61\x00\x00\x0c\x00\x01"),
				[]byte("1.50.168.192.in-addr.arpa"),
				Header{
					ID:      0x0001,
					Bits:    0b0000000100000000,
					QDCount: 0x01,
					ANCount: 0x00,
					NSCount: 0x00,
					ARCount: 0x00,
				},
				Question{
					Name:  []byte("\x011\x0250\x03168\x03192\x07in-addr\x04arpa\x00"),
					Type:  TypePTR,
					Class: ClassINET,
				},
			},
		},
		{
			/*
				Domain Name System (query)
				    Transaction ID: 0x0002
				    Flags: 0x0100 Standard query
				        0... .... .... .... = Response: Message is a query
				        .000 0... .... .... = Opcode: Standard query (0)
				        .... ..0. .... .... = Truncated: Message is not truncated
				        .... ...1 .... .... = Recursion desired: Do query recursively
				        .... .... .0.. .... = Z: reserved (0)
				        .... .... ...0 .... = Non-authenticated data: Unacceptable
				    Questions: 1
				    Answer RRs: 0
				    Authority RRs: 0
				    Additional RRs: 0
				    Queries
				        hk.phus.lu: type A, class IN
				            Name: hk.phus.lu
				            [Name Length: 10]
				            [Label Count: 3]
				            Type: A (Host Address) (1)
				            Class: IN (0x0001)
			*/
			&Message{
				[]byte("\x00\x02\x81\x00\x00\x01\x00\x01\x00\x00\x00\x00\x02\x68\x6b\x04\x70\x68\x75\x73\x02\x6c\x75\x00\x00\x01\x00\x01"),
				[]byte("hk.phus.lu"),
				Header{
					ID:      0x0002,
					Bits:    0b0000000100000000,
					QDCount: 0x01,
					ANCount: 0x00,
					NSCount: 0x00,
					ARCount: 0x00,
				},
				Question{
					Name:  []byte("\x02hk\x04phus\x02lu\x00"),
					Type:  TypeA,
					Class: ClassINET,
				},
			},
		},
	}

	for _, c := range cases {
		if got, want := AppendHeaderQuestion(nil, c.Message, RcodeSuccess, 1, 1, 0, 0), c.Message.Raw; !bytes.Equal(got, want) {
			t.Errorf("AppendHeaderQuestion(%v) error got=%x want=%x", c.Message, got, want)
		}
	}
}

func TestAppendHostRecord(t *testing.T) {
	cases := []struct {
		Hex string
		IPs []net.IP
		TTL uint32
	}{
		{
			"c00c000100010000012c000401010101c00c000100010000012c000408080808c00c000100010000012c00047b2d064e",
			[]net.IP{{1, 1, 1, 1}, {8, 8, 8, 8}, {123, 45, 6, 78}},
			300,
		},
		{
			"c00c001c00010000012c001000000000000000000000000000000001c00c001c00010000012c001020014860486000000000000000008888",
			[]net.IP{net.ParseIP("::1"), net.ParseIP("2001:4860:4860::8888")},
			300,
		},
	}

	req := new(Message)
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendHostRecord(nil, req, c.TTL, c.IPs)), c.Hex; got != want {
			t.Errorf("AppendHostRecord(%v) error got=%#v want=%#v", c.IPs, got, want)
		}
	}

}

func TestAppendCNAMERecord(t *testing.T) {
	cases := []struct {
		Hex    string
		CNAMEs []string
		IPs    []net.IP
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
			[]net.IP{net.ParseIP("2001:4860:4860::8888")},
			300,
		},
		{
			"c00c000500010000012c00090470687573026c7500c028000500010000012c000c02686b0470687573026c7500c040000100010000012c000401010101c040000100010000012c000408080808",
			[]string{"phus.lu", "hk.phus.lu"},
			[]net.IP{{1, 1, 1, 1}, {8, 8, 8, 8}},
			300,
		},
	}

	req := new(Message)
	req.Question.Name = EncodeDomain(nil, "ip.phus.lu")
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendCNAMERecord(nil, req, c.TTL, c.CNAMEs, c.IPs)), c.Hex; got != want {
			t.Errorf("AppendCNAMERecord(%v) error got=%#v want=%#v", c.IPs, got, want)
		}
	}

}

func TestAppendNSRecord(t *testing.T) {
	cases := []struct {
		Hex         string
		Nameservers []string
		TTL         uint32
	}{
		{
			"c00c000200010000012c0010036e733106676f6f676c6503636f6d00",
			[]string{"ns1.google.com"},
			300,
		},
		{
			"c00c000200010000012c0010036e733106676f6f676c6503636f6d00c00c000200010000012c0010036e733206676f6f676c6503636f6d00",
			[]string{"ns1.google.com", "ns2.google.com"},
			300,
		},
	}

	req := new(Message)
	req.Question.Name = EncodeDomain(nil, "ip.phus.lu")
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendNSRecord(nil, req, c.TTL, c.Nameservers)), c.Hex; got != want {
			t.Errorf("AppendNSRecord(%v) error got=%#v want=%#v", c.Nameservers, got, want)
		}
	}

}

func TestAppendSOARecord(t *testing.T) {
	cases := []struct {
		Hex     string
		TTL     uint32
		MName   string
		RName   string
		Serial  uint32
		Refresh uint32
		Retry   uint32
		Expire  uint32
		Minimum uint32
	}{
		{
			"c00c000600010000012c003a036e733106676f6f676c6503636f6d0009646e732d61646d696e06676f6f676c6503636f6d00400000000000038400000384000007080000003c",
			300,
			"ns1.google.com",
			"dns-admin.google.com",
			1073741824,
			900,
			900,
			1800,
			60,
		},
	}

	req := new(Message)
	req.Question.Name = EncodeDomain(nil, "www.google.com")
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendSOARecord(nil, req, c.TTL, c.MName, c.RName, c.Serial, c.Refresh, c.Retry, c.Expire, c.Minimum)), c.Hex; got != want {
			t.Errorf("AppendSOARecord(%v) error got=%#v want=%#v", c.MName, got, want)
		}
	}

}

func TestAppendSRVRecord(t *testing.T) {
	cases := []struct {
		Hex       string
		SRV       string
		Priovrity uint16
		Weight    uint16
		Port      uint16
		TTL       uint32
	}{
		{
			"c00c002100010000012c001203e803e8005002686b0470687573026c7500",
			"hk.phus.lu",
			1000,
			1000,
			80,
			300,
		},
		{
			"c00c002100010000012c00120400040001bb0273670470687573026c7500",
			"sg.phus.lu",
			1024,
			1024,
			443,
			300,
		},
	}

	req := new(Message)
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendSRVRecord(nil, req, c.TTL, c.SRV, c.Priovrity, c.Weight, c.Port)), c.Hex; got != want {
			t.Errorf("AppendSRVRecord(%v) error got=%#v want=%#v", c.SRV, got, want)
		}
	}

}

func TestAppendMXRecord(t *testing.T) {
	cases := []struct {
		Hex string
		MX  string
		TTL uint32
	}{
		{
			"c00c000f00010000012c000e000a02686b0470687573026c7500",
			"hk.phus.lu",
			300,
		},
		{
			"c00c000f00010000012c000e000a0273670470687573026c7500",
			"sg.phus.lu",
			300,
		},
	}

	req := new(Message)
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendMXRecord(nil, req, c.TTL, []MXRecord{{10, c.MX}})), c.Hex; got != want {
			t.Errorf("AppendMXRecord(%v) error got=%#v want=%#v", c.MX, got, want)
		}
	}

}

func TestAppendPTRRecord(t *testing.T) {
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

	req := new(Message)
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendPTRRecord(nil, req, c.TTL, c.PTR)), c.Hex; got != want {
			t.Errorf("AppendPTRRecord(%v) error got=%#v want=%#v", c.PTR, got, want)
		}
	}

}

func TestAppendTXTRecord(t *testing.T) {
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

	req := new(Message)
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendTXTRecord(nil, req, c.TTL, c.TXT)), c.Hex; got != want {
			t.Errorf("AppendTXTRecord(%v) error got=%#v want=%#v", c.TXT, got, want)
		}
	}

}

func BenchmarkAppendHostRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	ips := []net.IP{net.ParseIP("8.8.8.8")}
	for i := 0; i < b.N; i++ {
		payload = AppendHostRecord(payload[:0], req, 3000, ips)
	}
}

func BenchmarkAppendCNAMERecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	cnames := []string{"cname.example.org"}
	for i := 0; i < b.N; i++ {
		payload = AppendCNAMERecord(payload[:0], req, 3000, cnames, nil)
	}
}

func BenchmarkAppendNSRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	nameservers := []string{"ns1.google.com", "ns2.google.com"}
	for i := 0; i < b.N; i++ {
		payload = AppendNSRecord(payload[:0], req, 300, nameservers)
	}
}

func BenchmarkAppendSOARecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	for i := 0; i < b.N; i++ {
		payload = AppendSOARecord(payload[:0], req, 300, "ns1.google.com", "dns-admin.google.com", 1073741824, 900, 900, 1800, 60)
	}
}

func BenchmarkAppendSRVRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	srv := "service1.example.org"
	for i := 0; i < b.N; i++ {
		payload = AppendSRVRecord(payload[:0], req, 3000, srv, 100, 100, 443)
	}
}

func BenchmarkAppendPTRRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	ptr := "ptr.example.org"
	for i := 0; i < b.N; i++ {
		payload = AppendPTRRecord(payload[:0], req, 3000, ptr)
	}
}

func BenchmarkAppendMXRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	mx := []MXRecord{{100, "mail.google.com"}}
	for i := 0; i < b.N; i++ {
		payload = AppendMXRecord(payload[:0], req, 3000, mx)
	}
}

func BenchmarkAppendTXTRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Message)

	if err := ParseMessage(req, payload, false); err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	txt := "iamatxtrecord"
	for i := 0; i < b.N; i++ {
		payload = AppendTXTRecord(payload[:0], req, 3000, txt)
	}
}

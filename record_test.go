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
	QR      byte
	Opcode  Opcode
	AA      byte
	TC      byte
	RD      byte
	RA      byte
	Z       byte
	RCODE   Rcode
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
		Request *Request
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
			&Request{
				[]byte("\x00\x01\x81\x00\x00\x01\x00\x01\x00\x00\x00\x00\x01\x31\x02\x35\x30\x03\x31\x36\x38\x03\x31\x39\x32\x07\x69\x6e\x2d\x61\x64\x64\x72\x04\x61\x72\x70\x61\x00\x00\x0c\x00\x01"),
				[]byte("1.50.168.192.in-addr.arpa"),
				Header{
					ID:      0x0001,
					QR:      0x00,
					Opcode:  0x0000,
					AA:      0x00,
					TC:      0x00,
					RD:      0x01,
					RA:      0x00,
					Z:       0x00,
					RCODE:   0x00,
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
			&Request{
				[]byte("\x00\x02\x81\x00\x00\x01\x00\x01\x00\x00\x00\x00\x02\x68\x6b\x04\x70\x68\x75\x73\x02\x6c\x75\x00\x00\x01\x00\x01"),
				[]byte("hk.phus.lu"),
				Header{
					ID:      0x0002,
					QR:      0x00,
					Opcode:  0x0000,
					AA:      0x00,
					TC:      0x00,
					RD:      0x01,
					RA:      0x00,
					Z:       0x00,
					RCODE:   0x00,
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
		if got, want := AppendHeaderQuestion(nil, c.Request, RcodeSuccess, 1, 1, 0, 0), c.Request.Raw; !bytes.Equal(got, want) {
			t.Errorf("AppendHeaderQuestion(%v) error got=%x want=%x", c.Request, got, want)
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

	req := new(Request)
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendHostRecord(nil, req, c.IPs, c.TTL)), c.Hex; got != want {
			t.Errorf("AppendHostRecord(%v) error got=%#v want=%#v", c.IPs, got, want)
		}
	}

}

func TestAppendCNameRecord(t *testing.T) {
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

	req := new(Request)
	req.Question.Name = EncodeDomain(nil, "ip.phus.lu")
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendCNameRecord(nil, req, c.CNAMEs, c.IPs, c.TTL)), c.Hex; got != want {
			t.Errorf("AppendCNameRecord(%v) error got=%#v want=%#v", c.IPs, got, want)
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

	req := new(Request)
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendSRVRecord(nil, req, c.SRV, c.Priovrity, c.Weight, c.Port, c.TTL)), c.Hex; got != want {
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

	req := new(Request)
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendMXRecord(nil, req, []MXRecord{{10, c.MX}}, c.TTL)), c.Hex; got != want {
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

	req := new(Request)
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendPTRRecord(nil, req, c.PTR, c.TTL)), c.Hex; got != want {
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

	req := new(Request)
	req.Question.Class = ClassINET

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendTXTRecord(nil, req, c.TXT, c.TTL)), c.Hex; got != want {
			t.Errorf("AppendTXTRecord(%v) error got=%#v want=%#v", c.TXT, got, want)
		}
	}

}

func BenchmarkAppendHostRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Request)

	if err := ParseRequest(req, payload, false); err != nil {
		b.Errorf("ParseRequest(%+v) error: %+v", payload, err)
	}

	ips := []net.IP{net.ParseIP("8.8.8.8")}
	for i := 0; i < b.N; i++ {
		payload = AppendHostRecord(payload[:0], req, ips, 3000)
	}
}

func BenchmarkAppendCNameRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Request)

	if err := ParseRequest(req, payload, false); err != nil {
		b.Errorf("ParseRequest(%+v) error: %+v", payload, err)
	}

	cnames := []string{"cname.example.org"}
	for i := 0; i < b.N; i++ {
		payload = AppendCNameRecord(payload[:0], req, cnames, nil, 3000)
	}
}

func BenchmarkAppendSRVRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Request)

	if err := ParseRequest(req, payload, false); err != nil {
		b.Errorf("ParseRequest(%+v) error: %+v", payload, err)
	}

	srv := "service1.example.org"
	for i := 0; i < b.N; i++ {
		payload = AppendSRVRecord(payload[:0], req, srv, 100, 100, 443, 3000)
	}
}

func BenchmarkAppendPTRRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Request)

	if err := ParseRequest(req, payload, false); err != nil {
		b.Errorf("ParseRequest(%+v) error: %+v", payload, err)
	}

	ptr := "ptr.example.org"
	for i := 0; i < b.N; i++ {
		payload = AppendPTRRecord(payload[:0], req, ptr, 3000)
	}
}

func BenchmarkAppendMXRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Request)

	if err := ParseRequest(req, payload, false); err != nil {
		b.Errorf("ParseRequest(%+v) error: %+v", payload, err)
	}

	mx := []MXRecord{{100, "mail.google.com"}}
	for i := 0; i < b.N; i++ {
		payload = AppendMXRecord(payload[:0], req, mx, 3000)
	}
}

func BenchmarkAppendTXTRecord(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	req := new(Request)

	if err := ParseRequest(req, payload, false); err != nil {
		b.Errorf("ParseRequest(%+v) error: %+v", payload, err)
	}

	txt := "iamatxtrecord"
	for i := 0; i < b.N; i++ {
		payload = AppendTXTRecord(payload[:0], req, txt, 3000)
	}
}

package fastdns

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

//nolint
type Header struct {
	ID      uint16
	QR      byte
	OpCode  OpCode
	AA      byte
	TC      byte
	RD      byte
	RA      byte
	Z       byte
	RCODE   RCODE
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

//nolint
type Question struct {
	Name  QName
	Type  QType
	Class QClass
}

func TestAppendHeaderQuestion(t *testing.T) {
	var cases = []struct {
		Hex     string
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
			"0001810000010001000000000131023530033136380331393207696e2d61646472046172706100000c0001",
			&Request{
				Header{
					ID:      0x0001,
					QR:      0x00,
					OpCode:  0x0000,
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
					Name:  QName("\x011\x0250\x03168\x03192\x07in-addr\x04arpa\x00"),
					Type:  QTypePTR,
					Class: QClassIN,
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
			"00028100000100010000000002686b0470687573026c750000010001",
			&Request{
				Header{
					ID:      0x0002,
					QR:      0x00,
					OpCode:  0x0000,
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
					Name:  QName("\x02hk\x04phus\x02lu\x00"),
					Type:  QTypeA,
					Class: QClassIN,
				},
			},
		},
	}

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendHeaderQuestion(nil, c.Request, NOERROR, 1, 1, 0, 0)), c.Hex; got != want {
			t.Errorf("AppendHeaderQuestion(%v) error got=%#v want=%#v", c.Request, got, want)
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
	req.Question.Class = QClassIN

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
	req.Question.Name = encodeDomain(nil, "ip.phus.lu")
	req.Question.Class = QClassIN

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
	req.Question.Class = QClassIN

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendSRVRecord(nil, req, c.SRV, c.Priovrity, c.Weight, c.Port, c.TTL)), c.Hex; got != want {
			t.Errorf("AppendSRVRecord(%v) error got=%#v want=%#v", c.SRV, got, want)
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
			"c00c000c00010000012c000a02686b0470687573026c7500",
			"hk.phus.lu",
			300,
		},
		{
			"c00c000c00010000012c000a0273670470687573026c7500",
			"sg.phus.lu",
			300,
		},
	}

	req := new(Request)
	req.Question.Class = QClassIN

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
			"c00c001000010000012c000d0d69616d617478747265636f7264",
			"iamatxtrecord",
			300,
		},
		{
			"c00c001000010000012c010dff3030303030303030303030303030303030303030303030303030" +
				"3030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030" +
				"3030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030" +
				"3030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030" +
				"3030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030" +
				"30303030303030303030303030303030303030303030303030303030300e3069616d617478747265636f7264",
			strings.Repeat("0", 256) + "iamatxtrecord",
			300,
		},
	}

	req := new(Request)
	req.Question.Class = QClassIN

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendTXTRecord(nil, req, c.TXT, c.TTL)), c.Hex; got != want {
			t.Errorf("AppendTXTRecord(%v) error got=%#v want=%#v", c.TXT, got, want)
		}
	}

}

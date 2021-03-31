package fastdns

import (
	"encoding/hex"
	"net"
	"testing"
)

var mockHandlerRequest = &Request{
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
	[]byte("hk.phus.lu"),
}

func TestHandlerError(t *testing.T) {
	var cases = []struct {
		Hex   string
		Rcode Rcode
	}{
		{
			"000281030000000000000000",
			RcodeNameError,
		},
	}

	rw := &memResponseWriter{}
	if rw.RemoteAddr() != nil {
		t.Errorf("memResponseWriter shall return empty addr")
	}
	if rw.LocalAddr() != nil {
		t.Errorf("memResponseWriter shall return empty addr")
	}
	for _, c := range cases {
		Error(rw, mockHandlerRequest, c.Rcode)
		if got, want := hex.EncodeToString(rw.data), c.Hex; got != want {
			t.Errorf("Error(%v) error got=%#v want=%#v", c.Rcode, got, want)
		}
	}
}

func TestHandlerHost(t *testing.T) {
	var cases = []struct {
		Hex string
		IP  net.IP
		TTL uint32
	}{
		{
			"00028100000100010000000002686b0470687573026c750000010001c00c000100010000012c000401020408",
			net.IP{1, 2, 4, 8},
			300,
		},
	}

	rw := &memResponseWriter{}
	for _, c := range cases {
		HOST(rw, mockHandlerRequest, []net.IP{c.IP}, c.TTL)
		if got, want := hex.EncodeToString(rw.data), c.Hex; got != want {
			t.Errorf("HOST(%v) error got=%#v want=%#v", c.IP, got, want)
		}
	}
}

func TestHandlerCNAME(t *testing.T) {
	var cases = []struct {
		Hex   string
		CNAME string
		TTL   uint32
	}{
		{
			"00028100000100010000000002686b0470687573026c750000010001c00c000500010000012c001305636e616d65076578616d706c6503636f6d00",
			"cname.example.com",
			300,
		},
	}

	rw := &memResponseWriter{}
	for _, c := range cases {
		CNAME(rw, mockHandlerRequest, []string{c.CNAME}, nil, c.TTL)
		if got, want := hex.EncodeToString(rw.data), c.Hex; got != want {
			t.Errorf("CNAME(%v) error got=%#v want=%#v", c.CNAME, got, want)
		}
	}
}

func TestHandlerSRV(t *testing.T) {
	var cases = []struct {
		Hex       string
		SRV       string
		Priovrity uint16
		Weight    uint16
		Port      uint16
		TTL       uint32
	}{
		{
			"00028100000100010000000002686b0470687573026c750000010001c00c002100010000012c001c03e803e81f41087365727669636531076578616d706c6503636f6d00",
			"service1.example.com",
			1000,
			1000,
			8001,
			300,
		},
	}

	rw := &memResponseWriter{}
	for _, c := range cases {
		SRV(rw, mockHandlerRequest, c.SRV, c.Priovrity, c.Weight, c.Port, c.TTL)
		if got, want := hex.EncodeToString(rw.data), c.Hex; got != want {
			t.Errorf("SRV(%v) error got=%#v want=%#v", c.SRV, got, want)
		}
	}
}

func TestHandlerMX(t *testing.T) {
	var cases = []struct {
		Hex string
		MX  string
		TTL uint32
	}{
		{
			"00028100000100010000000002686b0470687573026c750000010001c00c000f00010000012c0013000a03707472076578616d706c65036f726700",
			"ptr.example.org",
			300,
		},
	}

	rw := &memResponseWriter{}
	for _, c := range cases {
		MX(rw, mockHandlerRequest, []MXRecord{{10, c.MX}}, c.TTL)
		if got, want := hex.EncodeToString(rw.data), c.Hex; got != want {
			t.Errorf("MX(%v) error got=%#v want=%#v", c.MX, got, want)
		}
	}
}

func TestHandlerPTR(t *testing.T) {
	var cases = []struct {
		Hex string
		PTR string
		TTL uint32
	}{
		{
			"00028100000100010000000002686b0470687573026c750000010001c00c000c00010000012c001103707472076578616d706c65036f726700",
			"ptr.example.org",
			300,
		},
	}

	rw := &memResponseWriter{}
	for _, c := range cases {
		PTR(rw, mockHandlerRequest, c.PTR, c.TTL)
		if got, want := hex.EncodeToString(rw.data), c.Hex; got != want {
			t.Errorf("PTR(%v) error got=%#v want=%#v", c.PTR, got, want)
		}
	}
}

func TestHandlerTXT(t *testing.T) {
	var cases = []struct {
		Hex string
		TXT string
		TTL uint32
	}{
		{
			"00028100000100010000000002686b0470687573026c750000010001c00c001000010000012c000e0d69616d617478747265636f7264",
			"iamatxtrecord",
			300,
		},
	}

	rw := &memResponseWriter{}
	for _, c := range cases {
		TXT(rw, mockHandlerRequest, c.TXT, c.TTL)
		if got, want := hex.EncodeToString(rw.data), c.Hex; got != want {
			t.Errorf("TXT(%v) error got=%#v want=%#v", c.TXT, got, want)
		}
	}
}

func BenchmarkHOST(b *testing.B) {
	ips := []net.IP{net.ParseIP("8.8.8.8")}
	for i := 0; i < b.N; i++ {
		HOST(&nilResponseWriter{}, mockHandlerRequest, ips, 3000)
	}
}

func BenchmarkCNAME(b *testing.B) {
	cnames := []string{"cname.example.org"}
	for i := 0; i < b.N; i++ {
		CNAME(&nilResponseWriter{}, mockHandlerRequest, cnames, nil, 3000)
	}
}

func BenchmarkSRV(b *testing.B) {
	srv := "service1.example.org"
	for i := 0; i < b.N; i++ {
		SRV(&nilResponseWriter{}, mockHandlerRequest, srv, 100, 100, 443, 3000)
	}
}

func BenchmarkPTR(b *testing.B) {
	ptr := "ptr.example.org"
	for i := 0; i < b.N; i++ {
		PTR(&nilResponseWriter{}, mockHandlerRequest, ptr, 3000)
	}
}

func BenchmarkMX(b *testing.B) {
	mx := []MXRecord{{100, "mail.google.com"}}
	for i := 0; i < b.N; i++ {
		MX(&nilResponseWriter{}, mockHandlerRequest, mx, 3000)
	}
}

func BenchmarkTXT(b *testing.B) {
	txt := "iamatxtrecord"
	for i := 0; i < b.N; i++ {
		TXT(&nilResponseWriter{}, mockHandlerRequest, txt, 3000)
	}
}

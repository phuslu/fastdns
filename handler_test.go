package fastdns

import (
	"encoding/hex"
	"net"
	"testing"
)

type mockResponseWriter struct {
	B []byte
}

func (rw *mockResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP{1, 1, 1, 1}, Port: 0}
}

func (rw *mockResponseWriter) Write(p []byte) (n int, err error) {
	rw.B = append(rw.B, p...)
	n = len(p)
	return
}

var handlerRequest = &Request{
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
}

func TestHandlerError(t *testing.T) {
	var cases = []struct {
		Hex   string
		RCODE RCODE
	}{
		{
			"000281030000000000000000",
			NXDOMAIN,
		},
	}

	rw := &mockResponseWriter{}
	for _, c := range cases {
		Error(rw, handlerRequest, c.RCODE)
		if got, want := hex.EncodeToString(rw.B), c.Hex; got != want {
			t.Errorf("Error(%v) error got=%#v want=%#v", c.RCODE, got, want)
		}
	}

}

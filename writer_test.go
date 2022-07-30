package fastdns

import (
	"net"
	"net/netip"
	"testing"
)

func TestResponseWriterUDP(t *testing.T) {
	rw := &udpResponseWriter{
		AddrPort: netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), 53),
	}

	var err error
	rw.Conn, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(rw.RemoteAddr()))
	if err != nil {
		t.Errorf("response writer dial udp error: %+v", err)
	}
	_, _ = rw.Write([]byte("test"))

	if s := rw.RemoteAddr().String(); s != "1.1.1.1:53" {
		t.Errorf("response writer return error remote address: %+v", s)
	}

	if s := rw.LocalAddr().String(); s == "" {
		t.Errorf("response writer return empty local address")
	}
}

func TestResponseWriterMem(t *testing.T) {
	rw := &MemResponseWriter{
		Laddr: netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), 53),
		Raddr: netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), 53),
	}

	const data = "testdata"

	n, err := rw.Write([]byte(data))
	if err != nil || n != len(data) {
		t.Errorf("response writer write error: %+v length: %d", err, n)
	}

	if s := rw.RemoteAddr().String(); s != "1.1.1.1:53" {
		t.Errorf("response writer return error remote address: %+v", s)
	}

	if s := rw.LocalAddr().String(); s != "1.1.1.1:53" {
		t.Errorf("response writer return error local address: %+v", s)
	}
}

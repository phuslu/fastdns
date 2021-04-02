package fastdns

import (
	"net"
	"testing"
)

func TestResponseWriterUDP(t *testing.T) {
	rw := UDPResponseWriter{
		Addr: &net.UDPAddr{IP: net.IP{1, 1, 1, 1}, Port: 53},
	}

	var err error
	rw.Conn, err = net.DialUDP("udp", nil, rw.RemoteAddr().(*net.UDPAddr))
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
	rw := &MemoryResponseWriter{
		Laddr: &net.UDPAddr{IP: net.IP{1, 1, 1, 1}, Port: 53},
		Raddr: &net.UDPAddr{IP: net.IP{1, 1, 1, 1}, Port: 53},
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

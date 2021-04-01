package fastdns

import (
	"context"
	"log"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

type mockServerHandler struct{}

func (h *mockServerHandler) ServeDNS(rw ResponseWriter, req *Request) {
	log.Printf("%s] %s: TYPE %s", rw.RemoteAddr(), req.Domain, req.Question.Type)
	HOST(rw, req, []net.IP{net.ParseIP("1.1.1.1")}, 300)
}

func TestServerHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, the resolver always uses C library functions, such as GetAddrInfo and DnsQuery.
		return
	}

	s := &Server{
		Handler: &mockServerHandler{},
		Logger:  log.New(os.Stdout, "", 0),
		index:   1, // disable fork
	}

	addr := allocAddr()
	if addr == "" {
		t.Errorf("allocAddr() failed.")
	}

	go func() {
		err := s.ListenAndServe(addr)
		if err != nil {
			t.Errorf("listen %+v error: %+v", addr, err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return net.Dial("udp", addr)
		},
	}

	ips, err := resolver.LookupHost(context.Background(), "example.org")
	if err != nil {
		t.Errorf("LookupHost return error: %+v", err)
	}
	if ips[0] != "1.1.1.1" {
		t.Errorf("LookupHost return mismatched reply: %+v", ips)
	}
}

func TestServerListenError(t *testing.T) {
	s := &Server{
		Handler: &mockServerHandler{},
		Logger:  log.New(os.Stdout, "", 0),
		index:   1, // disable fork
	}

	const addr = "127.0.1.1:-1"

	err := s.ListenAndServe(addr)
	if err == nil {
		t.Errorf("listen %+v shall return error but empty", addr)
	}
}

func TestServerParseRequestError(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, the resolver always uses C library functions, such as GetAddrInfo and DnsQuery.
		return
	}

	s := &Server{
		Handler: &mockServerHandler{},
		Logger:  log.New(os.Stdout, "", 0),
		index:   1, // disable fork
	}

	addr := allocAddr()
	if addr == "" {
		t.Errorf("allocAddr() failed.")
	}

	go func() {
		err := s.ListenAndServe(addr)
		if err != nil {
			t.Errorf("listen %+v error: %+v", addr, err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Errorf("dial to %+v return error: %+v", addr, err)
	}

	_, _ = conn.Write([]byte{0x00, 0x02, 0x01, 0x00, 0x00, 0x00})
}

func TestServerForkHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, the resolver always uses C library functions, such as GetAddrInfo and DnsQuery.
		return
	}

	os.Setenv("FASTDNS_CHILD_INDEX", "1")

	s := &ForkServer{
		Handler: &mockServerHandler{},
		Logger:  log.New(os.Stdout, "", 0),
	}

	addr := allocAddr()
	if addr == "" {
		t.Errorf("allocAddr() failed.")
	}

	go func() {
		err := s.ListenAndServe(addr)
		if err != nil {
			t.Errorf("listen %+v error: %+v", addr, err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return net.Dial("udp", addr)
		},
	}

	ips, err := resolver.LookupHost(context.Background(), "example.org")
	if err != nil {
		t.Errorf("LookupHost return error: %+v", err)
	}
	if ips[0] != "1.1.1.1" {
		t.Errorf("LookupHost return mismatched reply: %+v", ips)
	}
}

func TestServerForkParseRequestError(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, the resolver always uses C library functions, such as GetAddrInfo and DnsQuery.
		return
	}

	os.Setenv("FASTDNS_CHILD_INDEX", "1")

	s := &ForkServer{
		Handler: &mockServerHandler{},
		Logger:  log.New(os.Stdout, "", 0),
	}

	addr := allocAddr()
	if addr == "" {
		t.Errorf("allocAddr() failed.")
	}

	go func() {
		err := s.ListenAndServe(addr)
		if err != nil {
			t.Errorf("listen %+v error: %+v", addr, err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Errorf("dial to %+v return error: %+v", addr, err)
	}

	_, _ = conn.Write([]byte{0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

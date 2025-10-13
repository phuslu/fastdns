package fastdns

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"
)

// allocAddr picks an available localhost port for testing.
func allocAddr() string {
	for i := 20001; i < 50000; i++ {
		addr := fmt.Sprintf("127.0.0.1:%d", i)
		conn, err := net.Listen("tcp", addr)
		if err == nil {
			conn.Close()
			return addr
		}
	}
	return ""
}

type mockServerHandler struct{}

// ServeDNS writes a canned host record for the queried name.
func (h *mockServerHandler) ServeDNS(rw ResponseWriter, req *Message) {
	slog.Info("serve dns request", "remote_addr", rw.RemoteAddr(), "domain", req.Domain, "class", req.Question.Class, "type", req.Question.Type)
	ips := []netip.Addr{netip.AddrFrom4([4]byte{1, 1, 1, 1})}
	req.SetResponseHeader(RcodeNoError, uint16(len(ips)))
	req.AppendHOST(600, ips)
	_, _ = rw.Write(req.Raw)
}

// TestServerHost spins up the UDP server and verifies a basic lookup.
func TestServerHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, the resolver always uses C library functions, such as GetAddrInfo and DnsQuery.
		return
	}

	s := &Server{
		Handler:  &mockServerHandler{},
		ErrorLog: slog.Default(),
		MaxProcs: 1,
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

// func TestServerListenError(t *testing.T) {
// 	s := &Server{
// 		Handler:  &mockServerHandler{},
// 		ErrorLog: slog.Default(),
// 		MaxProcs: 1,
// 		index:    1,
// 	}

// 	const addr = "127.0.1.1:-1"

// 	err := s.ListenAndServe(addr)
// 	if err == nil {
// 		t.Errorf("listen %+v shall return error but empty", addr)
// 	}
// }

// TestServerParseMessageError ensures malformed packets are handled safely.
func TestServerParseMessageError(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, the resolver always uses C library functions, such as GetAddrInfo and DnsQuery.
		return
	}

	s := &Server{
		Handler:  &mockServerHandler{},
		ErrorLog: slog.Default(),
		MaxProcs: 1,
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

// TestServerForkHost validates the prefork server handles lookups.
func TestServerForkHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, the resolver always uses C library functions, such as GetAddrInfo and DnsQuery.
		return
	}

	os.Setenv("FASTDNS_CHILD_INDEX", "1")

	s := &ForkServer{
		Handler:  &mockServerHandler{},
		ErrorLog: slog.Default(),
		MaxProcs: 1,
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

// TestServerForkParseMessageError checks error handling in the prefork server.
func TestServerForkParseMessageError(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows, the resolver always uses C library functions, such as GetAddrInfo and DnsQuery.
		return
	}

	os.Setenv("FASTDNS_CHILD_INDEX", "1")

	s := &ForkServer{
		Handler:  &mockServerHandler{},
		ErrorLog: slog.Default(),
		MaxProcs: 1,
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

type nilResponseWriter struct{}

// RemoteAddr returns an empty remote address for test doubles.
func (rw *nilResponseWriter) RemoteAddr() netip.AddrPort { return netip.AddrPort{} }

// LocalAddr returns an empty local address for test doubles.
func (rw *nilResponseWriter) LocalAddr() netip.AddrPort { return netip.AddrPort{} }

// Write reports that the payload length was consumed.
func (rw *nilResponseWriter) Write(p []byte) (n int, err error) { return len(p), nil }

// mockMessage decodes a canned DNS response for reuse in benchmarks.
func mockMessage() (msg *Message) {
	// domain = hk.phus.lu
	payload, _ := hex.DecodeString("00028180000100010000000002686b0470687573026c750000010001c00c000100010000012b0004771c56be")
	msg = AcquireMessage()
	err := ParseMessage(msg, payload, true)
	if err != nil {
		panic(err)
	}

	return
}

// BenchmarkServerHandlerHOST1 measures the single-record append helper.
func BenchmarkServerHandlerHOST1(b *testing.B) {
	rw := &nilResponseWriter{}
	req := mockMessage()
	ip := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.SetResponseHeader(RcodeNoError, 1)
		req.AppendHOST1(600, ip)
		_, _ = rw.Write(req.Raw)
	}
}

// BenchmarkServerHandlerHOST measures bulk host record appends.
func BenchmarkServerHandlerHOST(b *testing.B) {
	rw := &nilResponseWriter{}
	req := mockMessage()
	ips := []netip.Addr{netip.AddrFrom4([4]byte{8, 8, 8, 8})}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.SetResponseHeader(RcodeNoError, uint16(len(ips)))
		req.AppendHOST(600, ips)
		_, _ = rw.Write(req.Raw)
	}
}

// BenchmarkServerHandlerCNAME measures combined CNAME and address appends.
func BenchmarkServerHandlerCNAME(b *testing.B) {
	rw := &nilResponseWriter{}
	req := mockMessage()
	cnames := []string{"cname.example.org"}
	ips := []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.SetResponseHeader(RcodeNoError, uint16(len(cnames)+len(ips)))
		req.AppendCNAME(600, cnames, ips)
		_, _ = rw.Write(req.Raw)
	}
}

// BenchmarkServerHandlerSRV measures SRV record append throughput.
func BenchmarkServerHandlerSRV(b *testing.B) {
	rw := &nilResponseWriter{}
	req := mockMessage()
	srvs := []net.SRV{{Target: "service1.example.org", Port: 8001, Priority: 1000, Weight: 1000}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.SetResponseHeader(RcodeNoError, uint16(len(srvs)))
		req.AppendSRV(600, srvs)
		_, _ = rw.Write(req.Raw)
	}
}

// BenchmarkServerHandlerNS measures NS record append throughput.
func BenchmarkServerHandlerNS(b *testing.B) {
	rw := &nilResponseWriter{}
	req := mockMessage()
	nameservers := []net.NS{{Host: "ns1.google.com"}, {Host: "ns2.google.com"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.SetResponseHeader(RcodeNoError, uint16(len(nameservers)))
		req.AppendNS(600, nameservers)
		_, _ = rw.Write(req.Raw)
	}
}

// BenchmarkServerHandlerSOA measures SOA record append throughput.
func BenchmarkServerHandlerSOA(b *testing.B) {
	rw := &nilResponseWriter{}
	req := mockMessage()
	mname := net.NS{Host: "ns1.google.com"}
	rname := net.NS{Host: "dns-admin.google.com"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.SetResponseHeader(RcodeNoError, 1)
		req.AppendSOA(600, mname, rname, 42, 900, 900, 1800, 60)
		_, _ = rw.Write(req.Raw)
	}
}

// BenchmarkServerHandlerMX measures MX record append throughput.
func BenchmarkServerHandlerMX(b *testing.B) {
	rw := &nilResponseWriter{}
	req := mockMessage()
	mxs := []net.MX{{Host: "mail.google.com", Pref: 100}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.SetResponseHeader(RcodeNoError, uint16(len(mxs)))
		req.AppendMX(600, mxs)
		_, _ = rw.Write(req.Raw)
	}
}

// BenchmarkServerHandlerPTR measures PTR record append throughput.
func BenchmarkServerHandlerPTR(b *testing.B) {
	rw := &nilResponseWriter{}
	req := mockMessage()
	ptr := "ptr.example.org"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.SetResponseHeader(RcodeNoError, 1)
		req.AppendPTR(600, ptr)
		_, _ = rw.Write(req.Raw)
	}
}

// BenchmarkServerHandlerTXT measures TXT record append throughput.
func BenchmarkServerHandlerTXT(b *testing.B) {
	rw := &nilResponseWriter{}
	req := mockMessage()
	txt := "iamatxtrecord"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.SetResponseHeader(RcodeNoError, 1)
		req.AppendTXT(600, txt)
		_, _ = rw.Write(req.Raw)
	}
}

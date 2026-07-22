package fastdns

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// newUDPBlackhole starts a local UDP server. It silently drops every query
// while respond is nil or false, and echoes a minimal valid DNS response once
// respond is set to true. It lets the pool tests run without any public DNS.
func newUDPBlackhole(t *testing.T, respond *atomic.Bool) *net.UDPConn {
	t.Helper()
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if respond == nil || !respond.Load() {
				continue // drop the query
			}
			var msg Message
			if ParseMessage(&msg, buf[:n], true) != nil {
				continue
			}
			msg.SetResponseHeader(RcodeNoError, 0)
			_, _ = server.WriteToUDP(msg.Raw, addr)
		}
	}()
	return server
}

// doExchange runs a single A-record query and returns the exchange error.
func doExchange(client *Client, ctx context.Context) error {
	req, resp := AcquireMessage(), AcquireMessage()
	defer ReleaseMessage(req)
	defer ReleaseMessage(resp)
	req.SetRequestQuestion("example.test", TypeA, ClassINET)
	return client.Exchange(ctx, req, resp)
}

// TestUDPDialerWaitHonorsContext verifies that waiting for a pooled connection
// returns when the caller's context is done instead of blocking forever.
func TestUDPDialerWaitHonorsContext(t *testing.T) {
	server := newUDPBlackhole(t, nil)
	defer server.Close()

	d := &UDPDialer{Addr: server.LocalAddr().(*net.UDPAddr), MaxConns: 1}

	// Take the only pooled connection and keep it.
	conn, err := d.DialContext(context.Background(), "udp", "")
	if err != nil {
		t.Fatalf("first DialContext: %v", err)
	}
	defer d.Put(conn)

	// The pool is now empty; a short context must make the wait return promptly.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = d.DialContext(ctx, "udp", "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("DialContext blocked for %v, want prompt return", elapsed)
	}
}

// TestClientExchangeCancelsUDPRead verifies that cancelling the context
// interrupts a UDP Read that is blocked waiting for a response, even when no
// Client.Timeout is configured.
func TestClientExchangeCancelsUDPRead(t *testing.T) {
	received := make(chan struct{}, 1)
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := server.ReadFromUDP(buf); err != nil {
				return
			}
			select {
			case received <- struct{}{}:
			default:
			}
		}
	}()

	client := &Client{
		// no Timeout: the Read would block forever without context cancellation.
		Dialer: &UDPDialer{Addr: server.LocalAddr().(*net.UDPAddr), MaxConns: 1},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- doExchange(client, ctx) }()

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("server never received the query")
	}
	cancel()

	select {
	case <-done:
		// returned promptly after cancellation
	case <-time.After(2 * time.Second):
		t.Fatal("Exchange did not return after context cancellation")
	}
}

// TestUDPDialerPoolSurvivesTimeouts verifies that repeated read timeouts do not
// drain the pool and that the client recovers once the server responds again.
func TestUDPDialerPoolSurvivesTimeouts(t *testing.T) {
	var respond atomic.Bool
	server := newUDPBlackhole(t, &respond)
	defer server.Close()

	client := &Client{
		Timeout: 50 * time.Millisecond,
		Dialer:  &UDPDialer{Addr: server.LocalAddr().(*net.UDPAddr), MaxConns: 1},
	}

	// Repeated timeouts must not permanently drain the single-connection pool.
	for i := 0; i < 5; i++ {
		start := time.Now()
		if err := doExchange(client, context.Background()); err == nil {
			t.Fatalf("exchange %d: expected a timeout error", i)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("exchange %d blocked for %v; pool likely drained", i, elapsed)
		}
	}

	// After the server recovers, the same client must resolve again.
	respond.Store(true)
	if err := doExchange(client, context.Background()); err != nil {
		t.Fatalf("exchange after recovery: %v", err)
	}
}

// TestClientExchangeDiscardsStaleResponse verifies that a late answer to a
// previous timed-out query on a reused UDP socket is not delivered as the
// answer to the next query: responses must echo the request ID.
func TestClientExchangeDiscardsStaleResponse(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer server.Close()

	// The server holds the answer to the first query until the second query
	// arrives, then answers both: the stale answer first, the real one second.
	go func() {
		buf := make([]byte, 512)
		var pending []byte
		for {
			n, addr, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			if pending == nil {
				pending = q // let the first query time out
				continue
			}
			for _, raw := range [][]byte{pending, q} {
				var msg Message
				if ParseMessage(&msg, raw, true) != nil {
					continue
				}
				msg.SetResponseHeader(RcodeNoError, 0)
				_, _ = server.WriteToUDP(msg.Raw, addr)
			}
		}
	}()

	client := &Client{
		Timeout: 100 * time.Millisecond,
		Dialer:  &UDPDialer{Addr: server.LocalAddr().(*net.UDPAddr), MaxConns: 1},
	}

	// First query times out; its answer is still queued on the server side.
	if err := doExchange(client, context.Background()); err == nil {
		t.Fatal("first exchange: expected a timeout error")
	}

	// Second query receives the stale answer first and must skip it.
	req, resp := AcquireMessage(), AcquireMessage()
	defer ReleaseMessage(req)
	defer ReleaseMessage(resp)
	req.SetRequestQuestion("example.test", TypeA, ClassINET)
	if err := client.Exchange(context.Background(), req, resp); err != nil {
		t.Fatalf("second exchange: %v", err)
	}
	if resp.Header.ID != req.Header.ID {
		t.Fatalf("response ID = %d, want request ID %d", resp.Header.ID, req.Header.ID)
	}
}

// TestTCPDialerReconnectsAfterFailure verifies that a broken pooled TCP
// connection is closed and cleared instead of being reused as-is, so the next
// query reconnects rather than deadlocking or replaying the error.
func TestTCPDialerReconnectsAfterFailure(t *testing.T) {
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()

	stop := make(chan struct{})
	defer close(stop)

	go func() {
		// First connection: read the query, then close to mimic a server that
		// dropped an idle connection and now returns EOF.
		if c, err := ln.Accept(); err == nil {
			readTCPQuery(c)
			_ = c.Close()
		}
		// Second connection: answer with a minimal valid DNS response and keep
		// it open for pooled reuse until the test ends.
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		query := readTCPQuery(c)
		if query == nil {
			return
		}
		var msg Message
		if ParseMessage(&msg, query, true) != nil {
			return
		}
		msg.SetResponseHeader(RcodeNoError, 0)
		framed := append([]byte{byte(len(msg.Raw) >> 8), byte(len(msg.Raw))}, msg.Raw...)
		if _, err := c.Write(framed); err != nil {
			return
		}
		<-stop
	}()

	client := &Client{Dialer: &TCPDialer{Addr: ln.Addr().(*net.TCPAddr), MaxConns: 1}}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// The first exchange fails on the broken connection.
	if err := doExchange(client, ctx); err == nil {
		t.Fatal("first exchange: expected failure on broken connection")
	}
	// The wrapper must have returned to the pool with its dead stream cleared,
	// so the next exchange reconnects and succeeds instead of deadlocking.
	if err := doExchange(client, ctx); err != nil {
		t.Fatalf("second exchange: expected reconnect, got %v", err)
	}
}

// readTCPQuery reads one length-prefixed DNS message from c.
func readTCPQuery(c net.Conn) []byte {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil
	}
	return buf
}

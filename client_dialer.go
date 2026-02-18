package fastdns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"time"
	"unsafe"
)

// UDPDialer is a custom dialer for creating UDP connections.
// It manages a pool of connections to optimize performance in scenarios
// where multiple UDP connections to the same server are required.
type UDPDialer struct {
	// Addr specifies the remote UDP address that the dialer will connect to.
	Addr *net.UDPAddr

	// MaxConns limits the maximum number of UDP connections that can be created
	// and reused. Once this limit is reached, no new connections will be made.
	// If not set, use 64 as default.
	MaxConns uint16

	once  sync.Once
	conns chan net.Conn
}

// DialContext returns a pooled UDP connection for the requested network.
func (d *UDPDialer) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	return d.get()
}

// get initializes the UDP pool on first use and returns a connection handle.
func (d *UDPDialer) get() (_ net.Conn, err error) {
	d.once.Do(func() {
		if d.MaxConns == 0 {
			d.MaxConns = 16
		}
		d.conns = make(chan net.Conn, d.MaxConns)
		for range d.MaxConns {
			var c *net.UDPConn
			c, err = net.DialUDP("udp", nil, d.Addr)
			if err != nil {
				break
			}
			d.conns <- c
		}
	})

	if err != nil {
		return
	}

	c := <-d.conns

	return c, nil
}

// Put returns the UDP connection to the pool for reuse.
func (d *UDPDialer) Put(conn net.Conn) {
	d.conns <- conn
}

// TCPDialer is a custom dialer for creating TLS connections.
// It manages a pool of connections to optimize performance in scenarios
// where multiple TLS connections to the same server are required.
type TCPDialer struct {
	// Addr specifies the remote TLS address that the dialer will connect to.
	Addr *net.TCPAddr

	// TLSConfig specifies the *tls.Config for TLS handshakes.
	// If set, use DoT instead of TCP protocol.
	TLSConfig *tls.Config

	// Timeout specifies the maximum duration for a query to complete.
	// If a query exceeds this duration, it will result in a timeout error.
	Timeout time.Duration

	// MaxConns limits the maximum number of TLS connections that can be created
	// and reused. Once this limit is reached, no new connections will be made.
	// If not set, use 8 as default.
	MaxConns uint16

	once  sync.Once
	conns chan net.Conn
}

// DialContext returns a pooled TCP or TLS connection based on the dialer settings.
func (d *TCPDialer) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	return d.get()
}

// get initializes the TCP pool on first use and returns a wrapped connection.
func (d *TCPDialer) get() (_ net.Conn, err error) {
	d.once.Do(func() {
		if d.MaxConns == 0 {
			d.MaxConns = 8
		}
		d.conns = make(chan net.Conn, d.MaxConns)
		for range d.MaxConns {
			d.conns <- &tcpConn{nil, d, make([]byte, 0, 1024)}
		}
	})

	if err != nil {
		return
	}

	c := <-d.conns

	return c, nil
}

// Put returns the TCP connection wrapper to the pool.
func (d *TCPDialer) Put(conn net.Conn) {
	d.conns <- conn
}

type tcpConn struct {
	net.Conn
	dialer *TCPDialer
	buffer []byte
}

// Write ensures the underlying TCP or TLS connection is ready and sends the framed payload.
func (c *tcpConn) Write(b []byte) (int, error) {
	if c.Conn == nil {
		var err error
		if c.dialer.TLSConfig != nil {
			c.Conn, err = tls.DialWithDialer(&net.Dialer{Timeout: c.dialer.Timeout}, "tcp", c.dialer.Addr.String(), c.dialer.TLSConfig)
		} else {
			c.Conn, err = (&net.Dialer{Timeout: c.dialer.Timeout}).Dial("tcp", c.dialer.Addr.String())
		}
		if err != nil {
			return 0, err
		}
	}

	n := len(b)
	c.buffer = append(c.buffer[:0], byte(n>>8), byte(n&0xFF))
	c.buffer = append(c.buffer, b...)
	_, err := c.Conn.Write(c.buffer)
	return n, err
}

// Read reads a framed DNS response from the TCP connection into b.
func (c *tcpConn) Read(b []byte) (n int, err error) {
	c.buffer = c.buffer[:cap(c.buffer)]
	n, err = c.Conn.Read(c.buffer)
	if err != nil {
		return
	}
	m := int(c.buffer[0])<<8 | int(c.buffer[1])
	if m+2 != n {
		return 0, ErrInvalidAnswer
	}
	copy(b, c.buffer[2:n])
	return n - 2, nil
}

// HTTPDialer is a custom dialer for creating HTTP connections.
// It allows sending HTTP requests with a specified endpoint, user agent, and transport configuration.
type HTTPDialer struct {
	// Endpoint specifies the HTTP server's URL that the dialer will connect to.
	// This is the base address used for sending HTTP requests.
	Endpoint *url.URL

	// Transport allows for customizing the underlying transport mechanism used
	// for making HTTP requests. If set, it overrides the default RoundTripper behavior.
	Transport http.RoundTripper

	// Header defines the request header that will be sent in the HTTP requests.
	// It can be customized for specific needs, E.g. User-Agent.
	Header http.Header

	once sync.Once
	pool sync.Pool
}

// DialContext returns an HTTP connection wrapper for DNS-over-HTTPS queries.
func (d *HTTPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.once.Do(func() {
		if d.Header == nil {
			d.Header = http.Header{
				"content-type": []string{"application/dns-message"},
				"user-agent":   []string{"fastdns/1.0"},
			}
		}
		d.pool = sync.Pool{
			New: func() any {
				return &httpConn{
					req: &http.Request{
						Method: http.MethodPost,
						URL:    d.Endpoint,
						Host:   d.Endpoint.Host,
						Header: d.Header,
					},
					reader: new(bufferreader),
					writer: new(bufferwriter),
				}
			},
		}
	})

	c := d.pool.Get().(*httpConn)
	c.dialer = d
	c.ctx = ctx
	c.writer.B = c.writer.B[:0]
	c.reader.B = nil
	c.resp = nil
	return c, nil
}

// Put releases the HTTP connection wrapper back to the pool.
func (d *HTTPDialer) Put(conn net.Conn) {
	if c, _ := conn.(*httpConn); c != nil {
		d.pool.Put(c)
	}
}

type httpConn struct {
	dialer *HTTPDialer
	ctx    context.Context
	req    *http.Request
	reader *bufferreader
	writer *bufferwriter
	resp   []byte
}

// Read copies buffered HTTP response bytes into b.
func (c *httpConn) Read(b []byte) (n int, err error) {
	if c.resp == nil {
		err = io.EOF
		return
	}

	n = copy(b, c.resp)
	if n < len(c.resp) {
		c.resp = c.resp[n:]
	} else {
		c.resp = nil
	}

	return n, nil
}

// Write issues the DNS-over-HTTPS request and stores the response body for reads.
func (c *httpConn) Write(b []byte) (n int, err error) {
	var tr = c.dialer.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}

	c.reader.B = b
	c.req.Body = c.reader
	c.req.ContentLength = int64(len(b))

	// c.req.ctx = c.ctx
	*(*context.Context)(unsafe.Pointer(uintptr(unsafe.Pointer(c.req)) + httpctxoffset)) = c.ctx

	resp, err := tr.RoundTrip(c.req)
	if err != nil {
		return 0, fmt.Errorf("fastdns: roundtrip %s error: %w", c.dialer.Endpoint, err)
	}
	defer resp.Body.Close() // nolint:errcheck

	_, err = io.Copy(c.writer, resp.Body)
	if err != nil {
		return 0, fmt.Errorf("fastdns: read from %s error: %w", c.dialer.Endpoint, err)
	}
	if resp.StatusCode != http.StatusOK || resp.ContentLength <= 0 {
		return 0, fmt.Errorf("fastdns: read from %s error: %s: %s", c.dialer.Endpoint, resp.Status, c.writer.B)
	}

	c.resp = c.writer.B
	return len(b), nil
}

// Close is a no-op to satisfy the net.Conn interface.
func (c *httpConn) Close() (err error) {
	return
}

// LocalAddr returns a placeholder local address for compatibility.
func (c *httpConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

// RemoteAddr returns a placeholder remote address for compatibility.
func (c *httpConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

// SetDeadline is a stub to satisfy the net.Conn interface.
func (c *httpConn) SetDeadline(t time.Time) error {
	return errors.ErrUnsupported
}

// SetReadDeadline is a stub to satisfy the net.Conn interface.
func (c *httpConn) SetReadDeadline(t time.Time) error {
	return errors.ErrUnsupported
}

// SetWriteDeadline is a stub to satisfy the net.Conn interface.
func (c *httpConn) SetWriteDeadline(t time.Time) error {
	return errors.ErrUnsupported
}

var httpctxoffset = func() uintptr {
	var req http.Request
	v := reflect.TypeOf(req)
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Name == "ctx" {
			return field.Offset
		}
	}
	panic("unsupported go version, please upgrade fastdns")
}()

type bufferwriter struct {
	B []byte
}

// Write appends p to the buffered writer backing store.
func (b *bufferwriter) Write(p []byte) (int, error) {
	b.B = append(b.B, p...)
	return len(p), nil
}

type bufferreader struct {
	B []byte
}

// Read copies buffered data into b or reports EOF when exhausted.
func (r *bufferreader) Read(b []byte) (int, error) {
	if r.B == nil {
		return 0, io.EOF
	}

	n := copy(b, r.B)
	if n < len(r.B) {
		r.B = r.B[n:]
	} else {
		r.B = nil
	}

	return n, nil
}

// Close releases the buffered reader resources.
func (r *bufferreader) Close() error {
	r.B = nil
	return nil
}

// WriteTo writes the buffered data to w.
func (r *bufferreader) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(r.B)
	return int64(n), err
}

var _ io.Writer = (*bufferwriter)(nil)
var _ io.ReadCloser = (*bufferreader)(nil)
var _ io.WriterTo = (*bufferreader)(nil)

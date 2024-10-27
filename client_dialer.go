package fastdns

import (
	"context"
	"crypto/tls"
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

	// Timeout specifies the maximum duration for a query to complete.
	// If a query exceeds this duration, it will result in a timeout error.
	Timeout time.Duration

	// MaxConns limits the maximum number of UDP connections that can be created
	// and reused. Once this limit is reached, no new connections will be made.
	// If not set, use 64 as default.
	MaxConns uint16

	once  sync.Once
	conns chan net.Conn
}

func (d *UDPDialer) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	return d.get()
}

func (d *UDPDialer) get() (_ net.Conn, err error) {
	d.once.Do(func() {
		if d.MaxConns == 0 {
			d.MaxConns = 64
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

func (d *UDPDialer) put(conn net.Conn) {
	d.conns <- conn
}

// TLSDialer is a custom dialer for creating TLS connections.
// It manages a pool of connections to optimize performance in scenarios
// where multiple TLS connections to the same server are required.
type TLSDialer struct {
	// Addr specifies the remote TLS address that the dialer will connect to.
	Addr *net.TCPAddr

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

func (d *TLSDialer) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	return d.get()
}

func (d *TLSDialer) get() (_ net.Conn, err error) {
	d.once.Do(func() {
		if d.MaxConns == 0 {
			d.MaxConns = 8
		}
		d.conns = make(chan net.Conn, d.MaxConns)
		for range d.MaxConns {
			d.conns <- &tlsConn{nil, d, make([]byte, 0, 1024)}
		}
	})

	if err != nil {
		return
	}

	c := <-d.conns

	return c, nil
}

func (d *TLSDialer) put(conn net.Conn) {
	d.conns <- conn
}

type tlsConn struct {
	*tls.Conn
	dialer *TLSDialer
	buffer []byte
}

func (c *tlsConn) Write(b []byte) (int, error) {
	if c.Conn == nil {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: c.dialer.Timeout}, "tcp", c.dialer.Addr.String(), c.dialer.TLSConfig)
		if err != nil {
			return 0, err
		}
		c.Conn = conn
	}

	n := len(b)
	c.buffer = append(c.buffer[:0], byte(n>>8), byte(n&0xFF))
	c.buffer = append(c.buffer, b...)
	_, err := c.Conn.Write(c.buffer)
	return n, err
}

func (c *tlsConn) Read(b []byte) (n int, err error) {
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
}

func (d *HTTPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c := httpconnpool.Get().(*httpConn)
	c.dialer = d
	c.ctx = ctx
	if c.req.Header == nil {
		if d.Header != nil {
			c.req.Header = d.Header
		} else {
			c.req.Header = httpconnheader
		}
		c.req.URL = d.Endpoint
		c.req.Host = d.Endpoint.Host
	}
	c.writer.B = c.writer.B[:0]
	c.reader.B = nil
	c.resp = nil
	return c, nil
}

func (d *HTTPDialer) put(conn net.Conn) {
	if c, _ := conn.(*httpConn); c != nil {
		httpconnpool.Put(c)
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
	defer resp.Body.Close()

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

func (c *httpConn) Close() (err error) {
	return
}

func (c *httpConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *httpConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *httpConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *httpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *httpConn) SetWriteDeadline(t time.Time) error {
	return nil
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

var httpconnheader = http.Header{
	"content-type": {"application/dns-message"},
	"user-agent":   {"fastdns/1.0"},
}

var httpconnpool = sync.Pool{
	New: func() any {
		return &httpConn{
			req: &http.Request{
				Method: http.MethodPost,
			},
			reader: new(bufferreader),
			writer: new(bufferwriter),
		}
	},
}

type bufferwriter struct {
	B []byte
}

func (b *bufferwriter) Write(p []byte) (int, error) {
	b.B = append(b.B, p...)
	return len(p), nil
}

type bufferreader struct {
	B []byte
}

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

func (r *bufferreader) Close() error {
	r.B = nil
	return nil
}

func (r *bufferreader) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(r.B)
	return int64(n), err
}

var _ io.Writer = (*bufferwriter)(nil)
var _ io.ReadCloser = (*bufferreader)(nil)
var _ io.WriterTo = (*bufferreader)(nil)

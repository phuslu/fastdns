package fastdns

import (
	"context"
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
	conns []*udpConn
}

func (d *UDPDialer) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	return d.get()
}

func (d *UDPDialer) get() (net.Conn, error) {
	d.once.Do(func() {
		if d.MaxConns == 0 {
			d.MaxConns = 64
		}
		d.conns = make([]*udpConn, d.MaxConns)
		for i := range d.MaxConns {
			d.conns[i] = new(udpConn)
			d.conns[i].UDPConn, _ = net.DialUDP("udp", nil, d.Addr)
		}
	})

	c := d.conns[cheaprandn(uint32(d.MaxConns))]
	if !c.mu.TryLock() {
		c = d.conns[cheaprandn(uint32(d.MaxConns))]
		c.mu.Lock()
	}

	if d.Timeout > 0 {
		_ = c.SetDeadline(time.Now().Add(d.Timeout))
	}

	return c, nil
}

func (d *UDPDialer) Put(conn net.Conn) {
	if c, _ := conn.(*udpConn); c != nil {
		c.mu.Unlock()
	}
}

type udpConn struct {
	*net.UDPConn
	mu sync.Mutex
}

// HTTPDialer is a custom dialer for creating HTTP connections.
// It allows sending HTTP requests with a specified endpoint, user agent, and transport configuration.
type HTTPDialer struct {
	// Endpoint specifies the HTTP server's URL that the dialer will connect to.
	// This is the base address used for sending HTTP requests.
	Endpoint *url.URL

	// UserAgent defines the User-Agent header that will be included in the HTTP requests
	// sent by this dialer. It can be customized for specific needs.
	UserAgent string

	// Transport allows for customizing the underlying transport mechanism used
	// for making HTTP requests. If set, it overrides the default RoundTripper behavior.
	Transport http.RoundTripper
}

func (d *HTTPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c := httpconnpool.Get().(*httpConn)
	c.dialer = d
	c.ctx = ctx
	c.req.Body = nil
	c.req.URL = d.Endpoint
	c.req.Host = d.Endpoint.Host
	c.reader.B = nil
	c.writer.B = c.writer.B[:0]
	c.resp = nil
	return c, nil
}

func (d *HTTPDialer) Put(conn net.Conn) {
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

var httpconnpool = sync.Pool{
	New: func() any {
		return &httpConn{
			req: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					"content-type": []string{"application/dns-message"},
					"user-agent":   []string{"fastdns/1.0"},
				},
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

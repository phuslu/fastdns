package fastdns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type NetDialer struct {
	// MaxIdleConns int
	// MaxConns     int
	// Timeout      time.Duration
	Dialer *net.Dialer
}

func (d *NetDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, addr)
}

func (d *NetDialer) Put(c net.Conn) {
}

type HTTPDialer struct {
	Endpoint  *url.URL
	UserAgent string
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

	resp, err := tr.RoundTrip(c.req.WithContext(c.ctx))
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

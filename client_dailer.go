package fastdns

import (
	"bytes"
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
	return
}

type HTTPDialer struct {
	Endpoint  *url.URL
	UserAgent string
	Transport http.RoundTripper
}

func (d *HTTPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return &httpConn{ctx: ctx, dialer: d}, nil
}

type httpConn struct {
	ctx    context.Context
	dialer *HTTPDialer
	buffer *buffer
	data   []byte
}

func (c *httpConn) Read(b []byte) (n int, err error) {
	if c.data == nil {
		err = io.EOF
		return
	}

	n = copy(b, c.data)
	if n < len(c.data) {
		c.data = c.data[n:]
	} else {
		c.data = nil
		bufferpool.Put(c.buffer)
	}

	return n, nil
}

func (c *httpConn) Write(b []byte) (n int, err error) {
	req := &http.Request{
		Method: http.MethodPost,
		URL:    c.dialer.Endpoint,
		Header: http.Header{
			"content-type": []string{"application/dns-message"},
			"user-agent":   []string{c.dialer.UserAgent},
		},
		Body:          io.NopCloser(bytes.NewReader(b)),
		Host:          c.dialer.Endpoint.Host,
		ContentLength: int64(len(b)),
	}

	var tr = c.dialer.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}

	resp, err := tr.RoundTrip(req.WithContext(c.ctx))
	if err != nil {
		return 0, fmt.Errorf("fastdns: roundtrip %s error: %w", c.dialer.Endpoint, err)
	}
	defer resp.Body.Close()

	c.buffer = bufferpool.Get().(*buffer)
	c.buffer.B = c.buffer.B[:0]

	_, err = io.Copy(c.buffer, resp.Body)
	if err != nil {
		return 0, fmt.Errorf("fastdns: read from %s error: %w", c.dialer.Endpoint, err)
	}
	if resp.StatusCode != http.StatusOK || resp.ContentLength <= 0 {
		defer bufferpool.Put(c.buffer)
		return 0, fmt.Errorf("fastdns: read from %s error: %s: %s", c.dialer.Endpoint, resp.Status, c.buffer.B)
	}

	c.data = c.buffer.B
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
		return new(httpConn)
	},
}

type buffer struct {
	B []byte
}

func (b *buffer) Write(p []byte) (int, error) {
	b.B = append(b.B, p...)
	return len(p), nil
}

var bufferpool = sync.Pool{
	New: func() any {
		return new(buffer)
	},
}

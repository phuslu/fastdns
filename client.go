package fastdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

var (
	// ErrMaxConns is returned when dns client reaches the max connections limitation.
	ErrMaxConns = errors.New("dns client reaches the max connections limitation")
)

// Client is an UDP client that supports DNS protocol.
type Client struct {
	AddrPort netip.AddrPort

	// MaxIdleConns controls the maximum number of idle (keep-alive)
	// connections. Zero means no limit.
	MaxIdleConns int

	// MaxConns optionally limits the total number of
	// connections per host, including connections in the dialing,
	// active, and idle states. On limit violation, ErrMaxConns will be return.
	//
	// Zero means no limit.
	MaxConns int

	// Timeout is the maximum duration for contecting/reading the dns server.
	Timeout time.Duration

	// DialContext specifies the dial function for creating TCP/UDP connections.
	// If it is set, MaxIdleConns, MaxConns and Timeout will be ignored.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	mu    sync.Mutex
	conns []net.Conn
}

// Exchange executes a single DNS transaction, returning
// a Response for the provided Request.
func (c *Client) Exchange(ctx context.Context, req, resp *Message) (err error) {
	err = c.exchange(ctx, req, resp)
	// if err != nil && os.IsTimeout(err) {
	// 	err = c.exchange(req, resp)
	// }
	return err
}

func (c *Client) exchange(ctx context.Context, req, resp *Message) error {
	var fresh bool
	conn, err := c.get()
	if conn == nil && err == nil {
		conn, err = c.dial(ctx, "udp", c.AddrPort.String())
		fresh = true
	}
	if err != nil {
		return err
	}

	_, err = conn.Write(req.Raw)
	if err != nil && !fresh {
		// if error is a pooled conn, let's close it & retry again
		conn.Close()
		if conn, err = c.dial(ctx, "udp", c.AddrPort.String()); err != nil {
			return err
		}
		if _, err = conn.Write(req.Raw); err != nil {
			return err
		}
	}

	if c.Timeout > 0 {
		err = conn.SetDeadline(time.Now().Add(c.Timeout))
		if err != nil {
			return err
		}
	}

	resp.Raw = resp.Raw[:cap(resp.Raw)]
	n, err := conn.Read(resp.Raw)
	if err == nil {
		resp.Raw = resp.Raw[:n]
		err = ParseMessage(resp, resp.Raw, false)
	}

	c.put(conn)

	return err
}

func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.DialContext != nil {
		return c.DialContext(ctx, network, addr)
	}
	return (&net.Dialer{Timeout: c.Timeout}).DialContext(ctx, network, addr)
}

func (c *Client) get() (conn net.Conn, err error) {
	if c.DialContext != nil {
		return nil, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	count := len(c.conns)
	if c.MaxConns != 0 && count > c.MaxConns {
		err = ErrMaxConns

		return
	}
	if count > 0 {
		conn = c.conns[len(c.conns)-1]
		c.conns = c.conns[:len(c.conns)-1]
	}

	return
}

func (c *Client) put(conn net.Conn) {
	if c.DialContext != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if (c.MaxIdleConns != 0 && len(c.conns) > c.MaxIdleConns) ||
		(c.MaxConns != 0 && len(c.conns) > c.MaxConns) {
		conn.Close()

		return
	}

	c.conns = append(c.conns, conn)
}

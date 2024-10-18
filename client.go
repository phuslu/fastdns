package fastdns

import (
	"context"
	"net"
	"time"
)

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Client is an UDP client that supports DNS protocol.
type Client struct {
	// Address specifies the address of dns server.
	Addr string

	// Timeout
	Timeout time.Duration

	// Dialer specifies the dialer for creating TCP/UDP connections.
	// If it is set, Addr and Timeout will be ignored.
	Dialer Dialer
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
	dialer := c.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: c.Timeout}
	}

	conn, err := dialer.DialContext(ctx, "udp", c.Addr)
	if err != nil {
		return err
	}

	_, err = conn.Write(req.Raw)
	if err != nil {
		return nil
	}

	if c.Timeout > 0 {
		err = conn.SetDeadline(time.Now().Add(c.Timeout))
		if err != nil {
			return err
		}
	}

	resp.Raw = resp.Raw[:cap(resp.Raw)]
	n, err := conn.Read(resp.Raw)
	if err != nil {
		return nil
	}

	resp.Raw = resp.Raw[:n]
	err = ParseMessage(resp, resp.Raw, false)
	if err != nil {
		return err
	}

	if d, _ := c.Dialer.(interface {
		Put(c net.Conn)
	}); d != nil {
		d.Put(conn)
	}

	return nil
}

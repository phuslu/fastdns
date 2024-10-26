package fastdns

import (
	"context"
	"net"
	"time"
)

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Client represents a DNS client that communicates over UDP.
// It supports sending DNS queries to a specified server.
type Client struct {
	// Addr defines the DNS server's address to which the client will send queries.
	// This field is used if no custom Dialer is provided.
	Addr string

	// Timeout specifies the maximum duration for a query to complete.
	// If a query exceeds this duration, it will result in a timeout error.
	Timeout time.Duration

	// Dialer allows for customizing the way connections are established.
	// If set, Addr and Timeout will be ignore.
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

	if c.Timeout > 0 && c.Dialer == nil {
		err = conn.SetDeadline(time.Now().Add(c.Timeout))
		if err != nil {
			return err
		}
	}

	_, err = conn.Write(req.Raw)
	if err != nil {
		return err
	}

	resp.Raw = resp.Raw[:cap(resp.Raw)]
	n, err := conn.Read(resp.Raw)
	if err != nil {
		return err
	}

	resp.Raw = resp.Raw[:n]
	err = ParseMessage(resp, resp.Raw, false)
	if err != nil {
		return err
	}

	if d, _ := c.Dialer.(interface {
		put(c net.Conn)
	}); d != nil {
		d.put(conn)
	}

	return nil
}

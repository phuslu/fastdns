package fastdns

import (
	"context"
	"errors"
	"net"
	"time"
)

var (
	// ErrMaxConns is returned when dns client reaches the max connections limitation.
	ErrMaxConns = errors.New("dns client reaches the max connections limitation")
)

// Client is an UDP client that supports DNS protocol.
type Client struct {
	// AddrPort specifies the network of dns connection.
	Network string

	// Address specifies the address of dns server.
	Addr string

	// Timeout
	Timeout time.Duration

	// DialContext specifies the dial function for creating TCP/UDP connections.
	// If it is set, Network, AddrPort and Timeout will be ignored.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
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
	dial := c.DialContext
	if dial == nil {
		dial = defaultDialer.DialContext
	}

	conn, err := dial(ctx, c.Network, c.Addr)
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

	return nil
}

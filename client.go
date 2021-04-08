package fastdns

import (
	"errors"
	"net"
	"sync"
	"time"
)

var (
	// ErrMaxConns is returned when dns client reaches the max connections limitation.
	ErrMaxConns = errors.New("dns client reaches the max connections limitation")
)

// Client is an UDP client that supports DNS protocol.
type Client struct {
	ServerAddr *net.UDPAddr
	ReadTimout time.Duration
	MaxConns   int

	mu    sync.Mutex
	conns []*net.UDPConn
}

// Exchange executes a single DNS transaction, returning
// a Response for the provided Request.
func (c *Client) Exchange(req, resp *Message) (err error) {
	err = c.exchange(req, resp)
	if err != nil {
		err = c.exchange(req, resp)
	}
	return err
}

func (c *Client) exchange(req, resp *Message) error {
	var fresh bool
	conn, err := c.get()
	if conn == nil && err == nil {
		conn, err = c.dial()
		fresh = true
	}
	if err != nil {
		return err
	}

	_, err = conn.Write(req.Raw)
	if err != nil && !fresh {
		// if error is a pooled conn, let's close it & retry again
		conn.Close()
		if conn, err = c.dial(); err != nil {
			return err
		}
		if _, err = conn.Write(req.Raw); err != nil {
			return err
		}
	}

	if c.ReadTimout > 0 {
		err = conn.SetReadDeadline(time.Now().Add(c.ReadTimout))
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

func (c *Client) dial() (conn *net.UDPConn, err error) {
	conn, err = net.DialUDP("udp", nil, c.ServerAddr)
	return
}

func (c *Client) get() (conn *net.UDPConn, err error) {
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

func (c *Client) put(conn *net.UDPConn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.MaxConns != 0 && len(c.conns) > c.MaxConns {
		conn.Close()

		return
	}

	c.conns = append(c.conns, conn)
}

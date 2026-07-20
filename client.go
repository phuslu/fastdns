package fastdns

import (
	"context"
	"errors"
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

// Exchange executes a DNS transaction and unmarshals the response into resp.
func (c *Client) Exchange(ctx context.Context, req, resp *Message) (err error) {
	err = c.exchange(ctx, req, resp)
	// if err != nil && os.IsTimeout(err) {
	// 	err = c.exchange(req, resp)
	// }
	return err
}

// exchange performs the transport-level DNS round trip with the configured dialer.
func (c *Client) exchange(ctx context.Context, req, resp *Message) (err error) {
	var conn net.Conn

	if c.Dialer != nil {
		conn, err = c.Dialer.DialContext(ctx, "udp", c.Addr)
	} else {
		conn, err = net.Dial("udp", c.Addr)
	}
	if err != nil {
		return err
	}

	// Release the connection on every return path, so a failed exchange can
	// never permanently remove a slot from a pooled dialer. Registered first,
	// so it runs last: after the deadline reset installed below.
	switch d := c.Dialer.(type) {
	case nil:
		defer conn.Close() // nolint:errcheck
	case interface{ release(net.Conn, error) }:
		defer func() { d.release(conn, err) }()
	case interface{ Put(net.Conn) }:
		// Backward compatibility for third-party pooled dialers.
		defer func() {
			if err == nil {
				d.Put(conn)
			} else {
				_ = conn.Close()
			}
		}()
	}

	if options, ok := ctx.Value(clientOptionsContextKey).(*clientOptionsContextValue); ok {
		roa, e := req.OptionsAppender()
		if e != nil {
			return e
		}
		if options.prefix.IsValid() {
			roa.AppendSubnet(options.prefix)
		}
		if options.cookie != "" {
			roa.AppendCookie(options.cookie)
		}
		if options.padding != 0 {
			roa.AppendPadding(options.padding)
		}
	}

	_, err = conn.Write(req.Raw)
	if err != nil {
		return err
	}

	// Bound the response Read by the earlier of Client.Timeout and the context
	// deadline. The Write above establishes the pooled connection, so deadline
	// handling always runs on a live socket; DNS payloads are small, so bounding
	// the Read is what keeps an unanswered query from blocking forever.
	deadline := time.Time{}
	if c.Timeout > 0 {
		deadline = time.Now().Add(c.Timeout)
	}
	if t, ok := ctx.Deadline(); ok && (deadline.IsZero() || t.Before(deadline)) {
		deadline = t
	}
	if !deadline.IsZero() {
		if e := conn.SetDeadline(deadline); e != nil && e != errors.ErrUnsupported {
			return e
		}
	}

	// Cancel a blocked Read when the context is done, and always clear the
	// deadline before the connection returns to the pool. Registered after the
	// release above, so it runs first.
	if !deadline.IsZero() || ctx.Done() != nil {
		var callbackDone chan struct{}
		var stop func() bool
		if ctx.Done() != nil {
			callbackDone = make(chan struct{})
			stop = context.AfterFunc(ctx, func() {
				_ = conn.SetDeadline(time.Now())
				close(callbackDone)
			})
		}
		defer func() {
			if stop != nil && !stop() {
				<-callbackDone
			}
			_ = conn.SetDeadline(time.Time{}) // nolint:errcheck
		}()
	}

	resp.Raw = resp.Raw[:cap(resp.Raw)]
	n, err := conn.Read(resp.Raw)
	if err != nil {
		return err
	}

	resp.Raw = resp.Raw[:n]
	err = ParseMessage(resp, resp.Raw, false)
	return err
}

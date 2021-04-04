package fastdns

import (
	"errors"
	"net"
	"sync"
	"time"
)

var (
	// ErrMaxConns is returned when dns transport reaches the max connections limitation.
	ErrMaxConns = errors.New("dns transport reaches the max connections limitation")
)

type Transport struct {
	Address  *net.UDPAddr
	Timout   time.Duration
	MaxConns int

	mu    sync.Mutex
	conns []*net.UDPConn
}

func (tr *Transport) RoundTrip(req, resp *Message) (err error) {
	err = tr.roundTrip(req, resp)
	if err != nil {
		err = tr.roundTrip(req, resp)
	}
	return err
}

func (tr *Transport) roundTrip(req, resp *Message) error {
	conn, pooled, err := tr.get()
	if err != nil {
		return err
	}

	n, err := conn.Write(req.Raw)
	if err != nil && pooled {
		// if error from pooled conn, let's close it & retry again
		conn.Close()
		if conn, err = tr.dial(); err != nil {
			return err
		}
		if _, err = conn.Write(req.Raw); err != nil {
			return err
		}
	}

	resp.Raw = resp.Raw[:cap(resp.Raw)]
	n, err = conn.Read(resp.Raw)
	if err == nil {
		resp.Raw = resp.Raw[:n]
		err = ParseMessage(resp, resp.Raw, false)
	}

	tr.put(conn)

	return err
}

func (tr *Transport) dial() (conn *net.UDPConn, err error) {
	conn, err = net.DialUDP("udp", nil, tr.Address)
	return
}

func (tr *Transport) get() (conn *net.UDPConn, pooled bool, err error) {
	tr.mu.Lock()
	count := len(tr.conns)
	if tr.MaxConns != 0 && count > tr.MaxConns {
		err = ErrMaxConns
		tr.mu.Unlock()
		return
	}
	if count > 0 {
		conn = tr.conns[len(tr.conns)-1]
		tr.conns = tr.conns[:len(tr.conns)-1]
		pooled = true
	}
	tr.mu.Unlock()

	if conn == nil {
		conn, err = tr.dial()
	}

	return
}

func (tr *Transport) put(conn *net.UDPConn) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	if tr.MaxConns != 0 && len(tr.conns) > tr.MaxConns {
		conn.Close()
		return
	}

	tr.conns = append(tr.conns, conn)
}

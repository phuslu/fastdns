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

func (tr *Transport) RoundTrip(dst []byte, req *Request) (n int, err error) {
	n, err = tr.roundTrip(dst, req)
	if n == 0 || err != nil {
		n, err = tr.roundTrip(dst, req)
	}
	return
}

func (tr *Transport) roundTrip(dst []byte, req *Request) (n int, err error) {
	var conn *net.UDPConn
	var pooled bool

	conn, pooled, err = tr.get()
	if err != nil {
		return
	}

	_, err = conn.Write(req.Raw)
	if err != nil && pooled {
		// if error from pooled conn, let's close it & retry again
		conn.Close()
		if conn, err = tr.dial(); err != nil {
			return
		}
		if _, err = conn.Write(req.Raw); err != nil {
			return
		}
	}

	n, err = conn.Read(dst)

	tr.put(conn)

	return
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

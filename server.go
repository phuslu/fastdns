package fastdns

import (
	"errors"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

// Server implements a mutli-listener DNS server.
type Server struct {
	// handler to invoke
	Handler Handler

	// Logger specifies a logger
	Logger Logger

	// The maximum number of procs the server may spawn. use runtime.NumCPU() if empty
	MaxProcs int

	// The maximum number of concurrent clients the server may serve.
	Concurrency int

	// Index indicates the index of Server instances.
	index int
}

// ListenAndServe serves DNS requests from the given UDP addr.
func (s *Server) ListenAndServe(addr string) error {
	if s.Index() == 0 {
		// only prefork for linux(reuse_port)
		return s.spawn(addr, s.MaxProcs)
	}

	conn, err := listen("udp", addr)
	if err != nil {
		s.Logger.Printf("server-%d listen on addr=%s failed: %+v", s.Index(), addr, err)
		return err
	}

	s.Logger.Printf("server-%d pid-%d serving dns on %s", s.Index(), os.Getpid(), conn.LocalAddr())

	return serve(conn, s.Handler, s.Logger, s.Concurrency)
}

// Index indicates the index of Server instances.
func (s *Server) Index() (index int) {
	index = s.index
	return
}

func (s *Server) spawn(addr string, maxProcs int) (err error) {
	type racer struct {
		index int
		err   error
	}

	if maxProcs == 0 {
		maxProcs = runtime.NumCPU()
	}
	if runtime.GOOS != "linux" {
		maxProcs = 1
	}

	ch := make(chan racer, maxProcs)

	// create multiple receive worker for performance
	for i := 1; i <= maxProcs; i++ {
		go func(index int) {
			server := &Server{
				Handler:     s.Handler,
				Logger:      s.Logger,
				MaxProcs:    s.MaxProcs,
				Concurrency: s.Concurrency,
				index:       index,
			}
			err := server.ListenAndServe(addr)
			ch <- racer{index, err}
		}(i)
	}

	var exited int
	for sig := range ch {
		s.Logger.Printf("server one of the child workers exited with error: %v", sig.err)

		if exited++; exited > 200 {
			s.Logger.Printf("server child workers exit too many times(%d)", exited)
			err = errors.New("server child workers exit too many times")
			break
		}

		go func(index int) {
			server := &Server{
				Handler:     s.Handler,
				Logger:      s.Logger,
				MaxProcs:    s.MaxProcs,
				Concurrency: s.Concurrency,
				index:       index,
			}
			err := server.ListenAndServe(addr)
			ch <- racer{index, err}
		}(sig.index)
	}

	return
}

type udpItem struct {
	rw  *udpResponseWriter
	req *Request
}

var udpItemPool = sync.Pool{
	New: func() interface{} {
		item := new(udpItem)
		item.rw = new(udpResponseWriter)
		item.req = new(Request)
		item.req.Raw = make([]byte, 0, 1024)
		item.req.Domain = make([]byte, 0, 256)
		return item
	},
}

func serve(conn *net.UDPConn, handler Handler, logger Logger, concurrency int) error {
	if concurrency == 0 {
		concurrency = 256 * 1024
	}

	pool := &workerPool{
		WorkerFunc: func(item *udpItem) error {
			err := ParseRequest(item.req, item.req.Raw, false)
			if err != nil {
				udpItemPool.Put(item)

				return err
			}

			handler.ServeDNS(item.rw, item.req)

			udpItemPool.Put(item)

			return nil
		},
		MaxWorkersCount:       concurrency,
		LogAllErrors:          false,
		MaxIdleWorkerDuration: 2 * time.Minute,
		Logger:                logger,
	}
	pool.Start()

	for {
		item := udpItemPool.Get().(*udpItem)

		item.req.Raw = item.req.Raw[:cap(item.req.Raw)]
		n, addr, err := conn.ReadFromUDP(item.req.Raw)
		if err != nil {
			udpItemPool.Put(item)
			time.Sleep(10 * time.Millisecond)

			continue
		}

		item.req.Raw = item.req.Raw[:n]
		item.rw.Conn = conn
		item.rw.Addr = addr

		pool.Serve(item)
	}
}

// ListenAndServe serves DNS requests from the given UDP addr
// using the given handler.
func ListenAndServe(addr string, handler Handler) error {
	return (&Server{Handler: handler, Logger: log.Default()}).ListenAndServe(addr)
}

package fastdns

import (
	"errors"
	"log"
	"net"
	"os"
	"runtime"
	"time"
)

// Server implements a mutli-listener DNS server.
type Server struct {
	// handler to invoke
	Handler Handler

	// Logger specifies a logger
	Logger Logger

	// The maximum number of concurrent clients the server may serve.
	//
	// DefaultConcurrency is used if not set.
	//
	// Concurrency only works if you either call Serve once, or only ServeConn multiple times.
	// It works with ListenAndServe as well.
	Concurrency int

	// Index indicates the index of Server instances.
	index int
}

// ListenAndServe serves DNS requests from the given UDP addr.
func (s *Server) ListenAndServe(addr string) error {
	if s.Index() == 0 {
		// only prefork for linux(reuse_port)
		return s.spawn(addr)
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

func (s *Server) spawn(addr string) (err error) {
	type racer struct {
		index int
		err   error
	}

	maxProcs := runtime.NumCPU()
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
				Concurrency: s.Concurrency,
				index:       index,
			}
			err := server.ListenAndServe(addr)
			ch <- racer{index, err}
		}(sig.index)
	}

	return
}

func serve(conn *net.UDPConn, handler Handler, logger Logger, concurrency int) error {
	if concurrency == 0 {
		concurrency = 256 * 1024
	}

	pool := &workerPool{
		WorkerFunc: func(rw *UDPResponseWriter) error {
			req := AcquireRequest()

			err := ParseRequest(req, rw.Data)
			if err != nil {
				ReleaseRequest(req)
				udpResponseWriterPool.Put(rw)

				return err
			}

			handler.ServeDNS(rw, req)

			ReleaseRequest(req)
			udpResponseWriterPool.Put(rw)

			return nil
		},
		MaxWorkersCount:       concurrency,
		LogAllErrors:          false,
		MaxIdleWorkerDuration: 2 * time.Minute,
		Logger:                logger,
	}
	pool.Start()

	for {
		rw := udpResponseWriterPool.Get().(*UDPResponseWriter)

		rw.Data = rw.Data[:cap(rw.Data)]
		n, addr, err := conn.ReadFromUDP(rw.Data)
		if err != nil {
			udpResponseWriterPool.Put(rw)
			time.Sleep(10 * time.Millisecond)

			continue
		}

		rw.Data = rw.Data[:n]
		rw.Conn = conn
		rw.Addr = addr

		pool.Serve(rw)
	}
}

// ListenAndServe serves DNS requests from the given UDP addr
// using the given handler.
func ListenAndServe(addr string, handler Handler) error {
	return (&Server{Handler: handler, Logger: log.Default()}).ListenAndServe(addr)
}

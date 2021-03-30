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

	// Index indicates the index of Server instances.
	Index int

	// The maximum number of concurrent clients the server may serve.
	//
	// DefaultConcurrency is used if not set.
	//
	// Concurrency only works if you either call Serve once, or only ServeConn multiple times.
	// It works with ListenAndServe as well.
	Concurrency int
}

// ListenAndServe serves DNS requests from the given UDP addr.
func (s *Server) ListenAndServe(addr string) error {
	if s.Index == 0 && runtime.GOOS == "linux" {
		// only prefork for linux(reuse_port)
		return s.spawn(addr)
	}

	conn, err := listen("udp", addr)
	if err != nil {
		s.Logger.Printf("server-%d listen on addr=%s failed: %+v", s.Index, addr, err)
		return err
	}

	s.Logger.Printf("server-%d pid-%d serving dns on %s", s.Index, os.Getpid(), conn.LocalAddr())

	return serve(conn, s.Handler, s.Logger, s.Concurrency)
}

func (s *Server) spawn(addr string) (err error) {
	type racer struct {
		index int
		err   error
	}

	maxProcs := runtime.NumCPU()

	ch := make(chan racer, maxProcs)

	for i := 1; i <= maxProcs; i++ {
		go func(index int) {
			server := &Server{
				Handler: s.Handler,
				Logger:  s.Logger,
				Index:   index,
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
				Handler: s.Handler,
				Logger:  s.Logger,
				Index:   index,
			}
			err := server.ListenAndServe(addr)
			ch <- racer{index, err}
		}(sig.index)
	}

	return
}

// DefaultConcurrency is the maximum number of concurrent clients
// the Server may serve by default (i.e. if Server.Concurrency isn't set).
const DefaultConcurrency = 256 * 1024

func serve(conn *net.UDPConn, handler Handler, logger Logger, concurrency int) error {
	if concurrency == 0 {
		concurrency = DefaultConcurrency
	}

	pool := &workerPool{
		WorkerFunc: func(rw ResponseWriter, b *ByteBuffer) error {
			defer ReleaseByteBuffer(b)

			req := AcquireRequest()
			defer ReleaseRequest(req)

			err := ParseRequest(req, b.B)
			if err != nil {
				return err
			}

			handler.ServeDNS(rw, req)
			return nil
		},
		MaxWorkersCount:       concurrency,
		LogAllErrors:          false,
		MaxIdleWorkerDuration: 2 * time.Minute,
		Logger:                logger,
	}
	pool.Start()

	for {
		b := AcquireByteBuffer()

		b.B = b.B[:cap(b.B)]
		n, addr, err := conn.ReadFromUDP(b.B)
		b.B = b.B[:n]

		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		pool.Serve(&udpResponseWriter{conn, addr}, b)
	}
}

// ListenAndServe serves DNS requests from the given UDP addr
// using the given handler.
func ListenAndServe(addr string, handler Handler) error {
	s := &Server{
		Handler: handler,
		Logger:  log.Default(),
	}
	return s.ListenAndServe(addr)
}

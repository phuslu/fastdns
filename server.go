package fastdns

import (
	"errors"
	"log"
	"net"
	"runtime"
	"sync"
	"time"
)

// Server implements a mutli-listener DNS server.
type Server struct {
	// handler to invoke
	Handler Handler

	// ErrorLog specifies an optional logger for errors accepting
	// connections, unexpected behavior from handlers, and
	// underlying FileSystem errors.
	// If nil, logging is done via the log package's standard logger.
	ErrorLog *log.Logger

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

	if s.ErrorLog == nil {
		s.ErrorLog = log.Default()
	}

	conn, err := listen("udp", addr)
	if err != nil {
		s.ErrorLog.Printf("server-%d listen on addr=%s failed: %+v", s.Index(), addr, err)
		return err
	}

	// s.ErrorLog.Printf("server-%d pid-%d serving dns on %s", s.Index(), os.Getpid(), conn.LocalAddr())

	return serve(conn, s.Handler, s.ErrorLog, s.Concurrency)
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
				ErrorLog:    s.ErrorLog,
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
		s.ErrorLog.Printf("server one of the child workers exited with error: %v", sig.err)

		if exited++; exited > 200 {
			s.ErrorLog.Printf("server child workers exit too many times(%d)", exited)
			err = errors.New("server child workers exit too many times")
			break
		}

		go func(index int) {
			server := &Server{
				Handler:     s.Handler,
				ErrorLog:    s.ErrorLog,
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

type udpCtx struct {
	rw  *udpResponseWriter
	req *Message
}

var udpCtxPool = sync.Pool{
	New: func() interface{} {
		ctx := new(udpCtx)
		ctx.rw = new(udpResponseWriter)
		ctx.req = new(Message)
		ctx.req.Raw = make([]byte, 0, 1024)
		ctx.req.Domain = make([]byte, 0, 256)
		return ctx
	},
}

func serve(conn *net.UDPConn, handler Handler, logger *log.Logger, concurrency int) error {
	if concurrency == 0 {
		concurrency = 256 * 1024
	}

	pool := &workerPool{
		WorkerFunc: func(ctx *udpCtx) error {
			rw, req := ctx.rw, ctx.req

			err := ParseMessage(req, req.Raw, false)
			if err != nil {
				udpCtxPool.Put(ctx)

				return err
			}

			handler.ServeDNS(rw, req)

			udpCtxPool.Put(ctx)

			return nil
		},
		MaxWorkersCount:       concurrency,
		LogAllErrors:          false,
		MaxIdleWorkerDuration: 2 * time.Minute,
		Logger:                logger,
	}
	pool.Start()

	for {
		ctx := udpCtxPool.Get().(*udpCtx)
		rw, req := ctx.rw, ctx.req

		req.Raw = req.Raw[:cap(req.Raw)]
		n, addr, err := conn.ReadFromUDP(req.Raw)
		if err != nil {
			udpCtxPool.Put(ctx)
			time.Sleep(10 * time.Millisecond)

			continue
		}

		req.Raw = req.Raw[:n]
		rw.Conn = conn
		rw.Addr = addr

		pool.Serve(ctx)
	}
}

// ListenAndServe serves DNS requests from the given UDP addr
// using the given handler.
func ListenAndServe(addr string, handler Handler) error {
	return (&Server{Handler: handler, ErrorLog: log.Default()}).ListenAndServe(addr)
}

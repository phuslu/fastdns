package fastdns

import (
	"errors"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"time"
)

// Handler is implemented by any value that implements ServeDNS.
type Handler interface {
	ServeDNS(rw ResponseWriter, req *Message)
}

// Server implements a mutli-listener DNS server.
type Server struct {
	// handler to invoke
	Handler Handler

	// Stats to invoke
	Stats Stats

	// ErrorLog specifies an optional logger for errors accepting
	// connections, unexpected behavior from handlers, and
	// underlying FileSystem errors.
	// If nil, logging is disabled.
	ErrorLog *slog.Logger

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
		if s.ErrorLog != nil {
			s.ErrorLog.Error("server listen failed", "error", err, "index", s.Index(), "addr", addr)
		}
		return err
	}

	// s.ErrorLog.Printf("server-%d pid-%d serving dns on %s", s.Index(), os.Getpid(), conn.LocalAddr())

	return serve(conn, s.Handler, s.Stats, s.ErrorLog, s.Concurrency)
}

// Serve serves DNS requests from the given UDP addr.
func (s *Server) Serve(conn *net.UDPConn) error {
	if s.MaxProcs > 1 {
		return errors.New("Server.MaxProcs cannot large than 1 when using Serve")
	}
	return serve(conn, s.Handler, s.Stats, s.ErrorLog, s.Concurrency)
}

// Index indicates the index of Server instances.
func (s *Server) Index() (index int) {
	index = s.index
	return
}

// spawn starts worker processes and restarts them when they exit.
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
				Stats:       s.Stats,
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
		if s.ErrorLog != nil {
			s.ErrorLog.Error("server one of the child workers exited", "error", sig.err)
		}

		if exited++; exited > 200 {
			if s.ErrorLog != nil {
				s.ErrorLog.Error("server child workers exit too many times", "count", exited)
			}
			err = errors.New("server child workers exit too many times")
			break
		}

		go func(index int) {
			server := &Server{
				Handler:     s.Handler,
				Stats:       s.Stats,
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
	rw      *udpResponseWriter
	req     *Message
	handler Handler
	stats   Stats
}

var udpCtxPool = &sync.Pool{
	New: func() interface{} {
		ctx := new(udpCtx)
		ctx.rw = new(udpResponseWriter)
		ctx.req = new(Message)
		ctx.req.Raw = make([]byte, 0, 1024)
		ctx.req.Domain = make([]byte, 0, 256)
		return ctx
	},
}

// serve reads UDP packets and dispatches them to the worker pool.
func serve(conn *net.UDPConn, handler Handler, stats Stats, logger *slog.Logger, concurrency int) error {
	if concurrency == 0 {
		concurrency = 256 * 1024
	}

	pool := &workerPool{
		WorkerFunc:            serveCtx,
		MaxWorkersCount:       concurrency,
		LogAllErrors:          false,
		MaxIdleWorkerDuration: 2 * time.Minute,
		Logger:                logger,
	}
	pool.Start()

	for {
		ctx := udpCtxPool.Get().(*udpCtx)

		ctx.req.Raw = ctx.req.Raw[:cap(ctx.req.Raw)]
		n, addrPort, err := conn.ReadFromUDPAddrPort(ctx.req.Raw)
		if err != nil {
			udpCtxPool.Put(ctx)
			time.Sleep(10 * time.Millisecond)

			continue
		}

		ctx.req.Raw = ctx.req.Raw[:n]
		ctx.rw.Conn = conn
		ctx.rw.AddrPort = addrPort

		ctx.handler = handler
		ctx.stats = stats

		pool.Serve(ctx)
	}
}

// serveCtx executes the handler for a single incoming DNS request.
func serveCtx(ctx *udpCtx) error {
	var start time.Time
	if ctx.stats != nil {
		start = time.Now()
	}

	rw, req := ctx.rw, ctx.req

	err := ParseMessage(req, req.Raw, false)
	if err != nil {
		req.SetResponseHeader(RcodeFormErr, 0)
		_, _ = rw.Write(req.Raw)
	} else {
		ctx.handler.ServeDNS(rw, req)
	}

	if ctx.stats != nil {
		ctx.stats.UpdateStats(rw.RemoteAddr(), req, time.Since(start))
	}

	udpCtxPool.Put(ctx)

	return err
}

// Error replies to the request with the specified Rcode.
func Error(rw ResponseWriter, req *Message, rcode Rcode) {
	req.SetResponseHeader(rcode, 0)
	_, _ = rw.Write(req.Raw)
}

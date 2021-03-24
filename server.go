package fastdns

import (
	"errors"
	"net"
	"os"
	"time"
)

type Server struct {
	Network string
	Handler Handler
	Logger  Logger

	index int
}

func (s *Server) ListenAndServe(addr string) error {
	if s.Index() == 0 {
		return s.spwan(addr)
	}

	if s.Network == "" {
		s.Network = "udp"
	}

	conn, err := listen(s.Network, addr)
	if err != nil {
		s.Logger.Printf("server-%d listen on addr=%s failed: %+v", s.Index(), addr, err)
		return err
	}

	s.Logger.Printf("server-%d pid-%d serving dns on %s", s.Index(), os.Getpid(), conn.LocalAddr())

	return serve(conn, s.Handler, s.Logger)
}

func (s *Server) Index() (index int) {
	index = s.index
	return
}

func (s *Server) spwan(addr string) (err error) {
	type racer struct {
		index int
		err   error
	}

	maxProcs := getMaxProcs()

	ch := make(chan racer, maxProcs)

	for i := 1; i <= maxProcs; i++ {
		go func(index int) {
			server := &Server{
				Handler: s.Handler,
				Logger:  s.Logger,
				index:   index,
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
				index:   index,
			}
			err := server.ListenAndServe(addr)
			ch <- racer{index, err}
		}(sig.index)
	}

	return
}

func serve(conn *net.UDPConn, handler Handler, logger Logger) error {
	pool := &workerPool{
		WorkerFunc: func(rw ResponseWriter, b *ByteBuffer) error {
			defer ReleaseByteBuffer(b)

			req := AcquireRequest()
			defer ReleaseRequest(req)

			err := ParseRequest(b.B, req)
			if err != nil {
				return err
			}

			handler.ServeDNS(rw, req)
			return nil
		},
		MaxWorkersCount:       200000,
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

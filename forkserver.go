package fastdns

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

type ForkServer struct {
	Network string
	Handler Handler
	Logger  Logger

	HTTPPortBase uint16
	HTTPHandler  http.Handler

	index int
	conn  *net.UDPConn
}

func (s *ForkServer) ListenAndServe(addr string) error {
	s.index, _ = strconv.Atoi(os.Getenv("FASTDNS_CHILD_INDEX"))
	if s.Index() == 0 {
		return s.prefork(addr)
	}

	runtime.GOMAXPROCS(1)
	err := taskset((s.Index() - 1) % runtime.NumCPU())
	if err != nil {
		s.Logger.Printf("dnsserver(%d) set cpu affinity=%d failed: %+v", s.Index(), s.Index()-1, err)
	}

	if s.Network == "" {
		s.Network = "udp"
	}

	conn, err := listen(s.Network, addr)
	if err != nil {
		s.Logger.Printf("dnsserver(%d) listen on addr=%s failed: %+v", s.Index(), addr, err)
		return err
	}
	s.conn = conn

	if s.HTTPPortBase > 0 {
		host, _, _ := net.SplitHostPort(addr)
		httpAddr := fmt.Sprintf("%s:%d", host, int(s.HTTPPortBase)+s.Index())
		go http.ListenAndServe(httpAddr, s.HTTPHandler)
		s.Logger.Printf("dnsserver(%d) pid(%d) serving http on port %s", s.Index(), os.Getpid(), httpAddr)
	}

	s.Logger.Printf("dnsserver(%d) pid(%d) serving dns on %s", s.Index(), os.Getpid(), conn.LocalAddr())

	pool := newGoroutinePool(1 * time.Minute)
	for {
		b := AcquireByteBuffer()

		b.B = b.B[:cap(b.B)]
		n, addr, err := conn.ReadFromUDP(b.B)
		b.B = b.B[:n]

		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		pool.Go(func() {
			defer ReleaseByteBuffer(b)

			req := AcquireRequest()
			defer ReleaseRequest(req)

			err := ParseRequest(b.B, req)
			if err != nil {
				return
			}

			s.Handler.ServeDNS(&responseWriter{conn, addr}, req)
		})
	}

	return nil
}

func (s *ForkServer) Index() (index int) {
	index = s.index
	return
}

func (s *ForkServer) fork(index int) (*exec.Cmd, error) {
	/* #nosec G204 */
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append([]string{fmt.Sprintf("FASTDNS_CHILD_INDEX=%d", index)}, os.Environ()...)
	return cmd, cmd.Start()
}

func (s *ForkServer) prefork(addr string) (err error) {
	type racer struct {
		index int
		pid   int
		err   error
	}

	maxProcs := runtime.GOMAXPROCS(0)
	if runtime.GOOS != "linux" {
		maxProcs = 1
	}

	ch := make(chan racer, maxProcs)
	childs := make(map[int]*exec.Cmd)

	defer func() {
		for _, proc := range childs {
			_ = proc.Process.Kill()
		}
	}()

	for i := 1; i <= maxProcs; i++ {
		var cmd *exec.Cmd
		if cmd, err = s.fork(i); err != nil {
			s.Logger.Printf("failed to start a child prefork process, error: %v\n", err)
			return
		}

		childs[cmd.Process.Pid] = cmd
		go func(index int) {
			ch <- racer{index, cmd.Process.Pid, cmd.Wait()}
		}(i)
	}

	var exited int
	for sig := range ch {
		delete(childs, sig.pid)

		s.Logger.Printf("one of the child prefork processes exited with error: %v", sig.err)

		if exited++; exited > 200 {
			s.Logger.Printf("child workers exit too many times(%d)", exited)
			err = errors.New("child workers exit too many times")
			break
		}

		var cmd *exec.Cmd
		if cmd, err = s.fork(sig.index); err != nil {
			break
		}
		childs[cmd.Process.Pid] = cmd
		go func(index int) {
			ch <- racer{index, cmd.Process.Pid, cmd.Wait()}
		}(sig.index)
	}

	return
}

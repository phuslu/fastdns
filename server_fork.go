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
)

type ForkServer struct {
	Network string
	Handler Handler
	Logger  Logger

	HTTPPortBase uint16
	HTTPHandler  http.Handler

	index int
}

func (s *ForkServer) ListenAndServe(addr string) error {
	s.index, _ = strconv.Atoi(os.Getenv("FASTDNS_CHILD_INDEX"))
	if s.Index() == 0 {
		return s.fork(addr)
	}

	// runtime.GOMAXPROCS(1)
	err := taskset((s.Index() - 1) % runtime.NumCPU())
	if err != nil {
		s.Logger.Printf("forkserver-%d set cpu_affinity=%d failed: %+v", s.Index(), s.Index()-1, err)
	}

	if s.Network == "" {
		s.Network = "udp"
	}

	conn, err := listen(s.Network, addr)
	if err != nil {
		s.Logger.Printf("forkserver-%d listen on addr=%s failed: %+v", s.Index(), addr, err)
		return err
	}

	if s.HTTPPortBase > 0 {
		host, _, _ := net.SplitHostPort(addr)
		httpAddr := fmt.Sprintf("%s:%d", host, int(s.HTTPPortBase)+s.Index())
		go func() {
			s.Logger.Printf("forkserver-%d pid-%d serving http on port %s", s.Index(), os.Getpid(), httpAddr)
			_ = http.ListenAndServe(httpAddr, s.HTTPHandler)
		}()
	}

	s.Logger.Printf("forkserver-%d pid-%d serving dns on %s", s.Index(), os.Getpid(), conn.LocalAddr())

	return serve(conn, s.Handler, s.Logger)
}

func (s *ForkServer) Index() (index int) {
	index = s.index
	return
}

func fork(index int) (*exec.Cmd, error) {
	/* #nosec G204 */
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append([]string{fmt.Sprintf("FASTDNS_CHILD_INDEX=%d", index)}, os.Environ()...)
	return cmd, cmd.Start()
}

func (s *ForkServer) fork(addr string) (err error) {
	type racer struct {
		index int
		pid   int
		err   error
	}

	maxProcs := getMaxProcs()

	ch := make(chan racer, maxProcs)
	childs := make(map[int]*exec.Cmd)

	defer func() {
		for _, proc := range childs {
			_ = proc.Process.Kill()
		}
	}()

	for i := 1; i <= maxProcs; i++ {
		var cmd *exec.Cmd
		if cmd, err = fork(i); err != nil {
			s.Logger.Printf("forkserver failed to start a child process, error: %v\n", err)
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

		s.Logger.Printf("forkserver one of the child processes exited with error: %v", sig.err)

		if exited++; exited > 200 {
			s.Logger.Printf("forkserver child workers exit too many times(%d)", exited)
			err = errors.New("forkserver child workers exit too many times")
			break
		}

		var cmd *exec.Cmd
		if cmd, err = fork(sig.index); err != nil {
			break
		}
		childs[cmd.Process.Pid] = cmd
		go func(index int) {
			ch <- racer{index, cmd.Process.Pid, cmd.Wait()}
		}(sig.index)
	}

	return
}

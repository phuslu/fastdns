package fastdns

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
)

// ForkServer implements a prefork DNS server.
type ForkServer struct {
	// handler to invoke
	Handler Handler

	// Logger specifies a logger
	Logger Logger

	// SetAffinity sets the CPU affinity mask of current process.
	SetAffinity bool

	// The maximum number of concurrent clients the server may serve.
	//
	// DefaultConcurrency is used if not set.
	//
	// Concurrency only works if you either call Serve once, or only ServeConn multiple times.
	// It works with ListenAndServe as well.
	Concurrency int
}

// ListenAndServe serves DNS requests from the given UDP addr.
func (s *ForkServer) ListenAndServe(addr string) error {
	if s.Index() == 0 {
		return s.fork(addr)
	}

	if s.SetAffinity {
		// set cpu affinity for performance
		err := taskset((s.Index() - 1) % runtime.NumCPU())
		if err != nil {
			s.Logger.Printf("forkserver-%d set cpu_affinity=%d failed: %+v", s.Index(), s.Index()-1, err)
		}
	}

	// so_reuseport listen for performance
	conn, err := listen("udp", addr)
	if err != nil {
		s.Logger.Printf("forkserver-%d listen on addr=%s failed: %+v", s.Index(), addr, err)
		return err
	}

	s.Logger.Printf("forkserver-%d pid-%d serving dns on %s", s.Index(), os.Getpid(), conn.LocalAddr())

	return serve(conn, s.Handler, s.Logger, s.Concurrency)
}

// Index indicates the index of Server instances.
func (s *ForkServer) Index() (index int) {
	index, _ = strconv.Atoi(os.Getenv("FASTDNS_CHILD_INDEX"))
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

	maxProcs := runtime.NumCPU()
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

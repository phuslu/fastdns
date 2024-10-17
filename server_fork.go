package fastdns

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
)

// ForkServer implements a prefork DNS server.
type ForkServer struct {
	// handler to invoke
	Handler Handler

	// stats to invoke
	Stats Stats

	// ErrorLog specifies an optional logger for errors accepting
	// connections, unexpected behavior from handlers, and
	// underlying FileSystem errors.
	// If nil, logging is disabled.
	ErrorLog *slog.Logger

	// The maximum number of procs the server may spawn. use runtime.NumCPU() if empty
	MaxProcs int

	// SetAffinity sets the CPU affinity mask of current process.
	SetAffinity bool

	// The maximum number of concurrent clients the server may serve.
	Concurrency int
}

// ListenAndServe serves DNS requests from the given UDP addr.
func (s *ForkServer) ListenAndServe(addr string) error {
	if s.Index() == 0 {
		return s.fork(addr, s.MaxProcs)
	}

	if s.SetAffinity {
		// set cpu affinity for performance
		err := taskset((s.Index() - 1) % runtime.NumCPU())
		if err != nil {
			if s.ErrorLog != nil {
				s.ErrorLog.Error("forkserver set cpu_affinity failed", "error", err, "index", s.Index(), "cpu_affinity", s.Index()-1)
			}
		}
	}

	// so_reuseport listen for performance
	conn, err := listen("udp", addr)
	if err != nil {
		if s.ErrorLog != nil {
			s.ErrorLog.Error("forkserver set listen on addr failed", "error", err, "index", s.Index(), "addr", addr)
		}
		return err
	}

	// s.ErrorLog.Printf("forkserver-%d pid-%d serving dns on %s", s.Index(), os.Getpid(), conn.LocalAddr())

	return serve(conn, s.Handler, s.Stats, s.ErrorLog, s.Concurrency)
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
	cmd.Env = append([]string{"FASTDNS_CHILD_INDEX=" + strconv.Itoa(index)}, os.Environ()...)
	return cmd, cmd.Start()
}

func (s *ForkServer) fork(addr string, maxProcs int) (err error) {
	type racer struct {
		index int
		pid   int
		err   error
	}

	if maxProcs == 0 {
		maxProcs = runtime.NumCPU()
	}
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
			if s.ErrorLog != nil {
				s.ErrorLog.Error("forkserver failed to start a child process", "error", err)
			}
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

		if s.ErrorLog != nil {
			s.ErrorLog.Error("forkserver one of the child processes exited", "error", err)
		}

		if exited++; exited > 200 {
			if s.ErrorLog != nil {
				s.ErrorLog.Error("forkserver child workers exit too many times", "count", exited)
			}
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

//go:build linux

package fastdns

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"unsafe"
)

func listen(network, address string) (*net.UDPConn, error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			return conn.Control(func(fd uintptr) {
				const SO_REUSEPORT = 15
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
		},
	}

	conn, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}

	return conn.(*net.UDPConn), nil
}

func taskset(cpu int) error {
	const SYS_SCHED_SETAFFINITY = 203

	if cpu < 0 {
		return fmt.Errorf("taskset: cpu(%d) must be non-negative", cpu)
	}
	if cpu >= 128*8 {
		return fmt.Errorf("taskset: cpu(%d) exceeds mask capacity", cpu)
	}

	maxCPU := runtime.NumCPU()
	if cpu >= maxCPU {
		return fmt.Errorf("taskset: cpu(%d) >= runtime.NumCPU(%d)", cpu, maxCPU)
	}

	var mask [128]byte
	mask[cpu/8] = byte(1 << (uint(cpu) % 8))

	_, _, e := syscall.RawSyscall(SYS_SCHED_SETAFFINITY, uintptr(0), uintptr(128), uintptr(unsafe.Pointer(&mask[0])))
	if e == 0 {
		return nil
	}
	if e == syscall.EPERM || e == syscall.EINVAL {
		// Sandboxes without sched_setaffinity permission surface EPERM/EINVAL; treat as best-effort.
		return nil
	}

	return e
}

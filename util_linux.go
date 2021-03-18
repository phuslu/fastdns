// +build linux

package fastdns

import (
	"context"
	"net"
	"syscall"
	"unsafe"
)

func ListenUDP(network, address string) (*net.UDPConn, error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			return conn.Control(func(fd uintptr) {
				const SO_REUSEPORT = 15
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
			})
		},
	}

	conn, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}

	return conn.(*net.UDPConn), nil
}

func Taskset(cpu int) error {
	const SYS_SCHED_SETAFFINITY = 203

	mask := make([]byte, 128)
	mask[cpu/8] = 1 << (cpu % 8)

	_, _, e := syscall.RawSyscall(SYS_SCHED_SETAFFINITY, uintptr(0), uintptr(len(mask)), uintptr(unsafe.Pointer(&mask[0])))
	if e == 0 {
		return nil
	}

	return e
}

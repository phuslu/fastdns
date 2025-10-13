//go:build !linux

package fastdns

import (
	"errors"
	"net"
)

// listen resolves the UDP address and binds a socket on non-Linux systems.
func listen(network, address string) (*net.UDPConn, error) {
	laddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}

	return net.ListenUDP(network, laddr)
}

// taskset reports that CPU affinity control is unavailable on this platform.
func taskset(cpu int) error {
	return errors.New("not implemented")
}

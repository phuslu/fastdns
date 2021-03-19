// +build !linux

package fastdns

import (
	"errors"
	"net"
)

func listen(network, address string) (*net.UDPConn, error) {
	laddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}

	return net.ListenUDP(network, laddr)
}

func taskset(cpu int) error {
	return errors.New("not implemented")
}

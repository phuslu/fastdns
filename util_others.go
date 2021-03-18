// +build !linux

package fastdns

import (
	"errors"
	"net"
)

func ListenUDP(network, address string) (*net.UDPConn, error) {
	laddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}

	return net.ListenUDP(network, laddr)
}

func Taskset(cpu int) error {
	return errors.New("not implemented")
}

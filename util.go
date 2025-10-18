package fastdns

import (
	"unsafe"
)

// b2s converts a byte slice to a string without allocation.
// nolint
func b2s(b []byte) string { return *(*string)(unsafe.Pointer(&b)) }

// cheaprandn returns a pseudorandom uint32 in [0, x).
//
//go:noescape
//go:linkname cheaprandn runtime.cheaprandn
func cheaprandn(x uint32) uint32

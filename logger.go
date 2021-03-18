package fastdns

// Logger is used for logging formatted messages.
type Logger interface {
	// Printf must have the same semantics as log.Printf.
	Printf(format string, args ...interface{})
}

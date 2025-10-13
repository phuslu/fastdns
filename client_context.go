package fastdns

import (
	"context"
	"net/netip"
)

type clientContextKey struct {
	name string
}

// String returns the namespaced identifier for the client context key.
func (key *clientContextKey) String() string {
	return "fastdns-" + key.name
}

var (
	ClientSubnetContextKey  any = &clientContextKey{"client-subnet-context-key"}
	ClientCookieContextKey  any = &clientContextKey{"client-cookie-context-key"}
	ClientPaddingContextKey any = &clientContextKey{"client-padding-context-key"}
)

// WithClientSubnet returns a context carrying the client subnet prefix.
func WithClientSubnet(ctx context.Context, prefix netip.Prefix) context.Context {
	return context.WithValue(ctx, ClientSubnetContextKey, prefix)
}

// WithClientCookie returns a context carrying the client cookie value.
func WithClientCookie(ctx context.Context, cookie string) context.Context {
	return context.WithValue(ctx, ClientCookieContextKey, cookie)
}

// WithClientPadding returns a context carrying the padded EDNS option.
func WithClientPadding(ctx context.Context, padding string) context.Context {
	return context.WithValue(ctx, ClientPaddingContextKey, padding)
}

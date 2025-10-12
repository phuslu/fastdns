package fastdns

import (
	"context"
	"net/netip"
)

type clientContextKey struct {
	name string
}

func (key *clientContextKey) String() string {
	return "fastdns-" + key.name
}

var (
	ClientSubnetContextKey  any = &clientContextKey{"client-subnet-context-key"}
	ClientCookieContextKey  any = &clientContextKey{"client-cookie-context-key"}
	ClientPaddingContextKey any = &clientContextKey{"client-padding-context-key"}
)

// WithClientSubnet stores the client subnet prefix in ctx.
func WithClientSubnet(ctx context.Context, prefix netip.Prefix) context.Context {
	return context.WithValue(ctx, ClientSubnetContextKey, prefix)
}

// WithClientCookie stores the client cookie in ctx.
func WithClientCookie(ctx context.Context, cookie string) context.Context {
	return context.WithValue(ctx, ClientCookieContextKey, cookie)
}

// WithClientPadding stores the client padding in ctx.
func WithClientPadding(ctx context.Context, padding string) context.Context {
	return context.WithValue(ctx, ClientPaddingContextKey, padding)
}

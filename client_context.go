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
	return "fastdns-" + key.name + "-context-key"
}

var clientOptionsContextKey any = &clientContextKey{"client-options"}

type clientOptionsContextValue struct {
	prefix  netip.Prefix
	cookie  string
	padding uint16
}

func withClientOptions(ctx context.Context) (clientOptionsContextValue, bool) {
	if v, ok := ctx.Value(clientOptionsContextKey).(*clientOptionsContextValue); ok {
		return *v, true // copy-on-write
	}
	return clientOptionsContextValue{}, false
}

// WithClientSubnet returns a context carrying the client subnet prefix.
func WithClientSubnet(ctx context.Context, prefix netip.Prefix) context.Context {
	v, ok := withClientOptions(ctx)
	if ok && v.prefix == prefix {
		return ctx
	}
	v.prefix = prefix
	return context.WithValue(ctx, clientOptionsContextKey, &v)
}

// WithClientCookie returns a context carrying the client cookie value.
func WithClientCookie(ctx context.Context, cookie string) context.Context {
	v, ok := withClientOptions(ctx)
	if ok && v.cookie == cookie {
		return ctx
	}
	v.cookie = cookie
	return context.WithValue(ctx, clientOptionsContextKey, &v)
}

// WithClientPadding returns a context carrying the padded EDNS option.
func WithClientPadding(ctx context.Context, padding uint16) context.Context {
	v, ok := withClientOptions(ctx)
	if ok && v.padding == padding {
		return ctx
	}
	v.padding = padding
	return context.WithValue(ctx, clientOptionsContextKey, &v)
}

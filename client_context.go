package fastdns

type clientContextKey struct {
	name string
}

var (
	ClientSubnetContextKey  any = &clientContextKey{"client-subnet-context-key"}
	ClientCookieContextKey  any = &clientContextKey{"client-cookie-context-key"}
	ClientPaddingContextKey any = &clientContextKey{"client-padding-context-key"}
)

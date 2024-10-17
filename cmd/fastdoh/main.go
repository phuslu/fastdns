package main

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/valyala/fasthttp"
)

type DNSHandler struct {
	DNSClient *fastdns.Client
	Debug     bool
}

// ServeDNS implements fastdns.Handler
func (h *DNSHandler) ServeDNS(rw fastdns.ResponseWriter, req *fastdns.Message) {
	if h.Debug {
		slog.Info("serve dns request", "remote_addr", rw.RemoteAddr(), "domain", req.Domain, "class", req.Question.Class, "type", req.Question.Type)
	}

	resp := fastdns.AcquireMessage()
	defer fastdns.ReleaseMessage(resp)

	ctx := context.Background()

	err := h.DNSClient.Exchange(ctx, req, resp)
	if err == fastdns.ErrMaxConns {
		time.Sleep(10 * time.Millisecond)
		err = h.DNSClient.Exchange(ctx, req, resp)
	}
	if err != nil {
		fastdns.Error(rw, req, fastdns.RcodeServFail)
	}

	if h.Debug {
		_ = resp.Walk(func(name []byte, typ fastdns.Type, class fastdns.Class, ttl uint32, data []byte) bool {
			switch typ {
			case fastdns.TypeCNAME:
				slog.Info("dns request CNAME", "name", resp.DecodeName(nil, name), "ttl", ttl, "class", class, "type", typ, "CNAME", resp.DecodeName(nil, data))
			case fastdns.TypeA:
				slog.Info("dns request A", "name", resp.DecodeName(nil, name), "ttl", ttl, "class", class, "type", typ, "A", netip.AddrFrom4(*(*[4]byte)(data)))
			case fastdns.TypeAAAA:
				slog.Info("dns request AAAA", "name", resp.DecodeName(nil, name), "ttl", ttl, "class", class, "type", typ, "AAAA", netip.AddrFrom16(*(*[16]byte)(data)))
			}
			return true
		})
		slog.Info("serve dns answers", "remote_addr", rw.RemoteAddr(), "domain", req.Domain, "remote_addr", h.DNSClient.AddrPort, "answer_count", resp.Header.ANCount)
	}

	_, _ = rw.Write(resp.Raw)
}

func main() {
	addr := os.Args[1]

	handler := (&DoHHandler{
		DNSQuery: "/dns-query",
		DNSHandler: &DNSHandler{
			DNSClient: &fastdns.Client{
				AddrPort: netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53),
				MaxConns: 8192,
			},
			Debug: os.Getenv("DEBUG") != "",
		},
		DoHStats: &fastdns.CoreStats{
			Prefix: "coredns_",
			Family: "1",
			Proto:  "http",
			Server: "doh://" + addr,
			Zone:   ".",
		},
	}).Handler

	slog.Info("start fast DoH server", "addr", addr)
	err := fasthttp.ListenAndServe(addr, handler)
	if err != nil {
		slog.Error("listen and serve DNS/DoH failed", "error", err)
		os.Exit(-1)
	}
}

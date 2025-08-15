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
	if err != nil {
		slog.Error("serve exchange dns request error", "error", err, "remote_addr", rw.RemoteAddr(), "domain", req.Domain, "class", req.Question.Class, "type", req.Question.Type)
		fastdns.Error(rw, req, fastdns.RcodeServFail)
	}

	if h.Debug {
		records := resp.Records()
		for records.Next() {
			r := records.Item()
			switch r.Type {
			case fastdns.TypeCNAME:
				slog.Info("dns request CNAME", "name", resp.DecodeName(nil, r.Name), "ttl", r.TTL, "class", r.Class, "type", r.Type, "CNAME", resp.DecodeName(nil, r.Data))
			case fastdns.TypeA:
				slog.Info("dns request A", "name", resp.DecodeName(nil, r.Name), "ttl", r.TTL, "class", r.Class, "type", r.Type, "A", netip.AddrFrom4(*(*[4]byte)(r.Data)))
			case fastdns.TypeAAAA:
				slog.Info("dns request AAAA", "name", resp.DecodeName(nil, r.Name), "ttl", r.TTL, "class", r.Class, "type", r.Type, "AAAA", netip.AddrFrom16(*(*[16]byte)(r.Data)))
			}
		}
		slog.Info("serve dns answers", "remote_addr", rw.RemoteAddr(), "domain", req.Domain, "remote_addr", h.DNSClient.Addr, "answer_count", resp.Header.ANCount)
	}

	_, _ = rw.Write(resp.Raw)
}

func main() {
	addr := os.Args[1]

	handler := (&DoHHandler{
		DNSQuery: "/dns-query",
		DNSHandler: &DNSHandler{
			DNSClient: &fastdns.Client{
				Addr:    "1.1.1.1:53",
				Timeout: 3 * time.Second,
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

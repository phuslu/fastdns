package fastdns

import (
	"encoding/hex"
	"net/netip"
	"testing"
	"time"
)

func BenchmarkUpdateStats(b *testing.B) {
	payload, _ := hex.DecodeString("8e5281800001000200000000047632657803636f6d0000020001c00c000200010000545f0014036b696d026e730a636c6f7564666c617265c011c00c000200010000545f000704746f6464c02a")

	resp := AcquireMessage()
	defer ReleaseMessage(resp)

	err := ParseMessage(resp, payload, true)
	if err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	stats := &CoreStats{
		Prefix: "coredns_",
		Family: "1",
		Proto:  "udp",
		Server: "dns://:53",
		Zone:   ".",
	}

	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 12345)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats.UpdateStats(addr, resp, time.Millisecond)
	}
}

func BenchmarkAppendOpenMetrics(b *testing.B) {
	payload, _ := hex.DecodeString("8e5281800001000200000000047632657803636f6d0000020001c00c000200010000545f0014036b696d026e730a636c6f7564666c617265c011c00c000200010000545f000704746f6464c02a")

	resp := AcquireMessage()
	defer ReleaseMessage(resp)

	err := ParseMessage(resp, payload, true)
	if err != nil {
		b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	stats := &CoreStats{
		Prefix: "coredns_",
		Family: "1",
		Proto:  "udp",
		Server: "dns://:53",
		Zone:   ".",
	}

	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 12345)

	stats.UpdateStats(addr, resp, time.Millisecond)

	buf := make([]byte, 0, 32*1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats.AppendOpenMetrics(buf[:0])
	}
}

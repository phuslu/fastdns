package fastdns

import (
	"net/netip"
	"testing"
	"time"
)

// BenchmarkServerUpdateStats measures the bookkeeping for incoming requests.
func BenchmarkServerUpdateStats(b *testing.B) {
	payload := []byte{
		0x8e, 0x52, // Transaction ID
		0x81, 0x80, // Flags: standard response
		0x00, 0x01, // Questions
		0x00, 0x02, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x04, 'p', 'h', 'u', 's',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x02, // QTYPE NS
		0x00, 0x01, // QCLASS IN
		0xc0, 0x0c, // NAME pointer to question
		0x00, 0x02, // TYPE NS
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x54, 0x5f, // TTL 0x545f
		0x00, 0x14, // RDLENGTH 20
		0x03, 's', 'u', 'e',
		0x02, 'n', 's',
		0x0a, 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e',
		0xc0, 0x11, // pointer to label "com"
		0xc0, 0x0c, // NAME pointer to question
		0x00, 0x02, // TYPE NS
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x54, 0x5f, // TTL 0x545f
		0x00, 0x07, // RDLENGTH 7
		0x04, 'j', 'a', 'k', 'e',
		0xc0, 0x2a, // pointer to "ns.cloudflare.com"
	}

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

// BenchmarkServerAppendOpenMetrics measures metrics rendering throughput.
func BenchmarkServerAppendOpenMetrics(b *testing.B) {
	payload := []byte{
		0x8e, 0x52, // Transaction ID
		0x81, 0x80, // Flags: standard response
		0x00, 0x01, // Questions
		0x00, 0x02, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x04, 'p', 'h', 'u', 's',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x02, // QTYPE NS
		0x00, 0x01, // QCLASS IN
		0xc0, 0x0c, // NAME pointer to question
		0x00, 0x02, // TYPE NS
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x54, 0x5f, // TTL 0x545f
		0x00, 0x14, // RDLENGTH 20
		0x03, 's', 'u', 'e',
		0x02, 'n', 's',
		0x0a, 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e',
		0xc0, 0x11, // pointer to label "com"
		0xc0, 0x0c, // NAME pointer to question
		0x00, 0x02, // TYPE NS
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x54, 0x5f, // TTL 0x545f
		0x00, 0x07, // RDLENGTH 7
		0x04, 'j', 'a', 'k', 'e',
		0xc0, 0x2a, // pointer to "ns.cloudflare.com"
	}

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

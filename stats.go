package fastdns

import (
	"net"
	"sync/atomic"
	"time"
)

type Stats interface {
	UpdateStats(raddr net.Addr, domain string, qtype Type, duration time.Duration)
	OpenMetrics() (metrics string)
}

type CoreStats struct {
	Family, Proto, Server, Zone string

	RequstCountTotal                     uint64
	RequestDurationSecondsBucket_0_00025 uint64
	RequestDurationSecondsBucket_0_0005  uint64
	RequestDurationSecondsBucket_0_001   uint64
	RequestDurationSecondsBucket_0_002   uint64
	RequestDurationSecondsBucket_0_004   uint64
	RequestDurationSecondsBucket_0_008   uint64
	RequestDurationSecondsBucket_0_016   uint64
	RequestDurationSecondsBucket_0_032   uint64
	RequestDurationSecondsBucket_0_064   uint64
	RequestDurationSecondsBucket_0_128   uint64
	RequestDurationSecondsBucket_0_256   uint64
	RequestDurationSecondsBucket_0_512   uint64
	RequestDurationSecondsBucket_1_024   uint64
	RequestDurationSecondsBucket_2_048   uint64
	RequestDurationSecondsBucket_4_096   uint64
	RequestDurationSecondsBucket_8_192   uint64
	RequestDurationSecondsBucket_Inf     uint64
}

func (s *CoreStats) UpdateStats(raddr net.Addr, domain string, qtype Type, duration time.Duration) {
	atomic.AddUint64(&s.RequstCountTotal, 1)
	switch {
	case duration < 250*time.Microsecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_00025, 1)
	case duration < 500*time.Microsecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_0005, 1)
	case duration < 1*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_001, 1)
	case duration < 2*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_002, 1)
	case duration < 4*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_004, 1)
	case duration < 8*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_008, 1)
	case duration < 16*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_016, 1)
	case duration < 32*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_032, 1)
	case duration < 64*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_064, 1)
	case duration < 128*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_128, 1)
	case duration < 256*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_256, 1)
	case duration < 512*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_512, 1)
	case duration < 1024*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_1_024, 1)
	case duration < 2048*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_2_048, 1)
	case duration < 4096*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_4_096, 1)
	case duration < 8192*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_8_192, 1)
	default:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_Inf, 1)
	}
}

func (s *CoreStats) OpenMetrics() string {
	return string(template(nil, `
coredns_dns_request_count_total{family="{family}",proto="{proto}",server="{server}",zone="{zone}"} {request_count_total}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.00025"} {request_duration_seconds_bucket_0_00025}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.0005"} {request_duration_seconds_bucket_0_0005}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.001"} {request_duration_seconds_bucket_0_001}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.002"} {request_duration_seconds_bucket_0_002}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.004"} {request_duration_seconds_bucket_0_004}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.008"} {request_duration_seconds_bucket_0_008}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.016"} {request_duration_seconds_bucket_0_016}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.032"} {request_duration_seconds_bucket_0_032}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.064"} {request_duration_seconds_bucket_0_064}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.128"} {request_duration_seconds_bucket_0_128}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.256"} {request_duration_seconds_bucket_0_256}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.512"} {request_duration_seconds_bucket_0_512}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="1.024"} {request_duration_seconds_bucket_1_024}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="2.048"} {request_duration_seconds_bucket_2_048}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="4.096"} {request_duration_seconds_bucket_4_096}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="8.192"} {request_duration_seconds_bucket_8_192}
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="+Inf"} {request_duration_seconds_bucket_Inf}
`, '{', '}', map[string]interface{}{
		"family":              s.Family,
		"proto":               s.Proto,
		"server":              s.Server,
		"zone":                s.Zone,
		"request_count_total": atomic.LoadUint64(&s.RequstCountTotal),
		"request_duration_seconds_bucket_0_00025": atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_00025),
		"request_duration_seconds_bucket_0_0005":  atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_0005),
		"request_duration_seconds_bucket_0_001":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_001),
		"request_duration_seconds_bucket_0_002":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_002),
		"request_duration_seconds_bucket_0_004":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_004),
		"request_duration_seconds_bucket_0_008":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_008),
		"request_duration_seconds_bucket_0_016":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_016),
		"request_duration_seconds_bucket_0_032":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_032),
		"request_duration_seconds_bucket_0_064":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_064),
		"request_duration_seconds_bucket_0_128":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_128),
		"request_duration_seconds_bucket_0_256":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_256),
		"request_duration_seconds_bucket_0_512":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_512),
		"request_duration_seconds_bucket_1_024":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_1_024),
		"request_duration_seconds_bucket_2_048":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_2_048),
		"request_duration_seconds_bucket_4_096":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_4_096),
		"request_duration_seconds_bucket_8_192":   atomic.LoadUint64(&s.RequestDurationSecondsBucket_8_192),
		"request_duration_seconds_bucket_Inf":     atomic.LoadUint64(&s.RequestDurationSecondsBucket_Inf),
	}, false))
}

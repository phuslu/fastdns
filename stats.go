package fastdns

import (
	"net"
	"sync/atomic"
	"time"
)

type Stats interface {
	UpdateStats(addr net.Addr, msg *Message, duration time.Duration)
	OpenMetrics() (metrics string)
}

type CoreStats struct {
	RequstCountTotal uint64

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
	RequestDurationSecondsSum            uint64
	RequestDurationSecondsCount          uint64

	RequestSizeBytesBucket_0     uint64
	RequestSizeBytesBucket_100   uint64
	RequestSizeBytesBucket_200   uint64
	RequestSizeBytesBucket_300   uint64
	RequestSizeBytesBucket_400   uint64
	RequestSizeBytesBucket_511   uint64
	RequestSizeBytesBucket_1023  uint64
	RequestSizeBytesBucket_2047  uint64
	RequestSizeBytesBucket_4095  uint64
	RequestSizeBytesBucket_8291  uint64
	RequestSizeBytesBucket_16000 uint64
	RequestSizeBytesBucket_32000 uint64
	RequestSizeBytesBucket_48000 uint64
	RequestSizeBytesBucket_64000 uint64
	RequestSizeBytesBucket_Inf   uint64
	RequestSizeBytesSum          uint64
	RequestSizeBytesCount        uint64

	RequestTypeCountTotal_A     uint64
	RequestTypeCountTotal_AAAA  uint64
	RequestTypeCountTotal_NS    uint64
	RequestTypeCountTotal_PTR   uint64
	RequestTypeCountTotal_SRV   uint64
	RequestTypeCountTotal_CNAME uint64
	RequestTypeCountTotal_SOA   uint64
	RequestTypeCountTotal_MX    uint64
	RequestTypeCountTotal_TXT   uint64

	ResponseRcodeCountTotal_NOERROR  uint64
	ResponseRcodeCountTotal_FORMERR  uint64
	ResponseRcodeCountTotal_SERVFAIL uint64
	ResponseRcodeCountTotal_NOTIMP   uint64
	ResponseRcodeCountTotal_NXDOMAIN uint64
	ResponseRcodeCountTotal_REFUSED  uint64
	ResponseRcodeCountTotal_YXDOMAIN uint64
	ResponseRcodeCountTotal_XRRSET   uint64
	ResponseRcodeCountTotal_NOTAUTH  uint64
	ResponseRcodeCountTotal_NOTZONE  uint64

	ResponseSizeBytesBucket_0     uint64
	ResponseSizeBytesBucket_100   uint64
	ResponseSizeBytesBucket_200   uint64
	ResponseSizeBytesBucket_300   uint64
	ResponseSizeBytesBucket_400   uint64
	ResponseSizeBytesBucket_511   uint64
	ResponseSizeBytesBucket_1023  uint64
	ResponseSizeBytesBucket_2047  uint64
	ResponseSizeBytesBucket_4095  uint64
	ResponseSizeBytesBucket_8291  uint64
	ResponseSizeBytesBucket_16000 uint64
	ResponseSizeBytesBucket_32000 uint64
	ResponseSizeBytesBucket_48000 uint64
	ResponseSizeBytesBucket_64000 uint64
	ResponseSizeBytesBucket_Inf   uint64
	ResponseSizeBytesSum          uint64
	ResponseSizeBytesCount        uint64

	Family, Proto, Server, Zone string
}

func (s *CoreStats) UpdateStats(addr net.Addr, msg *Message, duration time.Duration) {
	atomic.AddUint64(&s.RequstCountTotal, 1)
	// request seconds
	switch {
	case duration <= 250*time.Microsecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_00025, 1)
	case duration <= 500*time.Microsecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_0005, 1)
	case duration <= 1*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_001, 1)
	case duration <= 2*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_002, 1)
	case duration <= 4*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_004, 1)
	case duration <= 8*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_008, 1)
	case duration <= 16*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_016, 1)
	case duration <= 32*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_032, 1)
	case duration <= 64*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_064, 1)
	case duration <= 128*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_128, 1)
	case duration <= 256*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_256, 1)
	case duration <= 512*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_0_512, 1)
	case duration <= 1024*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_1_024, 1)
	case duration <= 2048*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_2_048, 1)
	case duration <= 4096*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_4_096, 1)
	case duration <= 8192*time.Millisecond:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_8_192, 1)
	default:
		atomic.AddUint64(&s.RequestDurationSecondsBucket_Inf, 1)
	}
	atomic.AddUint64(&s.RequestDurationSecondsSum, uint64(duration))
	atomic.AddUint64(&s.RequestDurationSecondsCount, 1)

	// request size
	size := 12 + len(msg.Question.Name) + 4
	switch {
	case size == 0:
		atomic.AddUint64(&s.RequestSizeBytesBucket_0, 1)
	case size <= 100:
		atomic.AddUint64(&s.RequestSizeBytesBucket_100, 1)
	case size <= 200:
		atomic.AddUint64(&s.RequestSizeBytesBucket_200, 1)
	case size <= 300:
		atomic.AddUint64(&s.RequestSizeBytesBucket_300, 1)
	case size <= 400:
		atomic.AddUint64(&s.RequestSizeBytesBucket_400, 1)
	case size <= 511:
		atomic.AddUint64(&s.RequestSizeBytesBucket_511, 1)
	case size <= 1023:
		atomic.AddUint64(&s.RequestSizeBytesBucket_1023, 1)
	case size <= 2047:
		atomic.AddUint64(&s.RequestSizeBytesBucket_2047, 1)
	case size <= 4095:
		atomic.AddUint64(&s.RequestSizeBytesBucket_4095, 1)
	case size <= 8291:
		atomic.AddUint64(&s.RequestSizeBytesBucket_8291, 1)
	case size <= 16000:
		atomic.AddUint64(&s.RequestSizeBytesBucket_16000, 1)
	case size <= 32000:
		atomic.AddUint64(&s.RequestSizeBytesBucket_32000, 1)
	case size <= 48000:
		atomic.AddUint64(&s.RequestSizeBytesBucket_48000, 1)
	case size <= 64000:
		atomic.AddUint64(&s.RequestSizeBytesBucket_64000, 1)
	default:
		atomic.AddUint64(&s.RequestSizeBytesBucket_Inf, 1)
	}
	atomic.AddUint64(&s.RequestSizeBytesSum, uint64(size))
	atomic.AddUint64(&s.RequestSizeBytesCount, 1)

	// request type
	switch msg.Question.Type {
	case TypeA:
		atomic.AddUint64(&s.RequestTypeCountTotal_A, 1)
	case TypeAAAA:
		atomic.AddUint64(&s.RequestTypeCountTotal_AAAA, 1)
	case TypeCNAME:
		atomic.AddUint64(&s.RequestTypeCountTotal_CNAME, 1)
	case TypeNS:
		atomic.AddUint64(&s.RequestTypeCountTotal_NS, 1)
	case TypeSOA:
		atomic.AddUint64(&s.RequestTypeCountTotal_SOA, 1)
	case TypeMX:
		atomic.AddUint64(&s.RequestTypeCountTotal_MX, 1)
	case TypeTXT:
		atomic.AddUint64(&s.RequestTypeCountTotal_TXT, 1)
	case TypePTR:
		atomic.AddUint64(&s.RequestTypeCountTotal_PTR, 1)
	case TypeSRV:
		atomic.AddUint64(&s.RequestTypeCountTotal_SRV, 1)
	}

	// response rcode
	switch msg.Header.Bits.Rcode() {
	case RcodeSuccess:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_NOERROR, 1)
	case RcodeFormatError:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_FORMERR, 1)
	case RcodeServerFailure:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_SERVFAIL, 1)
	case RcodeNameError:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_NOTIMP, 1)
	case RcodeNotImplemented:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_NXDOMAIN, 1)
	case RcodeRefused:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_REFUSED, 1)
	case RcodeYXDomain:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_YXDOMAIN, 1)
	case RcodeNXRrset:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_XRRSET, 1)
	case RcodeNotAuth:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_NOTAUTH, 1)
	case RcodeNotZone:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_NOTZONE, 1)
	}

	// response size
	size = len(msg.Raw)
	switch {
	case size == 0:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_0, 1)
	case size <= 100:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_100, 1)
	case size <= 200:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_200, 1)
	case size <= 300:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_300, 1)
	case size <= 400:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_400, 1)
	case size <= 511:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_511, 1)
	case size <= 1023:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_1023, 1)
	case size <= 2047:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_2047, 1)
	case size <= 4095:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_4095, 1)
	case size <= 8291:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_8291, 1)
	case size <= 16000:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_16000, 1)
	case size <= 32000:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_32000, 1)
	case size <= 48000:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_48000, 1)
	case size <= 64000:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_64000, 1)
	default:
		atomic.AddUint64(&s.ResponseSizeBytesBucket_Inf, 1)
	}
	atomic.AddUint64(&s.ResponseSizeBytesSum, uint64(size))
	atomic.AddUint64(&s.ResponseSizeBytesCount, 1)
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
coredns_dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="+Inf"} {request_duration_seconds_bucket_inf}
coredns_dns_request_duration_seconds_sum{server="{server}",zone="{zone}"} {request_duration_seconds_sum}
coredns_dns_request_duration_seconds_count{server="{server}",zone="{zone}"} {request_duration_seconds_count}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="0"} {request_size_bytes_bucket_0}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="100"} {request_size_bytes_bucket_100}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="200"} {request_size_bytes_bucket_200}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="300"} {request_size_bytes_bucket_300}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="400"} {request_size_bytes_bucket_400}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="511"} {request_size_bytes_bucket_511}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="1023"} {request_size_bytes_bucket_1023}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="2047"} {request_size_bytes_bucket_2047}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="4095"} {request_size_bytes_bucket_4095}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="8291"} {request_size_bytes_bucket_8291}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="16000"} {request_size_bytes_bucket_16000}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="32000"} {request_size_bytes_bucket_32000}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="48000"} {request_size_bytes_bucket_48000}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="64000"} {request_size_bytes_bucket_64000}
coredns_dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="+Inf"} {request_size_bytes_bucket_inf}
coredns_dns_request_size_bytes_sum{proto="{proto}",server="{server}",zone="{zone}"} {request_size_bytes_sum}
coredns_dns_request_size_bytes_count{proto="{proto}",server="{server}",zone="{zone}"} {request_size_bytes_count}
coredns_dns_request_type_count_total{server="{server}",type="A",zone="{zone}"} {request_type_count_total_a}
coredns_dns_request_type_count_total{server="{server}",type="AAAA",zone="{zone}"} {request_type_count_total_aaaa}
coredns_dns_request_type_count_total{server="{server}",type="NS",zone="{zone}"} {request_type_count_total_ns}
coredns_dns_request_type_count_total{server="{server}",type="PTR",zone="{zone}"} {request_type_count_total_ptr}
coredns_dns_request_type_count_total{server="{server}",type="SRV",zone="{zone}"} {request_type_count_total_srv}
coredns_dns_request_type_count_total{server="{server}",type="CNAME",zone="{zone}"} {request_type_count_total_cname}
coredns_dns_request_type_count_total{server="{server}",type="SOA",zone="{zone}"} {request_type_count_total_soa}
coredns_dns_request_type_count_total{server="{server}",type="MX",zone="{zone}"} {request_type_count_total_mx}
coredns_dns_request_type_count_total{server="{server}",type="TXT",zone="{zone}"} {request_type_count_total_txt}
coredns_dns_response_rcode_count_total{rcode="NOERROR",server="{server}",zone="{zone}"} {response_rcode_count_total_noerror}
coredns_dns_response_rcode_count_total{rcode="FORMERR",server="{server}",zone="{zone}"} {response_rcode_count_total_formerr}
coredns_dns_response_rcode_count_total{rcode="SERVFAIL",server="{server}",zone="{zone}"} {response_rcode_count_total_servfail}
coredns_dns_response_rcode_count_total{rcode="NXDOMAIN",server="{server}",zone="{zone}"} {response_rcode_count_total_nxdomain}
coredns_dns_response_rcode_count_total{rcode="NOTIMP",server="{server}",zone="{zone}"} {response_rcode_count_total_notimp}
coredns_dns_response_rcode_count_total{rcode="REFUSED",server="{server}",zone="{zone}"} {response_rcode_count_total_refused}
coredns_dns_response_rcode_count_total{rcode="YXDOMAIN",server="{server}",zone="{zone}"} {response_rcode_count_total_yxdomain}
coredns_dns_response_rcode_count_total{rcode="XRRSET",server="{server}",zone="{zone}"} {response_rcode_count_total_xrrset}
coredns_dns_response_rcode_count_total{rcode="NOTAUTH",server="{server}",zone="{zone}"} {response_rcode_count_total_notauth}
coredns_dns_response_rcode_count_total{rcode="NOTZONE",server="{server}",zone="{zone}"} {response_rcode_count_total_notzone}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="0"} {response_size_bytes_bucket_0}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="100"} {response_size_bytes_bucket_100}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="200"} {response_size_bytes_bucket_200}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="300"} {response_size_bytes_bucket_300}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="400"} {response_size_bytes_bucket_400}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="511"} {response_size_bytes_bucket_511}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="1023"} {response_size_bytes_bucket_1023}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="2047"} {response_size_bytes_bucket_2047}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="4095"} {response_size_bytes_bucket_4095}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="8291"} {response_size_bytes_bucket_8291}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="16000"} {response_size_bytes_bucket_16000}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="32000"} {response_size_bytes_bucket_32000}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="48000"} {response_size_bytes_bucket_48000}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="64000"} {response_size_bytes_bucket_64000}
coredns_dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="+Inf"} {response_size_bytes_bucket_inf}
coredns_dns_response_size_bytes_sum{proto="{proto}",server="{server}",zone="{zone}"} {response_size_bytes_sum}
coredns_dns_response_size_bytes_count{proto="{proto}",server="{server}",zone="{zone}"} {response_size_bytes_count}
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
		"request_duration_seconds_bucket_inf":     atomic.LoadUint64(&s.RequestDurationSecondsBucket_Inf),
		"request_duration_seconds_sum":            float64(atomic.LoadUint64(&s.RequestDurationSecondsSum)) / float64(time.Second),
		"request_duration_seconds_count":          atomic.LoadUint64(&s.RequestDurationSecondsCount),
		"request_size_bytes_bucket_0":             atomic.LoadUint64(&s.RequestSizeBytesBucket_0),
		"request_size_bytes_bucket_100":           atomic.LoadUint64(&s.RequestSizeBytesBucket_100),
		"request_size_bytes_bucket_200":           atomic.LoadUint64(&s.RequestSizeBytesBucket_200),
		"request_size_bytes_bucket_300":           atomic.LoadUint64(&s.RequestSizeBytesBucket_300),
		"request_size_bytes_bucket_400":           atomic.LoadUint64(&s.RequestSizeBytesBucket_400),
		"request_size_bytes_bucket_511":           atomic.LoadUint64(&s.RequestSizeBytesBucket_511),
		"request_size_bytes_bucket_1023":          atomic.LoadUint64(&s.RequestSizeBytesBucket_1023),
		"request_size_bytes_bucket_2047":          atomic.LoadUint64(&s.RequestSizeBytesBucket_2047),
		"request_size_bytes_bucket_4095":          atomic.LoadUint64(&s.RequestSizeBytesBucket_4095),
		"request_size_bytes_bucket_8291":          atomic.LoadUint64(&s.RequestSizeBytesBucket_8291),
		"request_size_bytes_bucket_16000":         atomic.LoadUint64(&s.RequestSizeBytesBucket_16000),
		"request_size_bytes_bucket_32000":         atomic.LoadUint64(&s.RequestSizeBytesBucket_32000),
		"request_size_bytes_bucket_48000":         atomic.LoadUint64(&s.RequestSizeBytesBucket_48000),
		"request_size_bytes_bucket_64000":         atomic.LoadUint64(&s.RequestSizeBytesBucket_64000),
		"request_size_bytes_bucket_inf":           atomic.LoadUint64(&s.RequestSizeBytesBucket_Inf),
		"request_size_bytes_sum":                  atomic.LoadUint64(&s.RequestSizeBytesSum),
		"request_size_bytes_count":                atomic.LoadUint64(&s.RequestSizeBytesCount),
		"request_type_count_total_a":              atomic.LoadUint64(&s.RequestTypeCountTotal_A),
		"request_type_count_total_aaaa":           atomic.LoadUint64(&s.RequestTypeCountTotal_AAAA),
		"request_type_count_total_ns":             atomic.LoadUint64(&s.RequestTypeCountTotal_NS),
		"request_type_count_total_ptr":            atomic.LoadUint64(&s.RequestTypeCountTotal_PTR),
		"request_type_count_total_srv":            atomic.LoadUint64(&s.RequestTypeCountTotal_SRV),
		"request_type_count_total_cname":          atomic.LoadUint64(&s.RequestTypeCountTotal_CNAME),
		"request_type_count_total_soa":            atomic.LoadUint64(&s.RequestTypeCountTotal_SOA),
		"request_type_count_total_mx":             atomic.LoadUint64(&s.RequestTypeCountTotal_MX),
		"request_type_count_total_txt":            atomic.LoadUint64(&s.RequestTypeCountTotal_TXT),
		"response_rcode_count_total_noerror":      atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOERROR),
		"response_rcode_count_total_formerr":      atomic.LoadUint64(&s.ResponseRcodeCountTotal_FORMERR),
		"response_rcode_count_total_servfail":     atomic.LoadUint64(&s.ResponseRcodeCountTotal_SERVFAIL),
		"response_rcode_count_total_nxdomain":     atomic.LoadUint64(&s.ResponseRcodeCountTotal_NXDOMAIN),
		"response_rcode_count_total_notimp":       atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOTIMP),
		"response_rcode_count_total_refused":      atomic.LoadUint64(&s.ResponseRcodeCountTotal_REFUSED),
		"response_rcode_count_total_yxdomain":     atomic.LoadUint64(&s.ResponseRcodeCountTotal_YXDOMAIN),
		"response_rcode_count_total_xrrset":       atomic.LoadUint64(&s.ResponseRcodeCountTotal_XRRSET),
		"response_rcode_count_total_notauth":      atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOTAUTH),
		"response_rcode_count_total_notzone":      atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOTZONE),
		"response_size_bytes_bucket_0":            atomic.LoadUint64(&s.ResponseSizeBytesBucket_0),
		"response_size_bytes_bucket_100":          atomic.LoadUint64(&s.ResponseSizeBytesBucket_100),
		"response_size_bytes_bucket_200":          atomic.LoadUint64(&s.ResponseSizeBytesBucket_200),
		"response_size_bytes_bucket_300":          atomic.LoadUint64(&s.ResponseSizeBytesBucket_300),
		"response_size_bytes_bucket_400":          atomic.LoadUint64(&s.ResponseSizeBytesBucket_400),
		"response_size_bytes_bucket_511":          atomic.LoadUint64(&s.ResponseSizeBytesBucket_511),
		"response_size_bytes_bucket_1023":         atomic.LoadUint64(&s.ResponseSizeBytesBucket_1023),
		"response_size_bytes_bucket_2047":         atomic.LoadUint64(&s.ResponseSizeBytesBucket_2047),
		"response_size_bytes_bucket_4095":         atomic.LoadUint64(&s.ResponseSizeBytesBucket_4095),
		"response_size_bytes_bucket_8291":         atomic.LoadUint64(&s.ResponseSizeBytesBucket_8291),
		"response_size_bytes_bucket_16000":        atomic.LoadUint64(&s.ResponseSizeBytesBucket_16000),
		"response_size_bytes_bucket_32000":        atomic.LoadUint64(&s.ResponseSizeBytesBucket_32000),
		"response_size_bytes_bucket_48000":        atomic.LoadUint64(&s.ResponseSizeBytesBucket_48000),
		"response_size_bytes_bucket_64000":        atomic.LoadUint64(&s.ResponseSizeBytesBucket_64000),
		"response_size_bytes_bucket_inf":          atomic.LoadUint64(&s.ResponseSizeBytesBucket_Inf),
		"response_size_bytes_sum":                 atomic.LoadUint64(&s.ResponseSizeBytesSum),
		"response_size_bytes_count":               atomic.LoadUint64(&s.ResponseSizeBytesCount),
	}, false))
}

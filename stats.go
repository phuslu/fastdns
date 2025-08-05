package fastdns

import (
	"net/netip"
	"sync/atomic"
	"time"
)

type Stats interface {
	UpdateStats(addr netip.AddrPort, msg *Message, duration time.Duration)
	AppendOpenMetrics(dst []byte) []byte
}

var _ Stats = (*CoreStats)(nil)

type CoreStats struct {
	RequestCountTotal uint64

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

	Prefix, Family, Proto, Server, Zone string
}

func (s *CoreStats) UpdateStats(addr netip.AddrPort, msg *Message, duration time.Duration) {
	atomic.AddUint64(&s.RequestCountTotal, 1)
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
	switch msg.Header.Flags.Rcode() {
	case RcodeNoError:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_NOERROR, 1)
	case RcodeFormErr:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_FORMERR, 1)
	case RcodeServFail:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_SERVFAIL, 1)
	case RcodeNXDomain:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_NXDOMAIN, 1)
	case RcodeNotImp:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_NOTIMP, 1)
	case RcodeRefused:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_REFUSED, 1)
	case RcodeYXDomain:
		atomic.AddUint64(&s.ResponseRcodeCountTotal_YXDOMAIN, 1)
	case RcodeNXRRSet:
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

func (s *CoreStats) AppendOpenMetrics(dst []byte) []byte {
	b := AppendableBytes(dst)

	b = b.Str(s.Prefix).Str(`dns_request_count_total{family="`).Str(s.Family).Str(`",proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`"} `).Uint64(atomic.LoadUint64(&s.RequestCountTotal), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.00025"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_00025), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.0005"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_0005), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.001"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_001), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.002"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_002), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.004"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_004), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.008"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_008), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.016"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_016), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.032"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_032), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.064"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_064), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.128"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_128), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.256"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_256), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0.512"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_512), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="1.024"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_1_024), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="2.048"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_2_048), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="4.096"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_4_096), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="8.192"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_8_192), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_bucket{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="+Inf"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsBucket_Inf), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_sum{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`"} `).Float64(float64(atomic.LoadUint64(&s.RequestDurationSecondsSum)) / float64(time.Second)).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_duration_seconds_count{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`"} `).Uint64(atomic.LoadUint64(&s.RequestDurationSecondsCount), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_0), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="100"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_100), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="200"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_200), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="300"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_300), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="400"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_400), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="511"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_511), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="1023"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_1023), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="2047"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_2047), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="4095"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_4095), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="8291"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_8291), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="16000"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_16000), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="32000"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_32000), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="48000"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_48000), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="64000"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_64000), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="+Inf"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesBucket_Inf), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_sum{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesSum), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_size_bytes_count{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`"} `).Uint64(atomic.LoadUint64(&s.RequestSizeBytesCount), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_type_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",type="A"} `).Uint64(atomic.LoadUint64(&s.RequestTypeCountTotal_A), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_type_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",type="AAAA"} `).Uint64(atomic.LoadUint64(&s.RequestTypeCountTotal_AAAA), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_type_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",type="NS"} `).Uint64(atomic.LoadUint64(&s.RequestTypeCountTotal_NS), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_type_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",type="PTR"} `).Uint64(atomic.LoadUint64(&s.RequestTypeCountTotal_PTR), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_type_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",type="SRV"} `).Uint64(atomic.LoadUint64(&s.RequestTypeCountTotal_SRV), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_type_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",type="CNAME"} `).Uint64(atomic.LoadUint64(&s.RequestTypeCountTotal_CNAME), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_type_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",type="SOA"} `).Uint64(atomic.LoadUint64(&s.RequestTypeCountTotal_SOA), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_type_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",type="MX"} `).Uint64(atomic.LoadUint64(&s.RequestTypeCountTotal_MX), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_request_type_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",type="TXT"} `).Uint64(atomic.LoadUint64(&s.RequestTypeCountTotal_TXT), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_rcode_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",rcode="NOERROR"}`).Uint64(atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOERROR), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_rcode_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",rcode="FORMERR"}`).Uint64(atomic.LoadUint64(&s.ResponseRcodeCountTotal_FORMERR), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_rcode_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",rcode="SERVFAIL"}`).Uint64(atomic.LoadUint64(&s.ResponseRcodeCountTotal_SERVFAIL), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_rcode_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",rcode="NXDOMAIN"}`).Uint64(atomic.LoadUint64(&s.ResponseRcodeCountTotal_NXDOMAIN), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_rcode_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",rcode="NOTIMP"}`).Uint64(atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOTIMP), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_rcode_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",rcode="REFUSED"}`).Uint64(atomic.LoadUint64(&s.ResponseRcodeCountTotal_REFUSED), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_rcode_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",rcode="YXDOMAIN"}`).Uint64(atomic.LoadUint64(&s.ResponseRcodeCountTotal_YXDOMAIN), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_rcode_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",rcode="XRRSET"}`).Uint64(atomic.LoadUint64(&s.ResponseRcodeCountTotal_XRRSET), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_rcode_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",rcode="NOTAUTH"}`).Uint64(atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOTAUTH), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_rcode_count_total{server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",rcode="NOTZONE"}`).Uint64(atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOTZONE), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="0"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_0), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="100"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_100), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="200"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_200), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="300"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_300), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="400"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_400), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="511"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_511), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="1023"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_1023), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="2047"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_2047), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="4095"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_4095), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="8291"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_8291), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="16000"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_16000), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="32000"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_32000), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="48000"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_48000), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="64000"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_64000), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_bucket{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`",le="+Inf"}`).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesBucket_Inf), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_sum{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`"} `).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesSum), 10).Byte('\n')
	b = b.Str(s.Prefix).Str(`dns_response_size_bytes_count{proto="`).Str(s.Proto).Str(`",server="`).Str(s.Server).Str(`",zone="`).Str(s.Zone).Str(`"} `).Uint64(atomic.LoadUint64(&s.ResponseSizeBytesCount), 10).Byte('\n')

	return b
}

package fastdns

import (
	"net/netip"
	"strconv"
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
	return s.template(dst, `
{prefix}dns_request_count_total{family="{family}",proto="{proto}",server="{server}",zone="{zone}"} {request_count_total}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.00025"} {request_duration_seconds_bucket_0_00025}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.0005"} {request_duration_seconds_bucket_0_0005}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.001"} {request_duration_seconds_bucket_0_001}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.002"} {request_duration_seconds_bucket_0_002}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.004"} {request_duration_seconds_bucket_0_004}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.008"} {request_duration_seconds_bucket_0_008}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.016"} {request_duration_seconds_bucket_0_016}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.032"} {request_duration_seconds_bucket_0_032}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.064"} {request_duration_seconds_bucket_0_064}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.128"} {request_duration_seconds_bucket_0_128}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.256"} {request_duration_seconds_bucket_0_256}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="0.512"} {request_duration_seconds_bucket_0_512}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="1.024"} {request_duration_seconds_bucket_1_024}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="2.048"} {request_duration_seconds_bucket_2_048}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="4.096"} {request_duration_seconds_bucket_4_096}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="8.192"} {request_duration_seconds_bucket_8_192}
{prefix}dns_request_duration_seconds_bucket{server="{server}",zone="{zone}",le="+Inf"} {request_duration_seconds_bucket_inf}
{prefix}dns_request_duration_seconds_sum{server="{server}",zone="{zone}"} {request_duration_seconds_sum}
{prefix}dns_request_duration_seconds_count{server="{server}",zone="{zone}"} {request_duration_seconds_count}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="0"} {request_size_bytes_bucket_0}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="100"} {request_size_bytes_bucket_100}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="200"} {request_size_bytes_bucket_200}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="300"} {request_size_bytes_bucket_300}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="400"} {request_size_bytes_bucket_400}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="511"} {request_size_bytes_bucket_511}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="1023"} {request_size_bytes_bucket_1023}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="2047"} {request_size_bytes_bucket_2047}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="4095"} {request_size_bytes_bucket_4095}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="8291"} {request_size_bytes_bucket_8291}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="16000"} {request_size_bytes_bucket_16000}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="32000"} {request_size_bytes_bucket_32000}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="48000"} {request_size_bytes_bucket_48000}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="64000"} {request_size_bytes_bucket_64000}
{prefix}dns_request_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="+Inf"} {request_size_bytes_bucket_inf}
{prefix}dns_request_size_bytes_sum{proto="{proto}",server="{server}",zone="{zone}"} {request_size_bytes_sum}
{prefix}dns_request_size_bytes_count{proto="{proto}",server="{server}",zone="{zone}"} {request_size_bytes_count}
{prefix}dns_request_type_count_total{server="{server}",zone="{zone}",type="A"} {request_type_count_total_a}
{prefix}dns_request_type_count_total{server="{server}",zone="{zone}",type="AAAA"} {request_type_count_total_aaaa}
{prefix}dns_request_type_count_total{server="{server}",zone="{zone}",type="NS"} {request_type_count_total_ns}
{prefix}dns_request_type_count_total{server="{server}",zone="{zone}",type="PTR"} {request_type_count_total_ptr}
{prefix}dns_request_type_count_total{server="{server}",zone="{zone}",type="SRV"} {request_type_count_total_srv}
{prefix}dns_request_type_count_total{server="{server}",zone="{zone}",type="CNAME"} {request_type_count_total_cname}
{prefix}dns_request_type_count_total{server="{server}",zone="{zone}",type="SOA"} {request_type_count_total_soa}
{prefix}dns_request_type_count_total{server="{server}",zone="{zone}",type="MX"} {request_type_count_total_mx}
{prefix}dns_request_type_count_total{server="{server}",zone="{zone}",type="TXT"} {request_type_count_total_txt}
{prefix}dns_response_rcode_count_total{server="{server}",zone="{zone}",rcode="NOERROR"} {response_rcode_count_total_noerror}
{prefix}dns_response_rcode_count_total{server="{server}",zone="{zone}",rcode="FORMERR"} {response_rcode_count_total_formerr}
{prefix}dns_response_rcode_count_total{server="{server}",zone="{zone}",rcode="SERVFAIL"} {response_rcode_count_total_servfail}
{prefix}dns_response_rcode_count_total{server="{server}",zone="{zone}",rcode="NXDOMAIN"} {response_rcode_count_total_nxdomain}
{prefix}dns_response_rcode_count_total{server="{server}",zone="{zone}",rcode="NOTIMP"} {response_rcode_count_total_notimp}
{prefix}dns_response_rcode_count_total{server="{server}",zone="{zone}",rcode="REFUSED"} {response_rcode_count_total_refused}
{prefix}dns_response_rcode_count_total{server="{server}",zone="{zone}",rcode="YXDOMAIN"} {response_rcode_count_total_yxdomain}
{prefix}dns_response_rcode_count_total{server="{server}",zone="{zone}",rcode="XRRSET"} {response_rcode_count_total_xrrset}
{prefix}dns_response_rcode_count_total{server="{server}",zone="{zone}",rcode="NOTAUTH"} {response_rcode_count_total_notauth}
{prefix}dns_response_rcode_count_total{server="{server}",zone="{zone}",rcode="NOTZONE"} {response_rcode_count_total_notzone}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="0"} {response_size_bytes_bucket_0}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="100"} {response_size_bytes_bucket_100}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="200"} {response_size_bytes_bucket_200}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="300"} {response_size_bytes_bucket_300}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="400"} {response_size_bytes_bucket_400}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="511"} {response_size_bytes_bucket_511}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="1023"} {response_size_bytes_bucket_1023}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="2047"} {response_size_bytes_bucket_2047}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="4095"} {response_size_bytes_bucket_4095}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="8291"} {response_size_bytes_bucket_8291}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="16000"} {response_size_bytes_bucket_16000}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="32000"} {response_size_bytes_bucket_32000}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="48000"} {response_size_bytes_bucket_48000}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="64000"} {response_size_bytes_bucket_64000}
{prefix}dns_response_size_bytes_bucket{proto="{proto}",server="{server}",zone="{zone}",le="+Inf"} {response_size_bytes_bucket_inf}
{prefix}dns_response_size_bytes_sum{proto="{proto}",server="{server}",zone="{zone}"} {response_size_bytes_sum}
{prefix}dns_response_size_bytes_count{proto="{proto}",server="{server}",zone="{zone}"} {response_size_bytes_count}
`, '{', '}')
}

func (s *CoreStats) template(dst []byte, template string, startTag, endTag byte) []byte {
	j := 0
	for i := 0; i < len(template); i++ {
		switch template[i] {
		case startTag:
			dst = append(dst, template[j:i]...)
			j = i
		case endTag:
			offset := 1
			switch template[j+1 : i] {
			case "prefix":
				dst = append(dst, s.Prefix...)
			case "family":
				dst = append(dst, s.Family...)
			case "proto":
				dst = append(dst, s.Proto...)
			case "server":
				dst = append(dst, s.Server...)
			case "zone":
				dst = append(dst, s.Zone...)
			case "request_count_total":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestCountTotal), 10)
			case "request_duration_seconds_bucket_0_00025":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_00025), 10)
			case "request_duration_seconds_bucket_0_0005":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_0005), 10)
			case "request_duration_seconds_bucket_0_001":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_001), 10)
			case "request_duration_seconds_bucket_0_002":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_002), 10)
			case "request_duration_seconds_bucket_0_004":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_004), 10)
			case "request_duration_seconds_bucket_0_008":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_008), 10)
			case "request_duration_seconds_bucket_0_016":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_016), 10)
			case "request_duration_seconds_bucket_0_032":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_032), 10)
			case "request_duration_seconds_bucket_0_064":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_064), 10)
			case "request_duration_seconds_bucket_0_128":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_128), 10)
			case "request_duration_seconds_bucket_0_256":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_256), 10)
			case "request_duration_seconds_bucket_0_512":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_0_512), 10)
			case "request_duration_seconds_bucket_1_024":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_1_024), 10)
			case "request_duration_seconds_bucket_2_048":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_2_048), 10)
			case "request_duration_seconds_bucket_4_096":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_4_096), 10)
			case "request_duration_seconds_bucket_8_192":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_8_192), 10)
			case "request_duration_seconds_bucket_inf":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsBucket_Inf), 10)
			case "request_duration_seconds_sum":
				dst = strconv.AppendFloat(dst, float64(atomic.LoadUint64(&s.RequestDurationSecondsSum))/float64(time.Second), 'f', -1, 64)
			case "request_duration_seconds_count":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestDurationSecondsCount), 10)
			case "request_size_bytes_bucket_0":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_0), 10)
			case "request_size_bytes_bucket_100":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_100), 10)
			case "request_size_bytes_bucket_200":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_200), 10)
			case "request_size_bytes_bucket_300":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_300), 10)
			case "request_size_bytes_bucket_400":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_400), 10)
			case "request_size_bytes_bucket_511":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_511), 10)
			case "request_size_bytes_bucket_1023":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_1023), 10)
			case "request_size_bytes_bucket_2047":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_2047), 10)
			case "request_size_bytes_bucket_4095":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_4095), 10)
			case "request_size_bytes_bucket_8291":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_8291), 10)
			case "request_size_bytes_bucket_16000":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_16000), 10)
			case "request_size_bytes_bucket_32000":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_32000), 10)
			case "request_size_bytes_bucket_48000":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_48000), 10)
			case "request_size_bytes_bucket_64000":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_64000), 10)
			case "request_size_bytes_bucket_inf":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesBucket_Inf), 10)
			case "request_size_bytes_sum":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesSum), 10)
			case "request_size_bytes_count":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestSizeBytesCount), 10)
			case "request_type_count_total_a":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestTypeCountTotal_A), 10)
			case "request_type_count_total_aaaa":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestTypeCountTotal_AAAA), 10)
			case "request_type_count_total_ns":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestTypeCountTotal_NS), 10)
			case "request_type_count_total_ptr":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestTypeCountTotal_PTR), 10)
			case "request_type_count_total_srv":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestTypeCountTotal_SRV), 10)
			case "request_type_count_total_cname":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestTypeCountTotal_CNAME), 10)
			case "request_type_count_total_soa":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestTypeCountTotal_SOA), 10)
			case "request_type_count_total_mx":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestTypeCountTotal_MX), 10)
			case "request_type_count_total_txt":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.RequestTypeCountTotal_TXT), 10)
			case "response_rcode_count_total_noerror":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOERROR), 10)
			case "response_rcode_count_total_formerr":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseRcodeCountTotal_FORMERR), 10)
			case "response_rcode_count_total_servfail":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseRcodeCountTotal_SERVFAIL), 10)
			case "response_rcode_count_total_nxdomain":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseRcodeCountTotal_NXDOMAIN), 10)
			case "response_rcode_count_total_notimp":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOTIMP), 10)
			case "response_rcode_count_total_refused":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseRcodeCountTotal_REFUSED), 10)
			case "response_rcode_count_total_yxdomain":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseRcodeCountTotal_YXDOMAIN), 10)
			case "response_rcode_count_total_xrrset":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseRcodeCountTotal_XRRSET), 10)
			case "response_rcode_count_total_notauth":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOTAUTH), 10)
			case "response_rcode_count_total_notzone":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseRcodeCountTotal_NOTZONE), 10)
			case "response_size_bytes_bucket_0":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_0), 10)
			case "response_size_bytes_bucket_100":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_100), 10)
			case "response_size_bytes_bucket_200":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_200), 10)
			case "response_size_bytes_bucket_300":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_300), 10)
			case "response_size_bytes_bucket_400":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_400), 10)
			case "response_size_bytes_bucket_511":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_511), 10)
			case "response_size_bytes_bucket_1023":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_1023), 10)
			case "response_size_bytes_bucket_2047":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_2047), 10)
			case "response_size_bytes_bucket_4095":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_4095), 10)
			case "response_size_bytes_bucket_8291":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_8291), 10)
			case "response_size_bytes_bucket_16000":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_16000), 10)
			case "response_size_bytes_bucket_32000":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_32000), 10)
			case "response_size_bytes_bucket_48000":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_48000), 10)
			case "response_size_bytes_bucket_64000":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_64000), 10)
			case "response_size_bytes_bucket_inf":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesBucket_Inf), 10)
			case "response_size_bytes_sum":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesSum), 10)
			case "response_size_bytes_count":
				dst = strconv.AppendUint(dst, atomic.LoadUint64(&s.ResponseSizeBytesCount), 10)
			default:
				dst = append(dst, template[j:i]...)
				offset = 0
			}
			j = i + offset
		}
	}
	dst = append(dst, template[j:]...)
	return dst
}

package fastdns

import (
	"testing"
)

func TestRCODE(t *testing.T) {
	var cases = []struct {
		RCODE  RCODE
		String string
	}{
		{NOERROR, "NOERROR"},
		{FORMERR, "FORMERR"},
		{SERVFAIL, "SERVFAIL"},
		{NXDOMAIN, "NXDOMAIN"},
		{NOTIMP, "NOTIMP"},
		{REFUSED, "REFUSED"},
		{YXDOMAIN, "YXDOMAIN"},
		{XRRSET, "XRRSET"},
		{NOTAUTH, "NOTAUTH"},
		{NOTZONE, "NOTZONE"},
		{RCODE(255), ""},
	}

	for _, c := range cases {
		if got, want := c.RCODE.String(), c.String; got != want {
			t.Errorf("RCODE.String(%v) error got=%s want=%s", c.RCODE, got, want)
		}
	}
}

func TestOpCode(t *testing.T) {
	var cases = []struct {
		OpCode OpCode
		String string
	}{
		{OpCodeQuery, "Query"},
		{OpCodeIquery, "Iquery"},
		{OpCodeStatus, "Status"},
		{OpCode(255), ""},
	}

	for _, c := range cases {
		if got, want := c.OpCode.String(), c.String; got != want {
			t.Errorf("OpCode.String(%v) error got=%s want=%s", c.OpCode, got, want)
		}
	}
}

func TestQClass(t *testing.T) {
	var cases = []struct {
		QClass QClass
		String string
	}{
		{QClassUnknown, "Unknown"},
		{QClassIN, "IN"},
		{QClassCS, "CS"},
		{QClassCH, "CH"},
		{QClassHS, "HS"},
		{QClassANY, "ANY"},
		{QClass(254), ""},
	}

	for _, c := range cases {
		if got, want := c.QClass.String(), c.String; got != want {
			t.Errorf("QClass.String(%v) error got=%s want=%s", c.QClass, got, want)
		}
	}
}

func TestQType(t *testing.T) {
	var cases = []struct {
		QType  QType
		String string
	}{
		{QTypeUnknown, "Unknown"},
		{QTypeA, "A"},
		{QTypeNS, "NS"},
		{QTypeMD, "MD"},
		{QTypeMF, "MF"},
		{QTypeCNAME, "CNAME"},
		{QTypeSOA, "SOA"},
		{QTypeMB, "MB"},
		{QTypeMG, "MG"},
		{QTypeMR, "MR"},
		{QTypeNULL, "NULL"},
		{QTypeWKS, "WKS"},
		{QTypePTR, "PTR"},
		{QTypeHINFO, "HINFO"},
		{QTypeMINFO, "MINFO"},
		{QTypeMX, "MX"},
		{QTypeTXT, "TXT"},
		{QTypeRP, "RP"},
		{QTypeAFSDB, "AFSDB"},
		{QTypeSIG, "SIG"},
		{QTypeKEY, "KEY"},
		{QTypeAAAA, "AAAA"},
		{QTypeLOC, "LOC"},
		{QTypeSRV, "SRV"},
		{QTypeNAPTR, "NAPTR"},
		{QTypeCERT, "CERT"},
		{QTypeDNAME, "DNAME"},
		{QTypeAPL, "APL"},
		{QTypeDS, "DS"},
		{QTypeSSHFP, "SSHFP"},
		{QTypeIPSECKEY, "IPSECKEY"},
		{QTypeRRSIG, "RRSIG"},
		{QTypeNSEC, "NSEC"},
		{QTypeDNSKEY, "DNSKEY"},
		{QTypeDHCID, "DHCID"},
		{QTypeNSEC3, "NSEC3"},
		{QTypeNSEC3PARAM, "NSEC3PARAM"},
		{QTypeHIP, "HIP"},
		{QTypeCDS, "CDS"},
		{QTypeCDNSKEY, "CDNSKEY"},
		{QTypeOPENPGPKEY, "OPENPGPKEY"},
		{QTypeSPF, "SPF"},
		{QTypeTKEY, "TKEY"},
		{QTypeTSIG, "TSIG"},
		{QTypeAXFR, "AXFR"},
		{QTypeMAILB, "MAILB"},
		{QTypeMAILA, "MAILA"},
		{QTypeANY, "ANY"},
		{QTypeURI, "URI"},
		{QTypeCAA, "CAA"},
		{QTypeTA, "TA"},
		{QTypeDLV, "DLV"},
		{QType(65534), ""},
	}

	for _, c := range cases {
		if got, want := c.QType.String(), c.String; got != want {
			t.Errorf("QType.String(%v) error got=%s want=%s", c.QType, got, want)
		}
	}
}

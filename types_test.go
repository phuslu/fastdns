package fastdns

import (
	"testing"
)

// TestTypeRcode verifies stringification of response codes.
func TestTypeRcode(t *testing.T) {
	var cases = []struct {
		Rcode  Rcode
		String string
	}{
		{RcodeNoError, "NoError"},
		{RcodeFormErr, "FormErr"},
		{RcodeServFail, "ServFail"},
		{RcodeNXDomain, "NXDomain"},
		{RcodeNotImp, "NotImp"},
		{RcodeRefused, "Refused"},
		{RcodeYXDomain, "YXDomain"},
		{RcodeYXRRSet, "YXRRSet"},
		{RcodeNXRRSet, "NXRRSet"},
		{RcodeNotAuth, "NotAuth"},
		{RcodeNotZone, "NotZone"},
		{RcodeBADSIG, "BadSig/BadVers"},
		{RcodeBADVERS, "BadSig/BadVers"},
		{RcodeBADKEY, "BadKey"},
		{RcodeBADTIME, "BadTime"},
		{RcodeBADMODE, "BadMode"},
		{RcodeBADNAME, "BadName"},
		{RcodeBADALG, "BadAlg"},
		{RcodeBADTRUNC, "BadTrunc"},
		{RcodeBADCOOKIE, "BadCookie"},
		{Rcode(253), ""},
	}

	for _, c := range cases {
		if got, want := c.Rcode.String(), c.String; got != want {
			t.Errorf("Rcode.String(%v) error got=%s want=%s", c.Rcode, got, want)
		}
	}
}

// TestTypeOpcode verifies opcode stringification.
func TestTypeOpcode(t *testing.T) {
	var cases = []struct {
		Opcode Opcode
		String string
	}{
		{OpcodeQuery, "Query"},
		{OpcodeIQuery, "IQuery"},
		{OpcodeStatus, "Status"},
		{OpcodeNotify, "Notify"},
		{OpcodeUpdate, "Update"},
		{Opcode(255), ""},
	}

	for _, c := range cases {
		if got, want := c.Opcode.String(), c.String; got != want {
			t.Errorf("Opcode.String(%v) error got=%s want=%s", c.Opcode, got, want)
		}
	}
}

// TestTypeClass verifies class stringification.
func TestTypeClass(t *testing.T) {
	var cases = []struct {
		Class  Class
		String string
	}{
		{ClassINET, "IN"},
		{ClassCSNET, "CS"},
		{ClassCHAOS, "CH"},
		{ClassHESIOD, "HS"},
		{ClassNONE, "NONE"},
		{ClassANY, "ANY"},
		{Class(253), ""},
	}

	for _, c := range cases {
		if got, want := c.Class.String(), c.String; got != want {
			t.Errorf("Class.String(%v) error got=%s want=%s", c.Class, got, want)
		}
	}
}

// TestTypeString verifies DNS type stringification over the supported set.
func TestTypeString(t *testing.T) {
	var cases = []struct {
		Type   Type
		String string
	}{
		{TypeNone, "None"},
		{TypeA, "A"},
		{TypeNS, "NS"},
		{TypeMD, "MD"},
		{TypeMF, "MF"},
		{TypeCNAME, "CNAME"},
		{TypeSOA, "SOA"},
		{TypeMB, "MB"},
		{TypeMG, "MG"},
		{TypeMR, "MR"},
		{TypeNULL, "NULL"},
		{TypePTR, "PTR"},
		{TypeHINFO, "HINFO"},
		{TypeMINFO, "MINFO"},
		{TypeMX, "MX"},
		{TypeTXT, "TXT"},
		{TypeRP, "RP"},
		{TypeAFSDB, "AFSDB"},
		{TypeX25, "X25"},
		{TypeISDN, "ISDN"},
		{TypeRT, "RT"},
		{TypeNSAPPTR, "NSAPPTR"},
		{TypeSIG, "SIG"},
		{TypeKEY, "KEY"},
		{TypePX, "PX"},
		{TypeGPOS, "GPOS"},
		{TypeAAAA, "AAAA"},
		{TypeLOC, "LOC"},
		{TypeNXT, "NXT"},
		{TypeEID, "EID"},
		{TypeNIMLOC, "NIMLOC"},
		{TypeSRV, "SRV"},
		{TypeATMA, "ATMA"},
		{TypeNAPTR, "NAPTR"},
		{TypeKX, "KX"},
		{TypeCERT, "CERT"},
		{TypeDNAME, "DNAME"},
		{TypeOPT, "OPT"},
		{TypeAPL, "APL"},
		{TypeDS, "DS"},
		{TypeSSHFP, "SSHFP"},
		{TypeRRSIG, "RRSIG"},
		{TypeNSEC, "NSEC"},
		{TypeDNSKEY, "DNSKEY"},
		{TypeDHCID, "DHCID"},
		{TypeNSEC3, "NSEC3"},
		{TypeNSEC3PARAM, "NSEC3PARAM"},
		{TypeTLSA, "TLSA"},
		{TypeSMIMEA, "SMIMEA"},
		{TypeHIP, "HIP"},
		{TypeNINFO, "NINFO"},
		{TypeRKEY, "RKEY"},
		{TypeTALINK, "TALINK"},
		{TypeCDS, "CDS"},
		{TypeCDNSKEY, "CDNSKEY"},
		{TypeOPENPGPKEY, "OPENPGPKEY"},
		{TypeCSYNC, "CSYNC"},
		{TypeZONEMD, "ZONEMD"},
		{TypeSVCB, "SVCB"},
		{TypeHTTPS, "HTTPS"},
		{TypeSPF, "SPF"},
		{TypeUINFO, "UINFO"},
		{TypeUID, "UID"},
		{TypeGID, "GID"},
		{TypeUNSPEC, "UNSPEC"},
		{TypeNID, "NID"},
		{TypeL32, "L32"},
		{TypeL64, "L64"},
		{TypeLP, "LP"},
		{TypeEUI48, "EUI48"},
		{TypeEUI64, "EUI64"},
		{TypeURI, "URI"},
		{TypeCAA, "CAA"},
		{TypeAVC, "AVC"},
		{TypeTKEY, "TKEY"},
		{TypeTSIG, "TSIG"},
		{TypeIXFR, "IXFR"},
		{TypeAXFR, "AXFR"},
		{TypeMAILB, "MAILB"},
		{TypeMAILA, "MAILA"},
		{TypeANY, "ANY"},
		{TypeTA, "TA"},
		{TypeDLV, "DLV"},
		{TypeReserved, "Reserved"},
		{Type(65534), ""},
	}

	for _, c := range cases {
		if got, want := c.Type.String(), c.String; got != want {
			t.Errorf("Type.String(%v) error got=%s want=%s", c.Type, got, want)
		}
	}
}

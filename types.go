package fastdns

// Rcode denotes a 4bit field that specifies the response
// code for a query.
type Rcode byte

// Message Response Codes, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
const (
	RcodeSuccess        Rcode = 0  // Success   - No Error                          [DNS]
	RcodeFormatError    Rcode = 1  // FormErr   - Format Error                      [DNS]
	RcodeServerFailure  Rcode = 2  // ServFail  - Server Failure                    [DNS]
	RcodeNameError      Rcode = 3  // NXDomain  - Non-Existent Domain               [DNS]
	RcodeNotImplemented Rcode = 4  // NotImp    - Not Implemented                   [DNS]
	RcodeRefused        Rcode = 5  // Refused   - Query Refused                     [DNS]
	RcodeYXDomain       Rcode = 6  // YXDomain  - Name Exists when it should not    [DNS Update]
	RcodeYXRrset        Rcode = 7  // YXRRSet   - RR Set Exists when it should not  [DNS Update]
	RcodeNXRrset        Rcode = 8  // NXRRSet   - RR Set that should exist does not [DNS Update]
	RcodeNotAuth        Rcode = 9  // NotAuth   - Server Not Authoritative for zone [DNS Update]
	RcodeNotZone        Rcode = 10 // NotZone   - Name not contained in zone        [DNS Update/TSIG]
	RcodeBadSig         Rcode = 16 // BADSIG    - TSIG Signature Failure            [TSIG]
	RcodeBadVers        Rcode = 16 // BADVERS   - Bad OPT Version                   [EDNS0]
	RcodeBadKey         Rcode = 17 // BADKEY    - Key not recognized                [TSIG]
	RcodeBadTime        Rcode = 18 // BADTIME   - Signature out of time window      [TSIG]
	RcodeBadMode        Rcode = 19 // BADMODE   - Bad TKEY Mode                     [TKEY]
	RcodeBadName        Rcode = 20 // BADNAME   - Duplicate key name                [TKEY]
	RcodeBadAlg         Rcode = 21 // BADALG    - Algorithm not supported           [TKEY]
	RcodeBadTrunc       Rcode = 22 // BADTRUNC  - Bad Truncation                    [TSIG]
	RcodeBadCookie      Rcode = 23 // BADCOOKIE - Bad/missing Server Cookie         [DNS Cookies]
)

func (c Rcode) String() string {
	switch c {
	case RcodeSuccess:
		return "Success"
	case RcodeFormatError:
		return "FormatError"
	case RcodeServerFailure:
		return "ServerFailure"
	case RcodeNameError:
		return "NameError"
	case RcodeNotImplemented:
		return "NotImplemented"
	case RcodeRefused:
		return "Refused"
	case RcodeYXDomain:
		return "YXDomain"
	case RcodeYXRrset:
		return "YXRrset"
	case RcodeNXRrset:
		return "NXRrset"
	case RcodeNotAuth:
		return "NotAuth"
	case RcodeNotZone:
		return "NotZone"
	case RcodeBadSig:
		return "BadSig"
	// case RcodeBadVers:
	// 	return "BadVers"
	case RcodeBadKey:
		return "BadKey"
	case RcodeBadTime:
		return "BadTime"
	case RcodeBadMode:
		return "BadMode"
	case RcodeBadName:
		return "BadName"
	case RcodeBadAlg:
		return "BadAlg"
	case RcodeBadTrunc:
		return "BadTrunc"
	case RcodeBadCookie:
		return "BadCookie"
	}
	return ""
}

// Opcode denotes a 4bit field that specified the query type.
type Opcode byte

// Wire constants and supported types.
const (
	OpcodeQuery  Opcode = 0
	OpcodeIQuery Opcode = 1
	OpcodeStatus Opcode = 2
	OpcodeNotify Opcode = 4
	OpcodeUpdate Opcode = 5
)

func (c Opcode) String() string {
	switch c {
	case OpcodeQuery:
		return "Query"
	case OpcodeIQuery:
		return "IQuery"
	case OpcodeStatus:
		return "Status"
	case OpcodeNotify:
		return "Notify"
	case OpcodeUpdate:
		return "Update"
	}
	return ""
}

// Flags is an arbitrary 16bit represents QR, Opcode, AA, TC, RD, RA, Z and RCODE.
//
//   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type Flags uint16

// QR is QR bit in Flags
func (f Flags) QR() byte {
	return byte(f >> 15)
}

// Opcode is Opcode in Flags
func (f Flags) Opcode() Opcode {
	return Opcode((f & 0b0111111111111111) >> 11)
}

// AA is AA bit in Flags
func (f Flags) AA() byte {
	return byte((f & 0b0000010000000000) >> 10)
}

// TC is TC bit in Flags
func (f Flags) TC() byte {
	return byte((f & 0b0000001000000000) >> 9)
}

// RD is RD bit in Flags
func (f Flags) RD() byte {
	return byte((f & 0b0000000100000000) >> 8)
}

// RA is RA bit in Flags
func (f Flags) RA() byte {
	return byte((f & 0b0000000010000000) >> 7)
}

// Z is Z bits in Flags
func (f Flags) Z() byte {
	return byte((f & 0b0000000001110000) >> 4)
}

// Rcode is Rcode in Flags
func (f Flags) Rcode() Rcode {
	return Rcode((f & 0b0000000000001111))
}

// Class is a DNS class.
type Class uint16

// Wire constants and supported types.
const (
	ClassINET   Class = 1
	ClassCSNET  Class = 2
	ClassCHAOS  Class = 3
	ClassHESIOD Class = 4
	ClassNONE   Class = 254
	ClassANY    Class = 255
)

func (c Class) String() string {
	switch c {
	case ClassINET:
		return "IN"
	case ClassCSNET:
		return "CS"
	case ClassCHAOS:
		return "CH"
	case ClassHESIOD:
		return "HS"
	case ClassNONE:
		return "NONE"
	case ClassANY:
		return "ANY"
	}
	return ""
}

// Type is a DNS type.
type Type uint16

// Wire constants and supported types.
const (
	TypeNone       Type = 0
	TypeA          Type = 1
	TypeNS         Type = 2
	TypeMD         Type = 3
	TypeMF         Type = 4
	TypeCNAME      Type = 5
	TypeSOA        Type = 6
	TypeMB         Type = 7
	TypeMG         Type = 8
	TypeMR         Type = 9
	TypeNULL       Type = 10
	TypePTR        Type = 12
	TypeHINFO      Type = 13
	TypeMINFO      Type = 14
	TypeMX         Type = 15
	TypeTXT        Type = 16
	TypeRP         Type = 17
	TypeAFSDB      Type = 18
	TypeX25        Type = 19
	TypeISDN       Type = 20
	TypeRT         Type = 21
	TypeNSAPPTR    Type = 23
	TypeSIG        Type = 24
	TypeKEY        Type = 25
	TypePX         Type = 26
	TypeGPOS       Type = 27
	TypeAAAA       Type = 28
	TypeLOC        Type = 29
	TypeNXT        Type = 30
	TypeEID        Type = 31
	TypeNIMLOC     Type = 32
	TypeSRV        Type = 33
	TypeATMA       Type = 34
	TypeNAPTR      Type = 35
	TypeKX         Type = 36
	TypeCERT       Type = 37
	TypeDNAME      Type = 39
	TypeOPT        Type = 41 // EDNS
	TypeAPL        Type = 42
	TypeDS         Type = 43
	TypeSSHFP      Type = 44
	TypeRRSIG      Type = 46
	TypeNSEC       Type = 47
	TypeDNSKEY     Type = 48
	TypeDHCID      Type = 49
	TypeNSEC3      Type = 50
	TypeNSEC3PARAM Type = 51
	TypeTLSA       Type = 52
	TypeSMIMEA     Type = 53
	TypeHIP        Type = 55
	TypeNINFO      Type = 56
	TypeRKEY       Type = 57
	TypeTALINK     Type = 58
	TypeCDS        Type = 59
	TypeCDNSKEY    Type = 60
	TypeOPENPGPKEY Type = 61
	TypeCSYNC      Type = 62
	TypeZONEMD     Type = 63
	TypeSVCB       Type = 64
	TypeHTTPS      Type = 65
	TypeSPF        Type = 99
	TypeUINFO      Type = 100
	TypeUID        Type = 101
	TypeGID        Type = 102
	TypeUNSPEC     Type = 103
	TypeNID        Type = 104
	TypeL32        Type = 105
	TypeL64        Type = 106
	TypeLP         Type = 107
	TypeEUI48      Type = 108
	TypeEUI64      Type = 109
	TypeURI        Type = 256
	TypeCAA        Type = 257
	TypeAVC        Type = 258
	TypeTKEY       Type = 249
	TypeTSIG       Type = 250
	TypeIXFR       Type = 251
	TypeAXFR       Type = 252
	TypeMAILB      Type = 253
	TypeMAILA      Type = 254
	TypeANY        Type = 255
	TypeTA         Type = 32768
	TypeDLV        Type = 32769
	TypeReserved   Type = 65535
)

func (t Type) String() string {
	switch t {
	case TypeNone:
		return "None"
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeMD:
		return "MD"
	case TypeMF:
		return "MF"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypeMB:
		return "MB"
	case TypeMG:
		return "MG"
	case TypeMR:
		return "MR"
	case TypeNULL:
		return "NULL"
	case TypePTR:
		return "PTR"
	case TypeHINFO:
		return "HINFO"
	case TypeMINFO:
		return "MINFO"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeRP:
		return "RP"
	case TypeAFSDB:
		return "AFSDB"
	case TypeX25:
		return "X25"
	case TypeISDN:
		return "ISDN"
	case TypeRT:
		return "RT"
	case TypeNSAPPTR:
		return "NSAPPTR"
	case TypeSIG:
		return "SIG"
	case TypeKEY:
		return "KEY"
	case TypePX:
		return "PX"
	case TypeGPOS:
		return "GPOS"
	case TypeAAAA:
		return "AAAA"
	case TypeLOC:
		return "LOC"
	case TypeNXT:
		return "NXT"
	case TypeEID:
		return "EID"
	case TypeNIMLOC:
		return "NIMLOC"
	case TypeSRV:
		return "SRV"
	case TypeATMA:
		return "ATMA"
	case TypeNAPTR:
		return "NAPTR"
	case TypeKX:
		return "KX"
	case TypeCERT:
		return "CERT"
	case TypeDNAME:
		return "DNAME"
	case TypeOPT:
		return "OPT"
	case TypeAPL:
		return "APL"
	case TypeDS:
		return "DS"
	case TypeSSHFP:
		return "SSHFP"
	case TypeRRSIG:
		return "RRSIG"
	case TypeNSEC:
		return "NSEC"
	case TypeDNSKEY:
		return "DNSKEY"
	case TypeDHCID:
		return "DHCID"
	case TypeNSEC3:
		return "NSEC3"
	case TypeNSEC3PARAM:
		return "NSEC3PARAM"
	case TypeTLSA:
		return "TLSA"
	case TypeSMIMEA:
		return "SMIMEA"
	case TypeHIP:
		return "HIP"
	case TypeNINFO:
		return "NINFO"
	case TypeRKEY:
		return "RKEY"
	case TypeTALINK:
		return "TALINK"
	case TypeCDS:
		return "CDS"
	case TypeCDNSKEY:
		return "CDNSKEY"
	case TypeOPENPGPKEY:
		return "OPENPGPKEY"
	case TypeCSYNC:
		return "CSYNC"
	case TypeZONEMD:
		return "ZONEMD"
	case TypeSVCB:
		return "SVCB"
	case TypeHTTPS:
		return "HTTPS"
	case TypeSPF:
		return "SPF"
	case TypeUINFO:
		return "UINFO"
	case TypeUID:
		return "UID"
	case TypeGID:
		return "GID"
	case TypeUNSPEC:
		return "UNSPEC"
	case TypeNID:
		return "NID"
	case TypeL32:
		return "L32"
	case TypeL64:
		return "L64"
	case TypeLP:
		return "LP"
	case TypeEUI48:
		return "EUI48"
	case TypeEUI64:
		return "EUI64"
	case TypeURI:
		return "URI"
	case TypeCAA:
		return "CAA"
	case TypeAVC:
		return "AVC"
	case TypeTKEY:
		return "TKEY"
	case TypeTSIG:
		return "TSIG"
	case TypeIXFR:
		return "IXFR"
	case TypeAXFR:
		return "AXFR"
	case TypeMAILB:
		return "MAILB"
	case TypeMAILA:
		return "MAILA"
	case TypeANY:
		return "ANY"
	case TypeTA:
		return "TA"
	case TypeDLV:
		return "DLV"
	case TypeReserved:
		return "Reserved"
	}
	return ""
}

// ParseType converts a question type string into a question type value.
func ParseType(s string) (t Type) {
	switch s {
	case "A", "a":
		t = TypeA
	case "NS", "ns":
		t = TypeNS
	case "MD", "md":
		t = TypeMD
	case "MF", "mf":
		t = TypeMF
	case "CNAME", "cname":
		t = TypeCNAME
	case "SOA", "soa":
		t = TypeSOA
	case "MB", "mb":
		t = TypeMB
	case "MG", "mg":
		t = TypeMG
	case "MR", "mr":
		t = TypeMR
	case "NULL", "null":
		t = TypeNULL
	case "PTR", "ptr":
		t = TypePTR
	case "HINFO", "hinfo":
		t = TypeHINFO
	case "MINFO", "minfo":
		t = TypeMINFO
	case "MX", "mx":
		t = TypeMX
	case "TXT", "txt":
		t = TypeTXT
	case "RP", "rp":
		t = TypeRP
	case "AFSDB", "afsdb":
		t = TypeAFSDB
	case "X25", "x25":
		t = TypeX25
	case "ISDN", "isdn":
		t = TypeISDN
	case "RT", "rt":
		t = TypeRT
	case "NSAPPTR", "nsapptr":
		t = TypeNSAPPTR
	case "SIG", "sig":
		t = TypeSIG
	case "KEY", "key":
		t = TypeKEY
	case "PX", "px":
		t = TypePX
	case "GPOS", "gpos":
		t = TypeGPOS
	case "AAAA", "aaaa":
		t = TypeAAAA
	case "LOC", "loc":
		t = TypeLOC
	case "NXT", "nxt":
		t = TypeNXT
	case "EID", "eid":
		t = TypeEID
	case "NIMLOC", "nimloc":
		t = TypeNIMLOC
	case "SRV", "srv":
		t = TypeSRV
	case "ATMA", "atma":
		t = TypeATMA
	case "NAPTR", "naptr":
		t = TypeNAPTR
	case "KX", "kx":
		t = TypeKX
	case "CERT", "cert":
		t = TypeCERT
	case "DNAME", "dname":
		t = TypeDNAME
	case "OPT", "opt":
		t = TypeOPT
	case "APL", "apl":
		t = TypeAPL
	case "DS", "ds":
		t = TypeDS
	case "SSHFP", "sshfp":
		t = TypeSSHFP
	case "RRSIG", "rrsig":
		t = TypeRRSIG
	case "NSEC", "nsec":
		t = TypeNSEC
	case "DNSKEY", "dnskey":
		t = TypeDNSKEY
	case "DHCID", "dhcid":
		t = TypeDHCID
	case "NSEC3", "nsec3":
		t = TypeNSEC3
	case "NSEC3PARAM", "nsec3param":
		t = TypeNSEC3PARAM
	case "TLSA", "tlsa":
		t = TypeTLSA
	case "SMIMEA", "smimea":
		t = TypeSMIMEA
	case "HIP", "hip":
		t = TypeHIP
	case "NINFO", "ninfo":
		t = TypeNINFO
	case "RKEY", "rkey":
		t = TypeRKEY
	case "TALINK", "talink":
		t = TypeTALINK
	case "CDS", "cds":
		t = TypeCDS
	case "CDNSKEY", "cdnskey":
		t = TypeCDNSKEY
	case "OPENPGPKEY", "openpgpkey":
		t = TypeOPENPGPKEY
	case "CSYNC", "csync":
		t = TypeCSYNC
	case "ZONEMD", "zonemd":
		t = TypeZONEMD
	case "SVCB", "svcb":
		t = TypeSVCB
	case "HTTPS", "https":
		t = TypeHTTPS
	case "SPF", "spf":
		t = TypeSPF
	case "UINFO", "uinfo":
		t = TypeUINFO
	case "UID", "uid":
		t = TypeUID
	case "GID", "gid":
		t = TypeGID
	case "UNSPEC", "unspec":
		t = TypeUNSPEC
	case "NID", "nid":
		t = TypeNID
	case "L32", "l32":
		t = TypeL32
	case "L64", "l64":
		t = TypeL64
	case "LP", "lp":
		t = TypeLP
	case "EUI48", "eui48":
		t = TypeEUI48
	case "EUI64", "eui64":
		t = TypeEUI64
	case "URI", "uri":
		t = TypeURI
	case "CAA", "caa":
		t = TypeCAA
	case "AVC", "avc":
		t = TypeAVC
	case "TKEY", "tkey":
		t = TypeTKEY
	case "TSIG", "tsig":
		t = TypeTSIG
	case "IXFR", "ixfr":
		t = TypeIXFR
	case "AXFR", "axfr":
		t = TypeAXFR
	case "MAILB", "mailb":
		t = TypeMAILB
	case "MAILA", "maila":
		t = TypeMAILA
	case "ANY", "any":
		t = TypeANY
	case "TA", "ta":
		t = TypeTA
	case "DLV", "dlv":
		t = TypeDLV
	case "Reserved", "reserved":
		t = TypeReserved
	}
	return
}

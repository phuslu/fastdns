package fastdns

type QName []byte
type QCount uint16

// RCODE denotes a 4bit field that specifies the response
// code for a query.
type RCODE byte

const (
	NOERROR  RCODE = 0 // DNS Query completed successfully
	FORMERR  RCODE = 1 // DNS Query Format Error
	SERVFAIL RCODE = 2 // Server failed to complete the DNS request
	NXDOMAIN RCODE = 3 // Domain name does not exist.
	NOTIMP   RCODE = 4 // Function not implemented
	REFUSED  RCODE = 5 // The server refused to answer for the query
	YXDOMAIN RCODE = 6 // Name that should not exist, does exist
	XRRSET   RCODE = 7 // RRset that should not exist, does exist
	NOTAUTH  RCODE = 8 // Server not authoritative for the zone
	NOTZONE  RCODE = 9 // Name not in zone
)

func (rcode RCODE) String() string {
	switch rcode {
	case NOERROR:
		return "NOERROR"
	case FORMERR:
		return "FORMERR"
	case SERVFAIL:
		return "SERVFAIL"
	case NXDOMAIN:
		return "NXDOMAIN"
	case NOTIMP:
		return "NOTIMP"
	case REFUSED:
		return "REFUSED"
	case YXDOMAIN:
		return "YXDOMAIN"
	case XRRSET:
		return "XRRSET"
	case NOTAUTH:
		return "NOTAUTH"
	case NOTZONE:
		return "NOTZONE"
	}
	return ""
}

// OpCode denotes a 4bit field that specified the query type.
type OpCode byte

const (
	OpCodeQuery  OpCode = 0
	OpCodeIquery OpCode = 1
	OpCodeStatus OpCode = 2
)

func (c OpCode) String() string {
	switch c {
	case OpCodeQuery:
		return "Query"
	case OpCodeIquery:
		return "Iquery"
	case OpCodeStatus:
		return "Status"
	}
	return ""
}

type QClass uint16

const (
	QClassUnknown QClass = 0
	QClassIN      QClass = 1
	QClassCS      QClass = 2
	QClassCH      QClass = 3
	QClassHS      QClass = 4
	QClassANY     QClass = 255
)

func (qc QClass) String() string {
	switch qc {
	case QClassUnknown:
		return "Unknown"
	case QClassIN:
		return "IN"
	case QClassCS:
		return "CS"
	case QClassCH:
		return "CH"
	case QClassHS:
		return "HS"
	case QClassANY:
		return "ANY"
	}
	return ""
}

type QType uint16

const (
	QTypeUnknown    QType = 0
	QTypeA          QType = 1
	QTypeNS         QType = 2
	QTypeMD         QType = 3
	QTypeMF         QType = 4
	QTypeCNAME      QType = 5
	QTypeSOA        QType = 6
	QTypeMB         QType = 7
	QTypeMG         QType = 8
	QTypeMR         QType = 9
	QTypeNULL       QType = 10
	QTypeWKS        QType = 11
	QTypePTR        QType = 12
	QTypeHINFO      QType = 13
	QTypeMINFO      QType = 14
	QTypeMX         QType = 15
	QTypeTXT        QType = 16
	QTypeRP         QType = 17
	QTypeAFSDB      QType = 18
	QTypeSIG        QType = 24
	QTypeKEY        QType = 25
	QTypeAAAA       QType = 28
	QTypeLOC        QType = 29
	QTypeSRV        QType = 33
	QTypeNAPTR      QType = 35
	QTypeCERT       QType = 37
	QTypeDNAME      QType = 39
	QTypeAPL        QType = 42
	QTypeDS         QType = 43
	QTypeSSHFP      QType = 44
	QTypeIPSECKEY   QType = 45
	QTypeRRSIG      QType = 46
	QTypeNSEC       QType = 47
	QTypeDNSKEY     QType = 48
	QTypeDHCID      QType = 49
	QTypeNSEC3      QType = 50
	QTypeNSEC3PARAM QType = 51
	QTypeHIP        QType = 55
	QTypeCDS        QType = 59
	QTypeCDNSKEY    QType = 60
	QTypeOPENPGPKEY QType = 61
	QTypeSPF        QType = 99
	QTypeTKEY       QType = 249
	QTypeTSIG       QType = 250
	QTypeAXFR       QType = 252
	QTypeMAILB      QType = 253
	QTypeMAILA      QType = 254
	QTypeANY        QType = 255
	QTypeURI        QType = 256
	QTypeCAA        QType = 257
	QTypeTA         QType = 32768
	QTypeDLV        QType = 32769
)

func (qt QType) String() string {
	switch qt {
	case QTypeUnknown:
		return "Unknown"
	case QTypeA:
		return "A"
	case QTypeNS:
		return "NS"
	case QTypeMD:
		return "MD"
	case QTypeMF:
		return "MF"
	case QTypeCNAME:
		return "CNAME"
	case QTypeSOA:
		return "SOA"
	case QTypeMB:
		return "MB"
	case QTypeMG:
		return "MG"
	case QTypeMR:
		return "MR"
	case QTypeNULL:
		return "NULL"
	case QTypeWKS:
		return "WKS"
	case QTypePTR:
		return "PTR"
	case QTypeHINFO:
		return "HINFO"
	case QTypeMINFO:
		return "MINFO"
	case QTypeMX:
		return "MX"
	case QTypeTXT:
		return "TXT"
	case QTypeRP:
		return "RP"
	case QTypeAFSDB:
		return "AFSDB"
	case QTypeSIG:
		return "SIG"
	case QTypeKEY:
		return "KEY"
	case QTypeAAAA:
		return "AAAA"
	case QTypeLOC:
		return "LOC"
	case QTypeSRV:
		return "SRV"
	case QTypeNAPTR:
		return "NAPTR"
	case QTypeCERT:
		return "CERT"
	case QTypeDNAME:
		return "DNAME"
	case QTypeAPL:
		return "APL"
	case QTypeDS:
		return "DS"
	case QTypeSSHFP:
		return "SSHFP"
	case QTypeIPSECKEY:
		return "IPSECKEY"
	case QTypeRRSIG:
		return "RRSIG"
	case QTypeNSEC:
		return "NSEC"
	case QTypeDNSKEY:
		return "DNSKEY"
	case QTypeDHCID:
		return "DHCID"
	case QTypeNSEC3:
		return "NSEC3"
	case QTypeNSEC3PARAM:
		return "NSEC3PARAM"
	case QTypeHIP:
		return "HIP"
	case QTypeCDS:
		return "CDS"
	case QTypeCDNSKEY:
		return "CDNSKEY"
	case QTypeOPENPGPKEY:
		return "OPENPGPKEY"
	case QTypeSPF:
		return "SPF"
	case QTypeTKEY:
		return "TKEY"
	case QTypeTSIG:
		return "TSIG"
	case QTypeAXFR:
		return "AXFR"
	case QTypeMAILB:
		return "MAILB"
	case QTypeMAILA:
		return "MAILA"
	case QTypeANY:
		return "ANY"
	case QTypeURI:
		return "URI"
	case QTypeCAA:
		return "CAA"
	case QTypeTA:
		return "TA"
	case QTypeDLV:
		return "DLV"
	}
	return ""
}

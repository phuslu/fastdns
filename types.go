package fastdns

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

// OpCode denotes a 4bit field that specified the query type.
type OpCode byte

const (
	OpCodeQuery OpCode = iota
	OpCodeIquery
	OpCodeStatus
)

type QType uint16

const (
	QTypeUnknown QType = iota

	// Host address
	QTypeA

	// Authoritative name server
	QTypeNS

	QTypeMD
	QTypeMF

	// Canonical name for an alias
	QTypeCNAME

	// Marks the start of a zone of authority
	QTypeSOA

	QTypeMB
	QTypeMG
	QTypeMR
	QTypeNULL
	QTypeWKS

	// Domain name pointer
	QTypePTR
	QTypeHINFO
	QTypeMINFO

	// Mail exchange
	QTypeMX
	QTypeTXT
	QTypeAXFR  QType = 252
	QTypeMAILB QType = 253
	QTypeMAILA QType = 254

	// All records
	QTypeWildcard QType = 255
)

type QClass uint16

const (
	QClassUnknown QClass = iota

	// Internet
	QClassIN

	QClassCS
	QClassCH
	QClassHS

	// Any class
	QClassWildcard QClass = 255
)

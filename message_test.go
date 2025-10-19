package fastdns

import (
	"reflect"
	"testing"
)

// TestMessageParseMessageOK ensures valid wire payloads round-trip into Message.
func TestMessageParseMessageOK(t *testing.T) {
	var cases = [2]struct {
		Raw     []byte
		Message *Message
	}{}

	/*
		Domain Name System (query)
		    Transaction ID: 0x0001
		    Flags: 0x0100 Standard query
		        0... .... .... .... = Response: Message is a query
		        .000 0... .... .... = Opcode: Standard query (0)
		        .... ..0. .... .... = Truncated: Message is not truncated
		        .... ...1 .... .... = Recursion desired: Do query recursively
		        .... .... .0.. .... = Z: reserved (0)
		        .... .... ...0 .... = Non-authenticated data: Unacceptable
		    Questions: 1
		    Answer RRs: 0
		    Authority RRs: 0
		    Additional RRs: 0
		    Queries
		        1.50.168.192.in-addr.arpa: type PTR, class IN
		            Name: 1.50.168.192.in-addr.arpa
		            [Name Length: 25]
		            [Label Count: 6]
		            Type: PTR (domain name PoinTeR) (12)
		            Class: IN (0x0001)
	*/
	cases[0].Raw = []byte{
		0x00, 0x01, // Transaction ID
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x01, '1',
		0x02, '5', '0',
		0x03, '1', '6', '8',
		0x03, '1', '9', '2',
		0x07, 'i', 'n', '-', 'a', 'd', 'd', 'r',
		0x04, 'a', 'r', 'p', 'a',
		0x00,
		0x00, 0x0c, // QTYPE PTR
		0x00, 0x01, // QCLASS IN
	}
	cases[0].Message = AcquireMessage()
	cases[0].Message.Raw = cases[0].Raw
	cases[0].Message.Domain = []byte("1.50.168.192.in-addr.arpa")
	cases[0].Message.Header.ID = 0x0001
	cases[0].Message.Header.Flags = 0b0000000100000000
	cases[0].Message.Header.QDCount = 0x01
	cases[0].Message.Header.ANCount = 0x00
	cases[0].Message.Header.NSCount = 0x00
	cases[0].Message.Header.ARCount = 0x00
	cases[0].Message.Question.Name = []byte("\x011\x0250\x03168\x03192\x07in-addr\x04arpa\x00")
	cases[0].Message.Question.Type = TypePTR
	cases[0].Message.Question.Class = ClassINET

	/*
		Domain Name System (query)
		    Transaction ID: 0x0002
		    Flags: 0x0100 Standard query
		        0... .... .... .... = Response: Message is a query
		        .000 0... .... .... = Opcode: Standard query (0)
		        .... ..0. .... .... = Truncated: Message is not truncated
		        .... ...1 .... .... = Recursion desired: Do query recursively
		        .... .... .0.. .... = Z: reserved (0)
		        .... .... ...0 .... = Non-authenticated data: Unacceptable
		    Questions: 1
		    Answer RRs: 0
		    Authority RRs: 0
		    Additional RRs: 0
		    Queries
		        ip.phus.lu: type A, class IN
		            Name: ip.phus.lu
		            [Name Length: 10]
		            [Label Count: 3]
		            Type: A (Host Address) (1)
		            Class: IN (0x0001)
	*/
	cases[1].Raw = []byte{
		0x00, 0x02, // Transaction ID
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x02, 'i', 'p',
		0x04, 'p', 'h', 'u', 's',
		0x02, 'l', 'u',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
	cases[1].Message = AcquireMessage()
	cases[1].Message.Raw = cases[1].Raw
	cases[1].Message.Domain = []byte("ip.phus.lu")
	cases[1].Message.Header.ID = 0x0002
	cases[1].Message.Header.Flags = 0b0000000100000000
	cases[1].Message.Header.QDCount = 0x01
	cases[1].Message.Header.ANCount = 0x00
	cases[1].Message.Header.NSCount = 0x00
	cases[1].Message.Header.ARCount = 0x00
	cases[1].Message.Question.Name = []byte("\x02ip\x04phus\x02lu\x00")
	cases[1].Message.Question.Type = TypeA
	cases[1].Message.Question.Class = ClassINET

	for _, c := range cases {
		msg := AcquireMessage()
		err := ParseMessage(msg, c.Raw, true)
		if err != nil {
			t.Errorf("ParseMessage(%x) error: %+v", c.Message.Raw, err)
		}
		if got, want := msg, c.Message; !reflect.DeepEqual(got, want) {
			t.Errorf("ParseMessage(%x) error got=%#v want=%#v", c.Message.Raw, got, want)
		}
		ReleaseMessage(msg)
	}
}

// TestMessageParseMessageError validates parser failures for malformed inputs.
func TestMessageParseMessageError(t *testing.T) {
	var cases = []struct {
		Raw   []byte
		Error error
	}{
		{
			Raw: []byte{
				0x00, 0x01, // Transaction ID
				0x01, 0x00, // Flags: recursion desired
				0x00, 0x01, // Questions
				0x00, 0x00, // Answer RRs
				0x00, 0x00, // Authority RRs
				0x00, // Truncated Additional RRs field
			},
			Error: ErrInvalidHeader,
		},
		{
			Raw: []byte{
				0x00, 0x02, // Transaction ID
				0x01, 0x00, // Flags: recursion desired
				0x00, 0x00, // Questions
				0x00, 0x00, // Answer RRs
				0x00, 0x00, // Authority RRs
				0x00, 0x00, // Additional RRs
				0x02, 'i', 'p',
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
				0x00, 0x01, // QTYPE A
				0x00, // Truncated QCLASS (missing low byte)
			},
			Error: ErrInvalidHeader,
		},
		{
			Raw: []byte{
				0x00, 0x02, // Transaction ID
				0x01, 0x00, // Flags: recursion desired
				0x00, 0x01, // Questions
				0x00, 0x00, // Answer RRs
				0x00, 0x00, // Authority RRs
				0x00, 0x00, // Additional RRs
				0x02, 'i', 'p',
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
				0x00, 0x01, // QTYPE A
				0x00, // Truncated QCLASS (missing low byte)
			},
			Error: ErrInvalidQuestion,
		},
	}

	for _, c := range cases {
		var msg Message
		err := ParseMessage(&msg, c.Raw, true)
		if err != c.Error {
			t.Errorf("ParseMessage(%x) should error: %+v", c.Raw, c.Error)
		}
	}
}

// TestMessageEncodeDomain encodes textual domains into DNS labels.
func TestMessageEncodeDomain(t *testing.T) {
	var cases = []struct {
		Domain string
		QName  string
	}{
		{"phus.lu", "\x04phus\x02lu\x00"},
		{"splunk.phus.lu", "\x06splunk\x04phus\x02lu\x00"},
	}

	for _, c := range cases {
		if got, want := string(EncodeDomain(nil, c.Domain)), c.QName; got != want {
			t.Errorf("EncodeDomain(%v) error got=%#v want=%#v", c.Domain, got, want)
		}
	}
}

// TestMessageSetQuestion populates a request header and question section.
func TestMessageSetQuestion(t *testing.T) {
	req := AcquireMessage()
	defer ReleaseMessage(req)

	req.SetRequestQuestion("mail.google.com", TypeA, ClassINET)

	if req.Header.ID == 0 {
		t.Errorf("req.Header.ID should not empty after SetQuestion")
	}

	if got, want := req.Header.Flags, Flags(0b0000000100000000); got != want {
		t.Errorf("req.Header.Flags got=%x want=%x", got, want)
	}

	if got, want := req.Header.QDCount, uint16(1); got != want {
		t.Errorf("req.Header.QDCount got=%d want=%d", got, want)
	}

	if got, want := req.Header.ANCount, uint16(0); got != want {
		t.Errorf("req.Header.ANCount got=%d want=%d", got, want)
	}

	if got, want := req.Header.NSCount, uint16(0); got != want {
		t.Errorf("req.Header.NSCount got=%d want=%d", got, want)
	}

	if got, want := req.Header.ARCount, uint16(0); got != want {
		t.Errorf("req.Header.ARCount got=%d want=%d", got, want)
	}

	if got, want := string(req.Question.Name), "\x04mail\x06google\x03com\x00"; got != want {
		t.Errorf("req.Question.Name got=%s want=%s", got, want)
	}

	if got, want := req.Question.Type, TypeA; got != want {
		t.Errorf("req.Question.Type got=%s want=%s", got, want)
	}

	if got, want := req.Question.Class, ClassINET; got != want {
		t.Errorf("req.Question.Class got=%s want=%s", got, want)
	}

	if got, want := string(req.Domain), "mail.google.com"; got != want {
		t.Errorf("req.Question.Class got=%s want=%s", got, want)
	}
}

// TestMessageDecodeName follows compression pointers back to the canon name.
func TestMessageDecodeName(t *testing.T) {
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
		t.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	if got, want := string(resp.DecodeName(nil, []byte("\x04todd\xc0\x2a"))), "todd.ns.cloudflare.com"; got != want {
		t.Errorf("DecodeName(0xc02a) got=%s want=%s", got, want)
	}
}

func TestMessageDecodeNameError(t *testing.T) {
	payload := []byte{
		// ---- Header ----
		0x12, 0x34, // Transaction ID
		0x81, 0x80, // Flags: standard response, recursion available
		0x00, 0x01, // Questions = 1
		0x00, 0x01, // Answer RRs = 1
		0x00, 0x00, // Authority RRs = 0
		0x00, 0x00, // Additional RRs = 0
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
		0x03, 'c', 'o', 'm', // "com"
		0x00,       // end of QNAME
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = IN
		// NAME field using a forward pointer (invalid per RFC)
		0xc0, 0x2a, // pointer to offset 0x002A (points forward!)
		0x00, 0x01, // TYPE = A
		0x00, 0x01, // CLASS = IN
		0x00, 0x00, 0x00, 0x3c, // TTL = 60
		0x00, 0x04, // RDLENGTH = 4
		0x7f, 0x00, 0x00, 0x01, // RDATA = 127.0.0.1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // filler bytes
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // filler bytes
		0x00, 0x00, 0x00, 0x00, // filler bytes
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}

	resp := AcquireMessage()
	defer ReleaseMessage(resp)

	err := ParseMessage(resp, payload, true)
	if err != nil {
		t.Errorf("ParseMessage(%+v) error: %+v", payload, err)
	}

	records := resp.Records()
	for records.Next() {
		item := records.Item()
		switch item.Type {
		case TypeA, TypeAAAA:
			t.Logf("records.Next().Item()=%#v, Name=%#v\n", item, string(resp.DecodeName(nil, item.Name)))
		default:
			t.Errorf("records.Next().Item()=%#v Invalid Type: %s\n", item, item.Type)
		}
	}
}

// BenchmarkMessageParseMessage measures ParseMessage throughput.
func BenchmarkMessageParseMessage(b *testing.B) {
	payload := []byte{
		0x00, 0x02, // Transaction ID
		0x01, 0x00, // Flags: recursion desired
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x02, 'i', 'p',
		0x04, 'p', 'h', 'u', 's',
		0x02, 'l', 'u',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
	var msg Message

	for i := 0; i < b.N; i++ {
		if err := ParseMessage(&msg, payload, false); err != nil {
			b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
		}
	}
}

// BenchmarkMessageEncodeDomain measures EncodeDomain allocation behavior.
func BenchmarkMessageEncodeDomain(b *testing.B) {
	dst := make([]byte, 0, 256)
	for i := 0; i < b.N; i++ {
		dst = EncodeDomain(dst[:0], "ip.phus.lu")
	}
}

// BenchmarkMessageSetQuestion measures building questions repeatedly.
func BenchmarkMessageSetQuestion(b *testing.B) {
	req := AcquireMessage()
	defer ReleaseMessage(req)

	for i := 0; i < b.N; i++ {
		req.SetRequestQuestion("mail.google.com", TypeA, ClassINET)
	}
}

// BenchmarkMessageSetResponseHeader measures response header updates.
func BenchmarkMessageSetResponseHeader(b *testing.B) {
	req := AcquireMessage()
	defer ReleaseMessage(req)

	req.SetRequestQuestion("mail.google.com", TypeA, ClassINET)

	for i := 0; i < b.N; i++ {
		req.SetResponseHeader(RcodeNoError, 4)
	}
}

// BenchmarkMessageDecodeName measures compressed name decoding speed.
func BenchmarkMessageDecodeName(b *testing.B) {
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

	var dst [256]byte
	name := []byte("\x04todd\xc0\x2a")
	for i := 0; i < b.N; i++ {
		resp.DecodeName(dst[:0], name)
	}
}

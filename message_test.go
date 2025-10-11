package fastdns

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestParseMessageOK(t *testing.T) {
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
	cases[0].Raw, _ = hex.DecodeString("0001010000010000000000000131023530033136380331393207696e2d61646472046172706100000c0001")
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
		        hk.phus.lu: type A, class IN
		            Name: hk.phus.lu
		            [Name Length: 10]
		            [Label Count: 3]
		            Type: A (Host Address) (1)
		            Class: IN (0x0001)
	*/
	cases[1].Raw, _ = hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	cases[1].Message = AcquireMessage()
	cases[1].Message.Raw = cases[1].Raw
	cases[1].Message.Domain = []byte("hk.phus.lu")
	cases[1].Message.Header.ID = 0x0002
	cases[1].Message.Header.Flags = 0b0000000100000000
	cases[1].Message.Header.QDCount = 0x01
	cases[1].Message.Header.ANCount = 0x00
	cases[1].Message.Header.NSCount = 0x00
	cases[1].Message.Header.ARCount = 0x00
	cases[1].Message.Question.Name = []byte("\x02hk\x04phus\x02lu\x00")
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

func TestParseMessageError(t *testing.T) {
	var cases = []struct {
		Hex   string
		Error error
	}{
		{
			"0001010000010000000000",
			ErrInvalidHeader,
		},
		{
			"00020100000000000000000002686b0470687573026c7500000100",
			ErrInvalidHeader,
		},
		{
			"00020100000100000000000002686b0470687573026c7500000100",
			ErrInvalidQuestion,
		},
	}

	for _, c := range cases {
		payload, err := hex.DecodeString(c.Hex)
		if err != nil {
			t.Errorf("hex.DecodeString(%v) error: %+v", c.Hex, err)
		}
		var msg Message
		err = ParseMessage(&msg, payload, true)
		if err != c.Error {
			t.Errorf("ParseMessage(%x) should error: %+v", payload, c.Error)
		}
	}
}

func TestParseMessageOptions(t *testing.T) {
	var cases = []struct {
		Hex string
	}{
		{
			"42140120000100000000000107312d322d332d340269700470687573026c75000001000100002904d00000000000170008000700011800010203000a00083a3c5b8c233e045b",
		},
	}

	for _, c := range cases {
		payload, err := hex.DecodeString(c.Hex)
		if err != nil {
			t.Errorf("hex.DecodeString(%v) error: %+v\n", c.Hex, err)
		}
		msg := AcquireMessage()
		err = ParseMessage(msg, payload, true)
		if err != nil {
			t.Errorf("ParseMessage(%x) error: %+v\n", payload, err)
		}
		t.Logf("msg.Header=%+v, msg.Domain=%s\n", msg.Header, msg.Domain)
		records := msg.Records()
		for records.Next() {
			record := records.Item()
			t.Logf("msg.Records().Item()=%#v\n", record)
			if record.Type == TypeOPT {
				options, err := record.AsOptions()
				if err != nil {
					t.Errorf("ParseMessage(%x) error: %+v\n", payload, err)
				}
				t.Logf("msg.Records().AsOptions()=%+v\n", options)
				for options.Next() {
					option := options.Item()
					t.Logf("msg.Records().AsOptions().Item()=%#v\n", option)
					switch option.Code {
					case OptionCodeECS:
						subnet, err := option.AsSubnet()
						if err != nil {
							t.Errorf("msg.Records().AsOptions().Item().AsSubnet() error: %+v", err)
						}
						t.Logf("msg.Records().AsOptions().Item().AsSubnet(): %+v", subnet)
					case OptionCodeCOOKIE:
						cookie, err := option.AsCookie()
						if err != nil {
							t.Errorf("msg.Records().AsOptions().Item().AsCookie() error: %+v", err)
						}
						t.Logf("msg.Records().AsOptions().Item().AsCookie(): %#v", cookie)
					case OptionCodePadding:
						padding, err := option.AsPadding()
						if err != nil {
							t.Errorf("msg.Records().AsOptions().Item().AsPadding() error: %+v", err)
						}
						t.Logf("msg.Records().AsOptions().Item().AsPadding(): %#v", padding)
					}
				}
				if err = options.Err(); err != nil {
					t.Errorf("ParseMessage(%x) error: %+v\n", payload, err)
				}
			}
		}
		if err = records.Err(); err != nil {
			t.Errorf("ParseMessage(%x) error: %+v\n", payload, err)
		}
	}
}

func TestSetQuestion(t *testing.T) {
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

func TestDecodeName(t *testing.T) {
	payload, _ := hex.DecodeString("8e5281800001000200000000047632657803636f6d0000020001c00c000200010000545f0014036b696d026e730a636c6f7564666c617265c011c00c000200010000545f000704746f6464c02a")

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

func BenchmarkParseMessage(b *testing.B) {
	payload, _ := hex.DecodeString("00020100000100000000000002686b0470687573026c750000010001")
	var msg Message

	for i := 0; i < b.N; i++ {
		if err := ParseMessage(&msg, payload, false); err != nil {
			b.Errorf("ParseMessage(%+v) error: %+v", payload, err)
		}
	}
}

func BenchmarkSetQuestion(b *testing.B) {
	req := AcquireMessage()
	defer ReleaseMessage(req)

	for i := 0; i < b.N; i++ {
		req.SetRequestQuestion("mail.google.com", TypeA, ClassINET)
	}
}

func BenchmarkSetResponseHeader(b *testing.B) {
	req := AcquireMessage()
	defer ReleaseMessage(req)

	req.SetRequestQuestion("mail.google.com", TypeA, ClassINET)

	for i := 0; i < b.N; i++ {
		req.SetResponseHeader(RcodeNoError, 4)
	}
}

func BenchmarkDecodeName(b *testing.B) {
	payload, _ := hex.DecodeString("8e5281800001000200000000047632657803636f6d0000020001c00c000200010000545f0014036b696d026e730a636c6f7564666c617265c011c00c000200010000545f000704746f6464c02a")

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

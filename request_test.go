package fastdns

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestParseRequestOK(t *testing.T) {
	var cases = []struct {
		Hex     string
		Domain  string
		Request *Request
	}{
		{
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
			"0001010000010000000000000131023530033136380331393207696e2d61646472046172706100000c0001",
			"1.50.168.192.in-addr.arpa",
			&Request{
				Header{
					ID:      0x0001,
					QR:      0x00,
					Opcode:  0x0000,
					AA:      0x00,
					TC:      0x00,
					RD:      0x01,
					RA:      0x00,
					Z:       0x00,
					RCODE:   0x00,
					QDCount: 0x01,
					ANCount: 0x00,
					NSCount: 0x00,
					ARCount: 0x00,
				},
				Question{
					Name:  []byte("\x011\x0250\x03168\x03192\x07in-addr\x04arpa\x00"),
					Type:  TypePTR,
					Class: ClassINET,
				},
			},
		},
		{
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
			"00020100000100000000000002686b0470687573026c750000010001",
			"hk.phus.lu",
			&Request{
				Header{
					ID:      0x0002,
					QR:      0x00,
					Opcode:  0x0000,
					AA:      0x00,
					TC:      0x00,
					RD:      0x01,
					RA:      0x00,
					Z:       0x00,
					RCODE:   0x00,
					QDCount: 0x01,
					ANCount: 0x00,
					NSCount: 0x00,
					ARCount: 0x00,
				},
				Question{
					Name:  []byte("\x02hk\x04phus\x02lu\x00"),
					Type:  TypeA,
					Class: ClassINET,
				},
			},
		},
	}

	for _, c := range cases {
		payload, err := hex.DecodeString(c.Hex)
		if err != nil {
			t.Errorf("hex.DecodeString(%v) error: %+v", c.Hex, err)
		}
		req := AcquireRequest()
		err = ParseRequest(payload, req)
		if err != nil {
			t.Errorf("ParseRequest(%v) error: %+v", payload, err)
		}
		if got, want := req, c.Request; !reflect.DeepEqual(got, want) {
			t.Errorf("ParseRequest(%v) error got=%#v want=%#v", payload, got, want)
		}
		if got, want := req.GetDomainName(), c.Domain; got != want {
			t.Errorf("Request.GetDomainName(%v) error got=%#v want=%#v", req.Question.Name, got, want)
		}
		if got, want := string(req.AppendDomainName(nil)), c.Domain; got != want {
			t.Errorf("Request.GetDomainName(%v) error got=%#v want=%#v", req.Question.Name, got, want)
		}
		ReleaseRequest(req)
	}
}

func TestParseRequestError(t *testing.T) {
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
		var req Request
		err = ParseRequest(payload, &req)
		if err != c.Error {
			t.Errorf("ParseRequest(%v) should error: %+v", payload, c.Error)
		}
	}
}

func TestAppendRequest(t *testing.T) {
	var cases = []struct {
		Hex     string
		Request *Request
	}{
		{
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
			"0001010000010000000000000131023530033136380331393207696e2d61646472046172706100000c0001",
			&Request{
				Header{
					ID:      0x0001,
					QR:      0x00,
					Opcode:  0x0000,
					AA:      0x00,
					TC:      0x00,
					RD:      0x01,
					RA:      0x00,
					Z:       0x00,
					RCODE:   0x00,
					QDCount: 0x01,
					ANCount: 0x00,
					NSCount: 0x00,
					ARCount: 0x00,
				},
				Question{
					Name:  []byte("\x011\x0250\x03168\x03192\x07in-addr\x04arpa\x00"),
					Type:  TypePTR,
					Class: ClassINET,
				},
			},
		},
		{
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
			"00020100000100000000000002686b0470687573026c750000010001",
			&Request{
				Header{
					ID:      0x0002,
					QR:      0x00,
					Opcode:  0x0000,
					AA:      0x00,
					TC:      0x00,
					RD:      0x01,
					RA:      0x00,
					Z:       0x00,
					RCODE:   0x00,
					QDCount: 0x01,
					ANCount: 0x00,
					NSCount: 0x00,
					ARCount: 0x00,
				},
				Question{
					Name:  []byte("\x02hk\x04phus\x02lu\x00"),
					Type:  TypeA,
					Class: ClassINET,
				},
			},
		},
	}

	for _, c := range cases {
		if got, want := hex.EncodeToString(AppendRequest(nil, c.Request)), c.Hex; got != want {
			t.Errorf("AppendRequest(%v) error got=%#v want=%#v", c.Request, got, want)
		}
	}
}

package fastdns

import (
	"net"
	"testing"
)

func TestTransportRoundTrip(t *testing.T) {
	var cases = []struct {
		Request *Message
	}{
		{
			/*
				Domain Name System (query)
				    Transaction ID: 0x0002
				    Flags: 0x0100 Standard query
				        0... .... .... .... = Response: Message is a query
				        .000 0... .... .... = Opcode: Standard wwquery (0)
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
			&Message{
				[]byte("\x52\x4c\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x04\x70\x68\x75\x73\x02\x6c\x75\x00\x00\x01\x00\x01"),
				[]byte("hk.phus.lu"),
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

	tr := &Transport{
		Address:  &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53},
		MaxConns: 1000,
	}

	for _, c := range cases {
		resp := AcquireMessage()
		err := tr.RoundTrip(c.Request, resp)
		if err != nil {
			t.Errorf("transport=%+v roundtrip(%v) error: %+v\n", tr, c.Request, err)
		}
		t.Logf("%s: CLASS %s TYPE %s\n", resp.Domain, resp.Question.Class, resp.Question.Type)
	}
}

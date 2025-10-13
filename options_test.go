package fastdns

import (
	"encoding/hex"
	"testing"
)

// TestMessageParseMessageOptions parses an OPT record and decodes its options.
func TestMessageParseMessageOptions(t *testing.T) {
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

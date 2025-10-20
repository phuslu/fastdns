package fastdns

import (
	"testing"
)

// TestMessageParseMessageOptions parses an OPT record and decodes its options.
func TestMessageParseMessageOptions(t *testing.T) {
	var cases = []struct {
		Raw []byte
	}{
		{
			Raw: []byte{
				0x42, 0x14, // Transaction ID
				0x01, 0x20, // Flags: recursion desired + EDNS
				0x00, 0x01, // Questions
				0x00, 0x00, // Answer RRs
				0x00, 0x00, // Authority RRs
				0x00, 0x01, // Additional RRs
				0x07, '1', '-', '2', '-', '3', '-', '4',
				0x02, 'i', 'p',
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
				0x00, 0x01, // QTYPE A
				0x00, 0x01, // QCLASS IN
				0x00, 0x00, // NAME (root) for OPT
				0x00, 0x29, // TYPE OPT
				0x04, 0xd0, // UDP payload size 1232
				0x00, 0x00, // Higher bits / extended RCODE
				0x00, 0x00, // Version, DO bit
				0x00, 0x17, // RDLENGTH 23
				0x00, 0x08, // OPTION: ECS (code 8)
				0x00, 0x07, // OPTION-LENGTH 7
				0x00, 0x01, 0x18, // FAMILY 1, SOURCE PREFIX 24
				0x00, 0x01, 0x02, 0x03, // ADDRESS 1.2.3.0/24
				0x00, 0x0a, // OPTION: COOKIE (code 10)
				0x00, 0x08, // OPTION-LENGTH 8
				0x3a, 0x3c, 0x5b, 0x8c, 0x23, 0x3e, 0x04, 0x5b, // COOKIE value
			},
		},
	}

	for _, c := range cases {
		msg := AcquireMessage()
		err := ParseMessage(msg, c.Raw, true)
		if err != nil {
			t.Errorf("ParseMessage(%x) error: %+v\n", c.Raw, err)
		}
		t.Logf("msg.Header=%+v, msg.Domain=%s\n", msg.Header, msg.Domain)
		records := msg.Records()
		for records.Next() {
			record := records.Item()
			t.Logf("msg.Records().Item()=%#v\n", record)
			if record.Type == TypeOPT {
				options, err := record.AsOptions()
				if err != nil {
					t.Errorf("ParseMessage(%x) error: %+v\n", c.Raw, err)
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
						if subnet.String() != "1.2.3.0/24" {
							t.Errorf("msg.Records().AsOptions().Item().AsSubnet() error: %+v", subnet)
						}
						t.Logf("msg.Records().AsOptions().Item().AsSubnet(): %+v", subnet)
					case OptionCodeCOOKIE:
						cookie, err := option.AsCookie(nil)
						if err != nil {
							t.Errorf("msg.Records().AsOptions().Item().AsCookie() error: %+v", err)
						}
						if string(cookie) != ":<[\x8c#>\x04[" {
							t.Errorf("msg.Records().AsOptions().Item().AsSubnet() error: %+v", string(cookie))
						}
						t.Logf("msg.Records().AsOptions().Item().AsCookie(): %#v", string(cookie))
					case OptionCodePadding:
						padding, err := option.AsPadding(nil)
						if err != nil {
							t.Errorf("msg.Records().AsOptions().Item().AsPadding() error: %+v", err)
						}
						t.Logf("msg.Records().AsOptions().Item().AsPadding(): %#v", string(padding))
					}
				}
				if err = options.Err(); err != nil {
					t.Errorf("ParseMessage(%x) error: %+v\n", c.Raw, err)
				}
			}
		}
		if err = records.Err(); err != nil {
			t.Errorf("ParseMessage(%x) error: %+v\n", c.Raw, err)
		}
	}
}

func TestMessageMessageOptionsAppendPadding(t *testing.T) {
	var cases = []struct {
		Raw []byte
	}{
		{
			Raw: []byte{
				0x42, 0x14, // Transaction ID
				0x01, 0x20, // Flags: recursion desired + EDNS
				0x00, 0x01, // Questions
				0x00, 0x00, // Answer RRs
				0x00, 0x00, // Authority RRs
				0x00, 0x01, // Additional RRs
				0x07, '1', '-', '2', '-', '3', '-', '4',
				0x02, 'i', 'p',
				0x04, 'p', 'h', 'u', 's',
				0x02, 'l', 'u',
				0x00,
				0x00, 0x01, // QTYPE A
				0x00, 0x01, // QCLASS IN
				0x00, 0x00, // NAME (root) for OPT
				0x00, 0x29, // TYPE OPT
				0x04, 0xd0, // UDP payload size 1232
				0x00, 0x00, // Higher bits / extended RCODE
				0x00, 0x00, // Version, DO bit
				0x00, 0x17, // RDLENGTH 23
				0x00, 0x08, // OPTION: ECS (code 8)
				0x00, 0x07, // OPTION-LENGTH 7
				0x00, 0x01, 0x18, // FAMILY 1, SOURCE PREFIX 24
				0x00, 0x01, 0x02, 0x03, // ADDRESS 1.2.3.0/24
				0x00, 0x0a, // OPTION: COOKIE (code 10)
				0x00, 0x08, // OPTION-LENGTH 8
				0x3a, 0x3c, 0x5b, 0x8c, 0x23, 0x3e, 0x04, 0x5b, // COOKIE value
			},
		},
	}

	for _, c := range cases {
		msg := AcquireMessage()
		err := ParseMessage(msg, c.Raw, true)
		if err != nil {
			t.Errorf("ParseMessage(%x) error: %+v\n", c.Raw, err)
		}
		moa, err := msg.OptionsAppender()
		if err != nil {
			t.Errorf("msg.OptionsAppender() error: %+v\n", err)
		}
		t.Logf("msg.Header=%+v, msg.Domain=%s, len(msg.Raw)=%d\n", msg.Header, msg.Domain, len(msg.Raw))
		moa.AppendPadding(128)
		if len(msg.Raw)%128 != 0 {
			t.Errorf("msg.Header=%+v, msg.Domain=%s, len(msg.Raw)=%d\n", msg.Header, msg.Domain, len(msg.Raw))
		}
		t.Logf("msg.Header=%+v, msg.Domain=%s, len(msg.Raw)=%d\n", msg.Header, msg.Domain, len(msg.Raw))
	}
}

package fastdns

import (
	"testing"
)

func TestDecodeQName(t *testing.T) {
	var cases = []struct {
		Domain string
		QName  string
	}{
		{"phus.lu", "\x04phus\x02lu\x00"},
		{"splunk.phus.lu", "\x06splunk\x04phus\x02lu\x00"},
	}

	for _, c := range cases {
		if got, want := string(decodeQName(nil, []byte(c.QName))), c.Domain; got != want {
			t.Errorf("decodeQName(%v) error got=%s want=%s", c.QName, got, want)
		}
	}
}

func TestEncodeDomain(t *testing.T) {
	var cases = []struct {
		Domain string
		QName  string
	}{
		{"phus.lu", "\x04phus\x02lu\x00"},
		{"splunk.phus.lu", "\x06splunk\x04phus\x02lu\x00"},
	}

	for _, c := range cases {
		if got, want := string(encodeDomain(nil, c.Domain)), c.QName; got != want {
			t.Errorf("encodeDomain(%v) error got=%s want=%s", c.Domain, got, want)
		}
	}
}

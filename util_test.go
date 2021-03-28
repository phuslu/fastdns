package fastdns

import (
	"runtime"
	"testing"
)

func TestDecodeQName(t *testing.T) {
	var cases = []struct {
		Domain string
		QName  string
	}{
		{"", "\x00"},
		{"phus.lu", "\x04phus\x02lu\x00"},
		{"splunk.phus.lu", "\x06splunk\x04phus\x02lu\x00"},
	}

	for _, c := range cases {
		if got, want := string(decodeQName(nil, []byte(c.QName))), c.Domain; got != want {
			t.Errorf("decodeQName(%v) error got=%#v want=%#v", c.QName, got, want)
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
			t.Errorf("encodeDomain(%v) error got=%#v want=%#v", c.Domain, got, want)
		}
	}
}

func TestListen(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}

	_, err := listen("udp", ":65537")
	if err == nil {
		t.Errorf("listen(:65537) at shall return error but empty")
	}

	var addr = ":19841"
	for i := 1; i <= 64; i++ {
		_, err := listen("udp", addr)
		if err != nil {
			t.Errorf("listen(%+v) at %d times got error: %+v", addr, i, err)
		}
	}
}

func TestTastset(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}

	err := taskset(1023)
	if err == nil {
		t.Errorf("taskset(65537) shall return error but empty")
	}

	err = taskset(0)
	if err != nil {
		t.Errorf("taskset(0) error: %+v", err)
	}
}

func BenchmarkDecodeQName(b *testing.B) {
	qname := []byte("\x02hk\x04phus\x02lu\x00")
	dst := make([]byte, 0, 256)
	for i := 0; i < b.N; i++ {
		dst = decodeQName(dst[:0], qname)
	}
}

func BenchmarkEncodeDomain(b *testing.B) {
	dst := make([]byte, 0, 256)
	for i := 0; i < b.N; i++ {
		dst = encodeDomain(dst[:0], "hk.phus.lu")
	}
}

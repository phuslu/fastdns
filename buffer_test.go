package fastdns

import (
	"fmt"
	"strings"
	"testing"
)

func TestByteBufferPool(t *testing.T) {
	const s = "hello world"

	b := AcquireByteBuffer()
	b.B = append(b.B[:0], s...)
	ReleaseByteBuffer(b)

	b = AcquireByteBuffer()
	if string(b.B) != s {
		t.Errorf("bytebuffer pool not working")
	}
	ReleaseByteBuffer(b)
}

func TestByteBufferOversize(t *testing.T) {
	var s = strings.Repeat("1", 65537)

	b := AcquireByteBuffer()
	b.B = append(b.B[:0], s...)
	ReleaseByteBuffer(b)

	b = AcquireByteBuffer()
	if string(b.B) != "" {
		t.Errorf("bytebuffer pool recyled a oversize buffer")
	}
	ReleaseByteBuffer(b)
}

func TestByteBufferPrintf(t *testing.T) {
	b := AcquireByteBuffer()
	b.B = b.B[:0]
	defer ReleaseByteBuffer(b)

	_, _ = fmt.Fprintf(b, "a=%s b=%d", "x", 42)

	if string(b.B) != "a=x b=42" {
		t.Errorf("bytebuffer printf result error: %s", b.B)
	}
}

func TestByteBufferWriteTo(t *testing.T) {
	b := AcquireByteBuffer()
	b.B = b.B[:0]
	defer ReleaseByteBuffer(b)

	b.B = append(b.B, "hello world"...)
	var sb strings.Builder

	_, err := b.WriteTo(&sb)
	if err != nil {
		t.Errorf("bytebuffer copy result error: %+v", err)
	}

	if string(b.B) != "hello world" {
		t.Errorf("bytebuffer copy result error: %s", b.B)
	}
}

type brokenReader struct{}

func (r *brokenReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("a reader error")
}

func TestByteBufferReadFrom(t *testing.T) {
	s := strings.Repeat("1", 2049)

	b := new(ByteBuffer)
	_, err := b.ReadFrom(strings.NewReader(s))
	if err != nil {
		t.Errorf("bytebuffer ReadFrom result error: %+v", err)
	}
	if string(b.B) != s {
		t.Errorf("bytebuffer ReadFrom result error: %s", b.B)
	}

	b.B = make([]byte, 0, 1024)
	_, err = b.ReadFrom(strings.NewReader(s))
	if err != nil {
		t.Errorf("bytebuffer ReadFrom result error: %+v", err)
	}
	if string(b.B) != s {
		t.Errorf("bytebuffer ReadFrom result error: %s", b.B)
	}

	b = new(ByteBuffer)
	_, err = b.ReadFrom(&brokenReader{})
	if err == nil {
		t.Errorf("bytebuffer ReadFrom result nil error")
	}
}

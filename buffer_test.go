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

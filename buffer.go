package fastdns

import (
	"sync"
)

type ByteBuffer struct {
	B []byte
}

func (b *ByteBuffer) Write(p []byte) (int, error) {
	b.B = append(b.B, p...)
	return len(p), nil
}

var bytesBufferPool = sync.Pool{
	New: func() interface{} {
		return &ByteBuffer{
			B: make([]byte, 0, 1024),
		}
	},
}

func AcquireByteBuffer() *ByteBuffer {
	return bytesBufferPool.Get().(*ByteBuffer)
}

func ReleaseByteBuffer(b *ByteBuffer) {
	// see https://github.com/golang/go/issues/23199
	if len(b.B) > 65536 {
		return
	}
	bytesBufferPool.Put(b)
}

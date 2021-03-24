package fastdns

import (
	"io"
	"sync"
)

// ByteBuffer provides byte buffer, which can be used for minimizing
// memory allocations.
//
// ByteBuffer may be used with functions appending data to the given []byte
// slice. See example code for details.
//
// Use Get for obtaining an empty byte buffer.
type ByteBuffer struct {

	// B is a byte buffer to use in append-like workloads.
	// See example code for details.
	B []byte
}

// ReadFrom implements io.ReaderFrom.
//
// The function appends all the data read from r to b.
func (b *ByteBuffer) ReadFrom(r io.Reader) (int64, error) {
	p := b.B
	nStart := int64(len(p))
	nMax := int64(cap(p))
	n := nStart
	if nMax == 0 {
		nMax = 64
		p = make([]byte, nMax)
	} else {
		p = p[:nMax]
	}
	for {
		if n == nMax {
			nMax *= 2
			bNew := make([]byte, nMax)
			copy(bNew, p)
			p = bNew
		}
		nn, err := r.Read(p[n:])
		n += int64(nn)
		if err != nil {
			b.B = p[:n]
			n -= nStart
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}
	}
}

// WriteTo implements io.WriterTo.
func (b *ByteBuffer) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(b.B)
	return int64(n), err
}

// Write implements io.Writer - it appends p to ByteBuffer.B
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

// AcquireByteBuffer returns new byte buffer.
//
// The byte buffer may be returned to the pool via Put after the use
// in order to minimize GC overhead.
func AcquireByteBuffer() *ByteBuffer {
	return bytesBufferPool.Get().(*ByteBuffer)
}

// ReleaseByteBuffer returnes the byte buffer to the pool.
func ReleaseByteBuffer(b *ByteBuffer) {
	// see https://github.com/golang/go/issues/23199
	if len(b.B) > 65536 {
		return
	}
	bytesBufferPool.Put(b)
}

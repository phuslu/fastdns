package fastdns

type Handler interface {
	ServeDNS(rw ResponseWriter, req *Request)
}

func Error(rw ResponseWriter, req *Request, code RCODE) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	b.B = AppendRequestToResponse(b.B[:0], req, code, 0, 0, 0, 0)

	_, _ = rw.Write(b.B)
}

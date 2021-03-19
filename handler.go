package fastdns

type Handler interface {
	ServeDNS(rw ResponseWriter, req *Request)
}

func Error(rw ResponseWriter, req *Request, code RCODE) {
	b := AcquireByteBuffer()
	defer ReleaseByteBuffer(b)

	req.Header.QR = 1
	req.Header.RCODE = code
	req.Header.QDCount = 0
	b.B = AppendRequest(b.B[:0], req)

	rw.Write(b.B)
}

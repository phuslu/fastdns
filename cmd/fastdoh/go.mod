module main

go 1.22

require (
	github.com/phuslu/fastdns v1.0.0
	github.com/valyala/bytebufferpool v1.0.0
	github.com/valyala/fasthttp v1.56.0
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
)

replace github.com/phuslu/fastdns => ../..

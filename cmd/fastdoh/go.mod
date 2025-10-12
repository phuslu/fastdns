module main

go 1.24.0

require (
	github.com/phuslu/fastdns v1.0.0
	github.com/valyala/bytebufferpool v1.0.0
	github.com/valyala/fasthttp v1.67.0
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
)

replace github.com/phuslu/fastdns => ../..

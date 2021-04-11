package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/phuslu/fastdns"
)

func main() {
	var qtype, domain, server string

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "" {
			continue
		}
		switch arg[0] {
		case '@':
			server = arg[1:]
		case '+', '-':
			fmt.Fprintf(os.Stderr, "unsupport parameter: %#v\n", arg)
			os.Exit(1)
		default:
			if domain == "" {
				qtype, domain = "", arg
			} else {
				qtype, domain = domain, arg
			}
		}
	}
	if server == "" {
		server = "8.8.8.8"
	}

	client := &fastdns.Client{
		ServerAddr:  &net.UDPAddr{IP: net.ParseIP(server), Port: 53},
		ReadTimeout: 2 * time.Second,
		MaxConns:    1000,
	}

	req := fastdns.AcquireMessage()
	defer fastdns.ReleaseMessage(req)

	if qtype != "" {
		req.SetQustion(domain, fastdns.ParseType(qtype), fastdns.ClassINET)
	} else {
		req.SetQustion(domain, fastdns.TypeA, fastdns.ClassINET)
	}

	resp := fastdns.AcquireMessage()
	defer fastdns.ReleaseMessage(resp)

	start := time.Now()
	err := client.Exchange(req, resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client=%+v exchange(\"%s\") error: %+v\n", client, domain, err)
		os.Exit(1)
	}
	end := time.Now()

	cmd(req, resp, server, end.Sub(start))
}

func cmd(req, resp *fastdns.Message, server string, dur time.Duration) {
	var flags string
	for _, f := range []struct {
		b byte
		s string
	}{
		{resp.Header.Bits.QR(), "qr"},
		{resp.Header.Bits.AA(), "aa"},
		{resp.Header.Bits.TC(), "tc"},
		{resp.Header.Bits.RD(), "rd"},
		{resp.Header.Bits.RA(), "ra"},
	} {
		if f.b == 0 {
			continue
		}
		flags += f.s + " "
	}
	flags = strings.TrimSpace(flags)

	fmt.Printf("\n")
	fmt.Printf("; <<>> DiG 0.0.1-Fastdns <<>> %s %s +noedns\n", req.Question.Type, req.Domain)
	fmt.Printf(";; global options: +cmd\n")
	fmt.Printf(";; Got answer:\n")
	fmt.Printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %d\n",
		resp.Header.Bits.Opcode(), resp.Header.Bits.Rcode(), resp.Header.ID)
	fmt.Printf(";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
		flags, resp.Header.QDCount, resp.Header.ANCount, resp.Header.NSCount, resp.Header.ARCount)

	fmt.Printf("\n")
	// fmt.Printf(";; OPT PSEUDOSECTION:\n")
	// fmt.Printf("; EDNS: version: 0, flags:; udp: 512\n")
	fmt.Printf(";; QUESTION SECTION:\n")
	fmt.Printf(";%s.		%s	%s\n", req.Domain, req.Question.Class, req.Question.Type)

	fmt.Printf("\n")
	if resp.Header.ANCount > 0 {
		fmt.Printf(";; ANSWER SECTION:\n")
	} else {
		fmt.Printf(";; AUTHORITY SECTION:\n")
	}
	_ = resp.VisitResourceRecords(func(name []byte, typ fastdns.Type, class fastdns.Class, ttl uint32, data []byte) bool {
		var v interface{}
		switch typ {
		case fastdns.TypeA, fastdns.TypeAAAA:
			v = net.IP(data)
		case fastdns.TypeCNAME, fastdns.TypeNS:
			v = resp.DecodeName(nil, data)
		case fastdns.TypeTXT:
			v = fmt.Sprintf("\"%s\"", data[1:])
		default:
			v = fmt.Sprintf("%x", data)
		}
		fmt.Printf("%s.	%d	%s	%s	%s\n", resp.DecodeName(nil, name), ttl, class, typ, v)
		return true
	})

	fmt.Printf("\n")
	fmt.Printf(";; Query time: %d msec\n", dur/time.Millisecond)
	fmt.Printf(";; SERVER: %s#53(%s)\n", server, server)
	fmt.Printf(";; WHEN: %s\n", time.Now().Format(time.UnixDate))
	fmt.Printf(";; MSG SIZE  rcvd: %d\n", len(resp.Raw))
	fmt.Printf("\n")
}
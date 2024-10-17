package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/phuslu/fastdns"
)

func main() {
	domain, qtype, server, options := parse(os.Args[1:])
	var client *fastdns.Client
	if strings.HasPrefix(server, "https://") {
		client = &fastdns.Client{
			DialContext: (&fastdns.HTTPDialer{
				Endpoint:  server,
				UserAgent: "fastdig/0.9",
			}).DialContext,
		}
	} else {
		client = &fastdns.Client{
			AddrPort: netip.AddrPortFrom(netip.MustParseAddr(server), 53),
			Timeout:  2 * time.Second,
			MaxConns: 1000,
		}
	}

	req, resp := fastdns.AcquireMessage(), fastdns.AcquireMessage()
	defer fastdns.ReleaseMessage(req)
	defer fastdns.ReleaseMessage(resp)

	req.SetRequestQuestion(domain, fastdns.ParseType(qtype), fastdns.ClassINET)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err := client.Exchange(ctx, req, resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client=%+v exchange(\"%s\") error: %+v\n", client, domain, err)
		os.Exit(1)
	}
	end := time.Now()

	if opt("raw", options) {
		fmt.Printf("%x\n", resp.Raw)
	}

	if opt("short", options) {
		short(resp)
	} else {
		cmd(req, resp, server, start, end)
	}
}

func parse(args []string) (domain, qtype, server string, options []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" {
			continue
		}
		switch arg[0] {
		case '@':
			server = arg[1:]
		case '+':
			options = append(options, arg[1:])
		default:
			if domain == "" {
				domain = arg
			} else {
				qtype = arg
			}
		}
	}
	if server == "" {
		server = "https://1.1.1.1/dns-query"
	}
	if qtype == "" {
		qtype = "A"
	}
	if fastdns.ParseType(qtype) == 0 && fastdns.ParseType(domain) != 0 {
		domain, qtype = qtype, domain
	}
	return
}

func opt(option string, options []string) bool {
	for _, s := range options {
		if s == option {
			return true
		}
	}
	return false
}

func short(resp *fastdns.Message) {
	_ = resp.Walk(func(name []byte, typ fastdns.Type, class fastdns.Class, ttl uint32, data []byte) bool {
		var v interface{}
		switch typ {
		case fastdns.TypeA, fastdns.TypeAAAA:
			v, _ = netip.AddrFromSlice(data)
		case fastdns.TypeCNAME, fastdns.TypeNS:
			v = fmt.Sprintf("%s.", resp.DecodeName(nil, data))
		case fastdns.TypeMX:
			v = fmt.Sprintf("%d %s.", binary.BigEndian.Uint16(data), resp.DecodeName(nil, data[2:]))
		case fastdns.TypeTXT:
			v = fmt.Sprintf("\"%s\"", data[1:])
		case fastdns.TypeSRV:
			priority := binary.BigEndian.Uint16(data)
			weight := binary.BigEndian.Uint16(data[2:])
			port := binary.BigEndian.Uint16(data[4:])
			target := resp.DecodeName(nil, data[6:])
			v = fmt.Sprintf("%d %d %d %s.", priority, weight, port, target)
		case fastdns.TypeSOA:
			var mname []byte
			for i, b := range data {
				if b == 0 {
					mname = data[:i+1]
					break
				} else if b&0b11000000 == 0b11000000 {
					mname = data[:i+2]
					break
				}
			}
			nname := resp.DecodeName(nil, data[len(mname):len(data)-20])
			mname = resp.DecodeName(nil, mname)
			serial := binary.BigEndian.Uint32(data[len(data)-20:])
			refresh := binary.BigEndian.Uint32(data[len(data)-16:])
			retry := binary.BigEndian.Uint32(data[len(data)-12:])
			expire := binary.BigEndian.Uint32(data[len(data)-8:])
			minimum := binary.BigEndian.Uint32(data[len(data)-4:])
			v = fmt.Sprintf("%s. %s. %d %d %d %d %d", mname, nname, serial, refresh, retry, expire, minimum)
		default:
			v = fmt.Sprintf("%x", data)
		}
		fmt.Printf("%s\n", v)
		return true
	})
}

func cmd(req, resp *fastdns.Message, server string, start, end time.Time) {
	var flags string
	for _, f := range []struct {
		b byte
		s string
	}{
		{resp.Header.Flags.QR(), "qr"},
		{resp.Header.Flags.AA(), "aa"},
		{resp.Header.Flags.TC(), "tc"},
		{resp.Header.Flags.RD(), "rd"},
		{resp.Header.Flags.RA(), "ra"},
	} {
		if f.b == 0 {
			continue
		}
		flags += f.s + " "
	}
	flags = strings.TrimSpace(flags)

	fmt.Printf("\n")
	fmt.Printf("; <<>> DiG 0.0.1-fastdns-%s <<>> %s\n", runtime.Version(), req.Domain)
	fmt.Printf(";; global options: +cmd +noedns\n")
	fmt.Printf(";; Got answer:\n")
	fmt.Printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %d\n",
		strings.ToUpper(resp.Header.Flags.Opcode().String()), strings.ToUpper(resp.Header.Flags.Rcode().String()), resp.Header.ID)
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
	_ = resp.Walk(func(name []byte, typ fastdns.Type, class fastdns.Class, ttl uint32, data []byte) bool {
		var v interface{}
		switch typ {
		case fastdns.TypeA, fastdns.TypeAAAA:
			v, _ = netip.AddrFromSlice(data)
		case fastdns.TypeCNAME, fastdns.TypeNS:
			v = fmt.Sprintf("%s.", resp.DecodeName(nil, data))
		case fastdns.TypeMX:
			v = fmt.Sprintf("%d %s.", binary.BigEndian.Uint16(data), resp.DecodeName(nil, data[2:]))
		case fastdns.TypeTXT:
			v = fmt.Sprintf("\"%s\"", data[1:])
		case fastdns.TypeSRV:
			priority := binary.BigEndian.Uint16(data)
			weight := binary.BigEndian.Uint16(data[2:])
			port := binary.BigEndian.Uint16(data[4:])
			target := resp.DecodeName(nil, data[6:])
			v = fmt.Sprintf("%d %d %d %s.", priority, weight, port, target)
		case fastdns.TypeSOA:
			var mname []byte
			for i, b := range data {
				if b == 0 {
					mname = data[:i+1]
					break
				} else if b&0b11000000 == 0b11000000 {
					mname = data[:i+2]
					break
				}
			}
			nname := resp.DecodeName(nil, data[len(mname):len(data)-20])
			mname = resp.DecodeName(nil, mname)
			serial := binary.BigEndian.Uint32(data[len(data)-20:])
			refresh := binary.BigEndian.Uint32(data[len(data)-16:])
			retry := binary.BigEndian.Uint32(data[len(data)-12:])
			expire := binary.BigEndian.Uint32(data[len(data)-8:])
			minimum := binary.BigEndian.Uint32(data[len(data)-4:])
			v = fmt.Sprintf("%s. %s. %d %d %d %d %d", mname, nname, serial, refresh, retry, expire, minimum)
		default:
			v = fmt.Sprintf("%x", data)
		}
		fmt.Printf("%s.	%d	%s	%s	%s\n", resp.DecodeName(nil, name), ttl, class, typ, v)
		return true
	})

	fmt.Printf("\n")
	fmt.Printf(";; Query time: %d msec\n", end.Sub(start)/time.Millisecond)
	fmt.Printf(";; SERVER: %s#53(%s)\n", server, server)
	fmt.Printf(";; WHEN: %s\n", start.Format("Mon Jan 02 15:04:05 MST 2006"))
	fmt.Printf(";; MSG SIZE  rcvd: %d\n", len(resp.Raw))
	fmt.Printf("\n")
}

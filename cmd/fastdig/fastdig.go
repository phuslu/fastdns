package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/phuslu/fastdns"
)

func main() {
	domain, qtype, server, options := parse(os.Args[1:])

	client := &fastdns.Client{
		ServerAddr:  &net.UDPAddr{IP: net.ParseIP(server), Port: 53},
		ReadTimeout: 2 * time.Second,
		MaxConns:    1000,
	}

	req, resp := fastdns.AcquireMessage(), fastdns.AcquireMessage()
	defer fastdns.ReleaseMessage(req)
	defer fastdns.ReleaseMessage(resp)

	req.SetQustion(domain, fastdns.ParseType(qtype), fastdns.ClassINET)

	start := time.Now()
	err := client.Exchange(req, resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client=%+v exchange(\"%s\") error: %+v\n", client, domain, err)
		os.Exit(1)
	}
	end := time.Now()

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
		server = "8.8.8.8"
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
	_ = resp.VisitResourceRecords(func(name []byte, typ fastdns.Type, class fastdns.Class, ttl uint32, data []byte) bool {
		var v interface{}
		switch typ {
		case fastdns.TypeA, fastdns.TypeAAAA:
			v = net.IP(data)
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
	fmt.Printf("; <<>> DiG 0.0.1-Fastdns <<>> %s %s\n", req.Question.Type, req.Domain)
	fmt.Printf(";; global options: +cmd +noedns\n")
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
	fmt.Printf(";; WHEN: %s\n", start.Format(time.UnixDate))
	fmt.Printf(";; MSG SIZE  rcvd: %d\n", len(resp.Raw))
	fmt.Printf("\n")
}

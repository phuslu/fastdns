package fastdns

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

func TestHTTPHandlerHost(t *testing.T) {
	testMode = true

	const addr = "127.0.0.1:40053"

	go func() {
		h := &mockServerHandler{}
		err := http.ListenAndServe(addr, HTTPHandlerFunc(h))
		if err != nil {
			t.Errorf("http listen %+v error: %+v", addr, err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	query := "00020100000100000000000002686b0470687573026c750000010001"

	body, _ := hex.DecodeString(query)
	resp, err := http.Post("http://"+addr, "application/dns-message", bytes.NewReader(body))
	if err != nil {
		t.Errorf("post query=%s return error: %+v", query, err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("read http response error: %+v", err)
	}

	t.Logf("%x\n", data)

	// ips, err := resolver.LookupHost(context.Background(), "example.org")
	// if err != nil {
	// 	t.Errorf("LookupHost return error: %+v", err)
	// }
	// if ips[0] != "1.1.1.1" {
	// 	t.Errorf("LookupHost return mismatched reply: %+v", ips)
	// }
}

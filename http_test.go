package fastdns

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"
)

func allocAddr() string {
	for i := 20001; i < 50000; i++ {
		addr := fmt.Sprintf("127.0.0.1:%d", i)
		conn, err := net.Listen("tcp", addr)
		if err == nil {
			conn.Close()
			return addr
		}
	}
	return ""
}

func TestHTTPHandlerHost(t *testing.T) {
	addr := allocAddr()
	if addr == "" {
		t.Errorf("allocAddr() failed.")
	}

	go func() {
		h := &mockServerHandler{}
		err := http.ListenAndServe(addr, HTTPHandlerFunc(h))
		if err != nil {
			t.Errorf("http listen %+v error: %+v", addr, err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	query := "00020100000100000000000002686b0470687573026c750000010001"
	reply := "00028100000100010000000002686b0470687573026c750000010001c00c000100010000012c000401010101"

	body, _ := hex.DecodeString(query)
	resp, err := http.Post("http://"+addr, "application/dns-message", bytes.NewReader(body))
	if err != nil {
		t.Errorf("post query=%s return error: %+v", query, err)
	} else {
		defer resp.Body.Close()
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("read http response error: %+v", err)
	}

	if hex.EncodeToString(data) != reply {
		t.Errorf("read http response mismatched, got: %x", data)
	}
}

func TestHTTPHandlerError(t *testing.T) {
	addr := allocAddr()
	if addr == "" {
		t.Errorf("allocAddr() failed.")
	}

	go func() {
		h := &mockServerHandler{}
		err := http.ListenAndServe(addr, HTTPHandlerFunc(h))
		if err != nil {
			t.Errorf("http listen %+v error: %+v", addr, err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	query := "00020100000000000000000002686b0470687573026c750000010001"

	body, _ := hex.DecodeString(query)
	resp, err := http.Post("http://"+addr, "application/dns-message", bytes.NewReader(body))
	if err != nil {
		t.Errorf("post query=%s return error: %+v", query, err)
	} else {
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("post query=%s shall return 400 status code, got: %d", query, resp.StatusCode)
	}
}

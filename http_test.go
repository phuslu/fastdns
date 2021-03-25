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

	const addr = "127.0.1.1:53001"

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
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("read http response error: %+v", err)
	}

	if hex.EncodeToString(data) != reply {
		t.Errorf("read http response mismatched, got: %x", data)
	}
}

func TestHTTPHandlerError(t *testing.T) {
	testMode = true

	const addr = "127.0.1.1:53002"

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
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("post query=%s shall return 400 status code, got: %d", query, resp.StatusCode)
	}
}

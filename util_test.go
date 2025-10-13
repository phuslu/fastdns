package fastdns

import (
	"runtime"
	"testing"
)

// TestUtilListen validates UDP listen behavior and error handling.
func TestUtilListen(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}

	_, err := listen("udp", ":65537")
	if err == nil {
		t.Errorf("listen(:65537) at shall return error but empty")
	}

	var addr = ":19841"
	for i := 1; i <= 64; i++ {
		_, err := listen("udp", addr)
		if err != nil {
			t.Errorf("listen(%+v) at %d times got error: %+v", addr, i, err)
		}
	}
}

// TestUtilTastset exercises CPU affinity setting on Linux.
func TestUtilTastset(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}

	err := taskset(1023)
	if err == nil {
		t.Errorf("taskset(65537) shall return error but empty")
	}

	err = taskset(0)
	if err != nil {
		t.Errorf("taskset(0) error: %+v", err)
	}
}

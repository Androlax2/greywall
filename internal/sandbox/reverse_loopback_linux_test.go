//go:build linux

package sandbox

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func TestReverseBridge_OnlyListensOnLocalhost(t *testing.T) {
	skipIfCommandNotFound(t, "socat")
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	bridge, err := NewReverseBridge([]int{port}, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridge.Cleanup)
	deadline := time.Now().Add(3 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reverse bridge never started: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A wildcard listener would occupy this address too. No LAN interface or
	// remote connection is needed to verify it is bound to 127.0.0.1 only.
	other, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("reverse bridge also occupies non-localhost addresses: %v", err)
	}
	_ = other.Close()
}

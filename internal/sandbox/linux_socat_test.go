//go:build linux

package sandbox

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProxyBridge_UsesSocat(t *testing.T) {
	skipIfCommandNotFound(t, "socat")
	bridge, err := NewProxyBridge("socks5://127.0.0.1:43052", false)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Cleanup()

	childLists, err := filepath.Glob("/proc/self/task/*/children")
	if err != nil {
		t.Fatal(err)
	}
	for _, childList := range childLists {
		children, err := os.ReadFile(childList)
		if err != nil {
			t.Fatal(err)
		}
		for _, child := range strings.Fields(string(children)) {
			name, err := os.ReadFile("/proc/" + child + "/comm")
			if err == nil && strings.TrimSpace(string(name)) == "socat" {
				return
			}
		}
	}
	t.Fatal("proxy bridge did not start socat")
}

// greyproxy's DNS server listens on IPv4 only, but its configured address is
// localhost:43053. Keep the regression check from the in-process relay.
func TestDnsBridge_ReachesIPv4OnlyServerNamedLocalhost(t *testing.T) {
	skipIfCommandNotFound(t, "socat")
	dnsServer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dnsServer.Close() }()
	go func() {
		buf := make([]byte, 512)
		n, peer, err := dnsServer.ReadFrom(buf)
		if err == nil {
			_, _ = dnsServer.WriteTo(append([]byte("reply:"), buf[:n]...), peer)
		}
	}()
	port := dnsServer.LocalAddr().(*net.UDPAddr).Port
	bridge, err := NewDnsBridge("localhost:"+strconv.Itoa(port), false)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Cleanup()
	conn, err := net.Dial("unix", bridge.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("reply:query"))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "reply:query" {
		t.Fatalf("unexpected DNS reply: %q", reply)
	}
}

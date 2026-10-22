//go:build linux

package sandbox

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startEchoServer accepts TCP connections on 127.0.0.1 and echoes every byte
// back until the client half-closes.
func startEchoServer(t *testing.T) (port int) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

// roundTrip writes payload, half-closes, and returns everything read back.
func roundTrip(t *testing.T, conn net.Conn, payload string) string {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(reply)
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func TestProxyBridge_RelaysUnixSocketToProxyTCP(t *testing.T) {
	skipIfCommandNotFound(t, "socat")
	port := startEchoServer(t)

	bridge, err := NewProxyBridge("socks5://127.0.0.1:"+strconv.Itoa(port), false)
	if err != nil {
		t.Fatalf("NewProxyBridge: %v", err)
	}
	defer bridge.Cleanup()

	conn, err := net.Dial("unix", bridge.SocketPath)
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if got := roundTrip(t, conn, "hello proxy"); got != "hello proxy" {
		t.Fatalf("expected echo %q, got %q", "hello proxy", got)
	}
}

func TestForwardBridge_RelaysUnixSocketToHostLocalhostPort(t *testing.T) {
	skipIfCommandNotFound(t, "socat")
	port := startEchoServer(t)

	bridge, err := NewForwardBridge([]int{port}, false)
	if err != nil {
		t.Fatalf("NewForwardBridge: %v", err)
	}
	defer bridge.Cleanup()

	conn, err := net.Dial("unix", bridge.SocketPaths[0])
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if got := roundTrip(t, conn, "hello forward"); got != "hello forward" {
		t.Fatalf("expected echo %q, got %q", "hello forward", got)
	}
}

func TestReverseBridge_WaitsForSandboxSocketThenRelays(t *testing.T) {
	skipIfCommandNotFound(t, "socat")
	port := freeTCPPort(t)

	bridge, err := NewReverseBridge([]int{port}, false)
	if err != nil {
		t.Fatalf("NewReverseBridge: %v", err)
	}
	defer bridge.Cleanup()

	conn, err := net.Dial("tcp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("dial host port: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// The sandbox-side listener appears after the host accepted the connection.
	time.Sleep(300 * time.Millisecond)
	sandboxListener, err := net.Listen("unix", bridge.SocketPaths[0])
	if err != nil {
		t.Fatalf("listen on sandbox socket: %v", err)
	}
	defer func() { _ = sandboxListener.Close() }()
	go func() {
		sandboxConn, err := sandboxListener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = sandboxConn.Close() }()
		_, _ = io.Copy(sandboxConn, sandboxConn)
	}()

	if got := roundTrip(t, conn, "hello reverse"); got != "hello reverse" {
		t.Fatalf("expected echo %q, got %q", "hello reverse", got)
	}
}

func TestReverseBridge_FailsWhenHostPortIsTaken(t *testing.T) {
	skipIfCommandNotFound(t, "socat")
	occupied, err := net.Listen("tcp4", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()
	port := occupied.Addr().(*net.TCPAddr).Port

	bridge, err := NewReverseBridge([]int{port}, false)
	if err == nil {
		bridge.Cleanup()
		t.Fatalf("expected an error for port %d already in use", port)
	}
}

func TestDnsBridge_SendsQueryAsDatagramAndReturnsReply(t *testing.T) {
	skipIfCommandNotFound(t, "socat")
	dnsServer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = dnsServer.Close() }()
	go func() {
		buf := make([]byte, 512)
		n, peer, err := dnsServer.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = dnsServer.WriteTo(append([]byte("reply:"), buf[:n]...), peer)
	}()

	bridge, err := NewDnsBridge(dnsServer.LocalAddr().String(), false)
	if err != nil {
		t.Fatalf("NewDnsBridge: %v", err)
	}
	defer bridge.Cleanup()

	conn, err := net.Dial("unix", bridge.SocketPath)
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Mirrors the in-sandbox socat: one query, then shut down the write side.
	if got := roundTrip(t, conn, "query"); got != "reply:query" {
		t.Fatalf("expected %q, got %q", "reply:query", got)
	}
}

// TestDnsBridge_AnswersTheInSandboxSocatRelay runs the same socat command the
// sandbox script starts (on a free port instead of 53) against the host relay.
func TestDnsBridge_AnswersTheInSandboxSocatRelay(t *testing.T) {
	skipIfCommandNotFound(t, "socat")
	dnsServer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = dnsServer.Close() }()
	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, err := dnsServer.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = dnsServer.WriteTo(append([]byte("reply:"), buf[:n]...), peer)
		}
	}()

	bridge, err := NewDnsBridge(dnsServer.LocalAddr().String(), false)
	if err != nil {
		t.Fatalf("NewDnsBridge: %v", err)
	}
	defer bridge.Cleanup()

	relayAddr, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick udp port: %v", err)
	}
	relayPort := relayAddr.LocalAddr().(*net.UDPAddr).Port
	_ = relayAddr.Close()

	socat := exec.Command("socat", //nolint:gosec // test-controlled arguments
		fmt.Sprintf("UDP4-RECVFROM:%d,bind=127.0.0.1,fork,reuseaddr", relayPort),
		"UNIX-CONNECT:"+bridge.SocketPath)
	if err := socat.Start(); err != nil {
		t.Fatalf("start socat: %v", err)
	}
	defer func() {
		_ = socat.Process.Kill()
		_ = socat.Wait()
	}()
	time.Sleep(200 * time.Millisecond)

	client, err := net.Dial("udp4", "127.0.0.1:"+strconv.Itoa(relayPort))
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer func() { _ = client.Close() }()

	for _, query := range []string{"first", "second"} {
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := client.Write([]byte(query)); err != nil {
			t.Fatalf("write %s: %v", query, err)
		}
		buf := make([]byte, 512)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("read reply to %s: %v", query, err)
		}
		if got := string(buf[:n]); got != "reply:"+query {
			t.Fatalf("expected %q, got %q", "reply:"+query, got)
		}
	}
}

func TestProxyBridge_CleanupClosesOpenConnections(t *testing.T) {
	skipIfCommandNotFound(t, "socat")
	port := startEchoServer(t)

	bridge, err := NewProxyBridge("socks5://127.0.0.1:"+strconv.Itoa(port), false)
	if err != nil {
		t.Fatalf("NewProxyBridge: %v", err)
	}

	conn, err := net.Dial("unix", bridge.SocketPath)
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	cleanupDone := make(chan struct{})
	go func() {
		bridge.Cleanup()
		close(cleanupDone)
	}()
	select {
	case <-cleanupDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Cleanup blocked on an open connection")
	}

	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the connection to be closed after Cleanup")
	}
}

func TestTun2socksProxyURL_SelectsUnixSocket(t *testing.T) {
	cases := []struct {
		name     string
		bridge   ProxyBridge
		wantUser string
		wantPass string
	}{
		{"without auth", ProxyBridge{SocketPath: "/tmp/greywall-proxy-ab.sock"}, "", ""},
		{"with auth", ProxyBridge{SocketPath: "/tmp/greywall-proxy-ab.sock", HasAuth: true, ProxyUser: "run-1", ProxyPass: "p@ss:word"}, "run-1", "p@ss:word"},
		{"path with space", ProxyBridge{SocketPath: "/tmp/my dir/greywall-proxy-ab.sock"}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse the way tun2socks v2.5.2 does (engine/parse.go): an empty
			// host means the path is a Unix socket.
			parsed, err := url.Parse(tun2socksProxyURL(&tc.bridge))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if parsed.Scheme != "socks5" || parsed.Host != "" || parsed.Path != tc.bridge.SocketPath {
				t.Fatalf("expected socks5 over %q, got scheme=%q host=%q path=%q", tc.bridge.SocketPath, parsed.Scheme, parsed.Host, parsed.Path)
			}
			password, _ := parsed.User.Password()
			if parsed.User.Username() != tc.wantUser || password != tc.wantPass {
				t.Fatalf("expected credentials %q/%q, got %q/%q", tc.wantUser, tc.wantPass, parsed.User.Username(), password)
			}
		})
	}
}

func TestWrapCommandLinux_TunModeHasNoProxySocat(t *testing.T) {
	features := DetectLinuxFeatures()
	if !features.HasBwrap || !features.CanUseTransparentProxy() {
		t.Skip("transparent proxy not available; env-var mode keeps the socat bridge")
	}
	bridge := &ProxyBridge{SocketPath: "/tmp/greywall-proxy-test.sock"}

	cmd, err := WrapCommandLinuxWithOptions(testConfigWithWorkspace(t.TempDir()), "true", bridge, nil, nil, nil, nil, "/tmp/fake-tun2socks", LinuxSandboxOptions{})
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}
	if strings.Contains(cmd, "UNIX-CONNECT:"+bridge.SocketPath) {
		t.Fatalf("tun2socks mode should not start a socat proxy bridge:\n%s", cmd)
	}
	if !strings.Contains(cmd, "socks5:///tmp/greywall-proxy-test.sock") {
		t.Fatalf("expected tun2socks to dial the bridge socket:\n%s", cmd)
	}
}

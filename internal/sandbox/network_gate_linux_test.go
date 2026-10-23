//go:build linux

package sandbox

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

func TestNetworkHelpers_RequiredCoverageCannotSkip(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"sandbox", "bwrap", "ip", "socat", "unshare", "setpriv", "ss", "python3"} {
		t.Run(missing, func(t *testing.T) {
			bin := t.TempDir()
			for _, tool := range []string{"bwrap", "ip", "socat", "unshare", "setpriv", "ss", "python3"} {
				if tool != missing {
					if err := os.Symlink(truePath, filepath.Join(bin, tool)); err != nil {
						t.Fatal(err)
					}
				}
			}
			isSandboxed := ""
			if missing == "sandbox" {
				isSandboxed = "1"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestNetworkHelpers_PrivateDevicesSupportDNSAndTUN$/^enforcing$", "-test.v") //nolint:gosec // real test entry point with deliberately missing prerequisites
			command.Env = append(os.Environ(), "GREYWALL_REQUIRE_NETWORK_TESTS=1", "GREYWALL_SANDBOX="+isSandboxed, "PATH="+bin)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("prerequisite check hung: %s", output)
			}
			if err == nil || !strings.Contains(string(output), "required network coverage unavailable") || strings.Contains(string(output), "--- SKIP:") {
				t.Fatalf("missing %s did not fail required coverage upfront: %v\n%s", missing, err, output)
			}
		})
	}
}

func TestNetworkHelpers_NetworkOwnedByFinalUserNamespace(t *testing.T) {
	proxy, dns, tunPath := networkHelperFixtures(t)
	skipIfCommandNotFound(t, "python3")
	command := `python3 -c 'import fcntl, os
with open("/proc/self/ns/net") as network:
    owner = fcntl.ioctl(network.fileno(), 0xb701)
    try:
        assert os.fstat(owner).st_ino == os.stat("/proc/self/ns/user").st_ino, "network belongs to another user namespace"
    finally:
        os.close(owner)
print("NETWORK_OWNER_OK")'`
	output, err := runNetworkHelperCommand(t, &config.Config{}, command, proxy, dns, tunPath, LinuxSandboxOptions{UseSeccomp: true})
	if err != nil || !strings.Contains(output, "NETWORK_OWNER_OK") {
		t.Fatalf("private devices left the network owned by another user namespace: %v\n%s", err, output)
	}
}

func TestNetworkHelpers_RequiredCoverageRejectsMissingTUN(t *testing.T) {
	requireNetworkHelperTools(t, "python3")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	//nolint:gosec // private device tree intentionally has no TUN device
	command := exec.CommandContext(ctx, "bwrap", "--unshare-net", "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--", executable,
		"-test.run=^TestNetworkHelpers_PrivateDevicesSupportDNSAndTUN$/^enforcing$", "-test.v")
	command.Env = append(os.Environ(), "GREYWALL_REQUIRE_NETWORK_TESTS=1", "GREYWALL_SANDBOX=")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("missing TUN prerequisite check hung: %s", output)
	}
	if err == nil || !strings.Contains(string(output), "required network coverage unavailable: TUN device unavailable") || strings.Contains(string(output), "--- SKIP:") {
		t.Fatalf("missing TUN did not fail required coverage upfront: %v\n%s", err, output)
	}
}

func TestNetworkHelpers_NegativeDeviceCheckHonorsCoverageMode(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []struct {
		name     string
		missing  string
		required string
	}{
		{"optional-missing-ip", "ip", ""},
		{"optional-missing-python", "python3", ""},
		{"required-missing-bwrap", "bwrap", "1"},
		{"required-missing-ip", "ip", "1"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			bin := t.TempDir()
			for _, tool := range []string{"bwrap", "ip", "socat", "unshare", "setpriv", "ss", "python3"} {
				if tool == mode.missing {
					continue
				}
				if err := os.Symlink(truePath, filepath.Join(bin, tool)); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestNetworkHelpers_RequiredCoverageRejectsMissingTUN$", "-test.v") //nolint:gosec // real negative-test entry point with controlled prerequisites
			command.Env = append(os.Environ(), "GREYWALL_REQUIRE_NETWORK_TESTS="+mode.required, "GREYWALL_SANDBOX=", "PATH="+bin)
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("negative device prerequisite check hung: %s", output)
			}
			if mode.required == "1" {
				if err == nil || !strings.Contains(string(output), "required network coverage unavailable") || strings.Contains(string(output), "--- SKIP:") {
					t.Fatalf("required coverage silently skipped %s: %v\n%s", mode.missing, err, output)
				}
			} else if err != nil || !strings.Contains(string(output), "--- SKIP:") {
				t.Fatalf("optional developer coverage failed instead of skipping %s: %v\n%s", mode.missing, err, output)
			}
		})
	}
}

func TestNetworkHelpers_SystemResolverUsesDNSBridge(t *testing.T) {
	proxy, _, tunPath := networkHelperFixtures(t)
	skipIfCommandNotFound(t, "python3")
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		buffer := make([]byte, 4096)
		for {
			length, peer, err := server.ReadFrom(buffer)
			if err != nil {
				return
			}
			if length < 12 || binary.BigEndian.Uint16(buffer[4:6]) != 1 {
				continue
			}
			questionEnd := 12
			for questionEnd < length && buffer[questionEnd] != 0 {
				questionEnd += int(buffer[questionEnd]) + 1
			}
			questionEnd += 5 // root label, query type and class
			if questionEnd > length || binary.BigEndian.Uint16(buffer[questionEnd-4:questionEnd-2]) != 1 {
				continue
			}
			response := append([]byte(nil), buffer[:questionEnd]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8180)
			binary.BigEndian.PutUint16(response[6:8], 1)
			binary.BigEndian.PutUint16(response[8:10], 0)
			binary.BigEndian.PutUint16(response[10:12], 0)
			response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 42)
			_, _ = server.WriteTo(response, peer)
		}
	}()
	dns, err := NewDnsBridge(server.LocalAddr().String(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dns.Cleanup)
	for _, mode := range []struct {
		name    string
		tunPath string
	}{
		{"transparent", tunPath},
		{"fallback", ""},
	} {
		t.Run(mode.name, func(t *testing.T) {
			command := `python3 -c 'import socket; print(socket.getaddrinfo("greywall-network-canary.test", 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0])'`
			output, err := runNetworkHelperCommand(t, &config.Config{}, command, proxy, dns, mode.tunPath, LinuxSandboxOptions{UseSeccomp: true})
			if err != nil || !strings.Contains(output, "203.0.113.42") {
				t.Fatalf("system resolver could not use the configured DNS relay: %v\n%s", err, output)
			}
		})
	}
}

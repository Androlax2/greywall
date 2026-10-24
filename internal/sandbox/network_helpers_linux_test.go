//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

func networkCoverageUnavailable(t *testing.T, format string, arguments ...any) {
	t.Helper()
	reason := fmt.Sprintf(format, arguments...)
	if os.Getenv("GREYWALL_REQUIRE_NETWORK_TESTS") == "1" {
		t.Fatalf("required network coverage unavailable: %s", reason)
	}
	t.Skip(reason)
}

func requireNetworkHelperTools(t *testing.T, additionalTools ...string) {
	t.Helper()
	if os.Getenv("GREYWALL_SANDBOX") == "1" {
		networkCoverageUnavailable(t, "already running inside Greywall sandbox")
	}
	tools := []string{"bwrap", "ip", "socat", "unshare", "setpriv", "ss"}
	if os.Getenv("GREYWALL_REQUIRE_NETWORK_TESTS") == "1" {
		tools = append(tools, "python3")
	}
	for _, tool := range append(tools, additionalTools...) {
		if _, err := exec.LookPath(tool); err != nil {
			networkCoverageUnavailable(t, "command %q not found", tool)
		}
	}
}

func networkHelperFixtures(t *testing.T) (*ProxyBridge, *DnsBridge, string) {
	t.Helper()
	requireNetworkHelperTools(t)
	if device, err := os.Stat("/dev/net/tun"); err != nil {
		networkCoverageUnavailable(t, "TUN device unavailable: %v", err)
	} else if device.Mode()&os.ModeCharDevice == 0 {
		networkCoverageUnavailable(t, "/dev/net/tun is not a character device")
	}
	seedGreyproxyDir(t)
	bridge, err := NewProxyBridge("socks5://127.0.0.1:1", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridge.Cleanup)
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() {
		buffer := make([]byte, 512)
		for {
			n, peer, err := server.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = server.WriteTo(append([]byte("reply:"), buffer[:n]...), peer)
		}
	}()
	dns, err := NewDnsBridge(server.LocalAddr().String(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dns.Cleanup)
	tunPath, err := extractTun2Socks()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(tunPath) })
	return bridge, dns, tunPath
}

func runNetworkHelperCommand(t *testing.T, cfg *config.Config, command string, proxy *ProxyBridge, dns *DnsBridge, tunPath string, opts LinuxSandboxOptions) (string, error) {
	t.Helper()
	wrapped, err := WrapCommandLinuxWithOptions(cfg, command, proxy, dns, nil, nil, nil, tunPath, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "bash", "-c", wrapped).CombinedOutput() //nolint:gosec // generated sandbox command
	if ctx.Err() != nil {
		t.Fatalf("sandbox startup exceeded deadline: %s", output)
	}
	return string(output), err
}

func TestNetworkHelpers_PrivateDevicesSupportDNSAndTUN(t *testing.T) {
	for _, mode := range []struct {
		name string
		opts LinuxSandboxOptions
	}{
		{"enforcing", LinuxSandboxOptions{UseSeccomp: true}},
		{"watch", LinuxSandboxOptions{Watch: true}},
		{"learning", LinuxSandboxOptions{Learning: true}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			proxy, dns, tunPath := networkHelperFixtures(t)
			command := fmt.Sprintf(`test "$(id -u)" = %d && test "$(id -g)" = %d &&
test -c /dev/ptmx && test -d /dev/pts && test ! -e /dev/snd &&
ip -o link show dev tun0 | grep -q LOWER_UP &&
printf query | socat -T2 - UDP4:127.0.0.1:53`, os.Getuid(), os.Getgid())
			output, err := runNetworkHelperCommand(t, &config.Config{}, command, proxy, dns, tunPath, mode.opts)
			if err != nil || !strings.Contains(output, "reply:query") {
				t.Fatalf("private devices broke network helpers: %v\n%s", err, output)
			}
		})
	}
}

func TestNetworkHelpers_UserCommandHasNoCapabilities(t *testing.T) {
	proxy, dns, tunPath := networkHelperFixtures(t)
	command := `test "$(grep -Ec '^Cap(Inh|Prm|Eff|Amb):[[:space:]]+0+$' /proc/self/status)" = 4 && echo NO_CAPABILITIES`
	output, err := runNetworkHelperCommand(t, &config.Config{}, command, proxy, dns, tunPath, LinuxSandboxOptions{})
	if err != nil || !strings.Contains(output, "NO_CAPABILITIES") {
		t.Fatalf("setup capabilities reached user command: %v\n%s", err, output)
	}
}

func TestNetworkHelpers_FallbackStillServesConfiguredDNS(t *testing.T) {
	proxy, dns, _ := networkHelperFixtures(t)
	output, err := runNetworkHelperCommand(t, &config.Config{}, "printf query | socat -T2 - UDP4:127.0.0.1:53", proxy, dns, "", LinuxSandboxOptions{})
	if err != nil || !strings.Contains(output, "reply:query") {
		t.Fatalf("fallback configured DNS without a working relay: %v\n%s", err, output)
	}
}

func TestNetworkHelpers_SetupShellHasNoSystemAdministrationCapabilities(t *testing.T) {
	proxy, dns, tunPath := networkHelperFixtures(t)
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	program := `#!/bin/bash
while read -r field value rest; do
    case "$field" in
        CapInh:|CapPrm:|CapEff:|CapAmb:|CapBnd:)
            (( (16#$value & ((1 << 21) | (1 << 8))) == 0 )) || exit 42
            ;;
    esac
done < /proc/self/status
exec ` + ShellQuoteSingle(ipPath) + ` "$@"
`
	if err := os.WriteFile(filepath.Join(bin, "ip"), []byte(program), 0o700); err != nil { // #nosec G306 -- owner-only executable test fixture
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	cfg := &config.Config{Filesystem: config.FilesystemConfig{AllowWrite: []string{bin}}}
	output, err := runNetworkHelperCommand(t, cfg, "ip -o link show dev tun0 | grep -q LOWER_UP && echo SETUP_PRIVILEGES_REMOVED", proxy, dns, tunPath, LinuxSandboxOptions{})
	if err != nil || !strings.Contains(output, "SETUP_PRIVILEGES_REMOVED") {
		t.Fatalf("SYS_ADMIN or SETPCAP survived into setup shell: %v\n%s", err, output)
	}
}

func TestNetworkHelpers_RequireSetupToolsBeforeReturningCommand(t *testing.T) {
	for _, missing := range []string{"unshare", "setpriv", "ss"} {
		t.Run(missing, func(t *testing.T) {
			overrideLinuxFeatures(t)
			bin := t.TempDir()
			for _, tool := range []string{"bwrap", "bash", "sleep", "git", "unshare", "setpriv", "ss"} {
				if tool == missing {
					continue
				}
				toolPath, err := exec.LookPath(tool)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(toolPath, filepath.Join(bin, tool)); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin)
			command, err := WrapCommandLinuxWithOptions(&config.Config{}, "echo USER_COMMAND_RAN", &ProxyBridge{SocketPath: "/unused"}, nil, nil, nil, nil, "", LinuxSandboxOptions{})
			if err == nil || command != "" || !strings.Contains(err.Error(), missing) {
				t.Fatalf("missing %s did not prevent command generation: %v\n%s", missing, err, command)
			}
		})
	}
}

func TestNetworkHelpers_StartupFailureNeverRunsUserCommand(t *testing.T) {
	for _, failure := range []string{"ip", "tun-exits", "tun-never-attaches", "dns"} {
		t.Run(failure, func(t *testing.T) {
			proxy, dns, tunPath := networkHelperFixtures(t)
			bin := t.TempDir()
			cfg := &config.Config{Filesystem: config.FilesystemConfig{AllowWrite: []string{bin}}}
			switch failure {
			case "ip":
				if err := os.WriteFile(filepath.Join(bin, "ip"), []byte("#!/bin/sh\necho INJECTED_IP_FAILURE >&2\nexit 42\n"), 0o700); err != nil { // #nosec G306 -- owner-only executable test fixture
					t.Fatal(err)
				}
			case "tun-exits", "tun-never-attaches":
				program := "#!/bin/sh\necho INJECTED_TUN_FAILURE >&2\nexit 42\n"
				if failure == "tun-never-attaches" {
					program = "#!/bin/sh\nexec sleep 10\n"
				}
				if err := os.WriteFile(tunPath, []byte(program), 0o700); err != nil { // #nosec G306 -- owner-only executable test fixture
					t.Fatal(err)
				}
			case "dns":
				socatPath, err := exec.LookPath("socat")
				if err != nil {
					t.Fatal(err)
				}
				program := "#!/bin/sh\ncase \"$1\" in UDP4-RECVFROM:53*) echo INJECTED_DNS_FAILURE >&2; exit 42;; esac\nexec " + ShellQuoteSingle(socatPath) + " \"$@\"\n"
				if err := os.WriteFile(filepath.Join(bin, "socat"), []byte(program), 0o700); err != nil { // #nosec G306 -- owner-only executable test fixture
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			output, err := runNetworkHelperCommand(t, cfg, "echo USER_COMMAND_RAN", proxy, dns, tunPath, LinuxSandboxOptions{})
			if err == nil || strings.Contains(output, "USER_COMMAND_RAN") {
				t.Fatalf("command ran despite %s failure: %v\n%s", failure, err, output)
			}
			if !strings.Contains(output, "[greywall:network]") {
				t.Fatalf("startup failed without a network diagnostic: %s", output)
			}
		})
	}
}

func TestNetworkHelpers_PreserveUserCommandExitStatus(t *testing.T) {
	proxy, dns, tunPath := networkHelperFixtures(t)
	output, err := runNetworkHelperCommand(t, &config.Config{}, "exit 37", proxy, dns, tunPath, LinuxSandboxOptions{})
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 37 {
		t.Fatalf("user command status changed: %v\n%s", err, output)
	}
}

func TestNetworkHelpers_WaitForDelayedPortBridges(t *testing.T) {
	for _, direction := range []string{"forward", "reverse"} {
		t.Run(direction, func(t *testing.T) {
			proxy, dns, tunPath := networkHelperFixtures(t)
			server, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			go func() {
				connection, err := server.Accept()
				if err == nil {
					_, _ = connection.Write([]byte("BRIDGE_READY"))
					_ = connection.Close()
				}
			}()
			port := server.Addr().(*net.TCPAddr).Port
			var forward *ForwardBridge
			var reverse *ReverseBridge
			var command, delayedAddress string
			if direction == "forward" {
				forward, err = NewForwardBridge([]int{port}, false)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(forward.Cleanup)
				command = fmt.Sprintf("socat -u TCP:127.0.0.1:%d -", port)
				delayedAddress = "TCP-LISTEN:" + strconv.Itoa(port) + ",*"
			} else {
				socketPath := filepath.Join(t.TempDir(), "reverse.sock")
				reverse = &ReverseBridge{Ports: []int{port}, SocketPaths: []string{socketPath}}
				command = "test -S " + ShellQuoteSingle(socketPath) + " && echo BRIDGE_READY"
				delayedAddress = "UNIX-LISTEN:*"
			}
			socatPath, err := exec.LookPath("socat")
			if err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			program := "#!/bin/sh\ncase \"$1\" in " + delayedAddress + ") sleep 1;; esac\nexec " + ShellQuoteSingle(socatPath) + " \"$@\"\n"
			if err := os.WriteFile(filepath.Join(bin, "socat"), []byte(program), 0o700); err != nil { // #nosec G306 -- owner-only executable test fixture
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			cfg := &config.Config{Filesystem: config.FilesystemConfig{AllowWrite: []string{bin}}}
			wrapped, err := WrapCommandLinuxWithOptions(cfg, command, proxy, dns, reverse, forward, nil, tunPath, LinuxSandboxOptions{})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, "bash", "-c", wrapped).CombinedOutput() //nolint:gosec // generated sandbox command
			if err != nil || !strings.Contains(string(output), "BRIDGE_READY") {
				t.Fatalf("user command raced %s bridge startup: %v\n%s", direction, err, output)
			}
		})
	}
}

func TestNetworkHelpers_BridgeStderrStaysOffTerminal(t *testing.T) {
	for _, mode := range []string{"tun", "fallback"} {
		t.Run(mode, func(t *testing.T) {
			proxy, dns, tunPath := networkHelperFixtures(t)
			if mode == "fallback" {
				tunPath = ""
			}
			socatPath, err := exec.LookPath("socat")
			if err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			program := "#!/bin/sh\ncase \"$1\" in UDP4-RECVFROM:53*) echo DNS_BRIDGE_NOISE >&2;; TCP-LISTEN:18321*) echo PROXY_BRIDGE_NOISE >&2;; esac\nexec " + ShellQuoteSingle(socatPath) + " \"$@\"\n"
			if err := os.WriteFile(filepath.Join(bin, "socat"), []byte(program), 0o700); err != nil { // #nosec G306 -- owner-only executable test fixture
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			cfg := &config.Config{Filesystem: config.FilesystemConfig{AllowWrite: []string{bin}}}
			// Bridges start in the background, so give them time to write before the command exits.
			output, err := runNetworkHelperCommand(t, cfg, "sleep 1; echo USER_COMMAND_RAN", proxy, dns, tunPath, LinuxSandboxOptions{})
			if err != nil || !strings.Contains(output, "USER_COMMAND_RAN") {
				t.Fatalf("sandbox command failed: %v\n%s", err, output)
			}
			if strings.Contains(output, "BRIDGE_NOISE") {
				t.Fatalf("bridge stderr reached the terminal:\n%s", output)
			}
		})
	}
}

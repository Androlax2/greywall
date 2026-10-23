//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

func TestSystemSSHConfig_UntrustedDirectoryIsNotCopied(t *testing.T) {
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "unsafe.conf"), "Host *\n ForwardAgent yes\n")
	args, redirections, err := systemSSHConfigArgs(directory, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 0 || redirections != "" {
		t.Fatal("user-controlled configuration was promoted into a trusted system snapshot")
	}
}

func TestSystemSSHConfig_MissingDirectoryNeedsNoMount(t *testing.T) {
	args, redirections, err := systemSSHConfigArgs(filepath.Join(t.TempDir(), "missing"), nil)
	if err != nil || len(args) != 0 || redirections != "" {
		t.Fatalf("missing directory: %v, %q, %v", args, redirections, err)
	}
}

func TestSystemSSHConfig_DenyReadAlsoMasksCopies(t *testing.T) {
	skipIfAlreadySandboxed(t)
	include := "/etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf"
	source, err := filepath.EvalSymlinks(include)
	if os.IsNotExist(err) {
		t.Skip("systemd SSH client include is not installed")
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, denied := range []string{source, filepath.Dir(source), include, "/etc/ssh/ssh_config.d/*.conf"} {
		t.Run(denied, func(t *testing.T) {
			seedGreyproxyDir(t)
			t.Chdir(t.TempDir())
			cfg := &config.Config{Filesystem: config.FilesystemConfig{DenyRead: []string{denied}}}
			command, err := WrapCommandLinuxWithOptions(cfg,
				"test ! -s "+ShellQuoteSingle(include)+" && printf DENIED_CONFIG_OK",
				nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
			if err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("bash", "-c", command).CombinedOutput() //nolint:gosec // generated offline sandbox command
			if err != nil || strings.TrimSpace(string(output)) != "DENIED_CONFIG_OK" {
				t.Fatalf("SSH snapshot bypassed denyRead: %v\n%s", err, output)
			}
		})
	}
}

func TestSystemSSHConfig_ParsesInRealSandbox(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "ssh")
	skipIfCommandNotFound(t, "bwrap")
	seedGreyproxyDir(t)
	if _, err := os.Stat("/etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf"); os.IsNotExist(err) {
		t.Skip("systemd SSH client include is not installed")
	} else if err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	t.Chdir(project)
	// This is strictly offline. -G prints configuration; localhost is just a
	// parse target, and ProxyCommand/Match exec are not invoked by this file.
	command, err := WrapCommandLinuxWithOptions(&config.Config{},
		`printf 'Include /etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf\n' | ssh -G -F /dev/stdin localhost >/dev/null && ! (printf injected >> /etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf) 2>/dev/null && printf SSH_CONFIG_OK`,
		nil, nil, nil, nil, nil, "", LinuxSandboxOptions{UseSeccomp: true})
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("bash", "-c", command).CombinedOutput() //nolint:gosec // generated sandbox command; ssh -G makes no connection
	if err != nil || !strings.HasSuffix(string(output), "SSH_CONFIG_OK") {
		t.Fatalf("offline SSH parsing or read-only protection failed: %v\n%s", err, output)
	}
	if strings.Contains(command, "--uid") || strings.Contains(command, "--gid") {
		t.Fatal("SSH compatibility must not change UID/GID mappings")
	}
}

func TestSystemSSHConfig_TrustRequiresRealRootAndSafePermissions(t *testing.T) {
	for _, tc := range []struct {
		name string
		uid  uint32
		mode os.FileMode
		want bool
	}{
		{"root config", 0, 0o644, true},
		{"root directory", 0, os.ModeDir | 0o755, true},
		{"root symlink checked through target", 0, os.ModeSymlink | 0o777, true},
		{"user owned", 1000, 0o644, false},
		{"overflow UID is not root", 65534, 0o644, false},
		{"group writable", 0, 0o664, false},
		{"world writable directory", 0, os.ModeDir | 0o777, false},
		{"user symlink", 1000, os.ModeSymlink | 0o777, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRootTrustedSSHEntry(tc.uid, tc.mode); got != tc.want {
				t.Errorf("trust = %v, want %v", got, tc.want)
			}
		})
	}
}

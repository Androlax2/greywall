//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

func ownedSessionDir(t *testing.T) string {
	t.Helper()
	// EvalSymlinks: t.TempDir may sit below a symlinked TMPDIR.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSessionMountArgs_BindsOwnedHostDirAtTarget(t *testing.T) {
	source := ownedSessionDir(t)
	mounts := []config.Mount{{Source: source, Target: "/tmp/codex-daemon-1000"}}

	args, err := sessionMountArgs(config.FilesystemConfig{Mounts: mounts}, t.TempDir())
	if err != nil {
		t.Fatalf("sessionMountArgs() error = %v", err)
	}
	if !hasBindTriple(args, "--bind", source, "/tmp/codex-daemon-1000") {
		t.Errorf("args %v lack --bind %s /tmp/codex-daemon-1000", args, source)
	}
}

func TestSessionMountArgs_RejectsUnsafeHostDirs(t *testing.T) {
	base := ownedSessionDir(t)
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(base, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(realDir, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	regularFile := filepath.Join(base, "file")
	if err := os.WriteFile(regularFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		source string
	}{
		{"missing dir", filepath.Join(base, "missing")},
		{"symlink as the dir", linkDir},
		{"symlink in a parent", filepath.Join(linkDir, "child")},
		{"regular file", regularFile},
		{"invalid config path", base + "/real/../real"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mounts := []config.Mount{{Source: tt.source, Target: "/tmp/x"}}
			if args, err := sessionMountArgs(config.FilesystemConfig{Mounts: mounts}, t.TempDir()); err == nil {
				t.Errorf("sessionMountArgs(%q) = %v, want error", tt.source, args)
			}
		})
	}
}

func TestSessionMountArgs_RejectsHostDirOwnedBySomeoneElse(t *testing.T) {
	foreignDir := dirOwnedBySomeoneElse(t)
	mounts := []config.Mount{{Source: foreignDir, Target: "/tmp/x"}}
	if args, err := sessionMountArgs(config.FilesystemConfig{Mounts: mounts}, t.TempDir()); err == nil {
		t.Errorf("sessionMountArgs(%q) = %v, want ownership error", foreignDir, args)
	}
}

// dirOwnedBySomeoneElse returns a symlink-free system directory the test
// process does not own. Inside a user-namespace sandbox / can be a tmpfs owned
// by the caller, so several candidates are tried.
func dirOwnedBySomeoneElse(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"/usr", "/etc", "/"} {
		info, err := os.Lstat(candidate)
		if err != nil || !info.IsDir() {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(candidate); err != nil || resolved != candidate {
			continue
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
			return candidate
		}
	}
	t.Skip("no system directory owned by another user")
	return ""
}

// The mount must come after --tmpfs /tmp, or the fresh tmpfs hides it.
func TestWrapCommandLinux_BindsSessionMountAfterTmpfsTmp(t *testing.T) {
	t.Chdir(t.TempDir()) // wrapping creates protection placeholders in the working directory
	source := ownedSessionDir(t)
	cfg := config.Default()
	cfg.Filesystem.Mounts = []config.Mount{{Source: source, Target: "/tmp/codex-daemon-1000"}}

	cmd, err := WrapCommandLinuxWithOptions(cfg, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{UseLandlock: true, UseSeccomp: true})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	mounts := parseBwrapMounts(cmd)
	tmpfsIndex := lastDestIndex(mounts, "/tmp")
	bindIndex := lastDestIndex(mounts, "/tmp/codex-daemon-1000")
	if bindIndex < 0 || mounts[bindIndex].flag != "--bind" || mounts[bindIndex].src != source {
		t.Fatalf("no --bind %s /tmp/codex-daemon-1000 in %v", source, mounts)
	}
	if bindIndex < tmpfsIndex {
		t.Errorf("session mount at %d comes before --tmpfs /tmp at %d", bindIndex, tmpfsIndex)
	}
}

func TestWrapCommandLinux_FailsOnUnsafeSessionMount(t *testing.T) {
	t.Chdir(t.TempDir()) // wrapping creates protection placeholders in the working directory
	cfg := config.Default()
	cfg.Filesystem.Mounts = []config.Mount{{Source: ownedSessionDir(t), Target: "/etc/x"}}

	if _, err := WrapCommandLinuxWithOptions(cfg, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{}); err == nil {
		t.Fatal("wrap with a mount outside /tmp succeeded, want error")
	}
}

// bubblewrap's last mount wins: an allowWrite bind of the host's /tmp, or of a
// host path matching the target, must not hide the session mount.
func TestWrapCommandLinux_KeepsSessionMountOverAllowWriteBinds(t *testing.T) {
	hostTarget, err := os.MkdirTemp("/tmp", "codex-daemon-test-")
	if err != nil {
		t.Skipf("cannot create a host dir in /tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(hostTarget) })

	for _, allowWrite := range []string{"/tmp", hostTarget, "/tmp/codex-daemon-test-*"} {
		t.Run(allowWrite, func(t *testing.T) {
			t.Chdir(t.TempDir()) // wrapping creates protection placeholders in the working directory
			source := ownedSessionDir(t)
			cfg := config.Default()
			cfg.Filesystem.AllowWrite = []string{allowWrite}
			cfg.Filesystem.Mounts = []config.Mount{{Source: source, Target: hostTarget}}

			cmd, err := WrapCommandLinuxWithOptions(cfg, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{UseLandlock: true, UseSeccomp: true})
			if err != nil {
				t.Fatalf("wrap: %v", err)
			}

			mounts := parseBwrapMounts(cmd)
			bindIndex := lastDestIndex(mounts, hostTarget)
			if bindIndex < 0 || mounts[bindIndex].src != source {
				t.Fatalf("session mount on %s is not the last mount there: %v", hostTarget, mounts)
			}
			for _, later := range mounts[bindIndex+1:] {
				if isSameOrParentPath(later.dest, hostTarget) {
					t.Errorf("mount %+v after the session mount covers %s", later, hostTarget)
				}
			}
		})
	}
}

func TestWrapCommandLinux_AcceptsNilConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := WrapCommandLinuxWithOptions(nil, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{}); err != nil {
		t.Fatalf("wrap with nil config: %v", err)
	}
}

// fakeHome points HOME (and the XDG dirs derived from it) at a fresh directory
// with a project folder inside, and returns both.
func fakeHome(t *testing.T) (home, cwd string) {
	t.Helper()
	home = ownedSessionDir(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("GREYPROXY_DATA_HOME", "")
	cwd = filepath.Join(home, "project")
	for _, dir := range []string{
		filepath.Join(cwd, "sub"),
		filepath.Join(home, "sessions", "abc"),
		filepath.Join(home, ".local", "share", "greyproxy", "sub"),
		filepath.Join(home, ".config", "greywall"),
		filepath.Join(home, "secrets", "inner"),
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".gnupg", "sub"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return home, cwd
}

func protectedFilesystem(home string, mounts ...config.Mount) config.FilesystemConfig {
	return config.FilesystemConfig{
		DenyRead:  []string{filepath.Join(home, "secrets"), "~/.ssh/id_*"},
		DenyWrite: []string{"~/.gnupg/**"},
		Mounts:    mounts,
	}
}

func TestSessionMountArgs_AcceptsDedicatedDirInsideHome(t *testing.T) {
	home, cwd := fakeHome(t)
	source := filepath.Join(home, "sessions", "abc")
	fs := protectedFilesystem(home, config.Mount{Source: source, Target: "/tmp/x"})

	if _, err := sessionMountArgs(fs, cwd); err != nil {
		t.Fatalf("sessionMountArgs(%q) error = %v, want nil", source, err)
	}
}

func TestSessionMountArgs_RejectsSourcesOverlappingProtectedPaths(t *testing.T) {
	home, cwd := fakeHome(t)
	tests := []struct {
		name      string
		source    string
		wantInErr string
	}{
		{"the project folder", cwd, "project folder"},
		{"inside the project folder", filepath.Join(cwd, "sub"), "project folder"},
		{"home", home, "home folder"},
		{"a folder containing home", filepath.Dir(home), "home folder"},
		{"the greyproxy data folder", filepath.Join(home, ".local", "share", "greyproxy"), "protected folder"},
		{"inside the greyproxy data folder", filepath.Join(home, ".local", "share", "greyproxy", "sub"), "protected folder"},
		{"a folder containing the greyproxy data folder", filepath.Join(home, ".local"), "protected folder"},
		{"the greywall config folder", filepath.Join(home, ".config", "greywall"), "protected folder"},
		{"a denyRead folder", filepath.Join(home, "secrets"), "deny entry"},
		{"inside a denyRead folder", filepath.Join(home, "secrets", "inner"), "deny entry"},
		{"the folder of a denyRead glob", filepath.Join(home, ".ssh"), "~/.ssh/id_*"},
		{"inside a denyWrite glob", filepath.Join(home, ".gnupg", "sub"), "~/.gnupg/**"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := protectedFilesystem(home, config.Mount{Source: tt.source, Target: "/tmp/x"})
			args, err := sessionMountArgs(fs, cwd)
			if err == nil {
				t.Fatalf("sessionMountArgs(%q) = %v, want error", tt.source, args)
			}
			if !strings.Contains(err.Error(), tt.wantInErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantInErr)
			}
		})
	}
}

// On systems where /home is a symlink (Fedora Silverblue: /home -> var/home),
// a deny glob written through HOME must still match the resolved source.
func TestSessionMountArgs_RejectsSourceMatchingDenyGlobThroughSymlinkedHome(t *testing.T) {
	base := ownedSessionDir(t)
	realHome := filepath.Join(base, "var-home")
	if err := os.MkdirAll(filepath.Join(realHome, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkHome := filepath.Join(base, "home")
	if err := os.Symlink(realHome, linkHome); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", linkHome)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("GREYPROXY_DATA_HOME", "")
	source := filepath.Join(realHome, ".ssh")
	fs := config.FilesystemConfig{
		DenyRead: []string{"~/.ssh/id_*"},
		Mounts:   []config.Mount{{Source: source, Target: "/tmp/x"}},
	}

	_, err := sessionMountArgs(fs, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "~/.ssh/id_*") {
		t.Errorf("sessionMountArgs(%q) error = %v, want the deny glob refusal", source, err)
	}
}

func TestSessionMountArgs_RejectsMountsWhenTheProjectFolderIsUnknown(t *testing.T) {
	fs := config.FilesystemConfig{Mounts: []config.Mount{{Source: ownedSessionDir(t), Target: "/tmp/x"}}}
	if args, err := sessionMountArgs(fs, ""); err == nil {
		t.Errorf("sessionMountArgs with no cwd = %v, want error", args)
	}
}

// A project folder below /tmp is bound at the same path in the sandbox, so a
// target overlapping it would hide or nest inside the project bind.
func TestSessionMountArgs_RejectsTargetsOverlappingAProjectFolderInTmp(t *testing.T) {
	cwd := ownedSessionDir(t)
	if !strings.HasPrefix(cwd, "/tmp/") {
		t.Skipf("t.TempDir %q is not below /tmp", cwd)
	}
	for _, target := range []string{cwd, filepath.Dir(cwd), filepath.Join(cwd, "sub")} {
		t.Run(target, func(t *testing.T) {
			fs := config.FilesystemConfig{Mounts: []config.Mount{{Source: ownedSessionDir(t), Target: target}}}
			_, err := sessionMountArgs(fs, cwd)
			if err == nil || !strings.Contains(err.Error(), "project folder") {
				t.Errorf("sessionMountArgs(target %q) error = %v, want project folder refusal", target, err)
			}
		})
	}
}

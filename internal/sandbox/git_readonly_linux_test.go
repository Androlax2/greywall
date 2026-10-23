//go:build linux

package sandbox

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

func snapshotReadOnlyFixture(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var contents []byte
		if info.Mode().IsRegular() {
			contents, err = os.ReadFile(path) //nolint:gosec // reads regular files in a disposable fixture snapshot
		} else if info.Mode()&os.ModeSymlink != 0 {
			var target string
			target, err = os.Readlink(path)
			contents = []byte(target)
		}
		if err != nil {
			return err
		}
		snapshot[path] = fmt.Sprintf("%s %d %x", info.Mode(), info.ModTime().UnixNano(), sha256.Sum256(contents))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestReadOnlyGitRuntimeContainsWritesAndSockets(t *testing.T) {
	skipIfAlreadySandboxed(t)
	for _, scenario := range []string{"ordinary", "linked", "submodule"} {
		t.Run(scenario, func(t *testing.T) {
			seedGreyproxyDir(t)
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			fixture := t.TempDir()
			repo := filepath.Join(fixture, "repo")
			if err := os.Mkdir(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			runFixtureGit(t, repo, "init", "-q")
			writeTestFile(t, filepath.Join(repo, "source.txt"), "readable source\n")
			runFixtureGit(t, repo, "add", "source.txt")
			runFixtureGit(t, repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "initial")
			cwd := repo
			switch scenario {
			case "linked":
				cwd = filepath.Join(fixture, "linked")
				runFixtureGit(t, repo, "worktree", "add", "-qb", "linked", cwd)
			case "submodule":
				source := filepath.Join(fixture, "source")
				runFixtureGit(t, fixture, "clone", "-q", repo, source)
				runFixtureGit(t, repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", source, "nested/sub")
			}
			gitDir := runFixtureGit(t, cwd, "rev-parse", "--absolute-git-dir")
			commonDir := filepath.Join(repo, ".git")
			runFixtureGit(t, repo, "pack-refs", "--all")
			writeTestFile(t, filepath.Join(commonDir, "packed-refs.replacement"), "replacement\n")
			if err := os.RemoveAll(filepath.Join(commonDir, "hooks")); err != nil {
				t.Fatal(err)
			}
			scratch := filepath.Join(fixture, "scratch")
			if err := os.Mkdir(scratch, 0o700); err != nil {
				t.Fatal(err)
			}
			var sockets []string
			for _, path := range []string{filepath.Join(cwd, "docker.sock"), filepath.Join(fixture, "other-session.sock"), filepath.Join(scratch, "control.sock")} {
				listener, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				sockets = append(sockets, path)
			}
			t.Chdir(cwd)
			cfg := &config.Config{Filesystem: config.FilesystemConfig{
				AllowRead:  []string{fixture},
				AllowWrite: []string{fixture, cwd, gitDir, filepath.Join(cwd, "nested")},
				DenyWrite:  []string{repo, cwd},
				DenyRead:   sockets[:2],
			}}
			probe := `import errno, os, socket, sys
root, metadata, common, scratch, hidden, sibling, control = sys.argv[1:]
connection = socket.socket(socket.AF_UNIX)
connection.connect(control)
connection.close()
for path in (hidden, sibling):
    connection = socket.socket(socket.AF_UNIX)
    try:
        connection.connect(path)
    except OSError:
        pass
    else:
        raise AssertionError("writer socket accessible: " + path)
    finally:
        connection.close()
replacement = os.path.join(scratch, "replacement")
with open(replacement, "w") as output:
    output.write("replacement")
operations = [
    lambda: open(os.path.join(root, "new-file"), "w"),
    lambda: open(os.path.join(root, "source.txt"), "a"),
    lambda: os.unlink(os.path.join(root, "source.txt")),
    lambda: os.rename(root, root + "-moved"),
    lambda: os.rename(metadata, metadata + "-moved"),
    lambda: open(os.path.join(metadata, "config.worktree"), "w"),
    lambda: open(os.path.join(metadata, "commondir"), "w"),
    lambda: open(os.path.join(metadata, "HEAD"), "w"),
    lambda: open(os.path.join(common, "refs", "heads", "injected"), "w"),
    lambda: os.replace(os.path.join(common, "packed-refs.replacement"), os.path.join(common, "packed-refs")),
    lambda: os.mkdir(os.path.join(common, "hooks")),
]
submodule = os.path.join(root, "nested", "sub")
if os.path.exists(os.path.join(submodule, ".git")):
    operations.append(lambda: open(os.path.join(submodule, "source.txt"), "w"))
    operations.append(lambda: open(os.path.join(common, "modules", "nested", "sub", "HEAD"), "w"))
for operation in operations:
    try:
        operation()
    except OSError as error:
        assert error.errno in (errno.EROFS, errno.EBUSY, errno.EACCES, errno.EPERM), error
    else:
        raise AssertionError("canonical write succeeded")
print("READ_ONLY_CONTAINMENT_OK")
`
			command := "git -c core.fsmonitor=false --no-optional-locks status --short && git --no-pager diff --no-ext-diff && git --no-pager log -1 --format=%s && cat source.txt && python3 -c " + ShellQuoteSingle(probe)
			for _, argument := range append([]string{cwd, gitDir, commonDir, scratch}, sockets...) {
				command += " " + ShellQuoteSingle(argument)
			}
			before := snapshotReadOnlyFixture(t, repo)
			beforeWorktree := snapshotReadOnlyFixture(t, cwd)
			wrapped, err := WrapCommandLinuxWithOptions(cfg, command, nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
			if err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("bash", "-c", wrapped).CombinedOutput() //nolint:gosec // generated sandbox command operates only on disposable fixtures
			if err != nil || !strings.HasSuffix(strings.TrimSpace(string(output)), "READ_ONLY_CONTAINMENT_OK") {
				t.Fatalf("read-only runtime failed: %v\n%s", err, output)
			}
			if after := snapshotReadOnlyFixture(t, repo); !reflect.DeepEqual(before, after) {
				t.Fatal("sandbox startup or runtime changed the canonical repository")
			}
			if after := snapshotReadOnlyFixture(t, cwd); !reflect.DeepEqual(beforeWorktree, after) {
				t.Fatal("sandbox startup or runtime changed the launched worktree")
			}
		})
	}
}

func TestReadOnlyGitStartupDoesNotChangeMetadata(t *testing.T) {
	for _, scenario := range []string{"ordinary", "linked", "submodule", "missing-custom-hooks", "missing-external-hooks", "rejected-include", "non-git", "relative-denial"} {
		t.Run(scenario, func(t *testing.T) {
			seedGreyproxyDir(t)
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			fixture := t.TempDir()
			repo := filepath.Join(fixture, "repo")
			if err := os.Mkdir(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			if scenario != "non-git" {
				runFixtureGit(t, repo, "init", "-q")
				runFixtureGit(t, repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-qm", "initial")
			}
			cwd := repo
			switch scenario {
			case "linked":
				cwd = filepath.Join(fixture, "linked")
				runFixtureGit(t, repo, "worktree", "add", "-qb", "linked", cwd)
			case "submodule":
				source := filepath.Join(fixture, "source")
				runFixtureGit(t, fixture, "clone", "-q", repo, source)
				runFixtureGit(t, repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", source, "nested/sub")
			case "missing-custom-hooks":
				runFixtureGit(t, repo, "config", "core.hooksPath", "absent-hooks/nested")
			case "missing-external-hooks":
				runFixtureGit(t, repo, "config", "core.hooksPath", filepath.Join(fixture, "absent-hooks", "nested"))
			case "rejected-include":
				runFixtureGit(t, repo, "config", "include.path", "missing.conf")
			}
			if err := os.RemoveAll(filepath.Join(repo, ".git", "hooks")); err != nil {
				t.Fatal(err)
			}
			t.Chdir(cwd)
			before := snapshotReadOnlyFixture(t, fixture)
			cfg := &config.Config{Filesystem: config.FilesystemConfig{
				AllowWrite: []string{fixture, cwd},
				DenyWrite:  []string{repo, cwd},
			}}
			if scenario == "relative-denial" {
				cfg.Filesystem.DenyWrite = []string{"."}
			}
			_, err := WrapCommandLinuxWithOptions(cfg, "git status --short", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
			if scenario == "rejected-include" || scenario == "missing-external-hooks" {
				if err == nil {
					t.Fatal("unprotected external configuration unexpectedly accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if after := snapshotReadOnlyFixture(t, fixture); !reflect.DeepEqual(before, after) {
				for path, contents := range after {
					if before[path] != contents {
						t.Errorf("read-only startup created or changed %s", path)
					}
				}
				for path := range before {
					if _, exists := after[path]; !exists {
						t.Errorf("read-only startup removed %s", path)
					}
				}
			}
		})
	}
}

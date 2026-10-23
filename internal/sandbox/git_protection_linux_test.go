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

func runFixtureGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // test fixture
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func TestGitProtection(t *testing.T) {
	for _, scenario := range []string{"normal", "missing-hooks", "custom-hooks", "external-hooks", "exact-hooks-grant", "include", "worktree", "linked-main-hooks", "registered-worktree", "submodule", "subdirectory"} {
		t.Run(scenario, func(t *testing.T) {
			seedGreyproxyDir(t)
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			repo := t.TempDir()
			runFixtureGit(t, repo, "init", "-q")
			runFixtureGit(t, repo, "config", "user.name", "Fixture")
			runFixtureGit(t, repo, "config", "user.email", "fixture@example.invalid")
			runFixtureGit(t, repo, "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-qm", "initial")
			cwd := repo
			configPath := filepath.Join(repo, ".git", "config")
			hooks := filepath.Join(repo, ".git", "hooks")
			pointer := ""
			extraWrite := ""
			included := ""
			outsideSecret := ""
			switch scenario {
			case "missing-hooks":
				if err := os.RemoveAll(hooks); err != nil {
					t.Fatal(err)
				}
			case "custom-hooks":
				hooks = filepath.Join(repo, "hook-parent", "hooks")
				runFixtureGit(t, repo, "config", "core.hooksPath", "hook-parent/hooks")
			case "external-hooks":
				extraWrite = t.TempDir()
				hooks = filepath.Join(extraWrite, "parent", "hooks")
				runFixtureGit(t, repo, "config", "core.hooksPath", hooks)
			case "exact-hooks-grant":
				parent := t.TempDir()
				hooks = filepath.Join(parent, "hooks")
				if err := os.Mkdir(hooks, 0o700); err != nil {
					t.Fatal(err)
				}
				extraWrite = hooks
				outsideSecret = filepath.Join(parent, "sibling-secret")
				writeTestFile(t, outsideSecret, "EXTERNAL_SECRET")
				runFixtureGit(t, repo, "config", "core.hooksPath", hooks)
			case "include":
				included = filepath.Join(repo, "config-fragments", "local.conf")
				writeTestFile(t, included, "[core]\n hooksPath = hook-parent/hooks\n")
				runFixtureGit(t, repo, "config", "include.path", "../config-fragments/local.conf")
				hooks = filepath.Join(repo, "hook-parent", "hooks")
			case "worktree":
				cwd = filepath.Join(t.TempDir(), "linked")
				runFixtureGit(t, repo, "worktree", "add", "-qb", "linked", cwd)
				pointer = filepath.Join(cwd, ".git")
			case "linked-main-hooks":
				hooks = filepath.Join(repo, "main-hooks")
				runFixtureGit(t, repo, "config", "core.hooksPath", "main-hooks")
				cwd = filepath.Join(t.TempDir(), "linked")
				runFixtureGit(t, repo, "worktree", "add", "-qb", "linked", cwd)
				pointer = filepath.Join(cwd, ".git")
			case "registered-worktree":
				linked := filepath.Join(repo, "linked")
				runFixtureGit(t, repo, "worktree", "add", "-qb", "linked", linked)
				pointer = filepath.Join(linked, ".git")
			case "submodule":
				source := t.TempDir()
				runFixtureGit(t, source, "init", "-q")
				runFixtureGit(t, source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-qm", "initial")
				runFixtureGit(t, repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", source, "nested/sub")
				configPath = filepath.Join(repo, ".git", "modules", "nested", "sub", "config")
				hooks = filepath.Join(repo, ".git", "modules", "nested", "sub", "hooks")
				pointer = filepath.Join(repo, "nested", "sub", ".git")
			case "subdirectory":
				cwd = filepath.Join(repo, "src")
				if err := os.Mkdir(cwd, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(cwd)
			worktreeConfig := filepath.Join(runFixtureGit(t, cwd, "rev-parse", "--absolute-git-dir"), "config.worktree")
			commonPointer := filepath.Join(filepath.Dir(worktreeConfig), "commondir")
			cfg := &config.Config{Filesystem: config.FilesystemConfig{AllowWrite: []string{repo, cwd}}}
			if extraWrite != "" {
				cfg.Filesystem.AllowWrite = append(cfg.Filesystem.AllowWrite, extraWrite)
			}
			probe := "test -r " + ShellQuoteSingle(configPath) +
				" && ! (printf injected >> " + ShellQuoteSingle(configPath) + ") 2>/dev/null" +
				" && ! (printf injected >> " + ShellQuoteSingle(worktreeConfig) + ") 2>/dev/null" +
				" && ! (printf injected >> " + ShellQuoteSingle(commonPointer) + ") 2>/dev/null" +
				" && ! (printf injected > " + ShellQuoteSingle(filepath.Join(hooks, "pre-commit")) + ") 2>/dev/null" +
				" && ! mv " + ShellQuoteSingle(filepath.Join(repo, ".git")) + " " + ShellQuoteSingle(filepath.Join(repo, ".git-old")) + " 2>/dev/null"
			if pointer != "" {
				probe += " && ! (printf injected > " + ShellQuoteSingle(pointer) + ") 2>/dev/null"
			}
			if scenario == "custom-hooks" || scenario == "external-hooks" {
				probe += " && ! mv " + ShellQuoteSingle(filepath.Dir(hooks)) + " " + ShellQuoteSingle(filepath.Join(filepath.Dir(filepath.Dir(hooks)), "hooks-old")) + " 2>/dev/null"
			}
			if included != "" {
				probe += " && ! (printf injected >> " + ShellQuoteSingle(included) + ") 2>/dev/null" +
					" && ! mv " + ShellQuoteSingle(filepath.Dir(included)) + " " + ShellQuoteSingle(filepath.Join(repo, "config-old")) + " 2>/dev/null"
			}
			if outsideSecret != "" {
				probe += " && ! cat " + ShellQuoteSingle(outsideSecret) + " 2>/dev/null"
			}
			probe += " && printf safe > git-test-file && git add git-test-file && git commit -qm sandbox-commit" +
				" && git update-index --refresh && git update-ref refs/heads/security-test HEAD && printf GIT_PROTECTION_OK"
			command, err := WrapCommandLinuxWithOptions(cfg, probe, nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
			if err != nil {
				t.Fatal(err)
			}
			mounts := parseBwrapMounts(command)
			for _, path := range []string{configPath, worktreeConfig, commonPointer, hooks, pointer} {
				if path == "" {
					continue
				}
				index := lastDestIndex(mounts, path)
				if index < 0 || mounts[index].flag != "--ro-bind" {
					t.Errorf("%s lacks a read-only bind", path)
				}
			}
			t.Run("runtime", func(t *testing.T) {
				skipIfAlreadySandboxed(t)
				output, err := exec.Command("bash", "-c", command).CombinedOutput() //nolint:gosec // generated sandbox command
				if err != nil || !strings.HasSuffix(string(output), "GIT_PROTECTION_OK") {
					t.Fatalf("protection or normal Git operations failed: %v\n%s", err, output)
				}
			})
		})
	}
}

func TestGitProtection_DoesNotGrantWritesToParentRepository(t *testing.T) {
	seedGreyproxyDir(t)
	repo := t.TempDir()
	runFixtureGit(t, repo, "init", "-q")
	cwd := filepath.Join(repo, "src")
	writeTestFile(t, filepath.Join(repo, ".env"), "SIBLING_SECRET")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	command, err := WrapCommandLinuxWithOptions(&config.Config{},
		`printf own > own-file && { printf parent > ../outside-file 2>/dev/null || true; } && ! cat ../.env 2>/dev/null && printf SCOPE_OK`,
		nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, mount := range parseBwrapMounts(command) {
		if mount.dest == repo && mount.flag == "--bind" {
			t.Fatal("protecting Git widened write access to the parent repository")
		}
	}
	t.Run("runtime", func(t *testing.T) {
		skipIfAlreadySandboxed(t)
		output, err := exec.Command("bash", "-c", command).CombinedOutput() //nolint:gosec // generated sandbox command
		if err != nil || !strings.HasSuffix(string(output), "SCOPE_OK") {
			t.Fatalf("write scope changed: %v\n%s", err, output)
		}
		// Writes to synthetic ancestors in the private tmpfs are harmless;
		// they must not reach the host parent repository.
		if _, err := os.Stat(filepath.Join(repo, "outside-file")); !os.IsNotExist(err) {
			t.Fatalf("sandbox changed the host parent repository: %v", err)
		}
	})
}

func TestGitProtection_RejectsSymlinkedMetadata(t *testing.T) {
	for _, name := range []string{"config", "hooks"} {
		t.Run(name, func(t *testing.T) {
			seedGreyproxyDir(t)
			repo := t.TempDir()
			runFixtureGit(t, repo, "init", "-q")
			path := filepath.Join(repo, ".git", name)
			target := filepath.Join(repo, "shared-"+name)
			if err := os.Rename(path, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			t.Chdir(repo)
			if _, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{}); err == nil {
				t.Fatal("replaceable symlinked metadata was accepted")
			}
		})
	}
}

func TestGitProtection_RejectedHooksPathDoesNotCreateDirectories(t *testing.T) {
	for _, pathKind := range []string{"relative", "absolute"} {
		t.Run(pathKind, func(t *testing.T) {
			seedGreyproxyDir(t)
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			repo := t.TempDir()
			outside := t.TempDir()
			runFixtureGit(t, repo, "init", "-q")
			link := filepath.Join(repo, "hooks-link")
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			hooksPath := filepath.Join("hooks-link", "new", "hooks")
			if pathKind == "absolute" {
				hooksPath = filepath.Join(repo, hooksPath)
			}
			runFixtureGit(t, repo, "config", "core.hooksPath", hooksPath)
			t.Chdir(repo)
			_, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
			if err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("replaceable hooks symlink was not rejected: %v", err)
			}
			entries, err := os.ReadDir(outside)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("rejected hooks path changed its external target: %v", entries)
			}
		})
	}
}

func TestGitProtection_RejectsConditionalIncludes(t *testing.T) {
	seedGreyproxyDir(t)
	repo := t.TempDir()
	runFixtureGit(t, repo, "init", "-q")
	include := filepath.Join(repo, "conditional.conf")
	writeTestFile(t, include, "[core]\n hooksPath = unsafe-hooks\n")
	runFixtureGit(t, repo, "config", "includeIf.onbranch:future.path", include)
	t.Chdir(repo)
	if _, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{}); err == nil {
		t.Fatal("branch-dependent hooks could activate after startup")
	}
}

func TestGitProtection_RejectsSymlinkedPointerTarget(t *testing.T) {
	seedGreyproxyDir(t)
	repo := t.TempDir()
	runFixtureGit(t, repo, "init", "-q")
	metadata := filepath.Join(repo, "actual-metadata")
	if err := os.Rename(filepath.Join(repo, ".git"), metadata); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(repo, "metadata-alias")
	if err := os.Symlink(metadata, alias); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(repo, ".git"), "gitdir: "+alias+"\n")
	t.Chdir(repo)
	if _, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{}); err == nil {
		t.Fatal("replaceable symlink in pointer target was accepted")
	}
}

func TestGitProtection_AllowsReadOnlyGlobalIncludeSymlinks(t *testing.T) {
	home, _ := seedGreyproxyDir(t)
	repo := t.TempDir()
	runFixtureGit(t, repo, "init", "-q")
	target := filepath.Join(t.TempDir(), "theme.gitconfig")
	writeTestFile(t, target, "[color]\n ui = auto\n")
	link := filepath.Join(home, "theme.gitconfig")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, repo, "config", "--global", "include.path", link)
	t.Chdir(repo)
	if _, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{}); err != nil {
		t.Fatalf("host-managed read-only include rejected: %v", err)
	}
}

func TestGitProtection_RejectsMutableIntermediateIncludeSymlink(t *testing.T) {
	home, _ := seedGreyproxyDir(t)
	repo := t.TempDir()
	runFixtureGit(t, repo, "init", "-q")
	target := filepath.Join(t.TempDir(), "theme.gitconfig")
	writeTestFile(t, target, "[color]\n ui = auto\n")
	intermediate := filepath.Join(repo, "mutable-link")
	if err := os.Symlink(target, intermediate); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "theme.gitconfig")
	if err := os.Symlink(intermediate, link); err != nil {
		t.Fatal(err)
	}
	runFixtureGit(t, repo, "config", "--global", "include.path", link)
	t.Chdir(repo)
	if _, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{}); err == nil {
		t.Fatal("mutable intermediate include symlink was accepted")
	}
}

func TestGitProtection_RejectsUndiscoverableSeparateGitDirectory(t *testing.T) {
	seedGreyproxyDir(t)
	repo := t.TempDir()
	metadata := filepath.Join(t.TempDir(), "separate-metadata")
	runFixtureGit(t, repo, "init", "-q", "--separate-git-dir="+metadata)
	t.Chdir(repo)
	if _, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{}); err == nil {
		t.Fatal("separate common directory without a discoverable main worktree was accepted")
	}
}

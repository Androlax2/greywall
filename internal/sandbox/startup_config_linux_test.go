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

func TestStartupConfigProtection(t *testing.T) {
	for _, exists := range []bool{false, true} {
		name := "missing"
		if exists {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			seedGreyproxyDir(t)
			project := t.TempDir()
			t.Chdir(project)
			files := []string{".envrc", "opencode.json", "opencode.jsonc", ".claude/settings.json", ".claude/settings.local.json"}
			dirs := []string{".opencode", ".zed", ".cursor", ".devcontainer"}
			if exists {
				for _, path := range files {
					writeTestFile(t, filepath.Join(project, path), "preserve this content")
				}
				for _, dir := range dirs {
					writeTestFile(t, filepath.Join(project, dir, "existing-file"), "preserve this content")
				}
			}
			var checks []string
			for _, path := range files {
				checks = append(checks, "! (printf injected >> "+ShellQuoteSingle(path)+") 2>/dev/null")
			}
			for _, path := range dirs {
				checks = append(checks,
					"! (printf injected > "+ShellQuoteSingle(filepath.Join(path, "new-file"))+") 2>/dev/null",
					"! mv "+ShellQuoteSingle(path)+" "+ShellQuoteSingle(path+"-moved")+" 2>/dev/null")
			}
			checks = append(checks, "! mv .claude .claude-moved 2>/dev/null", "printf ordinary > ordinary-file", "printf STARTUP_PROTECTED")
			command, err := WrapCommandLinuxWithOptions(&config.Config{}, strings.Join(checks, " && "), nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range append(files, dirs...) {
				if _, err := os.Stat(filepath.Join(project, path)); err != nil {
					t.Errorf("startup path was not prepared: %s: %v", path, err)
				}
				mounts := parseBwrapMounts(command)
				index := lastDestIndex(mounts, filepath.Join(project, path))
				if index < 0 || mounts[index].flag != "--ro-bind" {
					t.Errorf("startup path is not read-only: %s", path)
				}
			}
			if exists {
				for _, path := range files {
					contents, err := os.ReadFile(filepath.Join(project, path)) // #nosec G304 -- reads fixed fixture names under this test's temporary project
					if err != nil || string(contents) != "preserve this content" {
						t.Errorf("existing content changed: %s: %v", path, err)
					}
				}
			}
			t.Run("runtime", func(t *testing.T) {
				skipIfAlreadySandboxed(t)
				output, err := exec.Command("bash", "-c", command).CombinedOutput() //nolint:gosec // generated sandbox command
				if err != nil || strings.TrimSpace(string(output)) != "STARTUP_PROTECTED" {
					t.Fatalf("startup protection or ordinary writes failed: %v\n%s", err, output)
				}
			})
		})
	}
}

func TestStartupConfigProtection_RejectsSymlinksWithoutChangingTarget(t *testing.T) {
	for _, path := range []string{"opencode.json", ".cursor", ".claude"} {
		t.Run(path, func(t *testing.T) {
			seedGreyproxyDir(t)
			project := t.TempDir()
			target := t.TempDir()
			if err := os.Symlink(target, filepath.Join(project, path)); err != nil {
				t.Fatal(err)
			}
			t.Chdir(project)
			if _, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{}); err == nil {
				t.Fatal("symlinked startup path accepted")
			}
			entries, err := os.ReadDir(target)
			if err != nil || len(entries) != 0 {
				t.Fatalf("symlink target changed: %v: %v", entries, err)
			}
		})
	}
}

func TestStartupConfigProtection_DoesNotCoverGitProtections(t *testing.T) {
	skipIfAlreadySandboxed(t)
	seedGreyproxyDir(t)
	project := t.TempDir()
	runFixtureGit(t, project, "init", "-q")
	writeTestFile(t, filepath.Join(project, ".claude", "nested", "git-config"), "[core]\n hooksPath = .claude/nested/hooks\n")
	runFixtureGit(t, project, "config", "include.path", "../.claude/nested/git-config")
	t.Chdir(project)
	command, err := WrapCommandLinuxWithOptions(&config.Config{},
		`! (printf injected >> .claude/nested/git-config) 2>/dev/null && ! (printf injected > .claude/nested/hooks/pre-commit) 2>/dev/null && ! mv .claude/nested .claude/moved 2>/dev/null && printf GIT_STILL_PROTECTED`,
		nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("bash", "-c", command).CombinedOutput() //nolint:gosec // generated sandbox command
	if err != nil || strings.TrimSpace(string(output)) != "GIT_STILL_PROTECTED" {
		t.Fatalf("startup mounts covered Git protection: %v\n%s", err, output)
	}
}

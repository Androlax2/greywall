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

func TestWrapCommandLinux_ProtectsSymlinkedGitconfig(t *testing.T) {
	for _, defaultDenyRead := range []bool{false, true} {
		name := "legacy"
		if defaultDenyRead {
			name = "deny-by-default"
		}
		t.Run(name, func(t *testing.T) {
			home, _ := seedGreyproxyDir(t)
			target := filepath.Join(home, ".config", "git", "config")
			writeTestFile(t, target, "[user]\nname = Test\n")
			link := filepath.Join(home, ".gitconfig")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{Filesystem: config.FilesystemConfig{
				DefaultDenyRead: &defaultDenyRead,
				AllowWrite:      []string{home},
			}}
			command, err := WrapCommandLinuxWithOptions(cfg,
				`cat "$HOME/.gitconfig" >/dev/null && ! (printf changed >> "$HOME/.gitconfig") 2>/dev/null && printf GITCONFIG_OK`,
				nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
			if err != nil {
				t.Fatal(err)
			}
			mounts := parseBwrapMounts(command)
			for _, mount := range mounts {
				if mount.dest == link {
					t.Errorf("bind mount targets a symlink: %+v", mount)
				}
			}
			last := lastDestIndex(mounts, target)
			if last < 0 || mounts[last].flag != "--ro-bind" {
				t.Fatalf("gitconfig target has no read-only bind: %+v", mounts)
			}
			t.Run("runtime", func(t *testing.T) {
				skipIfAlreadySandboxed(t)
				output, err := exec.Command("bash", "-c", command).CombinedOutput() //nolint:gosec // generated sandbox command
				if err != nil || strings.TrimSpace(string(output)) != "GITCONFIG_OK" {
					t.Fatalf("sandbox failed: %v\n%s", err, output)
				}
			})
		})
	}
}

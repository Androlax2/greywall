package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateMounts_AcceptsHostDirMountedUnderTmp(t *testing.T) {
	mounts := []Mount{{Source: "/home/user/session/codex-daemon", Target: "/tmp/codex-daemon-1000"}}
	if err := ValidateMounts(mounts); err != nil {
		t.Fatalf("ValidateMounts() = %v, want nil", err)
	}
}

func TestValidateMounts_RejectsInvalidPaths(t *testing.T) {
	tests := []struct {
		name      string
		mount     Mount
		wantInErr string
	}{
		{"empty source", Mount{Source: "", Target: "/tmp/x"}, "source"},
		{"relative source", Mount{Source: "session/dir", Target: "/tmp/x"}, "absolute"},
		{"source with ..", Mount{Source: "/home/user/../root", Target: "/tmp/x"}, ".."},
		{"unclean source", Mount{Source: "/home//user/", Target: "/tmp/x"}, "clean"},
		{"empty target", Mount{Source: "/home/user/dir", Target: ""}, "target"},
		{"relative target", Mount{Source: "/home/user/dir", Target: "tmp/x"}, "absolute"},
		{"target outside /tmp", Mount{Source: "/home/user/dir", Target: "/home/user/.ssh"}, "/tmp"},
		{"target is /tmp itself", Mount{Source: "/home/user/dir", Target: "/tmp"}, "/tmp"},
		{"target sharing the /tmp prefix", Mount{Source: "/home/user/dir", Target: "/tmpfoo/x"}, "/tmp"},
		{"target with ..", Mount{Source: "/home/user/dir", Target: "/tmp/../etc"}, ".."},
		{"unclean target", Mount{Source: "/home/user/dir", Target: "/tmp/x/"}, "clean"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMounts([]Mount{tt.mount})
			if err == nil {
				t.Fatalf("ValidateMounts(%+v) = nil, want error", tt.mount)
			}
			if !strings.Contains(err.Error(), tt.wantInErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantInErr)
			}
		})
	}
}

func TestValidateMounts_RejectsTwoMountsOnTheSameTarget(t *testing.T) {
	mounts := []Mount{
		{Source: "/home/user/a", Target: "/tmp/x"},
		{Source: "/home/user/b", Target: "/tmp/x"},
	}
	if err := ValidateMounts(mounts); err == nil {
		t.Fatal("ValidateMounts() = nil, want error for duplicate target")
	}
}

func TestValidateMounts_RejectsNestedTargets(t *testing.T) {
	for _, mounts := range [][]Mount{
		{{Source: "/home/user/a", Target: "/tmp/a"}, {Source: "/home/user/b", Target: "/tmp/a/b"}},
		{{Source: "/home/user/b", Target: "/tmp/a/b"}, {Source: "/home/user/a", Target: "/tmp/a"}},
	} {
		if err := ValidateMounts(mounts); err == nil {
			t.Errorf("ValidateMounts(%+v) = nil, want error for nested targets", mounts)
		}
	}
}

func TestValidateMounts_AcceptsTargetsSharingANamePrefix(t *testing.T) {
	mounts := []Mount{{Source: "/home/user/a", Target: "/tmp/a"}, {Source: "/home/user/b", Target: "/tmp/ab"}}
	if err := ValidateMounts(mounts); err != nil {
		t.Errorf("ValidateMounts() = %v, want nil", err)
	}
}

func TestValidateMounts_RejectsTargetsReservedForGreywall(t *testing.T) {
	for _, target := range []string{"/tmp/.greywall-wrapper", "/tmp/.greywall-wrapper/x", "/tmp/greywall-tun2socks", "/tmp/greywall-rev-abc/x"} {
		t.Run(target, func(t *testing.T) {
			if err := ValidateMounts([]Mount{{Source: "/home/user/a", Target: target}}); err == nil {
				t.Errorf("ValidateMounts(target %q) = nil, want error", target)
			}
		})
	}
}

func TestLoad_RejectsSettingsMountOutsideTmp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	settings := `{"filesystem": {"mounts": [{"source": "/home/user/dir", "target": "/etc/x"}]}}`
	if err := os.WriteFile(path, []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() = nil error, want mount validation error")
	}
}

func TestLoad_ReadsSettingsMounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	settings := `{"filesystem": {"mounts": [{"source": "/home/user/dir", "target": "/tmp/x"}]}}`
	if err := os.WriteFile(path, []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := Mount{Source: "/home/user/dir", Target: "/tmp/x"}
	if len(cfg.Filesystem.Mounts) != 1 || cfg.Filesystem.Mounts[0] != want {
		t.Errorf("Mounts = %+v, want [%+v]", cfg.Filesystem.Mounts, want)
	}
}

func TestMerge_KeepsMountsFromBaseAndOverride(t *testing.T) {
	base := &Config{Filesystem: FilesystemConfig{Mounts: []Mount{{Source: "/a", Target: "/tmp/a"}}}}
	override := &Config{Filesystem: FilesystemConfig{Mounts: []Mount{{Source: "/b", Target: "/tmp/b"}}}}

	merged := Merge(base, override)

	want := []Mount{{Source: "/a", Target: "/tmp/a"}, {Source: "/b", Target: "/tmp/b"}}
	if len(merged.Filesystem.Mounts) != 2 || merged.Filesystem.Mounts[0] != want[0] || merged.Filesystem.Mounts[1] != want[1] {
		t.Errorf("merged Mounts = %+v, want %+v", merged.Filesystem.Mounts, want)
	}
}

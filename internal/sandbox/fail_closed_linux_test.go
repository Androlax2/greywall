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

func overrideLinuxFeatures(t *testing.T) *LinuxFeatures {
	t.Helper()
	seedGreyproxyDir(t)
	features := DetectLinuxFeatures()
	original := *features
	t.Cleanup(func() { *features = original })
	return features
}

func TestWrapCommandLinux_RequiresNetworkNamespaceDespiteFailedProbe(t *testing.T) {
	overrideLinuxFeatures(t).CanUnshareNet = false
	for _, mode := range []LinuxSandboxOptions{{}, {Watch: true}, {Learning: true}} {
		command, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", mode)
		if err != nil {
			t.Fatal(err)
		}
		outer, _, _ := strings.Cut(command, " -- ")
		if !strings.Contains(outer, " --unshare-net ") {
			t.Errorf("failed probe allowed a command with the host network: %s", outer)
		}
	}
}

func TestWrapCommandLinux_FailedNamespaceNeverRunsCommand(t *testing.T) {
	overrideLinuxFeatures(t).CanUnshareNet = false
	bin := t.TempDir()
	// Simulate bubblewrap failing namespace setup. Without --unshare-net,
	// this fake instead reaches the command, exposing the fail-open path.
	program := "#!/bin/sh\nfor arg in \"$@\"; do\n" +
		"if [ \"$arg\" = --unshare-net ]; then exit 42; fi\n" +
		"done\nprintf HOST_NETWORK_COMMAND_RAN\n"
	if err := os.WriteFile(filepath.Join(bin, "bwrap"), []byte(program), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	command, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("bash", "-c", command).CombinedOutput() //nolint:gosec // generated sandbox command with fake bwrap
	if err == nil {
		t.Fatalf("namespace failure did not stop startup: %s", output)
	}
	if strings.Contains(string(output), "HOST_NETWORK_COMMAND_RAN") {
		t.Fatal("command ran despite namespace failure")
	}
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 42 {
		t.Fatalf("expected namespace setup failure exit 42, got %v: %s", err, output)
	}
}

func TestWrapCommandLinux_RejectsUnavailableRequestedSeccomp(t *testing.T) {
	overrideLinuxFeatures(t).HasSeccomp = false
	_, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{UseSeccomp: true})
	if err == nil {
		t.Fatal("requested seccomp silently omitted")
	}
}

func TestWrapCommandLinux_RejectsSeccompGenerationFailure(t *testing.T) {
	overrideLinuxFeatures(t).HasSeccomp = true
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", blocked)
	_, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{UseSeccomp: true})
	if err == nil {
		t.Fatal("seccomp generation failed but an unfiltered command was returned")
	}
}

func TestApplyLandlockFromConfig_RejectsUnavailableLandlock(t *testing.T) {
	overrideLinuxFeatures(t).HasLandlock = false
	if err := ApplyLandlockFromConfig(&config.Config{}, "", nil, MaskedPaths{}, false); err == nil {
		t.Fatal("Landlock reported success without enforcing anything")
	}
}

func TestWrapCommandLinux_RejectsUnavailableRequestedLandlock(t *testing.T) {
	overrideLinuxFeatures(t).HasLandlock = false
	_, err := WrapCommandLinuxWithOptions(&config.Config{}, "true", nil, nil, nil, nil, nil, "", LinuxSandboxOptions{UseLandlock: true})
	if err == nil {
		t.Fatal("requested Landlock silently omitted")
	}
}

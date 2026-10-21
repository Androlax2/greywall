//go:build linux

package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

const landlockHelperEnvVar = "GREYWALL_TEST_LANDLOCK_HELPER"

// TestLandlockHelperProcess is not a test: TestLandlockAloneHidesMaskedSecrets
// runs it in a child process, which applies Landlock and reports what it can
// read. Landlock cannot be undone, so it must not run in the test process.
func TestLandlockHelperProcess(t *testing.T) {
	if os.Getenv(landlockHelperEnvVar) != "1" {
		t.Skip("helper process only")
	}
	if !DetectLinuxFeatures().CanUseLandlock() {
		fmt.Println("LANDLOCK=unavailable")
		os.Exit(0)
	}
	var masked MaskedPaths
	if err := json.Unmarshal([]byte(os.Getenv(MaskedPathsEnvVar)), &masked); err != nil {
		fmt.Println("ERROR=" + err.Error())
		os.Exit(1)
	}
	defaultDenyRead := os.Getenv("GREYWALL_TEST_DEFAULT_DENY_READ") == "1"
	cfg := &config.Config{Filesystem: config.FilesystemConfig{DefaultDenyRead: &defaultDenyRead}}
	cwd, _ := os.Getwd()
	if err := ApplyLandlockFromConfig(cfg, cwd, nil, masked, false); err != nil {
		fmt.Println("ERROR=" + err.Error())
		os.Exit(1)
	}
	for _, path := range strings.Split(os.Getenv("GREYWALL_TEST_PROBE_PATHS"), "\n") {
		if _, err := os.ReadFile(path); err == nil { //nolint:gosec // test probe
			fmt.Println("READABLE=" + path)
		} else {
			fmt.Println("BLOCKED=" + path)
		}
	}
	os.Exit(0)
}

// The #103 (greyproxy secrets) and #112 (~/.ssh keys under a denyWrite parent)
// leaks came from bind-mount order. With no mounts at all, Landlock alone must
// keep the masked paths unreadable while their neighbours stay readable.
func TestLandlockAloneHidesMaskedSecrets(t *testing.T) {
	for _, defaultDenyRead := range []bool{false, true} {
		t.Run(fmt.Sprintf("defaultDenyRead=%v", defaultDenyRead), func(t *testing.T) {
			// HOME must lie outside /tmp and the working directory: both get
			// writable rules, which are not split around masked paths.
			homeParent, err := os.MkdirTemp(".", ".landlock-test-home-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(homeParent) })
			home, err := filepath.Abs(homeParent)
			if err != nil {
				t.Fatal(err)
			}
			for path, contents := range map[string]string{
				".ssh/id_ed25519":                      "PRIVATE KEY",
				".ssh/config":                          "Host *",
				".local/share/greyproxy/session.key":   "SESSION KEY",
				".local/share/greyproxy/ca-key.pem":    "CA KEY",
				".local/share/greyproxy/greyproxy.db":  "DB",
				".local/share/greyproxy/ca-cert.pem":   "CA CERT",
				".local/share/other-app/settings.json": "{}",
			} {
				writeTestFile(t, filepath.Join(home, path), contents)
			}
			dataDir := filepath.Join(home, ".local", "share", "greyproxy")
			masked := MaskedPaths{
				Files:      []string{filepath.Join(home, ".ssh", "id_ed25519")},
				Dirs:       []string{dataDir},
				Exceptions: []string{filepath.Join(dataDir, "ca-cert.pem")},
			}
			maskedJSON, err := json.Marshal(masked)
			if err != nil {
				t.Fatal(err)
			}
			mustBeBlocked := []string{
				filepath.Join(home, ".ssh", "id_ed25519"),
				filepath.Join(dataDir, "session.key"),
				filepath.Join(dataDir, "ca-key.pem"),
				filepath.Join(dataDir, "greyproxy.db"),
			}
			mustBeReadable := []string{
				filepath.Join(dataDir, "ca-cert.pem"),
				filepath.Join(home, ".local", "share", "other-app", "settings.json"),
			}
			if !defaultDenyRead {
				// Deny-by-default grants no rule on ~/.ssh in the first place.
				mustBeReadable = append(mustBeReadable, filepath.Join(home, ".ssh", "config"))
			}

			helper := exec.Command(os.Args[0], "-test.run=^TestLandlockHelperProcess$") //nolint:gosec // re-runs this test binary
			helper.Dir = t.TempDir()
			helper.Env = append(os.Environ(),
				landlockHelperEnvVar+"=1",
				"HOME="+home,
				MaskedPathsEnvVar+"="+string(maskedJSON),
				"GREYWALL_TEST_PROBE_PATHS="+strings.Join(append(append([]string{}, mustBeBlocked...), mustBeReadable...), "\n"),
				fmt.Sprintf("GREYWALL_TEST_DEFAULT_DENY_READ=%v", map[bool]int{false: 0, true: 1}[defaultDenyRead]),
			)
			output, err := helper.CombinedOutput()
			report := string(output)
			if strings.Contains(report, "LANDLOCK=unavailable") {
				t.Skip("skipping: Landlock is not available here")
			}
			if err != nil {
				t.Fatalf("helper process failed: %v\n%s", err, report)
			}
			for _, path := range mustBeBlocked {
				if !strings.Contains(report, "BLOCKED="+path+"\n") {
					t.Errorf("%s is readable with Landlock alone\n%s", path, report)
				}
			}
			for _, path := range mustBeReadable {
				if !strings.Contains(report, "READABLE="+path+"\n") {
					t.Errorf("%s should stay readable\n%s", path, report)
				}
			}
		})
	}
}

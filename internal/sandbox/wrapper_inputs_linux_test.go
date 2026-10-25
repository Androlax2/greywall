//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Above Linux's 128 KiB limit on one argument (MAX_ARG_STRLEN), the size a
// config with ~320 denyWrite paths reached as a single `sh -c` argument.
const oversizedArgumentBytes = 200 * 1024

func oversizedJSON() []byte {
	return []byte(`{"denyWrite":["` + strings.Repeat("x", oversizedArgumentBytes) + `"]}`)
}

func runScriptFile(t *testing.T, script string) ([]byte, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "command.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	return exec.Command("sh", path).CombinedOutput() //nolint:gosec // runs the script written above
}

func TestDataFileArgs_DeliversDataLargerThanOneArgumentOnItsFD(t *testing.T) {
	data := oversizedJSON()
	_, redirection, err := dataFileArgs(wrapperConfigFD, data, WrapperConfigFile)
	if err != nil {
		t.Fatal(err)
	}

	output, err := runScriptFile(t, redirection+"exec cat <&4\n")
	if err != nil {
		t.Fatalf("script failed: %v\n%.200s", err, output)
	}
	if strings.TrimSuffix(string(output), "\n") != string(data) {
		t.Errorf("fd 4 delivered %d bytes, want the %d bytes of data", len(output), len(data))
	}
}

func TestDataFileArgs_RejectsMultiLineData(t *testing.T) {
	_, _, err := dataFileArgs(wrapperConfigFD, []byte("{}\nGREYWALL_DATA_4\nrm -rf ~"), WrapperConfigFile)
	if err == nil {
		t.Error("multi-line data could end the here-document early")
	}
}

func TestDataFileArgs_BwrapWritesDataLargerThanOneArgumentIntoTheSandbox(t *testing.T) {
	skipIfAlreadySandboxed(t)
	skipIfCommandNotFound(t, "bwrap")
	data := oversizedJSON()
	args, redirection, err := dataFileArgs(wrapperConfigFD, data, WrapperConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	bwrapArgs := append([]string{"bwrap", "--ro-bind", "/", "/", "--tmpfs", "/tmp"}, args...)
	bwrapArgs = append(bwrapArgs, "--", "cat", WrapperConfigFile)

	output, err := runScriptFile(t, redirection+"exec "+ShellQuote(bwrapArgs)+"\n")
	if err != nil {
		t.Fatalf("bwrap failed: %v\n%.200s", err, output)
	}
	if strings.TrimSuffix(string(output), "\n") != string(data) {
		t.Errorf("sandbox read %d bytes from %s, want the %d bytes of data", len(output), WrapperConfigFile, len(data))
	}
}

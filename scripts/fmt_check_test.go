package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatCheck_PropagatesFormatterFailures(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make unavailable")
	}
	shellPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("POSIX shell unavailable")
	}
	makefile, err := filepath.Abs("../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name        string
		formatter   string
		wantSuccess bool
		wantOutput  string
	}{
		{"missing formatter", "", false, "gofumpt"},
		{"formatter error", "echo FORMATTER_FAILED >&2\nexit 42", false, "FORMATTER_FAILED"},
		{"unformatted files", "echo fixture.go", false, "fixture.go"},
		{"formatted files", "exit 0", true, "All files are formatted."},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			directory := t.TempDir()
			bin := filepath.Join(directory, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			if scenario.formatter != "" {
				program := "#!" + shellPath + "\n" +
					"[ \"$#\" = 2 ] && [ \"$1\" = -l ] && [ \"$2\" = . ] || exit 91\n" + scenario.formatter + "\n"
				if err := os.WriteFile(filepath.Join(bin, "gofumpt"), []byte(program), 0o700); err != nil { // #nosec G306 -- owner-only executable formatter fixture
					t.Fatal(err)
				}
			}
			// Isolate recipe lookup without breaking make launchers that need the caller's PATH.
			command := exec.Command(makePath, "--no-print-directory", "-f", makefile, "SHELL="+shellPath, "PATH="+bin, "fmt-check") // #nosec G204 -- exercises the repository Makefile with an isolated formatter fixture
			command.Dir = directory
			command.Env = append(os.Environ(), "MAKEFLAGS=", "MFLAGS=", "GNUMAKEFLAGS=", "MAKEFILES=")
			output, err := command.CombinedOutput()
			if (err == nil) != scenario.wantSuccess {
				t.Fatalf("format check success = %t, want %t: %v\n%s", err == nil, scenario.wantSuccess, err, output)
			}
			if !strings.Contains(string(output), scenario.wantOutput) {
				t.Fatalf("missing %q in output:\n%s", scenario.wantOutput, output)
			}
			if !scenario.wantSuccess && strings.Contains(string(output), "All files are formatted.") {
				t.Fatalf("failed format check reported success:\n%s", output)
			}
		})
	}
}

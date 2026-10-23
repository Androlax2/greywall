package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSmokeTests_DoNotPassInteractiveInputToGreywall(t *testing.T) {
	script, err := filepath.Abs("smoke_test.sh")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	fixture := filepath.Join(directory, "greywall-fixture")
	// Stop after --version so this tests input handling, not the rest of the
	// smoke suite. If stdin leaks, the first invocation consumes our line.
	program := "#!/bin/bash\nif read -r line; then echo INPUT_REACHED_GREYWALL; exit 99; fi\n" +
		"if [[ $1 == --version ]]; then exit 0; fi\necho FIXTURE_STOP; exit 99\n"
	if err := os.WriteFile(fixture, []byte(program), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", script, fixture)
	command.Dir = directory
	command.Stdin = strings.NewReader("interactive answer\n")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("fixture should stop the smoke script after its version check")
	}
	if strings.Contains(string(output), "INPUT_REACHED_GREYWALL") {
		t.Fatalf("smoke script passed interactive input to greywall:\n%s", output)
	}
	if !strings.Contains(string(output), "FIXTURE_STOP") {
		t.Fatalf("script did not reach the deliberate fixture stop:\n%s", output)
	}
}

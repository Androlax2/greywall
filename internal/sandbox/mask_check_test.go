package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMaskedPathsFromArgs(t *testing.T) {
	emptyFile := filepath.Join(os.TempDir(), "greywall", "empty")
	args := []string{
		"--ro-bind", "/dev/null", "/home/u/.ssh/id_ed25519",
		"--tmpfs", "/home/u/.aws",
		"--ro-bind", emptyFile, "/work/.env",
		"--ro-bind", "/tmp/rewritten-env", "/work/.env.local",
		"--tmpfs", "/home/u/.local/share/greyproxy",
		"--ro-bind", "/home/u/.local/share/greyproxy/ca-cert.pem", "/home/u/.local/share/greyproxy/ca-cert.pem",
	}

	got := maskedPathsFromArgs(args)

	wantFiles := []string{"/home/u/.ssh/id_ed25519", "/work/.env"}
	wantDirs := []string{"/home/u/.aws", "/home/u/.local/share/greyproxy"}
	wantExceptions := []string{"/home/u/.local/share/greyproxy/ca-cert.pem"}
	if !slices.Equal(got.Files, wantFiles) {
		t.Errorf("Files = %v, want %v", got.Files, wantFiles)
	}
	if !slices.Equal(got.Dirs, wantDirs) {
		t.Errorf("Dirs = %v, want %v", got.Dirs, wantDirs)
	}
	if !slices.Equal(got.Exceptions, wantExceptions) {
		t.Errorf("Exceptions = %v, want %v", got.Exceptions, wantExceptions)
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyMasks_PassesWhenMaskedPathsReadEmpty(t *testing.T) {
	root := t.TempDir()
	emptyKey := filepath.Join(root, "id_ed25519")
	writeTestFile(t, emptyKey, "")
	maskedDir := filepath.Join(root, "greyproxy")
	writeTestFile(t, filepath.Join(maskedDir, "session.key"), "")
	writeTestFile(t, filepath.Join(maskedDir, "ca-cert.pem"), "public certificate")

	err := VerifyMasks(MaskedPaths{
		Files:      []string{emptyKey, filepath.Join(root, "missing")},
		Dirs:       []string{maskedDir},
		Exceptions: []string{filepath.Join(maskedDir, "ca-cert.pem")},
	})
	if err != nil {
		t.Errorf("VerifyMasks: %v", err)
	}
}

func TestVerifyMasks_FailsWhenAMaskedFileIsReadable(t *testing.T) {
	root := t.TempDir()
	key := filepath.Join(root, "id_ed25519")
	writeTestFile(t, key, "PRIVATE KEY")

	err := VerifyMasks(MaskedPaths{Files: []string{key}})
	if err == nil || !strings.Contains(err.Error(), key) {
		t.Errorf("VerifyMasks = %v, want an error naming %s", err, key)
	}
}

func TestVerifyMasks_FailsWhenAFileInAMaskedDirIsReadable(t *testing.T) {
	root := t.TempDir()
	maskedDir := filepath.Join(root, ".aws")
	credentials := filepath.Join(maskedDir, "nested", "credentials")
	writeTestFile(t, credentials, "aws_secret_access_key=x")

	err := VerifyMasks(MaskedPaths{Dirs: []string{maskedDir}})
	if err == nil || !strings.Contains(err.Error(), credentials) {
		t.Errorf("VerifyMasks = %v, want an error naming %s", err, credentials)
	}
}

func TestMaskedPathsFromEnv(t *testing.T) {
	t.Setenv(MaskedPathsEnvVar, `{"files":["/a"],"dirs":["/b"],"exceptions":["/b/c"]}`)

	masked, err := MaskedPathsFromEnv()
	if err != nil {
		t.Fatalf("MaskedPathsFromEnv: %v", err)
	}
	if !slices.Equal(masked.Files, []string{"/a"}) || !slices.Equal(masked.Dirs, []string{"/b"}) || !slices.Equal(masked.Exceptions, []string{"/b/c"}) {
		t.Errorf("got %+v", masked)
	}
}

func TestMaskedPathsFromEnv_FailsOnInvalidJSON(t *testing.T) {
	t.Setenv(MaskedPathsEnvVar, "not json")

	if _, err := MaskedPathsFromEnv(); err == nil {
		t.Error("invalid JSON was accepted")
	}
}

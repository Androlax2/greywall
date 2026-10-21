//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// landlockRuleAccess returns the access a planned rule grants on path, or 0.
func landlockRuleAccess(rules []landlockRule, path string) uint64 {
	var access uint64
	for _, rule := range rules {
		if rule.path == path {
			access |= rule.access
		}
	}
	return access
}

// effectiveLandlockAccess is what Landlock grants on path: the union of the
// rules on path and on every one of its ancestors.
func effectiveLandlockAccess(rules []landlockRule, path string) uint64 {
	var access uint64
	for current := path; ; current = filepath.Dir(current) {
		access |= landlockRuleAccess(rules, current)
		if filepath.Dir(current) == current {
			return access
		}
	}
}

const testReadRights = uint64(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE)

func seedLandlockHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	writeTestFile(t, filepath.Join(home, ".ssh", "id_ed25519"), "key")
	writeTestFile(t, filepath.Join(home, ".ssh", "config"), "Host *")
	writeTestFile(t, filepath.Join(home, ".bashrc"), "alias")
	writeTestFile(t, filepath.Join(home, ".local", "share", "greyproxy", "session.key"), "secret")
	writeTestFile(t, filepath.Join(home, ".local", "share", "greyproxy", "ca-cert.pem"), "cert")
	writeTestFile(t, filepath.Join(home, ".local", "share", "app", "data"), "data")
	return home
}

func TestExcludeMaskedPaths_ReadOnlyRuleNoLongerGrantsAMaskedFile(t *testing.T) {
	home := seedLandlockHome(t)
	key := filepath.Join(home, ".ssh", "id_ed25519")

	rules := excludeMaskedPaths([]landlockRule{{home, testReadRights}}, MaskedPaths{Files: []string{key}})

	if effectiveLandlockAccess(rules, key)&LANDLOCK_ACCESS_FS_READ_FILE != 0 {
		t.Errorf("the masked key is still readable; rules=%+v", rules)
	}
	for _, sibling := range []string{filepath.Join(home, ".ssh", "config"), filepath.Join(home, ".bashrc"), filepath.Join(home, ".local", "share", "app", "data")} {
		if effectiveLandlockAccess(rules, sibling) != testReadRights {
			t.Errorf("%s lost access; rules=%+v", sibling, rules)
		}
	}
	if effectiveLandlockAccess(rules, home)&LANDLOCK_ACCESS_FS_READ_DIR == 0 {
		t.Errorf("the home folder can no longer be listed; rules=%+v", rules)
	}
}

func TestExcludeMaskedPaths_MaskedDirKeepsOnlyItsExceptions(t *testing.T) {
	home := seedLandlockHome(t)
	dataDir := filepath.Join(home, ".local", "share", "greyproxy")
	caCert := filepath.Join(dataDir, "ca-cert.pem")

	rules := excludeMaskedPaths(
		[]landlockRule{{filepath.Join(home, ".local"), testReadRights}},
		MaskedPaths{Dirs: []string{dataDir}, Exceptions: []string{caCert}},
	)

	if effectiveLandlockAccess(rules, filepath.Join(dataDir, "session.key"))&LANDLOCK_ACCESS_FS_READ_FILE != 0 {
		t.Errorf("session.key is still readable; rules=%+v", rules)
	}
	if effectiveLandlockAccess(rules, caCert)&LANDLOCK_ACCESS_FS_READ_FILE == 0 {
		t.Errorf("ca-cert.pem is no longer readable; rules=%+v", rules)
	}
	if effectiveLandlockAccess(rules, filepath.Join(home, ".local", "share", "app", "data")) != testReadRights {
		t.Errorf("an unrelated file lost access; rules=%+v", rules)
	}
}

func TestExcludeMaskedPaths_RuleOnTheMaskedPathItselfIsDropped(t *testing.T) {
	home := seedLandlockHome(t)
	sshDir := filepath.Join(home, ".ssh")

	rules := excludeMaskedPaths([]landlockRule{{sshDir, testReadRights}}, MaskedPaths{Dirs: []string{sshDir}})

	if effectiveLandlockAccess(rules, filepath.Join(sshDir, "id_ed25519"))&LANDLOCK_ACCESS_FS_READ_FILE != 0 {
		t.Errorf("a file in the masked dir is still readable; rules=%+v", rules)
	}
}

// A writable rule cannot be split without making files the sandbox creates
// later unreadable to it, so it stays as is: the mask and VerifyMasks cover it.
func TestExcludeMaskedPaths_LeavesWritableRulesUnchanged(t *testing.T) {
	project := t.TempDir()
	writeTestFile(t, filepath.Join(project, ".env"), "SECRET=x")
	writable := testReadRights | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_REG

	rules := excludeMaskedPaths([]landlockRule{{project, writable}}, MaskedPaths{Files: []string{filepath.Join(project, ".env")}})

	if len(rules) != 1 || rules[0].path != project || rules[0].access != writable {
		t.Errorf("writable rule changed: %+v", rules)
	}
}

func TestExcludeMaskedPaths_SkipsASymlinkThatLeadsToAMaskedFile(t *testing.T) {
	home := seedLandlockHome(t)
	key := filepath.Join(home, ".ssh", "id_ed25519")
	link := filepath.Join(home, "key-link")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}

	rules := excludeMaskedPaths([]landlockRule{{home, testReadRights}}, MaskedPaths{Files: []string{key}})

	if landlockRuleAccess(rules, link) != 0 {
		t.Errorf("the symlink to the masked key got a rule; rules=%+v", rules)
	}
}

func TestExcludeMaskedPaths_LeavesUnrelatedRulesUnchanged(t *testing.T) {
	home := seedLandlockHome(t)
	rules := []landlockRule{{"/usr", testReadRights}}

	got := excludeMaskedPaths(rules, MaskedPaths{Files: []string{filepath.Join(home, ".ssh", "id_ed25519")}})

	if !slices.Equal(got, rules) {
		t.Errorf("got %+v, want %+v", got, rules)
	}
}

// The wrapper learns what to check from the real mask helpers' arguments.
func TestMaskedPathsFromArgs_ReadsTheMaskHelpersOutput(t *testing.T) {
	home, cwd := seedMountOrderTree(t)
	dataDir := seedGreyproxyDirIn(t, filepath.Join(home, ".local", "share"))
	cfg := &config.Config{Filesystem: config.FilesystemConfig{DenyRead: []string{"~/.ssh/id_*", "~/.aws"}}}

	maskArgs := slices.Concat(
		sensitiveProjectFileArgs(cwd, nil, false),
		denyReadMaskArgs(cfg),
		greyproxyDenyReadArgs(),
	)
	masked := maskedPathsFromArgs(maskArgs)

	for _, file := range []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(cwd, ".env"),
		filepath.Join(dataDir, "session.key"),
		filepath.Join(dataDir, "ca-key.pem"),
	} {
		if !slices.Contains(masked.Files, file) {
			t.Errorf("Files lacks %s: %+v", file, masked)
		}
	}
	for _, dir := range []string{filepath.Join(home, ".aws"), dataDir} {
		if !slices.Contains(masked.Dirs, dir) {
			t.Errorf("Dirs lacks %s: %+v", dir, masked)
		}
	}
	if !slices.Equal(masked.Exceptions, []string{filepath.Join(dataDir, "ca-cert.pem")}) {
		t.Errorf("Exceptions = %v, want only ca-cert.pem", masked.Exceptions)
	}
}

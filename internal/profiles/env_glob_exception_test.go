package profiles

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/sandbox"
)

func reviewedEnvProfile(t *testing.T, marker bool, explicitGlob bool) *config.Config {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := sandbox.LearnedTemplatePath("claude")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	denied := `[".env", "~/.ssh/id_*"]`
	if explicitGlob {
		denied = `[".env", ".env.*", "~/.ssh/id_*"]`
	}
	contents := fmt.Sprintf(`{"preserveEnvGlobException":%v,"filesystem":{"allowWrite":[".","~/approved"],"denyRead":%s}}`, marker, denied)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestReviewedEnvExceptionSurvivesDriftMerges(t *testing.T) {
	for _, tc := range []struct {
		name         string
		marker       bool
		explicitGlob bool
		wantGlob     bool
	}{
		{"generic profile", false, false, true},
		{"reviewed omission", true, false, false},
		{"explicit profile deny wins", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			learned := reviewedEnvProfile(t, tc.marker, tc.explicitGlob)
			bundled := &config.Config{Filesystem: config.FilesystemConfig{DenyRead: []string{".env", ".env.*", "~/.ssh/id_*", "~/another-secret"}}}
			for iteration := 0; iteration < 2; iteration++ {
				if _, err := ApplyDriftAction(ActionMerge, learned, bundled, "claude"); err != nil {
					t.Fatal(err)
				}
				var err error
				learned, err = config.Load(sandbox.LearnedTemplatePath("claude"))
				if err != nil {
					t.Fatal(err)
				}
				if got := slices.Contains(learned.Filesystem.DenyRead, ".env.*"); got != tc.wantGlob {
					t.Errorf("merge %d: broad env deny = %v, want %v", iteration, got, tc.wantGlob)
				}
				if !slices.Contains(learned.Filesystem.DenyRead, "~/another-secret") || !slices.Contains(learned.Filesystem.AllowWrite, "~/approved") {
					t.Fatal("exception changed unrelated reviewed grants or bundled denies")
				}
				if tc.marker {
					data, err := os.ReadFile(sandbox.LearnedTemplatePath("claude"))
					if err != nil || !bytes.Contains(data, []byte(`"preserveEnvGlobException": true`)) {
						t.Fatalf("exception metadata was lost: %v\n%s", err, data)
					}
				}
			}
		})
	}
}

func TestReviewedEnvExceptionDoesNotChangeGlobalDenies(t *testing.T) {
	learned := reviewedEnvProfile(t, true, false)
	global := &config.Config{Filesystem: config.FilesystemConfig{DenyRead: []string{".env.*", "modified.env", "untracked.env"}}}
	effective := config.Merge(global, learned)
	for _, denied := range global.Filesystem.DenyRead {
		if !slices.Contains(effective.Filesystem.DenyRead, denied) {
			t.Errorf("global or launcher deny removed: %s", denied)
		}
	}
}

func TestReviewedEnvExceptionDoesNotAlterOtherProfiles(t *testing.T) {
	bundled := &config.Config{Filesystem: config.FilesystemConfig{DenyRead: []string{".env.*"}}}
	marked := reviewedEnvProfile(t, true, false)
	if _, err := ApplyDriftAction(ActionMerge, marked, bundled, "claude"); err != nil {
		t.Fatal(err)
	}
	ordinary := reviewedEnvProfile(t, false, false)
	merged, err := ApplyDriftAction(ActionMerge, ordinary, bundled, "claude")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(merged.Filesystem.DenyRead, ".env.*") {
		t.Fatal("one reviewed exception weakened another profile's bundled deny")
	}
}

func TestReviewedEnvExceptionMatchesDriftDisplayAndHash(t *testing.T) {
	learned := reviewedEnvProfile(t, true, false)
	bundled := &config.Config{Filesystem: config.FilesystemConfig{DenyRead: []string{".env", ".env.*", "~/.ssh/id_*"}}}
	if hash := DriftHash(learned, bundled); hash != "" {
		t.Errorf("excluded glob still contributes to drift hash: %s", hash)
	}
	var output bytes.Buffer
	renderDriftDiffs(&output, learned, bundled)
	if strings.Contains(output.String(), "+ .env.*") {
		t.Errorf("prompt offers to restore the reviewed exception:\n%s", output.String())
	}
}

func TestReviewedEnvExceptionSurvivesKeepAndTemplateSave(t *testing.T) {
	learned := reviewedEnvProfile(t, true, false)
	if _, err := ApplyDriftAction(ActionKeep, learned, BaseProfile(), "claude"); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(sandbox.LearnedTemplatePath("claude"))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveAsTemplate(loaded, "claude", false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(sandbox.LearnedTemplatePath("claude"))
	if err != nil || !bytes.Contains(data, []byte(`"preserveEnvGlobException": true`)) {
		t.Fatalf("save lost the exception: %v\n%s", err, data)
	}
}

package profiles

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/GreyhavenHQ/greywall/internal/sandbox"
)

func TestDetectDrift(t *testing.T) {
	bundled := &config.Config{}
	cases := []struct {
		name    string
		learned *config.Config
		running string
		want    DriftReason
		drift   bool
	}{
		{
			name:    "missing stamp",
			learned: &config.Config{},
			running: "v1.0.0",
			want:    DriftMissingStamp,
			drift:   true,
		},
		// Older-schema case only exercisable once CurrentSchemaVersion > 1;
		// at v=1 the (v-1=0) case collapses into DriftMissingStamp.
		{
			name:    "version mismatch",
			learned: &config.Config{SchemaVersion: config.CurrentSchemaVersion, GeneratedBy: "v0.9.0"},
			running: "v1.0.0",
			want:    DriftVersion,
			drift:   true,
		},
		{
			name:    "up to date",
			learned: &config.Config{SchemaVersion: config.CurrentSchemaVersion, GeneratedBy: "v1.0.0"},
			running: "v1.0.0",
			want:    DriftNone,
			drift:   false,
		},
		{
			name:    "no bundled profile",
			learned: &config.Config{},
			running: "v1.0.0",
			want:    DriftNone,
			drift:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b *config.Config
			if tc.name != "no bundled profile" {
				b = bundled
			}
			info := DetectDrift(tc.learned, b, tc.running, "chrome")
			if info.HasDrift != tc.drift {
				t.Fatalf("HasDrift=%v want %v", info.HasDrift, tc.drift)
			}
			if tc.drift && info.Reason != tc.want {
				t.Fatalf("Reason=%q want %q", info.Reason, tc.want)
			}
		})
	}
}

func TestDetectDrift_AckSuppressesReprompt(t *testing.T) {
	bundled := &config.Config{
		Network: config.NetworkConfig{
			Rules: []config.NetworkRule{
				{Destination: "api.example.com", Port: "443", Action: "allow"},
			},
		},
	}
	learned := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		GeneratedBy:   "dev",
	}

	// First run: drift detected.
	info := DetectDrift(learned, bundled, "dev", "chrome")
	if !info.HasDrift {
		t.Fatal("expected drift before ack")
	}

	// User picks ignore: stamp the hash.
	learned.DriftAckHash = DriftHash(learned, bundled)

	// Next run: no drift despite bundled unchanged.
	info = DetectDrift(learned, bundled, "dev", "chrome")
	if info.HasDrift {
		t.Errorf("ack should suppress drift, got %+v", info)
	}

	// Bundled gains another rule: drift reappears.
	bundled.Network.Rules = append(bundled.Network.Rules,
		config.NetworkRule{Destination: "api2.example.com", Port: "443", Action: "allow"})
	info = DetectDrift(learned, bundled, "dev", "chrome")
	if !info.HasDrift {
		t.Errorf("drift should reappear when bundled changes, got %+v", info)
	}
}

func TestDetectDrift_Content(t *testing.T) {
	// Stamps match exactly, but bundled has a network rule the learned file
	// doesn't. This is the dev-build case: version string never changes but
	// rules do.
	learned := &config.Config{
		SchemaVersion: config.CurrentSchemaVersion,
		GeneratedBy:   "dev",
	}
	bundled := &config.Config{
		Network: config.NetworkConfig{
			Rules: []config.NetworkRule{
				{Destination: "api.example.com", Port: "443", Action: "allow"},
			},
		},
	}
	info := DetectDrift(learned, bundled, "dev", "chrome")
	if !info.HasDrift {
		t.Fatal("expected content drift, got none")
	}
	if info.Reason != DriftContent {
		t.Errorf("Reason=%q want %q", info.Reason, DriftContent)
	}
}

func TestPromptDriftResolution(t *testing.T) {
	info := DriftInfo{HasDrift: true, Reason: DriftMissingStamp, CmdName: "chrome", RunningVersion: "v1.0.0"}
	cases := map[string]DriftAction{
		"\n":        ActionSkip,
		"m\n":       ActionMerge,
		"merge\n":   ActionMerge,
		"k\n":       ActionKeep, // permanent keep
		"keep\n":    ActionKeep,
		"i\n":       ActionSkip,
		"ignore\n":  ActionSkip,
		"o\n":       ActionSkip,
		"garbage\n": ActionSkip,
		"maybe\n":   ActionSkip,
		"":          ActionSkip,
		"m":         ActionSkip,
		"merge":     ActionSkip,
		"k":         ActionSkip,
	}
	learned := &config.Config{}
	bundled := &config.Config{}
	for input, want := range cases {
		var out bytes.Buffer
		got := promptDriftResolution(info, learned, bundled, strings.NewReader(input), &out)
		if got != want {
			t.Errorf("input %q: got %v want %v", input, got, want)
		}
	}
}

func TestDriftWithoutExplicitConsentPreservesReviewedProfile(t *testing.T) {
	for _, input := range []string{"", "\n", "garbage\n", "maybe\n", "m", "merge", "k"} {
		t.Run(input, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			learned := &config.Config{
				SchemaVersion: config.CurrentSchemaVersion,
				GeneratedBy:   "0.3.7",
				DriftAckHash:  "reviewed-acknowledgment",
				Filesystem: config.FilesystemConfig{
					AllowWrite: []string{".", "~/.claude", "~/approved-by-host"},
					DenyRead:   []string{".env"},
				},
			}
			bundled := &config.Config{Filesystem: config.FilesystemConfig{
				AllowWrite: []string{"~/.skills", "~/.agents", "~/AGENTS.md", "~/.config/gh", "~/.local/share/gh"},
				DenyRead:   []string{".env.*"},
			}}
			path := sandbox.LearnedTemplatePath("claude")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			before, err := json.MarshalIndent(learned, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, before, 0o600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			action := promptDriftResolution(DriftInfo{HasDrift: true, CmdName: "claude"}, learned, bundled, strings.NewReader(input), &output)
			if _, err := ApplyDriftAction(action, learned, bundled, "claude"); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path) // #nosec G304 -- reads this test's profile under its temporary XDG_CONFIG_HOME
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("reviewed profile changed without explicit consent:\n%s", after)
			}
		})
	}
}

func TestKeepReviewedProfilePreservesExplicitHostGrants(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := os.MkdirAll(sandbox.LearnedTemplateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	learned := &config.Config{Filesystem: config.FilesystemConfig{
		AllowWrite: []string{".", "~/approved-by-host", "~/.config/gh"},
		DenyRead:   []string{".env", "~/private-review"},
	}}
	bundled := &config.Config{Filesystem: config.FilesystemConfig{AllowWrite: []string{"~/.skills"}}}
	ack := DriftHash(learned, bundled)
	if _, err := ApplyDriftAction(ActionKeep, learned, bundled, "claude"); err != nil {
		t.Fatal(err)
	}
	saved, err := config.Load(sandbox.LearnedTemplatePath("claude"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(saved.Filesystem.AllowWrite, []string{".", "~/approved-by-host", "~/.config/gh"}) ||
		!slices.Equal(saved.Filesystem.DenyRead, []string{".env", "~/private-review"}) || saved.DriftAckHash != ack {
		t.Fatalf("explicit reviewed policy or acknowledgment changed: %+v", saved)
	}
}

func TestPromptDriftResolution_Diff(t *testing.T) {
	info := DriftInfo{HasDrift: true, Reason: DriftVersion, CmdName: "chrome", RunningVersion: "v1.1.0", LearnedVersion: "v1.0.0"}
	learned := &config.Config{
		Filesystem: config.FilesystemConfig{AllowRead: []string{"~/old"}},
	}
	bundled := &config.Config{
		Network: config.NetworkConfig{Rules: []config.NetworkRule{{Destination: "api.example.com", Port: "443", Action: "allow"}}},
	}

	// Diff is always shown before the prompt; "m" commits merge.
	var out bytes.Buffer
	got := promptDriftResolution(info, learned, bundled, strings.NewReader("m\n"), &out)
	if got != ActionMerge {
		t.Fatalf("got %v want ActionMerge", got)
	}
	output := out.String()
	if !strings.Contains(output, "+ api.example.com:443 allow") {
		t.Errorf("expected merge diff to show added rule, got:\n%s", output)
	}
	if !strings.Contains(output, "[m] merge would add") {
		t.Errorf("expected merge diff header, got:\n%s", output)
	}
	if strings.Contains(output, "overwrite") {
		t.Errorf("overwrite option should not appear, got:\n%s", output)
	}
	if strings.Contains(output, " - ") {
		t.Errorf("removal lines should not appear in diff, got:\n%s", output)
	}
}

func TestApplyDriftAction_Merge(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	cmdName := "chrome"
	path := sandbox.LearnedTemplatePath(cmdName)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}

	learned := &config.Config{
		Filesystem: config.FilesystemConfig{AllowRead: []string{"~/custom"}},
	}
	bundled := &config.Config{
		Network: config.NetworkConfig{Rules: []config.NetworkRule{{Destination: "api.chrome.com", Port: "443", Action: "allow"}}},
	}

	// Seed the existing learned file so we exercise the backup path.
	if err := os.WriteFile(path, []byte("// old\n{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	resolved, err := ApplyDriftAction(ActionMerge, learned, bundled, cmdName)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.Network.Rules) != 1 {
		t.Fatalf("expected bundled rule to be merged, got %+v", resolved.Network.Rules)
	}
	if len(resolved.Filesystem.AllowRead) != 1 || resolved.Filesystem.AllowRead[0] != "~/custom" {
		t.Fatalf("expected learned allowRead to be preserved, got %+v", resolved.Filesystem.AllowRead)
	}

	// Backup exists.
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatalf("backup missing: %v", err)
	}

	// New file is stamped and loadable.
	written, err := os.ReadFile(path) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(written, []byte(`"schemaVersion"`)) {
		t.Errorf("stamp missing from rewritten file: %s", written)
	}
}

func TestBuildTemplateStamp(t *testing.T) {
	// Ensure a freshly-saved profile via SaveAsTemplate carries the stamp.
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	sandbox.SetGreywallVersion("v9.9.9-test")

	cfg := &config.Config{
		Filesystem: config.FilesystemConfig{AllowWrite: []string{"~/foo"}},
	}
	if err := SaveAsTemplate(cfg, "chrome", false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(sandbox.LearnedTemplatePath("chrome")) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	// Skip comment header by locating the first '{'.
	idx := bytes.IndexByte(data, '{')
	if idx < 0 {
		t.Fatalf("no JSON object found: %s", data)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data[idx:], &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, data)
	}
	if v, _ := parsed["schemaVersion"].(float64); int(v) != config.CurrentSchemaVersion {
		t.Errorf("schemaVersion=%v want %d", parsed["schemaVersion"], config.CurrentSchemaVersion)
	}
	if parsed["generatedBy"] != "v9.9.9-test" {
		t.Errorf("generatedBy=%v want v9.9.9-test", parsed["generatedBy"])
	}
}

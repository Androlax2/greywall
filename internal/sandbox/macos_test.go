package sandbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

func writeMacOSTestCA(t *testing.T, dataDir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dataDir, "ca-cert.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath
}

func newMacOSTestManager(t *testing.T, cfg *config.Config) *Manager {
	t.Helper()
	manager := NewManager(cfg, false, false)
	manager.macOSCARoot = filepath.Join(t.TempDir(), "shared-ca-root")
	t.Cleanup(manager.Cleanup)
	return manager
}

func TestMacOS_PublicCAWrapperDoesNotPointIntoDeniedDirectory(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GREYPROXY_DATA_HOME", dataDir)
	certPath := writeMacOSTestCA(t, dataDir)
	cfg := &config.Config{
		Network: config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"},
		Filesystem: config.FilesystemConfig{
			DenyRead:  []string{dataDir},
			DenyWrite: []string{dataDir},
		},
	}

	manager := newMacOSTestManager(t, cfg)
	manager.macOSTmpDir = t.TempDir()
	t.Cleanup(manager.Cleanup)
	command, err := manager.wrapMacOSCommand("true")
	if err != nil {
		t.Fatal(err)
	}
	var snapshotPath string
	for _, name := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"} {
		var value string
		for _, part := range strings.Fields(command) {
			if strings.HasPrefix(part, name+"=") {
				value = strings.TrimPrefix(part, name+"=")
				break
			}
		}
		if value == "" {
			t.Errorf("%s is not set", name)
			continue
		}
		if value == certPath {
			t.Errorf("%s points into the explicitly denied proxy directory", name)
		}
		if snapshotPath == "" {
			snapshotPath = value
		} else if value != snapshotPath {
			t.Errorf("%s points to %q, want %q", name, value, snapshotPath)
		}
	}
	snapshot, err := os.ReadFile(snapshotPath) //nolint:gosec // snapshot path comes from the test fixture
	if err != nil {
		t.Fatalf("read CA snapshot: %v", err)
	}
	block, remaining := pem.Decode(snapshot)
	if block == nil || block.Type != "CERTIFICATE" || len(remaining) != 0 {
		t.Fatal("snapshot does not contain exactly one certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("parse CA snapshot: %v", err)
	}
	for _, operation := range []string{"file-read-data", "file-write*"} {
		rule := fmt.Sprintf("(deny %s\n  (subpath %q)", operation, NormalizePath(dataDir))
		if !strings.Contains(command, rule) {
			t.Errorf("managed proxy directory %s deny is missing", operation)
		}
	}
}

func TestMacOS_PublicCARejectsExplicitCertificateDeny(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GREYPROXY_DATA_HOME", dataDir)
	certPath := writeMacOSTestCA(t, dataDir)
	cfg := &config.Config{
		Network:    config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"},
		Filesystem: config.FilesystemConfig{DenyRead: []string{certPath}},
	}
	manager := newMacOSTestManager(t, cfg)
	t.Cleanup(manager.Cleanup)
	_, err := manager.wrapMacOSCommand("true")
	if err == nil || !strings.Contains(err.Error(), "explicitly denied") {
		t.Fatalf("expected explicit deny error, got %v", err)
	}
}

func TestMacOS_PublicCARejectsAncestorDeny(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "greyproxy")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GREYPROXY_DATA_HOME", dataDir)
	writeMacOSTestCA(t, dataDir)
	cfg := &config.Config{
		Network:    config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"},
		Filesystem: config.FilesystemConfig{DenyRead: []string{parent}},
	}
	manager := newMacOSTestManager(t, cfg)
	if _, err := manager.wrapMacOSCommand("true"); err == nil {
		t.Fatal("CA was exposed despite an explicit ancestor deny")
	}
}

func TestMacOS_PublicCARejectsAliasedGlobDeny(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "actual")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(dataDir, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GREYPROXY_DATA_HOME", dataDir)
	writeMacOSTestCA(t, dataDir)
	cfg := &config.Config{
		Network:    config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"},
		Filesystem: config.FilesystemConfig{DenyRead: []string{filepath.Join(alias, "ca-*.pem")}},
	}
	manager := newMacOSTestManager(t, cfg)
	t.Cleanup(manager.Cleanup)
	if _, err := manager.wrapMacOSCommand("true"); err == nil {
		t.Fatal("CA explicitly denied through an aliased glob was exposed")
	}
}

func TestMacOS_PublicCARejectsUnsafeSources(t *testing.T) {
	for _, source := range []string{"private key", "symlink", "malformed", "malformed prefix"} {
		t.Run(source, func(t *testing.T) {
			dataDir := t.TempDir()
			t.Setenv("GREYPROXY_DATA_HOME", dataDir)
			certPath := filepath.Join(dataDir, "ca-cert.pem")
			switch source {
			case "private key":
				writeMacOSTestCA(t, dataDir)
				file, err := os.OpenFile(certPath, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // path is inside the test fixture
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteString("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n"); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, certPath); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(certPath, []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "malformed prefix":
				writeMacOSTestCA(t, dataDir)
				valid, err := os.ReadFile(certPath) //nolint:gosec // path is inside the test fixture
				if err != nil {
					t.Fatal(err)
				}
				contents := append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), valid...)
				if err := os.WriteFile(certPath, contents, 0o600); err != nil { //nolint:gosec // path is inside the test fixture
					t.Fatal(err)
				}
			}
			cfg := &config.Config{Network: config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"}}
			manager := newMacOSTestManager(t, cfg)
			t.Cleanup(manager.Cleanup)
			if _, err := manager.wrapMacOSCommand("true"); err == nil {
				t.Fatal("unsafe CA source was accepted")
			}
			if manager.macOSCADir != "" {
				t.Error("unsafe CA source left a snapshot directory")
			}
		})
	}
}

func TestMacOS_PublicCASnapshotRemovedOnCleanup(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GREYPROXY_DATA_HOME", dataDir)
	writeMacOSTestCA(t, dataDir)
	cfg := &config.Config{Network: config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"}}
	manager := newMacOSTestManager(t, cfg)
	t.Cleanup(manager.Cleanup)
	if _, err := manager.wrapMacOSCommand("true"); err != nil {
		t.Fatal(err)
	}
	dir := manager.macOSCADir
	manager.Cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("snapshot directory remains after cleanup: %v", err)
	}
}

func TestMacOS_PublicCARejectsSnapshotInsideManagedDirectory(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GREYPROXY_DATA_HOME", dataDir)
	t.Setenv("TMPDIR", dataDir)
	writeMacOSTestCA(t, dataDir)
	cfg := &config.Config{Network: config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"}}
	manager := newMacOSTestManager(t, cfg)
	manager.macOSCARoot = filepath.Join(dataDir, "shared-ca-root")
	t.Cleanup(manager.Cleanup)
	if _, err := manager.wrapMacOSCommand("true"); err == nil {
		t.Fatal("snapshot inside the managed directory was accepted")
	}
}

func TestMacOS_PublicCARejectsSnapshotUnderAliasedManagedDirectory(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "actual")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(dataDir, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GREYPROXY_DATA_HOME", alias)
	writeMacOSTestCA(t, alias)
	cfg := &config.Config{Network: config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"}}
	manager := newMacOSTestManager(t, cfg)
	manager.macOSCARoot = filepath.Join(alias, "new-root")
	if _, err := manager.wrapMacOSCommand("true"); err == nil {
		t.Error("snapshot inside the aliased managed directory was accepted")
	}
	if _, err := os.Lstat(manager.macOSCARoot); !os.IsNotExist(err) {
		t.Errorf("overlapping snapshot root was created: %v", err)
	}
}

func TestMacOS_PublicCAAbsentOrProxyDisabledDoesNotCreateSnapshot(t *testing.T) {
	for _, test := range []struct {
		name       string
		proxyURL   string
		createCert bool
	}{
		{name: "absent CA", proxyURL: "socks5://127.0.0.1:12345"},
		{name: "absent explicitly denied CA", proxyURL: "socks5://127.0.0.1:12345"},
		{name: "proxy disabled", createCert: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir := t.TempDir()
			t.Setenv("GREYPROXY_DATA_HOME", dataDir)
			if test.createCert {
				writeMacOSTestCA(t, dataDir)
			}
			cfg := &config.Config{Network: config.NetworkConfig{ProxyURL: test.proxyURL}}
			if test.name == "absent explicitly denied CA" {
				cfg.Filesystem.DenyRead = []string{filepath.Join(dataDir, "ca-cert.pem")}
			}
			manager := newMacOSTestManager(t, cfg)
			t.Cleanup(manager.Cleanup)
			command, err := manager.wrapMacOSCommand("true")
			if err != nil {
				t.Fatal(err)
			}
			if manager.macOSCADir != "" || strings.Contains(command, "SSL_CERT_FILE=") {
				t.Error("unexpected CA snapshot or environment variable")
			}
		})
	}
}

func TestMacOS_PublicCAAbsentSnapshotNeverExportsSource(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GREYPROXY_DATA_HOME", dataDir)
	writeMacOSTestCA(t, dataDir)
	cfg := &config.Config{Network: config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"}}
	command, err := wrapCommandMacOS(cfg, "true", nil, nil, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"} {
		if strings.Contains(command, name+"=") {
			t.Errorf("%s exported without a validated snapshot", name)
		}
	}
}

func TestMacOS_StandaloneWrapperRejectsCAWithoutManagedSnapshot(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GREYPROXY_DATA_HOME", dataDir)
	writeMacOSTestCA(t, dataDir)
	cfg := &config.Config{Network: config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"}}
	if _, err := WrapCommandMacOS(cfg, "true", nil, nil, "", false); err == nil {
		t.Fatal("standalone wrapper silently discarded the configured CA")
	}
}

func TestMacOS_ProtectsSharedCARootWithoutProxy(t *testing.T) {
	root := filepath.Join("/private/tmp", fmt.Sprintf("greywall-ca-%d", os.Getuid()))
	profile := GenerateSandboxProfile(MacOSSandboxParams{
		WriteAllowPaths: []string{"/private/tmp"},
	})
	for _, path := range []string{root, strings.TrimPrefix(root, "/private")} {
		rule := fmt.Sprintf("(deny file-write* (subpath %q))", path)
		if !strings.Contains(profile, rule) {
			t.Errorf("shared CA root is not protected at %q", path)
		}
	}
}

func TestMacOS_ProtectsOtherSessionSnapshot(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GREYPROXY_DATA_HOME", dataDir)
	writeMacOSTestCA(t, dataDir)
	root := filepath.Join(t.TempDir(), "shared-ca-root")
	first := newMacOSTestManager(t, &config.Config{Network: config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"}})
	first.macOSCARoot = root
	if _, err := first.wrapMacOSCommand("true"); err != nil {
		t.Fatal(err)
	}
	second := newMacOSTestManager(t, &config.Config{Filesystem: config.FilesystemConfig{AllowWrite: []string{filepath.Dir(root)}}})
	second.macOSCARoot = root
	command, err := second.wrapMacOSCommand("true")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command, fmt.Sprintf("(deny file-write* (subpath %q))", root)) {
		t.Fatal("second session does not protect the first session's snapshot")
	}
}

func TestMacOS_ProtectsManagedProxyDirectoryWithoutConfiguredDenies(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GREYPROXY_DATA_HOME", dataDir)
	profile := GenerateSandboxProfile(MacOSSandboxParams{})
	for _, operation := range []string{"file-read-data", "file-write*"} {
		rule := fmt.Sprintf("(deny %s\n  (subpath %q)", operation, NormalizePath(dataDir))
		if !strings.Contains(profile, rule) {
			t.Errorf("managed directory lacks mandatory %s deny", operation)
		}
	}
}

func TestMacOS_RejectsRelativeGreyproxyDataHome(t *testing.T) {
	t.Setenv("GREYPROXY_DATA_HOME", "relative/proxy")
	manager := newMacOSTestManager(t, &config.Config{})
	if _, err := manager.wrapMacOSCommand("true"); err == nil {
		t.Error("relative GREYPROXY_DATA_HOME was accepted")
	}
	if _, err := WrapCommandMacOS(&config.Config{}, "true", nil, nil, "", false); err == nil {
		t.Error("standalone wrapper accepted relative GREYPROXY_DATA_HOME")
	}
}

func TestMacOS_PublicCARejectsUnsafeSharedRoot(t *testing.T) {
	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{name: "world writable", mode: 0o777},
		{name: "world readable", mode: 0o755},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir := t.TempDir()
			t.Setenv("GREYPROXY_DATA_HOME", dataDir)
			writeMacOSTestCA(t, dataDir)
			manager := newMacOSTestManager(t, &config.Config{Network: config.NetworkConfig{ProxyURL: "socks5://127.0.0.1:12345"}})
			if err := os.Mkdir(manager.macOSCARoot, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(manager.macOSCARoot, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.wrapMacOSCommand("true"); err == nil {
				t.Fatal("unsafe snapshot root was accepted")
			}
		})
	}
}

// TestMacOS_NetworkRestrictionWithProxy verifies that when a proxy URL is set,
// the macOS sandbox profile allows outbound to the proxy host:port.
func TestMacOS_NetworkRestrictionWithProxy(t *testing.T) {
	tests := []struct {
		name      string
		proxyURL  string
		wantProxy bool
		proxyHost string
		proxyPort string
	}{
		{
			name:      "no proxy - network blocked",
			proxyURL:  "",
			wantProxy: false,
		},
		{
			name:      "socks5 proxy - outbound allowed to proxy",
			proxyURL:  "socks5://proxy.example.com:1080",
			wantProxy: true,
			proxyHost: "proxy.example.com",
			proxyPort: "1080",
		},
		{
			name:      "socks5h proxy - outbound allowed to proxy",
			proxyURL:  "socks5h://localhost:1080",
			wantProxy: true,
			proxyHost: "localhost",
			proxyPort: "1080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Network: config.NetworkConfig{
					ProxyURL: tt.proxyURL,
				},
				Filesystem: config.FilesystemConfig{
					AllowWrite: []string{"/tmp/test"},
				},
			}

			params := buildMacOSParamsForTest(cfg)

			if tt.wantProxy {
				if params.ProxyHost != tt.proxyHost {
					t.Errorf("expected ProxyHost %q, got %q", tt.proxyHost, params.ProxyHost)
				}
				if params.ProxyPort != tt.proxyPort {
					t.Errorf("expected ProxyPort %q, got %q", tt.proxyPort, params.ProxyPort)
				}

				profile := GenerateSandboxProfile(params)
				expectedRule := `(allow network-outbound (remote tcp "` + tt.proxyHost + ":" + tt.proxyPort + `"))`
				if !strings.Contains(profile, expectedRule) {
					t.Errorf("profile should contain proxy outbound rule %q", expectedRule)
				}
			}

			// Network should always be restricted (proxy or not)
			if !params.NeedsNetworkRestriction {
				t.Error("NeedsNetworkRestriction should always be true")
			}
		})
	}
}

// buildMacOSParamsForTest is a helper to build MacOSSandboxParams from config,
// replicating the logic in WrapCommandMacOS for testing.
func buildMacOSParamsForTest(cfg *config.Config) MacOSSandboxParams {
	allowPaths := append(GetDefaultWritePaths(), cfg.Filesystem.AllowWrite...)
	allowLocalBinding := cfg.Network.AllowLocalBinding
	allowLocalOutbound := allowLocalBinding
	if cfg.Network.AllowLocalOutbound != nil {
		allowLocalOutbound = *cfg.Network.AllowLocalOutbound
	}

	var proxyHost, proxyPort string
	if cfg.Network.ProxyURL != "" {
		// Simple parsing for tests
		parts := strings.SplitN(cfg.Network.ProxyURL, "://", 2)
		if len(parts) == 2 {
			hostPort := parts[1]
			colonIdx := strings.LastIndex(hostPort, ":")
			if colonIdx >= 0 {
				proxyHost = hostPort[:colonIdx]
				proxyPort = hostPort[colonIdx+1:]
			}
		}
	}

	return MacOSSandboxParams{
		Command:                 "echo test",
		NeedsNetworkRestriction: true,
		ProxyURL:                cfg.Network.ProxyURL,
		ProxyHost:               proxyHost,
		ProxyPort:               proxyPort,
		AllowUnixSockets:        cfg.Network.AllowUnixSockets,
		AllowAllUnixSockets:     cfg.Network.AllowAllUnixSockets,
		AllowLocalBinding:       allowLocalBinding,
		AllowLocalOutbound:      allowLocalOutbound,
		DefaultDenyRead:         cfg.Filesystem.IsDefaultDenyRead(),
		Cwd:                     "/tmp/test-project",
		ReadAllowPaths:          cfg.Filesystem.AllowRead,
		ReadDenyPaths:           cfg.Filesystem.DenyRead,
		WriteAllowPaths:         allowPaths,
		WriteDenyPaths:          cfg.Filesystem.DenyWrite,
		AllowPty:                cfg.AllowPty,
		AllowGitConfig:          cfg.Filesystem.AllowGitConfig,
	}
}

// TestMacOS_ProfileNetworkSection verifies the network section of generated profiles.
func TestMacOS_ProfileNetworkSection(t *testing.T) {
	tests := []struct {
		name           string
		restricted     bool
		wantContains   []string
		wantNotContain []string
	}{
		{
			name:       "unrestricted network allows all",
			restricted: false,
			wantContains: []string{
				"(allow network*)", // Blanket allow all network operations
			},
			wantNotContain: []string{},
		},
		{
			name:       "restricted network does not allow all",
			restricted: true,
			wantContains: []string{
				"; Network", // Should have network section
			},
			wantNotContain: []string{
				"(allow network*)", // Should NOT have blanket allow
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := MacOSSandboxParams{
				Command:                 "echo test",
				NeedsNetworkRestriction: tt.restricted,
			}

			profile := GenerateSandboxProfile(params)

			for _, want := range tt.wantContains {
				if !strings.Contains(profile, want) {
					t.Errorf("profile should contain %q, got:\n%s", want, profile)
				}
			}

			for _, notWant := range tt.wantNotContain {
				if strings.Contains(profile, notWant) {
					t.Errorf("profile should NOT contain %q", notWant)
				}
			}
		})
	}
}

// TestMacOS_ProfileForwardPorts verifies that -f/--forward ports produce
// per-port localhost outbound allow rules in the Seatbelt profile, and that
// they are omitted when localhost outbound is already broadly allowed.
func TestMacOS_ProfileForwardPorts(t *testing.T) {
	tests := []struct {
		name               string
		allowLocalOutbound bool
		forwardPorts       []int
		wantContains       []string
		wantNotContain     []string
	}{
		{
			name:         "single forwarded port",
			forwardPorts: []int{42000},
			wantContains: []string{
				`(allow network-outbound (remote ip "localhost:42000"))`,
			},
			wantNotContain: []string{
				`(allow network-outbound (local ip "localhost:*"))`,
			},
		},
		{
			name:         "multiple forwarded ports",
			forwardPorts: []int{5432, 6379},
			wantContains: []string{
				`(allow network-outbound (remote ip "localhost:5432"))`,
				`(allow network-outbound (remote ip "localhost:6379"))`,
			},
		},
		{
			name:               "broad localhost outbound supersedes per-port rules",
			allowLocalOutbound: true,
			forwardPorts:       []int{42000},
			wantContains: []string{
				`(allow network-outbound (local ip "localhost:*"))`,
			},
			wantNotContain: []string{
				`(allow network-outbound (remote ip "localhost:42000"))`,
			},
		},
		{
			name:         "no forwarded ports, no per-port rules",
			forwardPorts: nil,
			wantNotContain: []string{
				`(allow network-outbound (remote ip "localhost:`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := MacOSSandboxParams{
				Command:                 "echo test",
				NeedsNetworkRestriction: true,
				AllowLocalOutbound:      tt.allowLocalOutbound,
				ForwardPorts:            tt.forwardPorts,
			}

			profile := GenerateSandboxProfile(params)

			for _, want := range tt.wantContains {
				if !strings.Contains(profile, want) {
					t.Errorf("profile should contain %q, got:\n%s", want, profile)
				}
			}
			for _, notWant := range tt.wantNotContain {
				if strings.Contains(profile, notWant) {
					t.Errorf("profile should NOT contain %q, got:\n%s", notWant, profile)
				}
			}
		})
	}
}

// TestMacOS_DefaultDenyRead verifies that the defaultDenyRead option properly restricts filesystem reads.
func TestMacOS_DefaultDenyRead(t *testing.T) {
	tests := []struct {
		name                      string
		defaultDenyRead           bool
		cwd                       string
		allowRead                 []string
		wantContainsBlanketAllow  bool
		wantContainsMetadataAllow bool
		wantContainsSystemAllows  bool
		wantContainsUserAllowRead bool
		wantContainsCwdAllow      bool
	}{
		{
			name:                      "legacy mode - blanket allow read",
			defaultDenyRead:           false,
			cwd:                       "/home/user/project",
			allowRead:                 nil,
			wantContainsBlanketAllow:  true,
			wantContainsMetadataAllow: false,
			wantContainsSystemAllows:  false,
			wantContainsUserAllowRead: false,
			wantContainsCwdAllow:      false,
		},
		{
			name:                      "defaultDenyRead enabled - metadata allow, system data allows, CWD allow",
			defaultDenyRead:           true,
			cwd:                       "/home/user/project",
			allowRead:                 nil,
			wantContainsBlanketAllow:  false,
			wantContainsMetadataAllow: true,
			wantContainsSystemAllows:  true,
			wantContainsUserAllowRead: false,
			wantContainsCwdAllow:      true,
		},
		{
			name:                      "defaultDenyRead with allowRead paths",
			defaultDenyRead:           true,
			cwd:                       "/home/user/project",
			allowRead:                 []string{"/home/user/other"},
			wantContainsBlanketAllow:  false,
			wantContainsMetadataAllow: true,
			wantContainsSystemAllows:  true,
			wantContainsUserAllowRead: true,
			wantContainsCwdAllow:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := MacOSSandboxParams{
				Command:         "echo test",
				DefaultDenyRead: tt.defaultDenyRead,
				Cwd:             tt.cwd,
				ReadAllowPaths:  tt.allowRead,
			}

			profile := GenerateSandboxProfile(params)

			hasBlanketAllow := strings.Contains(profile, "(allow file-read*)\n")
			if hasBlanketAllow != tt.wantContainsBlanketAllow {
				t.Errorf("blanket file-read allow = %v, want %v", hasBlanketAllow, tt.wantContainsBlanketAllow)
			}

			hasMetadataAllow := strings.Contains(profile, "(allow file-read-metadata)")
			if hasMetadataAllow != tt.wantContainsMetadataAllow {
				t.Errorf("file-read-metadata allow = %v, want %v", hasMetadataAllow, tt.wantContainsMetadataAllow)
			}

			hasSystemAllows := strings.Contains(profile, `(subpath "/usr")`) ||
				strings.Contains(profile, `(subpath "/bin")`)
			if hasSystemAllows != tt.wantContainsSystemAllows {
				t.Errorf("system path allows = %v, want %v\nProfile:\n%s", hasSystemAllows, tt.wantContainsSystemAllows, profile)
			}

			if tt.wantContainsCwdAllow && tt.cwd != "" {
				hasCwdAllow := strings.Contains(profile, fmt.Sprintf(`(subpath %q)`, tt.cwd))
				if !hasCwdAllow {
					t.Errorf("CWD path %q not found in profile", tt.cwd)
				}
			}

			if tt.wantContainsUserAllowRead && len(tt.allowRead) > 0 {
				hasUserAllow := strings.Contains(profile, tt.allowRead[0])
				if !hasUserAllow {
					t.Errorf("user allowRead path %q not found in profile", tt.allowRead[0])
				}
			}
		})
	}
}

// TestMacOS_DenyReadUsesExactOperation verifies that deny read rules use file-read-data
// (not file-read*) in the generated Seatbelt profile. Seatbelt ignores wildcard denies
// (file-read*) when a specific allow (file-read-data) covers the same path.
func TestMacOS_DenyReadUsesExactOperation(t *testing.T) {
	tests := []struct {
		name            string
		defaultDenyRead bool
		denyRead        []string
		cwd             string
	}{
		{
			name:            "defaultDenyRead with sensitive project files",
			defaultDenyRead: true,
			denyRead:        nil,
			cwd:             "/home/user/project",
		},
		{
			name:            "defaultDenyRead with user denyRead paths",
			defaultDenyRead: true,
			denyRead:        []string{"/home/user/secrets", "/home/user/.ssh/id_*"},
			cwd:             "/home/user/project",
		},
		{
			name:            "legacy mode with user denyRead paths",
			defaultDenyRead: false,
			denyRead:        []string{"/home/user/secrets"},
			cwd:             "/home/user/project",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := MacOSSandboxParams{
				Command:         "echo test",
				DefaultDenyRead: tt.defaultDenyRead,
				Cwd:             tt.cwd,
				ReadDenyPaths:   tt.denyRead,
			}

			profile := GenerateSandboxProfile(params)

			// Must NOT contain "deny file-read*" (wildcard deny is ineffective)
			if strings.Contains(profile, "(deny file-read*") {
				t.Errorf("profile must NOT use 'deny file-read*' (wildcard deny is ignored by Seatbelt when a specific allow covers the same path)\nProfile:\n%s", profile)
			}

			// Must contain "deny file-read-data" for deny rules to work
			if tt.defaultDenyRead || len(tt.denyRead) > 0 {
				if !strings.Contains(profile, "(deny file-read-data") {
					t.Errorf("profile must use 'deny file-read-data' for deny rules to be effective\nProfile:\n%s", profile)
				}
			}
		})
	}
}

// TestMacOS_DenyReadSensitiveProjectFiles verifies that the generated profile
// contains deny rules for all sensitive project files (.env, .env.local, etc.).
func TestMacOS_DenyReadSensitiveProjectFiles(t *testing.T) {
	cwd := "/home/user/project"
	params := MacOSSandboxParams{
		Command:         "cat .env",
		DefaultDenyRead: true,
		Cwd:             cwd,
	}

	profile := GenerateSandboxProfile(params)

	for _, f := range SensitiveProjectFiles {
		expected := fmt.Sprintf(`(deny file-read-data
  (literal %q)`, cwd+"/"+f)
		if !strings.Contains(profile, expected) {
			t.Errorf("profile missing deny rule for sensitive file %q\nExpected to contain: %s", f, expected)
		}
	}

	// Also check .env.* regex pattern
	if !strings.Contains(profile, `(deny file-read-data
  (regex`) {
		t.Errorf("profile missing regex deny rule for .env.* pattern")
	}
}

// TestMacOS_DenyReadUserPaths verifies that user-configured denyRead paths
// appear in the generated profile with file-read-data (not file-read*).
func TestMacOS_DenyReadUserPaths(t *testing.T) {
	params := MacOSSandboxParams{
		Command:         "echo test",
		DefaultDenyRead: false,
		Cwd:             "/home/user/project",
		ReadDenyPaths:   []string{"/home/user/secrets"},
	}

	profile := GenerateSandboxProfile(params)

	expected := `(deny file-read-data
  (subpath "/home/user/secrets")`
	if !strings.Contains(profile, expected) {
		t.Errorf("profile missing deny rule for user denyRead path\nExpected: %s\nProfile:\n%s", expected, profile)
	}
}

// TestMacOS_SessionAllowPaths verifies the Seatbelt profile distinguishes
// read+write grants (--allow-path) from read-only grants (--allow-read-path):
// a read-write path gets both a read-data and a file-write* allow, while a
// read-only path gets a read-data allow but NO file-write* allow. Covers both
// a directory and a single file (the file case must not get a write rule).
func TestMacOS_SessionAllowPaths(t *testing.T) {
	rwDir := "/home/user/scratch"
	roDir := "/home/user/reference"
	roFile := "/home/user/reference.csv"

	params := MacOSSandboxParams{
		Command:         "echo test",
		DefaultDenyRead: true,
		Cwd:             "/home/user/project",
		// --allow-path appends to both read and write; --allow-read-path to read only.
		ReadAllowPaths:  []string{roDir, roFile, rwDir},
		WriteAllowPaths: []string{rwDir},
	}

	profile := GenerateSandboxProfile(params)

	// Read-write path: present as both a read allow and a write allow.
	if !strings.Contains(profile, fmt.Sprintf(`(subpath %q)`, rwDir)) {
		t.Errorf("rw path %q missing read allow\nProfile:\n%s", rwDir, profile)
	}
	wantWrite := fmt.Sprintf("(allow file-write*\n  (subpath %q)", rwDir)
	if !strings.Contains(profile, wantWrite) {
		t.Errorf("rw path %q missing file-write* allow\nExpected: %s\nProfile:\n%s", rwDir, wantWrite, profile)
	}

	// Read-only directory and file: read allow present, write allow absent.
	for _, ro := range []string{roDir, roFile} {
		if !strings.Contains(profile, fmt.Sprintf(`(subpath %q)`, ro)) {
			t.Errorf("read-only path %q missing read allow\nProfile:\n%s", ro, profile)
		}
		unwantedWrite := fmt.Sprintf("(allow file-write*\n  (subpath %q)", ro)
		if strings.Contains(profile, unwantedWrite) {
			t.Errorf("read-only path %q must NOT have a file-write* allow\nProfile:\n%s", ro, profile)
		}
	}
}

// TestExpandMacOSTmpPaths verifies that /tmp and /private/tmp paths are properly mirrored.
func TestExpandMacOSTmpPaths(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "mirrors /tmp to /private/tmp",
			input: []string{".", "/tmp"},
			want:  []string{".", "/tmp", "/private/tmp"},
		},
		{
			name:  "mirrors /private/tmp to /tmp",
			input: []string{".", "/private/tmp"},
			want:  []string{".", "/private/tmp", "/tmp"},
		},
		{
			name:  "no change when both present",
			input: []string{".", "/tmp", "/private/tmp"},
			want:  []string{".", "/tmp", "/private/tmp"},
		},
		{
			name:  "no change when neither present",
			input: []string{".", "~/.cache"},
			want:  []string{".", "~/.cache"},
		},
		{
			name:  "mirrors /tmp/greywall to /private/tmp/greywall",
			input: []string{".", "/tmp/greywall"},
			want:  []string{".", "/tmp/greywall", "/private/tmp/greywall"},
		},
		{
			name:  "mirrors /private/tmp/greywall to /tmp/greywall",
			input: []string{".", "/private/tmp/greywall"},
			want:  []string{".", "/private/tmp/greywall", "/tmp/greywall"},
		},
		{
			name:  "mirrors nested subdirectory",
			input: []string{".", "/tmp/foo/bar"},
			want:  []string{".", "/tmp/foo/bar", "/private/tmp/foo/bar"},
		},
		{
			name:  "no duplicate when mirror already present",
			input: []string{".", "/tmp/greywall", "/private/tmp/greywall"},
			want:  []string{".", "/tmp/greywall", "/private/tmp/greywall"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandMacOSTmpPaths(tt.input)

			if len(got) != len(tt.want) {
				t.Errorf("expandMacOSTmpPaths() = %v, want %v", got, tt.want)
				return
			}

			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("expandMacOSTmpPaths()[%d] = %v, want %v", i, v, tt.want[i])
				}
			}
		})
	}
}

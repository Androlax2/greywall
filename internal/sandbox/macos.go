package sandbox

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/bmatcuk/doublestar/v4"
)

// sessionSuffix is a unique identifier for this process session.
var sessionSuffix = generateSessionSuffix()

func generateSessionSuffix() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		panic("failed to generate session suffix: " + err.Error())
	}
	return "_" + hex.EncodeToString(bytes)[:9] + "_SBX"
}

// MacOSSandboxParams contains parameters for macOS sandbox wrapping.
type MacOSSandboxParams struct {
	Command                 string
	NeedsNetworkRestriction bool
	ProxyURL                string // External proxy URL (for env vars)
	ProxyHost               string // Proxy host (for sandbox profile network rules)
	ProxyPort               string // Proxy port (for sandbox profile network rules)
	HTTPProxyHost           string // HTTP CONNECT proxy host
	HTTPProxyPort           string // HTTP CONNECT proxy port
	DnsProxyHost            string // DNS proxy host
	DnsProxyPort            string // DNS proxy port
	AllowUnixSockets        []string
	AllowAllUnixSockets     bool
	AllowLocalBinding       bool
	AllowLocalOutbound      bool
	ForwardPorts            []int // Host localhost ports to allow outbound to (-f/--forward)
	DefaultDenyRead         bool
	Cwd                     string // Current working directory (for deny-by-default CWD allowlisting)
	ReadAllowPaths          []string
	ReadDenyPaths           []string
	WriteAllowPaths         []string
	WriteDenyPaths          []string
	AllowPty                bool
	AllowGitConfig          bool
	Shell                   string
	RewrittenEnvFiles       map[string]string // original path -> rewritten temp path
	CACertPath              string
	CASnapshotRoot          string
}

// GlobToRegex converts a glob pattern to a regex for macOS sandbox profiles.
func GlobToRegex(glob string) string {
	result := "^"

	// Escape regex special characters (except glob chars)
	escaped := regexp.QuoteMeta(glob)

	// Restore glob patterns and convert them
	// Order matters: ** before *
	escaped = strings.ReplaceAll(escaped, `\*\*/`, "(.*/)?")
	escaped = strings.ReplaceAll(escaped, `\*\*`, ".*")
	escaped = strings.ReplaceAll(escaped, `\*`, "[^/]*")
	escaped = strings.ReplaceAll(escaped, `\?`, "[^/]")

	result += escaped + "$"
	return result
}

// escapePath escapes a path for sandbox profile using JSON encoding.
func escapePath(path string) string {
	// Use Go's string quoting which handles escaping
	return fmt.Sprintf("%q", path)
}

// getAncestorDirectories returns all ancestor directories of a path.
func getAncestorDirectories(pathStr string) []string {
	var ancestors []string
	current := filepath.Dir(pathStr)

	for current != "/" && current != "." {
		ancestors = append(ancestors, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return ancestors
}

// expandMacOSTmpPaths mirrors /tmp paths to /private/tmp equivalents and vice versa.
// On macOS, /tmp is a symlink to /private/tmp, and symlink resolution can fail if paths
// don't exist yet. Adding both variants ensures sandbox rules match kernel-resolved paths.
func expandMacOSTmpPaths(paths []string) []string {
	seen := make(map[string]bool)
	for _, p := range paths {
		seen[p] = true
	}

	var additions []string
	for _, p := range paths {
		var mirror string
		switch {
		case p == "/tmp":
			mirror = "/private/tmp"
		case p == "/private/tmp":
			mirror = "/tmp"
		case strings.HasPrefix(p, "/tmp/"):
			mirror = "/private" + p
		case strings.HasPrefix(p, "/private/tmp/"):
			mirror = strings.TrimPrefix(p, "/private")
		}

		if mirror != "" && !seen[mirror] {
			seen[mirror] = true
			additions = append(additions, mirror)
		}
	}

	return append(paths, additions...)
}

// getTmpdirParent gets the TMPDIR parent if it matches macOS pattern.
func getTmpdirParent() []string {
	tmpdir := os.Getenv("TMPDIR")
	if tmpdir == "" {
		return nil
	}

	// Match /var/folders/XX/YYY/T/
	pattern := regexp.MustCompile(`^/(private/)?var/folders/[^/]{2}/[^/]+/T/?$`)
	if !pattern.MatchString(tmpdir) {
		return nil
	}

	parent := strings.TrimSuffix(tmpdir, "/")
	parent = strings.TrimSuffix(parent, "/T")

	// Return both /var/ and /private/var/ versions
	if strings.HasPrefix(parent, "/private/var/") {
		return []string{parent, strings.Replace(parent, "/private", "", 1)}
	} else if strings.HasPrefix(parent, "/var/") {
		return []string{parent, "/private" + parent}
	}

	return []string{parent}
}

// generateReadRules generates filesystem read rules for the sandbox profile.
func generateReadRules(defaultDenyRead bool, cwd string, allowPaths, denyPaths []string, rewrittenEnvFiles map[string]string, logTag string) []string {
	var rules []string

	if defaultDenyRead {
		// When defaultDenyRead is enabled:
		// 1. Allow file-read-metadata globally (needed for directory traversal, stat, etc.)
		// 2. Allow file-read-data only for system paths + CWD + user-specified allowRead paths
		// This lets programs see what files exist but not read their contents.

		// Allow metadata operations globally (stat, readdir, etc.) and root dir (for path resolution)
		rules = append(rules, "(allow file-read-metadata)")
		rules = append(rules, `(allow file-read-data (literal "/"))`)

		// Allow reading data from essential system paths
		for _, systemPath := range GetDefaultReadablePaths() {
			rules = append(
				rules,
				"(allow file-read-data",
				fmt.Sprintf("  (subpath %s))", escapePath(systemPath)),
			)
		}

		// Allow reading CWD (full recursive read access)
		if cwd != "" {
			rules = append(
				rules,
				"(allow file-read-data",
				fmt.Sprintf("  (subpath %s))", escapePath(cwd)),
			)

			// Allow ancestor directory traversal (literal only, so programs can resolve CWD path)
			for _, ancestor := range getAncestorDirectories(cwd) {
				rules = append(
					rules,
					fmt.Sprintf("(allow file-read-data (literal %s))", escapePath(ancestor)),
				)
			}
		}

		// Allow home shell configs and tool caches (read-only)
		home, _ := os.UserHomeDir()
		if home != "" {
			// Shell config files (literal access)
			shellConfigs := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".inputrc"}
			for _, f := range shellConfigs {
				p := filepath.Join(home, f)
				rules = append(
					rules,
					fmt.Sprintf("(allow file-read-data (literal %s))", escapePath(p)),
				)
			}

			// Home tool caches (subpath access for package managers/configs)
			homeCaches := []string{".cache", ".npm", ".cargo", ".rustup", ".local", ".config", ".nvm", ".pyenv", ".rbenv", ".asdf"}
			for _, d := range homeCaches {
				p := filepath.Join(home, d)
				rules = append(
					rules,
					"(allow file-read-data",
					fmt.Sprintf("  (subpath %s))", escapePath(p)),
				)
			}
		}

		// Allow reading data from user-specified paths
		for _, pathPattern := range allowPaths {
			normalized := NormalizePath(pathPattern)

			if ContainsGlobChars(normalized) {
				regex := GlobToRegex(normalized)
				rules = append(
					rules,
					"(allow file-read-data",
					fmt.Sprintf("  (regex %s))", escapePath(regex)),
				)
			} else {
				rules = append(
					rules,
					"(allow file-read-data",
					fmt.Sprintf("  (subpath %s))", escapePath(normalized)),
				)
			}
		}

		// Deny sensitive files within CWD, unless credential substitution has
		// processed them (rewrittenEnvFiles). On macOS we cannot bind-mount
		// rewritten files, so we allow read access and rely on proxy-level
		// credential substitution to protect secrets in HTTP requests.
		// Must use file-read-data (not file-read*) because Seatbelt ignores
		// wildcard denies when a specific allow (file-read-data) covers the same path.
		if cwd != "" {
			var deniedFiles int
			for _, f := range SensitiveProjectFiles {
				p := filepath.Join(cwd, f)
				if _, ok := rewrittenEnvFiles[p]; ok {
					continue // credential substitution active; allow read
				}
				rules = append(
					rules,
					"(deny file-read-data",
					fmt.Sprintf("  (literal %s)", escapePath(p)),
					fmt.Sprintf("  (with message %q))", logTag),
				)
				deniedFiles++
			}
			// Only add the .env.* regex deny if not all files are handled by
			// credential substitution.
			if deniedFiles > 0 {
				rules = append(
					rules,
					"(deny file-read-data",
					fmt.Sprintf("  (regex %s)", escapePath("^"+regexp.QuoteMeta(cwd)+"/\\.env\\..*$")),
					fmt.Sprintf("  (with message %q))", logTag),
				)
			}
		}
	} else {
		// Allow all reads by default
		rules = append(rules, "(allow file-read*)")
	}

	// Deny sensitive system files (greyproxy encryption key, CA private key)
	for _, p := range SensitiveGreyproxyFiles() {
		rules = append(
			rules,
			"(deny file-read-data",
			fmt.Sprintf("  (literal %s)", escapePath(p)),
			fmt.Sprintf("  (with message %q))", logTag),
		)
	}

	// In both modes, deny specific paths (denyRead takes precedence).
	// Must use file-read-data (not file-read*) because Seatbelt ignores
	// wildcard denies when a specific allow (file-read-data) covers the same path.
	for _, pathPattern := range denyPaths {
		normalized := NormalizePath(pathPattern)

		if ContainsGlobChars(normalized) {
			regex := GlobToRegex(normalized)
			rules = append(
				rules,
				"(deny file-read-data",
				fmt.Sprintf("  (regex %s)", escapePath(regex)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		} else {
			rules = append(
				rules,
				"(deny file-read-data",
				fmt.Sprintf("  (subpath %s)", escapePath(normalized)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		}
	}

	// Block file movement to prevent bypass
	rules = append(rules, generateMoveBlockingRules(denyPaths, logTag)...)

	return rules
}

// generateWriteRules generates filesystem write rules for the sandbox profile.
// When cwd is non-empty, it is automatically included in the write allow paths.
func generateWriteRules(cwd string, allowPaths, denyPaths []string, allowGitConfig bool, logTag string) []string {
	var rules []string

	// Auto-allow CWD for writes (project directory should be writable)
	if cwd != "" {
		rules = append(
			rules,
			"(allow file-write*",
			fmt.Sprintf("  (subpath %s)", escapePath(cwd)),
			fmt.Sprintf("  (with message %q))", logTag),
		)
	}

	// Allow TMPDIR parent on macOS
	for _, tmpdirParent := range getTmpdirParent() {
		normalized := NormalizePath(tmpdirParent)
		rules = append(
			rules,
			"(allow file-write*",
			fmt.Sprintf("  (subpath %s)", escapePath(normalized)),
			fmt.Sprintf("  (with message %q))", logTag),
		)
	}

	// Generate allow rules
	for _, pathPattern := range allowPaths {
		normalized := NormalizePath(pathPattern)

		if ContainsGlobChars(normalized) {
			regex := GlobToRegex(normalized)
			rules = append(
				rules,
				"(allow file-write*",
				fmt.Sprintf("  (regex %s)", escapePath(regex)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		} else {
			rules = append(
				rules,
				"(allow file-write*",
				fmt.Sprintf("  (subpath %s)", escapePath(normalized)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		}
	}

	// Combine user-specified and mandatory deny patterns
	mandatoryCwd := cwd
	if mandatoryCwd == "" {
		mandatoryCwd, _ = os.Getwd()
	}
	mandatoryDeny := GetMandatoryDenyPatterns(mandatoryCwd, allowGitConfig)
	allDenyPaths := make([]string, 0, len(denyPaths)+len(mandatoryDeny))
	allDenyPaths = append(allDenyPaths, denyPaths...)
	allDenyPaths = append(allDenyPaths, mandatoryDeny...)

	for _, pathPattern := range allDenyPaths {
		normalized := NormalizePath(pathPattern)

		if ContainsGlobChars(normalized) {
			regex := GlobToRegex(normalized)
			rules = append(
				rules,
				"(deny file-write*",
				fmt.Sprintf("  (regex %s)", escapePath(regex)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		} else {
			rules = append(
				rules,
				"(deny file-write*",
				fmt.Sprintf("  (subpath %s)", escapePath(normalized)),
				fmt.Sprintf("  (with message %q))", logTag),
			)
		}
	}

	// Block file movement
	rules = append(rules, generateMoveBlockingRules(allDenyPaths, logTag)...)

	return rules
}

// generateMoveBlockingRules generates rules to prevent file movement bypasses.
func generateMoveBlockingRules(pathPatterns []string, logTag string) []string {
	var rules []string

	for _, pathPattern := range pathPatterns {
		normalized := NormalizePath(pathPattern)

		if ContainsGlobChars(normalized) {
			regex := GlobToRegex(normalized)
			rules = append(
				rules,
				"(deny file-write-unlink",
				fmt.Sprintf("  (regex %s)", escapePath(regex)),
				fmt.Sprintf("  (with message %q))", logTag),
			)

			// For globs, extract static prefix and block ancestor moves
			staticPrefix := strings.Split(normalized, "*")[0]
			if staticPrefix != "" && staticPrefix != "/" {
				baseDir := staticPrefix
				if strings.HasSuffix(baseDir, "/") {
					baseDir = baseDir[:len(baseDir)-1]
				} else {
					baseDir = filepath.Dir(staticPrefix)
				}

				rules = append(
					rules,
					"(deny file-write-unlink",
					fmt.Sprintf("  (literal %s)", escapePath(baseDir)),
					fmt.Sprintf("  (with message %q))", logTag),
				)

				for _, ancestor := range getAncestorDirectories(baseDir) {
					rules = append(
						rules,
						"(deny file-write-unlink",
						fmt.Sprintf("  (literal %s)", escapePath(ancestor)),
						fmt.Sprintf("  (with message %q))", logTag),
					)
				}
			}
		} else {
			rules = append(
				rules,
				"(deny file-write-unlink",
				fmt.Sprintf("  (subpath %s)", escapePath(normalized)),
				fmt.Sprintf("  (with message %q))", logTag),
			)

			for _, ancestor := range getAncestorDirectories(normalized) {
				rules = append(
					rules,
					"(deny file-write-unlink",
					fmt.Sprintf("  (literal %s)", escapePath(ancestor)),
					fmt.Sprintf("  (with message %q))", logTag),
				)
			}
		}
	}

	return rules
}

// GenerateSandboxProfile generates a complete macOS sandbox profile.
func GenerateSandboxProfile(params MacOSSandboxParams) string {
	logTag := "CMD64_" + EncodeSandboxedCommand(params.Command) + "_END" + sessionSuffix

	var profile strings.Builder

	// Header
	profile.WriteString("(version 1)\n")
	fmt.Fprintf(&profile, "(deny default (with message %q))\n\n", logTag)
	fmt.Fprintf(&profile, "; LogTag: %s\n\n", logTag)

	// Essential permissions - based on Chrome sandbox policy
	profile.WriteString(`; Essential permissions - based on Chrome sandbox policy
; Process permissions
(allow process-exec)
(allow process-fork)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow mach-priv-task-port (target same-sandbox))

; User preferences
(allow user-preference-read)

; Mach IPC - specific services only
(allow mach-lookup
  (global-name "com.apple.audio.systemsoundserver")
  (global-name "com.apple.audio.audiohald")
  (global-name "com.apple.audio.AudioComponentRegistrar")
  (global-name "com.apple.distributed_notifications@Uv3")
  (global-name "com.apple.FontObjectsServer")
  (global-name "com.apple.fonts")
  (global-name "com.apple.logd")
  (global-name "com.apple.lsd.mapdb")
  (global-name "com.apple.PowerManagement.control")
  (global-name "com.apple.system.logger")
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.TrustEvaluationAgent")
  (global-name "com.apple.system.opendirectoryd.libinfo")
  (global-name "com.apple.system.opendirectoryd.membership")
  (global-name "com.apple.bsd.dirhelper")
  (global-name "com.apple.securityd.xpc")
  (global-name "com.apple.coreservices.launchservicesd")
  (global-name "com.apple.FSEvents")
  (global-name "com.apple.fseventsd")
  (global-name "com.apple.SystemConfiguration.configd")
)

; POSIX IPC
(allow ipc-posix-shm)
(allow ipc-posix-sem)

; IOKit
(allow iokit-open
  (iokit-registry-entry-class "IOSurfaceRootUserClient")
  (iokit-registry-entry-class "RootDomainUserClient")
  (iokit-user-client-class "IOSurfaceSendRight")
)
(allow iokit-get-properties)

; System socket for network info
(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))

; sysctl reads
(allow sysctl-read
  (sysctl-name "hw.activecpu")
  (sysctl-name "hw.busfrequency_compat")
  (sysctl-name "hw.byteorder")
  (sysctl-name "hw.cacheconfig")
  (sysctl-name "hw.cachelinesize_compat")
  (sysctl-name "hw.cpufamily")
  (sysctl-name "hw.cpufrequency")
  (sysctl-name "hw.cpufrequency_compat")
  (sysctl-name "hw.cputype")
  (sysctl-name "hw.l1dcachesize_compat")
  (sysctl-name "hw.l1icachesize_compat")
  (sysctl-name "hw.l2cachesize_compat")
  (sysctl-name "hw.l3cachesize_compat")
  (sysctl-name "hw.logicalcpu")
  (sysctl-name "hw.logicalcpu_max")
  (sysctl-name "hw.machine")
  (sysctl-name "hw.memsize")
  (sysctl-name "hw.ncpu")
  (sysctl-name "hw.nperflevels")
  (sysctl-name "hw.packages")
  (sysctl-name "hw.pagesize_compat")
  (sysctl-name "hw.pagesize")
  (sysctl-name "hw.physicalcpu")
  (sysctl-name "hw.physicalcpu_max")
  (sysctl-name "hw.tbfrequency_compat")
  (sysctl-name "hw.vectorunit")
  (sysctl-name "kern.argmax")
  (sysctl-name "kern.bootargs")
  (sysctl-name "kern.hostname")
  (sysctl-name "kern.maxfiles")
  (sysctl-name "kern.maxfilesperproc")
  (sysctl-name "kern.maxproc")
  (sysctl-name "kern.ngroups")
  (sysctl-name "kern.osproductversion")
  (sysctl-name "kern.osrelease")
  (sysctl-name "kern.ostype")
  (sysctl-name "kern.osvariant_status")
  (sysctl-name "kern.osversion")
  (sysctl-name "kern.secure_kernel")
  (sysctl-name "kern.tcsm_available")
  (sysctl-name "kern.tcsm_enable")
  (sysctl-name "kern.usrstack64")
  (sysctl-name "kern.version")
  (sysctl-name "kern.willshutdown")
  (sysctl-name "machdep.cpu.brand_string")
  (sysctl-name "machdep.ptrauth_enabled")
  (sysctl-name "security.mac.lockdown_mode_state")
  (sysctl-name "sysctl.proc_cputype")
  (sysctl-name "vm.loadavg")
  (sysctl-name-prefix "hw.optional.arm")
  (sysctl-name-prefix "hw.optional.arm.")
  (sysctl-name-prefix "hw.optional.armv8_")
  (sysctl-name-prefix "hw.perflevel")
  (sysctl-name-prefix "kern.proc.all")
  (sysctl-name-prefix "kern.proc.pgrp.")
  (sysctl-name-prefix "kern.proc.pid.")
  (sysctl-name-prefix "machdep.cpu.")
  (sysctl-name-prefix "net.routetable.")
)

; V8 thread calculations
(allow sysctl-write
  (sysctl-name "kern.tcsm_enable")
)

; Distributed notifications
(allow distributed-notification-post)

; Security server
(allow mach-lookup (global-name "com.apple.SecurityServer"))

; Device I/O
(allow file-ioctl (literal "/dev/null"))
(allow file-ioctl (literal "/dev/zero"))
(allow file-ioctl (literal "/dev/random"))
(allow file-ioctl (literal "/dev/urandom"))
(allow file-ioctl (literal "/dev/dtracehelper"))
(allow file-ioctl (literal "/dev/tty"))
(allow file-ioctl (regex #"^/dev/ttys"))

(allow file-ioctl file-read-data file-write-data
  (require-all
    (literal "/dev/null")
    (vnode-type CHARACTER-DEVICE)
  )
)

; Inherited terminal access (TUI apps need read/write on the actual PTY device)
(allow file-read-data file-write-data (regex #"^/dev/ttys"))

`)

	// Network rules
	profile.WriteString("; Network\n")
	if !params.NeedsNetworkRestriction {
		profile.WriteString("(allow network*)\n")
	} else {
		// Always allow localhost binding and inbound connections.
		// This matches Linux behavior where the isolated network namespace
		// allows unrestricted local binding. Many tools need this for OAuth
		// callbacks, MCP servers, dev servers, etc.
		profile.WriteString(`(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))
`)
		// Process can make outbound connections to localhost
		if params.AllowLocalOutbound {
			profile.WriteString(`(allow network-outbound (local ip "localhost:*"))
`)
		} else {
			// Forwarded ports (-f/--forward): allow outbound to specific host
			// localhost ports. On macOS the network is shared with the host (no
			// namespace), so forwarding is just a targeted allow rule rather than
			// the socat bridge used on Linux. Redundant if AllowLocalOutbound is set.
			for _, port := range params.ForwardPorts {
				fmt.Fprintf(&profile, "(allow network-outbound (remote ip \"localhost:%d\"))\n", port)
			}
		}

		if params.AllowAllUnixSockets {
			profile.WriteString("(allow network* (subpath \"/\"))\n")
		} else if len(params.AllowUnixSockets) > 0 {
			for _, socketPath := range params.AllowUnixSockets {
				normalized := NormalizePath(socketPath)
				fmt.Fprintf(&profile, "(allow network* (subpath %s))\n", escapePath(normalized))
			}
		}

		// Allow outbound to the SOCKS5 proxy (TCP)
		if params.ProxyHost != "" && params.ProxyPort != "" {
			fmt.Fprintf(&profile, "(allow network-outbound (remote tcp \"%s:%s\"))\n", params.ProxyHost, params.ProxyPort)
		}

		// Allow outbound to the HTTP CONNECT proxy (TCP)
		if params.HTTPProxyHost != "" && params.HTTPProxyPort != "" {
			fmt.Fprintf(&profile, "(allow network-outbound (remote tcp \"%s:%s\"))\n", params.HTTPProxyHost, params.HTTPProxyPort)
		}

		// Allow outbound to the DNS proxy (TCP+UDP)
		if params.DnsProxyHost != "" && params.DnsProxyPort != "" {
			fmt.Fprintf(&profile, "(allow network-outbound (remote tcp \"%s:%s\"))\n", params.DnsProxyHost, params.DnsProxyPort)
			fmt.Fprintf(&profile, "(allow network-outbound (remote udp \"%s:%s\"))\n", params.DnsProxyHost, params.DnsProxyPort)
		}
	}
	profile.WriteString("\n")

	// Read rules
	profile.WriteString("; File read\n")
	readDenyPaths := append(append([]string(nil), params.ReadDenyPaths...), SensitiveGreyproxyDirs()...)
	for _, rule := range generateReadRules(params.DefaultDenyRead, params.Cwd, params.ReadAllowPaths, readDenyPaths, params.RewrittenEnvFiles, logTag) {
		profile.WriteString(rule + "\n")
	}
	if params.CACertPath != "" {
		fmt.Fprintf(&profile, "(allow file-read-data (literal %s))\n", escapePath(NormalizePath(params.CACertPath)))
	}
	profile.WriteString("\n")

	// Write rules
	profile.WriteString("; File write\n")
	writeDenyPaths := append(append([]string(nil), params.WriteDenyPaths...), SensitiveGreyproxyDirs()...)
	for _, rule := range generateWriteRules(params.Cwd, params.WriteAllowPaths, writeDenyPaths, params.AllowGitConfig, logTag) {
		profile.WriteString(rule + "\n")
	}
	root := params.CASnapshotRoot
	if root == "" {
		root = macOSCASnapshotRoot()
	}
	for _, path := range expandMacOSTmpPaths([]string{root}) {
		fmt.Fprintf(&profile, "(deny file-write* (subpath %s))\n", escapePath(path))
		fmt.Fprintf(&profile, "(deny file-write-unlink (subpath %s))\n", escapePath(path))
	}

	// PTY support
	if params.AllowPty {
		profile.WriteString(`
; Pseudo-terminal allocation (pty) support
(allow pseudo-tty)
(allow file-ioctl (literal "/dev/ptmx"))
(allow file-read* file-write* (literal "/dev/ptmx"))
`)
	}

	return profile.String()
}

// WrapCommandMacOS wraps a command with macOS sandbox restrictions.
// tmpDir is the per-session temp directory to set as TMPDIR; if empty, TMPDIR is not overridden.
func WrapCommandMacOS(cfg *config.Config, command string, exposedPorts []int, rewrittenEnvFiles map[string]string, tmpDir string, debug bool) (string, error) {
	if err := validateMacOSGreyproxyDataHome(); err != nil {
		return "", err
	}
	if cfg.Network.ProxyURL != "" || cfg.Network.HTTPProxyURL != "" {
		_, err := os.Lstat(filepath.Join(greyproxyDataDir(), "ca-cert.pem"))
		if err == nil {
			return "", fmt.Errorf("greyproxy CA requires a manager-owned snapshot")
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect greyproxy CA: %w", err)
		}
	}
	return wrapCommandMacOS(cfg, command, exposedPorts, rewrittenEnvFiles, tmpDir, "", debug)
}

func (m *Manager) wrapMacOSCommand(command string) (string, error) {
	if err := validateMacOSGreyproxyDataHome(); err != nil {
		return "", err
	}
	var certPath string
	if m.config.Network.ProxyURL != "" || m.config.Network.HTTPProxyURL != "" {
		var err error
		certPath, err = m.snapshotMacOSCA()
		if err != nil {
			return "", err
		}
	}
	return wrapCommandMacOSWithRoot(m.config, command, m.exposedPorts, m.rewrittenEnvFiles, m.macOSTmpDir, certPath, m.macOSCARoot, m.debug)
}

func validateMacOSGreyproxyDataHome() error {
	if dataHome := os.Getenv("GREYPROXY_DATA_HOME"); dataHome != "" && !filepath.IsAbs(dataHome) {
		return fmt.Errorf("invalid GREYPROXY_DATA_HOME: absolute path required on macOS")
	}
	return nil
}

func macOSCASnapshotRoot() string {
	return filepath.Join("/private/tmp", fmt.Sprintf("greywall-ca-%d", os.Getuid()))
}

func (m *Manager) snapshotMacOSCA() (string, error) {
	if m.macOSCADir != "" {
		return filepath.Join(m.macOSCADir, "ca-cert.pem"), nil
	}
	source := filepath.Join(greyproxyDataDir(), "ca-cert.pem")
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect Greyproxy CA: %w", err)
	}
	for _, pattern := range m.config.Filesystem.DenyRead {
		normalized := NormalizePath(pattern)
		if ContainsGlobChars(normalized) {
			prefix := filepath.Dir(normalized[:strings.IndexAny(normalized, "*?[")])
			if resolved, err := filepath.EvalSymlinks(prefix); err == nil {
				normalized = resolved + strings.TrimPrefix(normalized, prefix)
			}
			for path := NormalizePath(source); ; path = filepath.Dir(path) {
				matched, err := doublestar.Match(normalized, path)
				if err != nil {
					return "", fmt.Errorf("invalid denyRead pattern %q: %w", pattern, err)
				}
				if matched {
					return "", fmt.Errorf("greyproxy CA explicitly denied: %s", source)
				}
				if filepath.Dir(path) == path {
					break
				}
			}
			continue
		}
		if normalized == NormalizePath(filepath.Dir(source)) {
			continue
		}
		relative, err := filepath.Rel(normalized, NormalizePath(source))
		if err != nil {
			return "", fmt.Errorf("check denyRead path %q: %w", pattern, err)
		}
		if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			return "", fmt.Errorf("greyproxy CA explicitly denied: %s", source)
		}
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("greyproxy CA is not a regular file: %s", source)
	}
	file, err := os.Open(source) //nolint:gosec // source is the configured Greyproxy CA
	if err != nil {
		return "", fmt.Errorf("open Greyproxy CA: %w", err)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", fmt.Errorf("greyproxy CA changed while opening: %s", source)
	}
	contents, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil {
		return "", fmt.Errorf("read Greyproxy CA: %w", err)
	}
	if len(contents) > 1024*1024 {
		return "", fmt.Errorf("greyproxy CA exceeds 1 MiB")
	}
	var certificates []byte
	for len(contents) > 0 {
		contents = []byte(strings.TrimSpace(string(contents)))
		if len(contents) == 0 {
			break
		}
		if !strings.HasPrefix(string(contents), "-----BEGIN CERTIFICATE-----") {
			return "", fmt.Errorf("greyproxy CA contains non-certificate data")
		}
		endMarker := []byte("-----END CERTIFICATE-----")
		end := bytes.Index(contents, endMarker)
		if end < 0 {
			return "", fmt.Errorf("greyproxy CA contains non-certificate data")
		}
		end += len(endMarker)
		block, remaining := pem.Decode(contents[:end])
		if block == nil || len(remaining) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return "", fmt.Errorf("greyproxy CA contains non-certificate data")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return "", fmt.Errorf("greyproxy CA contains an invalid CA certificate")
		}
		certificates = append(certificates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
		contents = contents[end:]
	}
	if len(certificates) == 0 {
		return "", fmt.Errorf("greyproxy CA contains no certificates")
	}
	root := m.macOSCARoot
	if root == "" {
		root = macOSCASnapshotRoot()
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(root))
	if err != nil {
		return "", fmt.Errorf("resolve Greyproxy CA snapshot parent: %w", err)
	}
	tempDir := filepath.Join(resolvedParent, filepath.Base(root))
	protectedDirs := append(SensitiveGreyproxyDirs(), filepath.Dir(source))
	if m.macOSTmpDir != "" {
		protectedDirs = append(protectedDirs, m.macOSTmpDir)
	}
	for _, protected := range protectedDirs {
		relative, err := filepath.Rel(NormalizePath(protected), tempDir)
		if err != nil {
			return "", fmt.Errorf("check Greyproxy CA snapshot directory: %w", err)
		}
		if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			return "", fmt.Errorf("greyproxy CA snapshot directory overlaps a protected directory")
		}
	}
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("create Greyproxy CA root: %w", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", fmt.Errorf("inspect Greyproxy CA root: %w", err)
	}
	stat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 || int64(stat.Uid) != int64(os.Getuid()) {
		return "", fmt.Errorf("unsafe Greyproxy CA root: %s", root)
	}
	dir, err := os.MkdirTemp(root, "session-")
	if err != nil {
		return "", fmt.Errorf("create Greyproxy CA snapshot directory: %w", err)
	}
	path := filepath.Join(dir, "ca-cert.pem")
	if err := os.WriteFile(path, certificates, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("write Greyproxy CA snapshot: %w", err)
	}
	m.macOSCADir = dir
	return path, nil
}

func wrapCommandMacOS(cfg *config.Config, command string, exposedPorts []int, rewrittenEnvFiles map[string]string, tmpDir, certPath string, debug bool) (string, error) {
	return wrapCommandMacOSWithRoot(cfg, command, exposedPorts, rewrittenEnvFiles, tmpDir, certPath, "", debug)
}

func wrapCommandMacOSWithRoot(cfg *config.Config, command string, exposedPorts []int, rewrittenEnvFiles map[string]string, tmpDir, certPath, caRoot string, debug bool) (string, error) {
	if err := validateMacOSGreyproxyDataHome(); err != nil {
		return "", err
	}
	cwd, _ := os.Getwd()

	// Build allow paths: default + configured + per-session tmpdir
	allowPaths := append(GetDefaultWritePaths(), cfg.Filesystem.AllowWrite...)
	if tmpDir != "" {
		allowPaths = append(allowPaths, tmpDir)
	}

	// Expand /tmp <-> /private/tmp for macOS symlink compatibility
	allowPaths = expandMacOSTmpPaths(allowPaths)

	// Enable local binding if ports are exposed or if explicitly configured
	allowLocalBinding := cfg.Network.AllowLocalBinding || len(exposedPorts) > 0

	allowLocalOutbound := allowLocalBinding
	if cfg.Network.AllowLocalOutbound != nil {
		allowLocalOutbound = *cfg.Network.AllowLocalOutbound
	}

	// Parse proxy URLs for network rules
	var proxyHost, proxyPort string
	if cfg.Network.ProxyURL != "" {
		if u, err := url.Parse(cfg.Network.ProxyURL); err == nil {
			proxyHost = u.Hostname()
			proxyPort = u.Port()
		}
	}

	var httpProxyHost, httpProxyPort string
	if cfg.Network.HTTPProxyURL != "" {
		if u, err := url.Parse(cfg.Network.HTTPProxyURL); err == nil {
			httpProxyHost = u.Hostname()
			httpProxyPort = u.Port()
		}
	}

	var dnsProxyHost, dnsProxyPort string
	if cfg.Network.DnsAddr != "" {
		host, port, err := net.SplitHostPort(cfg.Network.DnsAddr)
		if err == nil {
			dnsProxyHost = host
			dnsProxyPort = port
		}
	}

	// Restrict network unless proxy is configured to an external host
	// If no proxy: block all outbound. If proxy: allow outbound only to proxy.
	needsNetworkRestriction := true

	params := MacOSSandboxParams{
		Command:                 command,
		NeedsNetworkRestriction: needsNetworkRestriction,
		ProxyURL:                cfg.Network.ProxyURL,
		ProxyHost:               proxyHost,
		ProxyPort:               proxyPort,
		HTTPProxyHost:           httpProxyHost,
		HTTPProxyPort:           httpProxyPort,
		DnsProxyHost:            dnsProxyHost,
		DnsProxyPort:            dnsProxyPort,
		AllowUnixSockets:        cfg.Network.AllowUnixSockets,
		AllowAllUnixSockets:     cfg.Network.AllowAllUnixSockets,
		AllowLocalBinding:       allowLocalBinding,
		AllowLocalOutbound:      allowLocalOutbound,
		ForwardPorts:            cfg.Network.ForwardPorts,
		DefaultDenyRead:         cfg.Filesystem.IsDefaultDenyRead(),
		Cwd:                     cwd,
		ReadAllowPaths:          cfg.Filesystem.AllowRead,
		ReadDenyPaths:           cfg.Filesystem.DenyRead,
		WriteAllowPaths:         allowPaths,
		WriteDenyPaths:          cfg.Filesystem.DenyWrite,
		AllowPty:                cfg.AllowPty,
		AllowGitConfig:          cfg.Filesystem.AllowGitConfig,
		RewrittenEnvFiles:       rewrittenEnvFiles,
		CASnapshotRoot:          caRoot,
	}
	if certPath != "" {
		params.CACertPath = certPath
		params.WriteDenyPaths = append(append([]string(nil), params.WriteDenyPaths...), expandMacOSTmpPaths([]string{filepath.Dir(certPath)})...)
	}

	if debug && len(exposedPorts) > 0 {
		fmt.Fprintf(os.Stderr, "[greywall:macos] Enabling local binding for exposed ports: %v\n", exposedPorts)
	}
	if debug && allowLocalBinding && !allowLocalOutbound {
		fmt.Fprintf(os.Stderr, "[greywall:macos] Blocking localhost outbound (AllowLocalOutbound=false)\n")
	}
	if debug && !allowLocalOutbound && len(cfg.Network.ForwardPorts) > 0 {
		fmt.Fprintf(os.Stderr, "[greywall:macos] Forwarding host localhost ports: %v\n", cfg.Network.ForwardPorts)
	}

	profile := GenerateSandboxProfile(params)

	// Find shell
	shell := params.Shell
	if shell == "" {
		shell = "bash"
	}
	shellPath, err := exec.LookPath(shell)
	if err != nil {
		return "", fmt.Errorf("shell %q not found: %w", shell, err)
	}

	proxyEnvs := generateProxyEnvVars(cfg.Network.ProxyURL, cfg.Network.HTTPProxyURL, tmpDir, certPath)

	// Build the command
	// env VAR1=val1 VAR2=val2 sandbox-exec -p 'profile' shell -c 'command'
	var parts []string
	parts = append(parts, "env")
	parts = append(parts, proxyEnvs...)
	parts = append(parts, "sandbox-exec", "-p", profile, shellPath, "-c", command)

	return ShellQuote(parts), nil
}

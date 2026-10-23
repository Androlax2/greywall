//go:build linux

package sandbox

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"github.com/bmatcuk/doublestar/v4"
	"golang.org/x/sys/unix"
)

// ApplyLandlockFromConfig creates and applies Landlock restrictions based on config.
// This should be called before exec'ing the sandboxed command.
// Returns an error if Landlock cannot be enforced.
func ApplyLandlockFromConfig(cfg *config.Config, cwd string, socketPaths []string, masked MaskedPaths, debug bool) error {
	features := DetectLinuxFeatures()
	if !features.CanUseLandlock() {
		return fmt.Errorf("cannot apply Landlock: feature is unavailable")
	}

	ruleset, err := NewLandlockRuleset(debug)
	if err != nil {
		return fmt.Errorf("create Landlock ruleset: %w", err)
	}
	defer func() { _ = ruleset.Close() }()

	var rules []landlockRule
	allowRead := func(path string) { rules = append(rules, landlockRule{path, ruleset.readAccess()}) }
	allowReadWrite := func(path string) {
		rules = append(rules, landlockRule{path, ruleset.readAccess() | ruleset.writeAccess()})
	}

	if err := ruleset.Initialize(); err != nil {
		return fmt.Errorf("initialize Landlock ruleset: %w", err)
	}

	// Essential system paths - allow read+execute
	// Note: /dev is handled separately with read+write for /dev/null, /dev/zero, etc.
	systemReadPaths := []string{
		"/usr",
		"/lib",
		"/lib64",
		"/lib32",
		"/bin",
		"/sbin",
		"/etc",
		"/proc",
		"/sys",
		"/run",
		"/var/lib",
		"/var/cache",
		"/opt",
		"/nix", // NixOS: all binaries and libraries live under /nix/store
	}

	for _, p := range systemReadPaths {
		allowRead(p)
	}

	// If /etc/resolv.conf is a cross-mount symlink (e.g., -> /mnt/wsl/resolv.conf
	// on WSL), Landlock needs a read rule for the resolved target's parent dir,
	// otherwise following the symlink hits EACCES.
	if target, err := filepath.EvalSymlinks("/etc/resolv.conf"); err == nil && target != "/etc/resolv.conf" {
		targetDir := filepath.Dir(target)
		allowRead(targetDir)
	}

	// Current working directory - read+write access (project directory)
	if cwd != "" {
		allowReadWrite(cwd)
	}

	// Home directory - read access only when not in deny-by-default mode.
	// In deny-by-default mode, only specific user tooling paths are allowed,
	// not the entire home directory. Masked paths under these read-only rules
	// are carved out by excludeMaskedPaths below; .env in the writable cwd
	// relies on the bwrap mask and VerifyMasks.
	defaultDenyRead := cfg != nil && cfg.Filesystem.IsDefaultDenyRead()
	if !defaultDenyRead {
		if home, err := os.UserHomeDir(); err == nil {
			allowRead(home)
		}
	} else {
		// In deny-by-default mode, allow specific user tooling paths
		if home, err := os.UserHomeDir(); err == nil {
			for _, p := range GetDefaultReadablePaths() {
				if strings.HasPrefix(p, home) {
					allowRead(p)
				}
			}
			// Shell configs
			shellConfigs := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".inputrc"}
			for _, f := range shellConfigs {
				p := filepath.Join(home, f)
				allowRead(p)
			}
			// Home caches
			homeCaches := []string{".cache", ".npm", ".cargo", ".rustup", ".local", ".config"}
			for _, d := range homeCaches {
				p := filepath.Join(home, d)
				allowRead(p)
			}
		}
	}

	// /tmp - allow read+write (many programs need this)
	allowReadWrite("/tmp")

	// /dev needs read+write for /dev/null, /dev/zero, /dev/tty, etc.
	// Landlock doesn't support rules on device files directly, so we allow the whole /dev
	allowReadWrite("/dev")

	// Socket paths for proxy communication
	for _, p := range socketPaths {
		dir := filepath.Dir(p)
		allowReadWrite(dir)
	}

	// User-configured allowRead paths
	if cfg != nil && cfg.Filesystem.AllowRead != nil {
		expandedPaths := ExpandGlobPatterns(cfg.Filesystem.AllowRead)
		for _, p := range expandedPaths {
			allowRead(p)
		}
		// Also add non-glob paths directly
		for _, p := range cfg.Filesystem.AllowRead {
			if !ContainsGlobChars(p) {
				normalized := NormalizePath(p)
				allowRead(normalized)
			}
		}
	}

	// User-configured allowWrite paths
	if cfg != nil && cfg.Filesystem.AllowWrite != nil {
		expandedPaths := ExpandGlobPatterns(cfg.Filesystem.AllowWrite)
		for _, p := range expandedPaths {
			allowReadWrite(p)
		}
		// Also add non-glob paths directly
		for _, p := range cfg.Filesystem.AllowWrite {
			if !ContainsGlobChars(p) {
				normalized := NormalizePath(p)
				allowReadWrite(normalized)
			}
		}
	}

	// Landlock can only grant, so a masked path is kept out by not granting it:
	// read-only rules above a masked path are split around it.
	for _, rule := range excludeMaskedPaths(rules, masked) {
		if err := ruleset.addPathRule(rule.path, rule.access); err != nil && debug {
			fmt.Fprintf(os.Stderr, "[greywall:landlock] Warning: failed to add rule for %s: %v\n", rule.path, err)
		}
	}

	// Apply the ruleset
	if err := ruleset.Apply(); err != nil {
		return fmt.Errorf("apply Landlock ruleset: %w", err)
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[greywall:landlock] Applied restrictions (ABI v%d)\n", features.LandlockABI)
	}

	return nil
}

// landlockRule is one path-beneath rule, before it is added to a ruleset.
type landlockRule struct {
	path   string
	access uint64
}

const landlockWriteRights = uint64(
	LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_REMOVE_DIR |
		LANDLOCK_ACCESS_FS_REMOVE_FILE |
		LANDLOCK_ACCESS_FS_MAKE_CHAR |
		LANDLOCK_ACCESS_FS_MAKE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_REG |
		LANDLOCK_ACCESS_FS_MAKE_SOCK |
		LANDLOCK_ACCESS_FS_MAKE_FIFO |
		LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		LANDLOCK_ACCESS_FS_MAKE_SYM,
)

// excludeMaskedPaths rewrites read-only rules so that none of them grants a
// masked path. Landlock can only grant, and a rule covers everything beneath
// its path, so a read-only rule above a masked path is replaced by:
//   - READ_DIR on the rule's path (names stay listable, contents do not),
//   - the full access on every entry beside the way down to each masked path,
//   - the full access on the exceptions inside masked dirs (ca-cert.pem).
//
// Entries that appear later directly in a split directory are not readable in
// the running sandbox. Writable rules are left unchanged: splitting them would
// hide the files the sandbox itself creates; there the bwrap mask and
// VerifyMasks are the protection.
func excludeMaskedPaths(rules []landlockRule, masked MaskedPaths) []landlockRule {
	hidden := make([]string, 0, len(masked.Files)+len(masked.Dirs)+len(masked.Future))
	for _, path := range slices.Concat(masked.Files, masked.Dirs, masked.Future) {
		hidden = append(hidden, resolvedPath(path))
	}
	exceptions := make([]string, 0, len(masked.Exceptions))
	for _, path := range masked.Exceptions {
		exceptions = append(exceptions, resolvedPath(path))
	}

	var planned []landlockRule
	for _, rule := range rules {
		root := resolvedPath(rule.path)
		if rule.access&landlockWriteRights != 0 || !slices.ContainsFunc(hidden, func(path string) bool { return isSameOrUnder(path, root) }) {
			planned = append(planned, rule)
			continue
		}
		planned = append(planned, splitAroundHidden(root, rule.access, hidden, exceptions)...)
	}
	return planned
}

func splitAroundHidden(root string, access uint64, hidden, exceptions []string) []landlockRule {
	if slices.Contains(hidden, root) {
		return exceptionRules(root, access, exceptions)
	}
	var planned []landlockRule
	if access&LANDLOCK_ACCESS_FS_READ_DIR != 0 {
		planned = append(planned, landlockRule{root, LANDLOCK_ACCESS_FS_READ_DIR})
	}
	var expand func(dir string)
	expand = func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return // nothing beside the masked path can be granted: fail closed
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			switch {
			case slices.ContainsFunc(hidden, func(hiddenPath string) bool { return matchesHiddenPath(hiddenPath, path) }):
				planned = append(planned, exceptionRules(path, access, exceptions)...)
			case entry.Type()&fs.ModeSymlink != 0:
				// addPathRule follows symlinks: never grant one that leads into,
				// onto or above a masked path.
				target, err := filepath.EvalSymlinks(path)
				if err != nil || slices.ContainsFunc(hidden, func(hiddenPath string) bool {
					return isSameOrUnder(target, hiddenPath) || isSameOrUnder(hiddenPath, target)
				}) {
					continue
				}
				planned = append(planned, landlockRule{path, access})
			case slices.ContainsFunc(hidden, func(hiddenPath string) bool { return isSameOrUnder(hiddenPath, path) }):
				expand(path)
			default:
				planned = append(planned, landlockRule{path, access})
			}
		}
	}
	expand(root)
	return planned
}

// matchesHiddenPath reports whether path is hiddenPath, or matches it when
// hiddenPath is a pattern from futureDenyReadPaths (~/.ssh/id_*).
func matchesHiddenPath(hiddenPath, path string) bool {
	if hiddenPath == path {
		return true
	}
	matched, err := filepath.Match(hiddenPath, path)
	return err == nil && matched
}

// exceptionRules grants access to the exceptions inside a masked path.
func exceptionRules(maskedPath string, access uint64, exceptions []string) []landlockRule {
	var planned []landlockRule
	for _, exception := range exceptions {
		if isSameOrUnder(exception, maskedPath) && exception != maskedPath {
			planned = append(planned, landlockRule{exception, access})
		}
	}
	return planned
}

// resolvedPath resolves symlinks in the longest existing prefix of path, so a
// path that does not exist yet compares equal to the rules' resolved paths.
func resolvedPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	missingTail := ""
	for existing := absolute; ; existing = filepath.Dir(existing) {
		if resolved, err := filepath.EvalSymlinks(existing); err == nil {
			return filepath.Join(resolved, missingTail)
		}
		if filepath.Dir(existing) == existing {
			return absolute
		}
		missingTail = filepath.Join(filepath.Base(existing), missingTail)
	}
}

// isSameOrUnder reports whether path is ancestor itself or lies beneath it.
func isSameOrUnder(path, ancestor string) bool {
	return path == ancestor || ancestor == "/" || strings.HasPrefix(path, ancestor+string(filepath.Separator))
}

// LandlockRuleset manages Landlock filesystem restrictions.
type LandlockRuleset struct {
	rulesetFd   int
	abiVersion  int
	debug       bool
	initialized bool
	readPaths   map[string]bool
	writePaths  map[string]bool
	denyPaths   map[string]bool
}

// NewLandlockRuleset creates a new Landlock ruleset.
func NewLandlockRuleset(debug bool) (*LandlockRuleset, error) {
	features := DetectLinuxFeatures()
	if !features.CanUseLandlock() {
		return nil, fmt.Errorf("landlock not available (kernel %d.%d, need 5.13+)",
			features.KernelMajor, features.KernelMinor)
	}

	return &LandlockRuleset{
		rulesetFd:  -1,
		abiVersion: features.LandlockABI,
		debug:      debug,
		readPaths:  make(map[string]bool),
		writePaths: make(map[string]bool),
		denyPaths:  make(map[string]bool),
	}, nil
}

// Initialize creates the Landlock ruleset.
func (l *LandlockRuleset) Initialize() error {
	if l.initialized {
		return nil
	}

	// Determine which access rights to handle based on ABI version
	fsAccess := l.getHandledAccessFS()

	attr := landlockRulesetAttr{
		handledAccessFS: fsAccess,
	}

	// Note: We do NOT enable Landlock network restrictions (handledAccessNet)
	// because:
	// 1. Network isolation is already handled by bwrap's network namespace
	// 2. Enabling network restrictions without proper allow rules would break
	//    the sandbox's proxy connections
	// 3. The proxy architecture requires localhost connections which would
	//    need complex rule management

	fd, _, err := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), //nolint:gosec // required for syscall
		unsafe.Sizeof(attr),
		0,
	)
	if err != 0 {
		return fmt.Errorf("failed to create Landlock ruleset: %w", err)
	}

	l.rulesetFd = int(fd) //nolint:gosec // fd from syscall fits in int
	l.initialized = true

	if l.debug {
		fmt.Fprintf(os.Stderr, "[greywall:landlock] Created ruleset (ABI v%d, fd=%d)\n", l.abiVersion, l.rulesetFd)
	}

	return nil
}

// getHandledAccessFS returns the filesystem access rights to handle.
func (l *LandlockRuleset) getHandledAccessFS() uint64 {
	// Base access rights (ABI v1)
	access := uint64(
		LANDLOCK_ACCESS_FS_EXECUTE |
			LANDLOCK_ACCESS_FS_WRITE_FILE |
			LANDLOCK_ACCESS_FS_READ_FILE |
			LANDLOCK_ACCESS_FS_READ_DIR |
			LANDLOCK_ACCESS_FS_REMOVE_DIR |
			LANDLOCK_ACCESS_FS_REMOVE_FILE |
			LANDLOCK_ACCESS_FS_MAKE_CHAR |
			LANDLOCK_ACCESS_FS_MAKE_DIR |
			LANDLOCK_ACCESS_FS_MAKE_REG |
			LANDLOCK_ACCESS_FS_MAKE_SOCK |
			LANDLOCK_ACCESS_FS_MAKE_FIFO |
			LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			LANDLOCK_ACCESS_FS_MAKE_SYM,
	)

	// ABI v2: add REFER (cross-directory renames)
	if l.abiVersion >= 2 {
		access |= LANDLOCK_ACCESS_FS_REFER
	}

	// ABI v3: add TRUNCATE
	if l.abiVersion >= 3 {
		access |= LANDLOCK_ACCESS_FS_TRUNCATE
	}

	// ABI v5: add IOCTL_DEV
	if l.abiVersion >= 5 {
		access |= LANDLOCK_ACCESS_FS_IOCTL_DEV
	}

	return access
}

// AllowRead adds read access to a path.
func (l *LandlockRuleset) AllowRead(path string) error {
	return l.addPathRule(path, l.readAccess())
}

// AllowWrite adds write access to a path.
func (l *LandlockRuleset) AllowWrite(path string) error {
	return l.addPathRule(path, l.writeAccess())
}

// readAccess is the access AllowRead grants.
func (l *LandlockRuleset) readAccess() uint64 {
	return LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE
}

// writeAccess is the access AllowWrite grants, for this ABI version.
func (l *LandlockRuleset) writeAccess() uint64 {
	access := uint64(
		LANDLOCK_ACCESS_FS_WRITE_FILE |
			LANDLOCK_ACCESS_FS_REMOVE_DIR |
			LANDLOCK_ACCESS_FS_REMOVE_FILE |
			LANDLOCK_ACCESS_FS_MAKE_CHAR |
			LANDLOCK_ACCESS_FS_MAKE_DIR |
			LANDLOCK_ACCESS_FS_MAKE_REG |
			LANDLOCK_ACCESS_FS_MAKE_SOCK |
			LANDLOCK_ACCESS_FS_MAKE_FIFO |
			LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			LANDLOCK_ACCESS_FS_MAKE_SYM,
	)

	// Add REFER for ABI v2+
	if l.abiVersion >= 2 {
		access |= LANDLOCK_ACCESS_FS_REFER
	}

	// Add TRUNCATE for ABI v3+
	if l.abiVersion >= 3 {
		access |= LANDLOCK_ACCESS_FS_TRUNCATE
	}

	// Add IOCTL_DEV for ABI v5+ so interactive TUI programs can put
	// terminals/PTYs into raw mode (TCGETS/TCSETS on /dev/tty, /dev/pts/*).
	if l.abiVersion >= 5 {
		access |= LANDLOCK_ACCESS_FS_IOCTL_DEV
	}

	return access
}

// AllowReadWrite adds full read/write access to a path.
func (l *LandlockRuleset) AllowReadWrite(path string) error {
	if err := l.AllowRead(path); err != nil {
		return err
	}
	return l.AllowWrite(path)
}

// addPathRule adds a rule for a specific path.
func (l *LandlockRuleset) addPathRule(path string, access uint64) error {
	if !l.initialized {
		if err := l.Initialize(); err != nil {
			return err
		}
	}

	// Resolve symlinks and get absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for %s: %w", path, err)
	}

	// Try to resolve symlinks, but don't fail if the path doesn't exist
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = resolved
	}

	// Check if path exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		if l.debug {
			fmt.Fprintf(os.Stderr, "[greywall:landlock] Skipping non-existent path: %s\n", absPath)
		}
		return nil
	}

	// Open the path with O_PATH
	fd, err := unix.Open(absPath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if l.debug {
			fmt.Fprintf(os.Stderr, "[greywall:landlock] Failed to open path %s: %v\n", absPath, err)
		}
		return nil // Don't fail on paths we can't access
	}
	defer func() { _ = unix.Close(fd) }()

	// Use fstat on the fd to avoid TOCTOU race between stat and open
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		if l.debug {
			fmt.Fprintf(os.Stderr, "[greywall:landlock] Failed to fstat path %s: %v\n", absPath, err)
		}
		return nil
	}
	isDir := (stat.Mode & unix.S_IFMT) == unix.S_IFDIR

	// Intersect with handled access to avoid invalid combinations
	access &= l.getHandledAccessFS()

	// Filter out directory-only access rights for non-directory paths (files, sockets, devices, etc.).
	// Landlock returns EINVAL if you try to add MAKE_*, REMOVE_*, READ_DIR, or REFER rights to a non-directory.
	// See: https://docs.kernel.org/userspace-api/landlock.html
	// File-compatible rights: EXECUTE, WRITE_FILE, READ_FILE, TRUNCATE
	// Directory-only rights: READ_DIR, REMOVE_*, MAKE_*, REFER
	if !isDir {
		dirOnlyRights := uint64(
			LANDLOCK_ACCESS_FS_READ_DIR |
				LANDLOCK_ACCESS_FS_REMOVE_DIR |
				LANDLOCK_ACCESS_FS_REMOVE_FILE |
				LANDLOCK_ACCESS_FS_MAKE_CHAR |
				LANDLOCK_ACCESS_FS_MAKE_DIR |
				LANDLOCK_ACCESS_FS_MAKE_REG |
				LANDLOCK_ACCESS_FS_MAKE_SOCK |
				LANDLOCK_ACCESS_FS_MAKE_FIFO |
				LANDLOCK_ACCESS_FS_MAKE_BLOCK |
				LANDLOCK_ACCESS_FS_MAKE_SYM |
				LANDLOCK_ACCESS_FS_REFER,
		)
		access &^= dirOnlyRights
	}

	if access == 0 {
		if l.debug {
			fmt.Fprintf(os.Stderr, "[greywall:landlock] Skipping %s: no applicable access rights\n", absPath)
		}
		return nil
	}

	attr := landlockPathBeneathAttr{
		allowedAccess: access,
		parentFd:      int32(fd), //nolint:gosec // fd from unix.Open fits in int32
	}

	_, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(l.rulesetFd), //nolint:gosec // fd fits in uintptr
		LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&attr)), //nolint:gosec // required for syscall
	)
	if errno != 0 {
		return fmt.Errorf("failed to add Landlock rule for %s: %w", absPath, errno)
	}

	if l.debug {
		fmt.Fprintf(os.Stderr, "[greywall:landlock] Added rule: %s (access=0x%x)\n", absPath, access)
	}

	return nil
}

// Apply applies the Landlock ruleset to the current process.
func (l *LandlockRuleset) Apply() error {
	if !l.initialized {
		return fmt.Errorf("landlock ruleset not initialized")
	}

	// Set NO_NEW_PRIVS first (required for Landlock)
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set NO_NEW_PRIVS: %w", err)
	}

	// Apply the ruleset
	_, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(l.rulesetFd), //nolint:gosec // fd fits in uintptr
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("failed to apply Landlock ruleset: %w", errno)
	}

	if l.debug {
		fmt.Fprintf(os.Stderr, "[greywall:landlock] Ruleset applied to process\n")
	}

	return nil
}

// Close closes the ruleset file descriptor.
func (l *LandlockRuleset) Close() error {
	if l.rulesetFd >= 0 {
		err := unix.Close(l.rulesetFd)
		l.rulesetFd = -1
		return err
	}
	return nil
}

// ExpandGlobPatterns expands glob patterns to actual paths for Landlock rules.
// Optimized for Landlock's PATH_BENEATH semantics:
//   - "dir/**" → returns just "dir" (Landlock covers descendants automatically)
//   - "**/pattern" → scoped to cwd only, skips already-covered directories
//   - "**/dir/**" → finds dirs in cwd, returns them (PATH_BENEATH covers contents)
func ExpandGlobPatterns(patterns []string) []string {
	var expanded []string
	seen := make(map[string]bool)

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	// First pass: collect directories covered by "dir/**" patterns
	// These will be skipped when walking for "**/pattern" patterns
	coveredDirs := make(map[string]bool)
	for _, pattern := range patterns {
		if !ContainsGlobChars(pattern) {
			continue
		}
		pattern = NormalizePath(pattern)
		if strings.HasSuffix(pattern, "/**") && !strings.Contains(strings.TrimSuffix(pattern, "/**"), "**") {
			dir := strings.TrimSuffix(pattern, "/**")
			if !strings.HasPrefix(dir, "/") {
				dir = filepath.Join(cwd, dir)
			}
			// Store relative path for matching during walk
			relDir, err := filepath.Rel(cwd, dir)
			if err == nil {
				coveredDirs[relDir] = true
			}
		}
	}

	for _, pattern := range patterns {
		if !ContainsGlobChars(pattern) {
			// Not a glob, use as-is
			normalized := NormalizePath(pattern)
			if !seen[normalized] {
				seen[normalized] = true
				expanded = append(expanded, normalized)
			}
			continue
		}

		// Normalize pattern
		pattern = NormalizePath(pattern)

		// Case 1: "dir/**" - just return the dir (PATH_BENEATH handles descendants)
		// This avoids walking the directory entirely
		if strings.HasSuffix(pattern, "/**") && !strings.Contains(strings.TrimSuffix(pattern, "/**"), "**") {
			dir := strings.TrimSuffix(pattern, "/**")
			if !strings.HasPrefix(dir, "/") {
				dir = filepath.Join(cwd, dir)
			}
			if !seen[dir] {
				seen[dir] = true
				expanded = append(expanded, dir)
			}
			continue
		}

		// Case 2: "**/pattern" or "**/dir/**" - scope to cwd only
		// Skip directories already covered by dir/** patterns
		if strings.HasPrefix(pattern, "**/") {
			// Extract what we're looking for after the **/
			suffix := strings.TrimPrefix(pattern, "**/")

			// If it ends with /**, we're looking for directories
			isDir := strings.HasSuffix(suffix, "/**")
			if isDir {
				suffix = strings.TrimSuffix(suffix, "/**")
			}

			// Walk cwd looking for matches, skipping covered directories
			fsys := os.DirFS(cwd)
			searchPattern := "**/" + suffix

			err := doublestar.GlobWalk(fsys, searchPattern, func(path string, d fs.DirEntry) error {
				// Skip directories that are already covered by dir/** patterns
				// Check each parent directory of the current path
				pathParts := strings.Split(path, string(filepath.Separator))
				for i := 1; i <= len(pathParts); i++ {
					parentPath := strings.Join(pathParts[:i], string(filepath.Separator))
					if coveredDirs[parentPath] {
						if d.IsDir() {
							return fs.SkipDir
						}
						return nil // Skip this file, it's under a covered dir
					}
				}

				absPath := filepath.Join(cwd, path)
				if !seen[absPath] {
					seen[absPath] = true
					expanded = append(expanded, absPath)
				}
				return nil
			})
			if err != nil {
				continue
			}
			continue
		}

		// Case 3: Other patterns with * but not ** - use standard glob scoped to cwd
		if !strings.Contains(pattern, "**") {
			var searchBase string
			var searchPattern string

			if strings.HasPrefix(pattern, "/") {
				// Absolute pattern - find the non-glob prefix
				parts := strings.Split(pattern, "/")
				var baseparts []string
				for _, p := range parts {
					if ContainsGlobChars(p) {
						break
					}
					baseparts = append(baseparts, p)
				}
				searchBase = strings.Join(baseparts, "/")
				if searchBase == "" {
					searchBase = "/"
				}
				searchPattern = strings.TrimPrefix(pattern, searchBase+"/")
			} else {
				searchBase = cwd
				searchPattern = pattern
			}

			fsys := os.DirFS(searchBase)
			matches, err := doublestar.Glob(fsys, searchPattern)
			if err != nil {
				continue
			}

			for _, match := range matches {
				absPath := filepath.Join(searchBase, match)
				if !seen[absPath] {
					seen[absPath] = true
					expanded = append(expanded, absPath)
				}
			}
		}
	}

	return expanded
}

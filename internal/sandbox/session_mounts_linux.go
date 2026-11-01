//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// sessionMountArgs returns the bwrap --bind args for filesystem.mounts. They
// must follow --tmpfs /tmp and the allowWrite binds, which would otherwise
// hide them.
//
// The host side is checked here rather than in config.Validate because it
// depends on the machine: a source that is missing, not a directory, reached
// through a symlink, or owned by another user is refused, so a caller cannot
// hand the sandbox someone else's directory. A source overlapping a path the
// policy protects is refused too: greywall's protections apply at the host
// path, so the same files reached through the target would be unprotected.
func sessionMountArgs(fs config.FilesystemConfig, cwd string) ([]string, error) {
	if err := config.ValidateMounts(fs.Mounts); err != nil {
		return nil, err
	}
	if len(fs.Mounts) > 0 && cwd == "" {
		return nil, fmt.Errorf("filesystem.mounts cannot be checked: the working directory is unknown")
	}
	var args []string
	for _, mount := range fs.Mounts {
		if err := checkMountTargetAvoidsProject(mount.Target, cwd); err != nil {
			return nil, err
		}
		if err := checkMountSource(mount.Source); err != nil {
			return nil, err
		}
		if err := checkMountSourceAvoidsProtectedPaths(mount.Source, fs, cwd); err != nil {
			return nil, err
		}
		args = append(args, "--bind", mount.Source, mount.Target)
	}
	return args, nil
}

// checkMountTargetAvoidsProject refuses a target overlapping a project folder
// below /tmp, which the sandbox binds at the same path.
func checkMountTargetAvoidsProject(target, cwd string) error {
	project := resolvedPath(cwd)
	if isSameOrBelowPath(target, project) || isSameOrBelowPath(project, target) {
		return fmt.Errorf("filesystem.mounts target %q overlaps the project folder %q", target, project)
	}
	return nil
}

func checkMountSourceAvoidsProtectedPaths(source string, fs config.FilesystemConfig, cwd string) error {
	if home, err := os.UserHomeDir(); err == nil {
		home = resolvedPath(home)
		if isSameOrBelowPath(home, source) {
			return fmt.Errorf("filesystem.mounts source %q is or contains the home folder %q", source, home)
		}
	}
	project := resolvedPath(cwd)
	if isSameOrBelowPath(source, project) || isSameOrBelowPath(project, source) {
		return fmt.Errorf("filesystem.mounts source %q overlaps the project folder %q", source, project)
	}
	protectedDirs := SensitiveGreyproxyDirs()
	if configDir, err := os.UserConfigDir(); err == nil {
		protectedDirs = append(protectedDirs, filepath.Join(configDir, "greywall"))
	}
	for _, dir := range protectedDirs {
		dir = resolvedPath(dir)
		if isSameOrBelowPath(source, dir) || isSameOrBelowPath(dir, source) {
			return fmt.Errorf("filesystem.mounts source %q overlaps greywall's protected folder %q", source, dir)
		}
	}
	for _, pattern := range append(slices.Clone(fs.DenyRead), fs.DenyWrite...) {
		if denyPatternOverlaps(source, pattern) {
			return fmt.Errorf("filesystem.mounts source %q overlaps the deny entry %q", source, pattern)
		}
	}
	return nil
}

// denyPatternOverlaps reports whether source is, contains or sits inside a
// path a denyRead/denyWrite entry protects. For a glob, source must not
// contain the glob's fixed leading folder (future matches appear there) nor
// lie inside a match.
func denyPatternOverlaps(source, pattern string) bool {
	normalized := NormalizePath(pattern)
	if !filepath.IsAbs(normalized) {
		return false
	}
	if !ContainsGlobChars(normalized) {
		protected := resolvedPath(normalized)
		return isSameOrBelowPath(source, protected) || isSameOrBelowPath(protected, source)
	}
	// The source has no symlinks, so the glob's fixed folders must not either.
	fixedPrefix := globFixedPrefix(normalized)
	resolvedPrefix := resolvedPath(fixedPrefix)
	resolvedPattern := resolvedPrefix + strings.TrimPrefix(normalized, fixedPrefix)
	if isSameOrBelowPath(resolvedPrefix, source) {
		return true
	}
	for candidate := source; ; candidate = filepath.Dir(candidate) {
		if matched, _ := doublestar.Match(resolvedPattern, candidate); matched {
			return true
		}
		if candidate == "/" {
			return false
		}
	}
}

// globFixedPrefix returns the folders of pattern before its first glob element.
func globFixedPrefix(pattern string) string {
	elements := strings.Split(pattern, "/")
	for i, element := range elements {
		if ContainsGlobChars(element) {
			return "/" + filepath.Join(elements[:i]...)
		}
	}
	return pattern
}

func isSameOrBelowPath(path, ancestor string) bool {
	return path == ancestor || ancestor == "/" || strings.HasPrefix(path, ancestor+"/")
}

func checkMountSource(source string) error {
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		return fmt.Errorf("filesystem.mounts source %q: %w", source, err)
	}
	if resolved != source {
		return fmt.Errorf("filesystem.mounts source %q goes through a symlink (resolves to %q)", source, resolved)
	}
	info, err := os.Lstat(source) // #nosec G703 -- source passed ValidateMounts and resolves to itself (no symlinks); only its metadata is read
	if err != nil {
		return fmt.Errorf("filesystem.mounts source %q: %w", source, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("filesystem.mounts source %q is not a directory", source)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("filesystem.mounts source %q: cannot read its owner", source)
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("filesystem.mounts source %q is owned by uid %d, not the caller (uid %d)", source, stat.Uid, os.Getuid())
	}
	return nil
}

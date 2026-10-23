//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var errUntrustedSSHConfig = errors.New("system SSH configuration is not root-trusted")

// systemSSHConfigArgs copies public system drop-ins through bubblewrap-owned
// read-only data files. Root is unmapped in the sandbox; keeping original
// ownership makes OpenSSH reject includes as owned by nobody. Never copy a
// source whose original root ownership and non-writable path cannot be proved.
func systemSSHConfigArgs(directory string, denied []string) ([]string, string, error) {
	if info, err := os.Lstat(directory); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, "", nil // a symlink is not a valid bubblewrap mount destination
	}
	if _, err := trustedSSHConfigPath(directory); err != nil {
		if errors.Is(err, errUntrustedSSHConfig) || errors.Is(err, os.ErrNotExist) {
			return nil, "", nil // leave originals subject to OpenSSH's own checks
		}
		return nil, "", err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, "", err
	}
	if len(entries) == 0 {
		return nil, "", nil
	}
	args := []string{"--tmpfs", directory}
	var redirections strings.Builder
	for i, entry := range entries {
		destination := filepath.Join(directory, entry.Name())
		source, err := trustedSSHConfigPath(destination)
		if errors.Is(err, errUntrustedSSHConfig) {
			return nil, "", nil
		}
		if err != nil {
			return nil, "", err
		}
		info, err := os.Stat(source)
		if err != nil {
			return nil, "", err
		}
		// shortcut: normalize flat, public drop-in directories only; preserve
		// the original tree for private files or nested layouts.
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o004 == 0 {
			return nil, "", nil
		}
		hidden := false
		for _, path := range denied {
			if isSameOrUnder(destination, path) || isSameOrUnder(source, NormalizePath(path)) {
				hidden = true
				break
			}
		}
		if hidden {
			// Copies are independent inodes: masking the original source alone
			// would leave its contents exposed through this compatibility copy.
			args = append(args, "--ro-bind", "/dev/null", destination)
			continue
		}
		fd := strconv.Itoa(i + 4) // fd 3 is reserved for the seccomp filter
		fmt.Fprintf(&redirections, "exec %s<%s || exit 1; ", fd, ShellQuoteSingle(source))
		args = append(args, "--perms", "0644", "--ro-bind-data", fd, destination)
	}
	args = append(args, "--remount-ro", directory)
	return args, redirections.String(), nil
}

// Verify every directory and symlink in the source chain, not just the final
// file: a root-owned file behind a user-replaceable link is not trusted.
func trustedSSHConfigPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errUntrustedSSHConfig
	}
	root, err := os.Lstat("/")
	if err != nil {
		return "", err
	}
	rootStat, ok := root.Sys().(*syscall.Stat_t)
	if !ok || !isRootTrustedSSHEntry(rootStat.Uid, root.Mode()) {
		return "", errUntrustedSSHConfig
	}
	for hops := 0; hops < 40; hops++ {
		parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
		current := "/"
		followed := false
		for _, part := range parts {
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if err != nil {
				return "", err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !isRootTrustedSSHEntry(stat.Uid, info.Mode()) {
				return "", errUntrustedSSHConfig
			}
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(current)
				if err != nil {
					return "", err
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(current), target)
				}
				remainder, err := filepath.Rel(current, filepath.Clean(path))
				if err != nil {
					return "", err
				}
				path = filepath.Join(target, remainder)
				followed = true
				break
			}
		}
		if !followed {
			return filepath.Clean(path), nil
		}
	}
	return "", fmt.Errorf("too many symlinks in system SSH configuration")
}

func isRootTrustedSSHEntry(uid uint32, mode os.FileMode) bool {
	return uid == 0 && (mode&os.ModeSymlink != 0 || mode.Perm()&0o022 == 0)
}

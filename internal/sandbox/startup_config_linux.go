//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/GreyhavenHQ/greywall/internal/config"
	"golang.org/x/sys/unix"
)

// startupConfigProtectionArgs reserves project-local startup paths before
// sandboxing. Placeholders persist on the host; existing contents are preserved.
func startupConfigProtectionArgs(cfg *config.Config, cwd string) ([]string, []string, error) {
	root, err := unix.Open(cwd, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = unix.Close(root) }()
	var parents, readOnly []string
	for _, name := range []string{".opencode", ".zed", ".cursor", ".devcontainer"} {
		fd, err := prepareStartupDirectory(root, name)
		if err != nil {
			return nil, nil, fmt.Errorf("protect startup directory %s: %w", name, err)
		}
		_ = unix.Close(fd)
		path := filepath.Join(cwd, name)
		readOnly = append(readOnly, "--ro-bind", path, path)
	}
	for _, file := range []struct{ name, initial string }{
		{".envrc", ""}, {"opencode.json", "{}\n"}, {"opencode.jsonc", "{}\n"},
	} {
		if err := prepareStartupFile(root, file.name, file.initial); err != nil {
			return nil, nil, fmt.Errorf("protect startup file %s: %w", file.name, err)
		}
		path := filepath.Join(cwd, file.name)
		readOnly = append(readOnly, "--ro-bind", path, path)
	}
	claude, err := prepareStartupDirectory(root, ".claude")
	if err != nil {
		return nil, nil, fmt.Errorf("protect .claude: %w", err)
	}
	defer func() { _ = unix.Close(claude) }()
	parent := filepath.Join(cwd, ".claude")
	flag := "--ro-bind"
	if cfg != nil && cfg.Filesystem.IsDefaultDenyRead() {
		flag = "--bind"
	}
	writeArgs := writableBindArgs(cfg)
	for i := 0; i+2 < len(writeArgs); i += 3 {
		if isSameOrUnder(parent, writeArgs[i+2]) {
			flag = "--bind"
		}
	}
	// Pin the parent so its protected files cannot be replaced by renaming it.
	parents = append(parents, flag, parent, parent)
	for i := 0; i+2 < len(writeArgs); i += 3 {
		if isSameOrUnder(writeArgs[i+2], parent) {
			parents = append(parents, writeArgs[i:i+3]...)
		}
	}
	for _, name := range []string{"settings.json", "settings.local.json"} {
		if err := prepareStartupFile(claude, name, "{}\n"); err != nil {
			return nil, nil, fmt.Errorf("protect .claude/%s: %w", name, err)
		}
		path := filepath.Join(parent, name)
		readOnly = append(readOnly, "--ro-bind", path, path)
	}
	return parents, readOnly, nil
}

// Parent mounts must precede every protected leaf, across both Git and startup
// configuration. Within each phase, bind ancestors before their descendants.
func orderedProtectionArgs(parents, readOnly []string) []string {
	var args []string
	for _, phase := range [][]string{parents, readOnly} {
		var mounts [][]string
		for i := 0; i+2 < len(phase); i += 3 {
			mounts = append(mounts, phase[i:i+3])
		}
		sort.SliceStable(mounts, func(i, j int) bool { return len(mounts[i][2]) < len(mounts[j][2]) })
		for _, mount := range mounts {
			args = append(args, mount...)
		}
	}
	return args
}

func prepareStartupDirectory(parent int, name string) (int, error) {
	if err := unix.Mkdirat(parent, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	// Do not follow links when preparing host files, including parent folders.
	return unix.Openat(parent, name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func prepareStartupFile(parent int, name, initial string) error {
	fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(parent, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(fd) }()
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("startup configuration must be a regular file")
		}
		return nil
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	written, writeErr := file.WriteString(initial)
	if writeErr == nil && written != len(initial) {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, file.Close())
}

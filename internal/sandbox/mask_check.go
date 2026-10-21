package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// MaskedPathsEnvVar carries the MaskedPaths of a sandbox, as JSON, from the
// greywall that builds it to the wrapper that runs inside it.
const MaskedPathsEnvVar = "GREYWALL_MASKED_PATHS"

// maxMaskedDirEntries bounds how much of a masked directory VerifyMasks reads.
// A working mask is an empty tmpfs, so only a broken one gets anywhere near it.
const maxMaskedDirEntries = 10000

// MaskedPaths lists what the bwrap command hides, so the sandbox can check
// from inside that the masks really took effect.
type MaskedPaths struct {
	// Files are masked with /dev/null or an empty file.
	Files []string `json:"files,omitempty"`
	// Dirs are masked with an empty tmpfs.
	Dirs []string `json:"dirs,omitempty"`
	// Exceptions are bound back inside a masked dir on purpose (greyproxy's
	// public ca-cert.pem).
	Exceptions []string `json:"exceptions,omitempty"`
	// Future are denyRead paths that did not exist at start, as literal paths
	// or with a glob in their last element. bwrap cannot mask them; Landlock
	// keeps them unreadable if they appear later in a read-only area.
	Future []string `json:"future,omitempty"`
}

// MaskedPathsFromEnv reads the MaskedPaths greywall passed to the wrapper.
// It returns no paths when the variable is unset.
func MaskedPathsFromEnv() (MaskedPaths, error) {
	var masked MaskedPaths
	encoded := os.Getenv(MaskedPathsEnvVar)
	if encoded == "" {
		return masked, nil
	}
	if err := json.Unmarshal([]byte(encoded), &masked); err != nil {
		return masked, fmt.Errorf("parse %s: %w", MaskedPathsEnvVar, err)
	}
	return masked, nil
}

// maskedPathsFromArgs reads the masks out of bwrap mount arguments built by
// the mask helpers (denyReadMaskArgs, sensitiveProjectFileArgs,
// greyproxyDenyReadArgs).
func maskedPathsFromArgs(args []string) MaskedPaths {
	emptyFile := filepath.Join(os.TempDir(), "greywall", "empty")
	var masked MaskedPaths
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--tmpfs":
			if i+1 < len(args) {
				masked.Dirs = append(masked.Dirs, args[i+1])
				i++
			}
		case "--ro-bind":
			if i+2 < len(args) {
				source, destination := args[i+1], args[i+2]
				switch source {
				case "/dev/null", emptyFile:
					masked.Files = append(masked.Files, destination)
				case destination:
					masked.Exceptions = append(masked.Exceptions, destination)
				}
				i += 2
			}
		}
	}
	return masked
}

// VerifyMasks fails when a masked path still shows content: a masked file
// that is not empty, or a non-empty file under a masked directory other than
// the exceptions. bubblewrap's last mount wins, so a later bind of the path or
// of a parent silently undoes a mask; this check catches that at start-up.
// A path that cannot be opened counts as hidden.
func VerifyMasks(masked MaskedPaths) error {
	for _, path := range masked.Files {
		if hasContent(path) {
			return fmt.Errorf("%s is masked but readable inside the sandbox", path)
		}
	}
	for _, dir := range masked.Dirs {
		if err := verifyMaskedDir(dir, masked.Exceptions); err != nil {
			return err
		}
	}
	return nil
}

func verifyMaskedDir(dir string, exceptions []string) error {
	entriesSeen := 0
	errFound := errors.New("found")
	var readablePath string
	walkErr := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable entry is a hidden entry
		}
		entriesSeen++
		if entriesSeen > maxMaskedDirEntries {
			readablePath = dir
			return errFound
		}
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || slices.Contains(exceptions, path) {
			return nil
		}
		if hasContent(path) {
			readablePath = path
			return errFound
		}
		return nil
	})
	if errors.Is(walkErr, errFound) {
		return fmt.Errorf("%s is under the masked directory %s but readable inside the sandbox", readablePath, dir)
	}
	return nil
}

// hasContent reports whether reading path yields at least one byte.
func hasContent(path string) bool {
	// O_NONBLOCK: a FIFO in a broken mask must not hang the check.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // paths come from greywall's own masks
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	buffer := make([]byte, 1)
	readCount, err := file.Read(buffer)
	return readCount > 0 && (err == nil || errors.Is(err, io.EOF))
}

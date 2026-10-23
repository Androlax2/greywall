//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GreyhavenHQ/greywall/internal/config"
)

// gitProtectionArgs pins repository metadata directories against rename and
// makes config, hooks and worktree pointers read-only. Git's index, refs and
// object database remain writable. Missing hooks directories are deliberately
// created on the host so future hooks cannot appear behind an absent mount.
func gitProtectionArgs(cfg *config.Config, cwd string) ([]string, []string, error) {
	writable := make(map[string]bool)
	if cfg != nil && cfg.Filesystem.IsDefaultDenyRead() {
		writable[cwd] = true
	}
	writeArgs := writableBindArgs(cfg)
	for i := 0; i+2 < len(writeArgs); i += 3 {
		writable[writeArgs[i+2]] = true
	}
	visible := func(path string) bool {
		if cfg == nil || !cfg.Filesystem.IsDefaultDenyRead() || isSameOrUnder(path, cwd) {
			return true
		}
		for grant := range writable {
			if isSameOrUnder(path, grant) {
				return true
			}
		}
		for _, grant := range ExpandGlobPatterns(cfg.Filesystem.AllowRead) {
			if isSameOrUnder(path, grant) {
				return true
			}
		}
		return false
	}
	root := cwd
	for {
		_, err := os.Lstat(filepath.Join(root, ".git"))
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("inspect Git metadata: %w", err)
		}
		parent := filepath.Dir(root)
		if parent == root {
			return nil, nil, nil
		}
		root = parent
	}
	var anchors, protected []string
	readOnlyRepository := isWriteDenied(cfg, root)
	pinParents := func(path string) {
		for grant := range writable {
			if isSameOrUnder(path, grant) {
				anchors = append(anchors, grant)
				if parent := filepath.Dir(path); isSameOrUnder(parent, grant) {
					anchors = append(anchors, intermediaryDirs(grant, parent)...)
				}
			}
		}
	}
	protect := func(path string) error {
		actual, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		if actual != filepath.Clean(path) {
			if err := checkGitSymlinkChain(path, writable, false); err != nil {
				return err
			}
			for grant := range writable {
				if isSameOrUnder(path, grant) || isSameOrUnder(actual, grant) {
					return fmt.Errorf("refusing replaceable symlinked Git metadata: %s", path)
				}
			}
			// Host-managed global includes may be symlinks in read-only areas.
			// Neither their link nor target is writable by this sandbox.
			path = actual
		}
		protected = append(protected, path)
		pinParents(path)
		return nil
	}
	seen := make(map[string]bool)
	seenWorktrees := make(map[string]bool)
	var repositories func(string, string) error
	repositories = func(worktree, gitDir string) error {
		if worktree != "" {
			actual, err := filepath.EvalSymlinks(worktree)
			if err != nil {
				return err
			}
			if seenWorktrees[actual] {
				return nil
			}
			seenWorktrees[actual] = true
		}
		resolved, err := filepath.EvalSymlinks(gitDir)
		if err != nil {
			return err
		}
		if resolved != filepath.Clean(gitDir) {
			return fmt.Errorf("refusing symlink in Git directory pointer target: %s", gitDir)
		}
		alreadySeen := seen[resolved]
		if alreadySeen && worktree == "" {
			return nil
		}
		seen[resolved] = true
		anchors = append(anchors, resolved)
		readOnly := readOnlyRepository || isWriteDenied(cfg, resolved) || (worktree != "" && isWriteDenied(cfg, worktree))
		if readOnly {
			protected = append(protected, resolved)
		}
		if !readOnly {
			// A missing commondir is equivalent to this directory. Reserve that
			// meaning so the sandbox cannot introduce a different common config.
			commonPointer, err := os.OpenFile(filepath.Join(resolved, "commondir"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G703 -- fixed metadata name in the canonical Git directory; exclusive creation preserves existing data
			if err == nil {
				_, writeErr := commonPointer.WriteString(".\n")
				closeErr := commonPointer.Close()
				if err := errors.Join(writeErr, closeErr); err != nil {
					return err
				}
			} else if !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("prepare Git common directory pointer: %w", err)
			}
			// A repository may already enable extensions.worktreeConfig while the
			// per-worktree file is still absent. Reserve it before sandbox startup.
			placeholder, err := os.OpenFile(filepath.Join(resolved, "config.worktree"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G703 -- linked-worktree metadata may be external; exclusive creation preserves existing config
			if err == nil {
				if err := placeholder.Close(); err != nil {
					return err
				}
			} else if !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("prepare Git worktree config: %w", err)
			}
		}
		for _, name := range []string{"config", "config.worktree", "commondir", "gitdir"} {
			path := filepath.Join(resolved, name)
			if _, err := os.Lstat(path); err == nil { // #nosec G703 -- inspects fixed metadata names without following symlinks before protecting them
				if err := protect(path); err != nil {
					return err
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		hooks := filepath.Join(resolved, "hooks")
		if !readOnly {
			if err := os.MkdirAll(hooks, 0o700); err != nil { // #nosec G703 -- reserves the canonical Git directory's hooks path before the sandbox can create it
				return fmt.Errorf("prepare Git hooks directory: %w", err)
			}
		}
		if _, err := os.Lstat(hooks); err == nil { // #nosec G703 -- fixed hooks name in the canonical metadata directory; does not follow symlinks
			if err := protect(hooks); err != nil {
				return err
			}
		} else if !readOnly || !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if worktree != "" {
			if visible(worktree) {
				anchors = append(anchors, worktree)
			}
			marker := filepath.Join(worktree, ".git")
			if info, err := os.Lstat(marker); err == nil && !info.IsDir() { // #nosec G703 -- inspects the registered worktree's .git marker without following symlinks
				if err := protect(marker); err != nil {
					return err
				}
			}
			if fileExists(filepath.Join(worktree, ".gitmodules")) {
				protected = append(protected, filepath.Join(worktree, ".gitmodules"))
			}
			command := exec.Command("git", "--git-dir="+resolved, "--work-tree="+worktree, "config", "--null", "--path", "--get", "core.hooksPath") //nolint:gosec // reads repository configuration, no hook execution
			command.Dir = worktree
			output, err := command.Output()
			if err == nil {
				custom := strings.TrimSuffix(string(output), "\x00")
				if !filepath.IsAbs(custom) {
					custom = filepath.Join(worktree, custom)
				}
				// /dev/null is Git's conventional way to disable hooks.
				if custom != "/dev/null" {
					if err := checkGitSymlinkChain(custom, writable, true); err != nil {
						return fmt.Errorf("validate core.hooksPath: %w", err)
					}
					if !readOnly && !isWriteDenied(cfg, custom) {
						if err := os.MkdirAll(custom, 0o700); err != nil { // #nosec G703 -- validates existing ancestors before reserving the configured external hooks path
							return fmt.Errorf("prepare core.hooksPath: %w", err)
						}
					}
					isHooksParentReadOnly := (readOnlyRepository && isSameOrUnder(custom, root)) || (readOnly && isSameOrUnder(custom, resolved))
					if _, err := os.Lstat(custom); err == nil { // #nosec G703 -- configured hooks path was validated above; inspect without following symlinks
						if err := protect(custom); err != nil {
							return err
						}
					} else if !errors.Is(err, os.ErrNotExist) {
						return err
					} else if !isHooksParentReadOnly {
						return fmt.Errorf("cannot protect missing external core.hooksPath without host writes: %s", custom)
					}
				}
			} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
				return fmt.Errorf("read core.hooksPath: %w", err)
			}
			// Include directives can later redirect hooks or fsmonitor without
			// touching the primary config. Protect even inactive includeIf files.
			command = exec.Command("git", "--git-dir="+resolved, "--work-tree="+worktree, "config", "--includes", "--null", "--show-origin", "--path", "--get-regexp", `^(include\.path|includeif\..*\.path)$`) //nolint:gosec // configuration inspection only
			command.Dir = worktree
			output, err = command.Output()
			if err != nil {
				if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
					return fmt.Errorf("read Git config includes: %w", err)
				}
			}
			records := strings.Split(string(output), "\x00")
			for i := 0; i+1 < len(records); i += 2 {
				origin, ok := strings.CutPrefix(records[i], "file:")
				key, include, hasValue := strings.Cut(records[i+1], "\n")
				if !ok || !hasValue {
					return fmt.Errorf("cannot protect non-file Git config include")
				}
				if strings.HasPrefix(strings.ToLower(key), "includeif.") {
					return fmt.Errorf("conditional Git config includes are not supported by sandbox metadata protection")
				}
				if !filepath.IsAbs(origin) {
					origin = filepath.Join(worktree, origin)
				}
				if !filepath.IsAbs(include) {
					include = filepath.Join(filepath.Dir(origin), include)
				}
				include = filepath.Clean(include)
				if !fileExists(include) {
					return fmt.Errorf("missing Git config include %s; create it before starting the sandbox", include)
				}
				if err := protect(include); err != nil {
					return err
				}
			}
		}
		if alreadySeen && (worktree == "" || !fileExists(filepath.Join(worktree, ".gitmodules"))) {
			return nil
		}
		if worktree == "" {
			backref := filepath.Join(resolved, "gitdir")
			if contents, err := os.ReadFile(backref); err == nil { //nolint:gosec // registered worktree metadata
				marker := strings.TrimSpace(string(contents))
				if !filepath.IsAbs(marker) {
					marker = filepath.Join(resolved, marker)
				}
				if fileExists(marker) {
					if err := repositories(filepath.Dir(marker), resolved); err != nil {
						return err
					}
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if contents, err := os.ReadFile(filepath.Join(resolved, "commondir")); err == nil { //nolint:gosec // repository metadata
			common := strings.TrimSpace(string(contents))
			if !filepath.IsAbs(common) {
				common = filepath.Join(resolved, common)
			}
			if err := repositories("", common); err != nil {
				return err
			}
			common = filepath.Clean(common)
			mainGitDir := common
			for filepath.Base(mainGitDir) != ".git" && filepath.Dir(mainGitDir) != mainGitDir {
				mainGitDir = filepath.Dir(mainGitDir)
			}
			if filepath.Base(mainGitDir) != ".git" {
				// A separate common directory need not record its main worktree.
				// Do not silently leave that worktree's pointers/hooks writable.
				return fmt.Errorf("cannot protect Git main worktree for separate common directory %s", common)
			}
			if err := repositories(filepath.Dir(mainGitDir), mainGitDir); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, tree := range []string{"modules", "worktrees"} {
			base := filepath.Join(resolved, tree)
			if !fileExists(base) {
				continue
			}
			// #nosec G703 -- walks fixed Git metadata subtrees; WalkDir does not follow directory symlinks
			if err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !entry.IsDir() {
					return nil
				}
				anchors = append(anchors, path)
				if path != base && fileExists(filepath.Join(path, "HEAD")) {
					if err := repositories("", path); err != nil {
						return err
					}
					return filepath.SkipDir
				}
				return nil
			}); err != nil {
				return err
			}
		}
		if worktree != "" && fileExists(filepath.Join(worktree, ".gitmodules")) {
			command := exec.Command("git", "config", "--file", filepath.Join(worktree, ".gitmodules"), "--null", "--get-regexp", `^submodule\..*\.path$`) //nolint:gosec // reads registered submodule paths only
			output, err := command.Output()
			if err != nil {
				if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
					return fmt.Errorf("read submodule paths: %w", err)
				}
			}
			for _, record := range strings.Split(string(output), "\x00") {
				_, relative, ok := strings.Cut(record, "\n")
				if !ok {
					continue
				}
				sub := filepath.Join(worktree, relative)
				if filepath.IsAbs(relative) || !isSameOrUnder(sub, worktree) || sub == worktree {
					return fmt.Errorf("invalid submodule path %q", relative)
				}
				marker := filepath.Join(sub, ".git")
				info, err := os.Lstat(marker) // #nosec G703 -- the submodule path was checked above to stay within its worktree
				if errors.Is(err, os.ErrNotExist) {
					continue // uninitialized submodule
				}
				if err != nil {
					return err
				}
				target := marker
				if !info.IsDir() {
					target, err = readGitDirPointer(marker)
					if err != nil {
						return err
					}
				}
				pinParents(sub)
				if err := repositories(sub, target); err != nil {
					return err
				}
			}
		}
		return nil
	}
	gitDir := filepath.Join(root, ".git")
	if info, err := os.Lstat(gitDir); err != nil {
		return nil, nil, err
	} else if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("refusing replaceable symlinked Git directory: %s", gitDir)
	} else if !info.IsDir() {
		gitDir, err = readGitDirPointer(gitDir)
		if err != nil {
			return nil, nil, err
		}
	}
	if err := repositories(root, gitDir); err != nil {
		return nil, nil, fmt.Errorf("protect Git metadata: %w", err)
	}
	// Pinning must not turn an ancestor of cwd or an external Git directory
	// into a new write grant. Reapply existing writable descendants after
	// read-only parent anchors, then protect the metadata leaves last.
	paths := make(map[string]string)
	for _, path := range anchors {
		paths[path] = "--ro-bind"
		for grant := range writable {
			if isSameOrUnder(path, grant) {
				paths[path] = "--bind"
			}
		}
	}
	for grant := range writable {
		for _, anchor := range anchors {
			if isSameOrUnder(grant, anchor) {
				paths[grant] = "--bind"
			}
		}
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return len(ordered[i]) < len(ordered[j])
	})
	var parents, readOnly []string
	for _, path := range ordered {
		parents = append(parents, paths[path], path, path)
	}
	for _, path := range protected {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, nil, err
		}
		readOnly = append(readOnly, "--ro-bind", resolved, resolved)
	}
	return parents, readOnly, nil
}

func readGitDirPointer(path string) (string, error) {
	info, err := os.Lstat(path) // #nosec G703 -- inspects a registered .git pointer without following symlinks
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return "", fmt.Errorf("invalid Git directory pointer: expected a small regular file: %s", path)
	}
	contents, err := os.ReadFile(path) //nolint:gosec // repository metadata
	if err != nil {
		return "", err
	}
	value, ok := strings.CutPrefix(strings.TrimSpace(string(contents)), "gitdir: ")
	if !ok || value == "" {
		return "", fmt.Errorf("invalid Git directory pointer %s", path)
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(filepath.Dir(path), value)
	}
	return filepath.Clean(value), nil
}

// Host-managed Git paths may contain symlinks only outside writable areas.
// New hooks paths may have missing suffixes; existing metadata must fail closed.
func checkGitSymlinkChain(path string, writable map[string]bool, allowMissingSuffix bool) error {
	for hops := 0; hops < 40; hops++ {
		parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
		current := "/"
		followed := false
		for i, part := range parts {
			current = filepath.Join(current, part)
			info, err := os.Lstat(current) // #nosec G703 -- inspects each Git config path component to reject replaceable symlinks
			if allowMissingSuffix && errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			for grant := range writable {
				if isSameOrUnder(current, grant) {
					return fmt.Errorf("refusing replaceable symlink in Git config chain: %s", current)
				}
			}
			target, err := os.Readlink(current)
			if err != nil {
				return err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(current), target)
			}
			path = filepath.Join(target, filepath.Join(parts[i+1:]...))
			followed = true
			break
		}
		if !followed {
			return nil
		}
	}
	return fmt.Errorf("too many symlinks in Git config chain")
}

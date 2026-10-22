# greywall security audit, 2026-10-22

Fork Androlax2/greywall, branch `dotfiles` at `e639a75` (v0.3.7 + #103, #112, the `.env` fix, proxy client secret, start-up mask check, Landlock carve-out, missing deny paths, `GREYPROXY_DATA_HOME`). Todo afe45d8a.

## Scope and method

- **Threat model:** an AI agent inside the sandbox follows malicious instructions (prompt injection). It tries to read secrets it was not granted, plant something the host runs later (with Theo's full rights), reach the network outside greyproxy's policy, or escape.
- **Machine:** single user, Arch Linux, kernel 7.2.11, rootless. Severity is judged for that machine.
- **Method:** code review only, in four areas (filesystem, network, config and trust inputs, processes and syscalls), each finding re-checked against `e639a75`. Nothing was run against a live sandbox; kernel and bubblewrap behaviour that was not tested is marked "suspected".
- **Out of scope:** macOS (`macos.go`), greyproxy itself (separate fork), the agent-cockpit launcher and its per-project config (it overrides the built-in profiles; findings H4 and H5 depend on what it grants).

## Summary

The bind-mount layer, the new start-up mask check and Landlock carve-out hold for what they cover. The biggest remaining gaps are wholesale grants that were never narrowed: the host's whole `/dev`, the whole of `~/.config`, `~/.local` and `~/.cache` readable, writable agent and tool config that the host executes later, and learning/watch modes that make all of home writable. Several protections also switch themselves off with a message shown only under `--debug`.

| # | Severity | Finding |
|---|---|---|
| H1 | High | The host's whole `/dev` is bound into the sandbox, other terminals included |
| H2 | High | Learning and watch modes: home writable, no denies, the generated profile auto-loads |
| H3 | High | `.git` protection can be bypassed (worktrees, submodules, missing hooks dir, renaming `.git`) |
| H4 | High | Symlinks planted in writable areas redirect the next run's allow paths |
| H5 | High | Built-in profiles grant write access to config the host executes later |
| H6 | High | No network namespace: the sandbox silently gets the host network |
| M1 | Medium | Seccomp: no architecture check, no block on user namespaces, new mount API or io_uring; CAP_NET_ADMIN reaches the agent |
| M2 | Medium | Inbound port bridge (`-p`) listens on all interfaces and can be pointed at any host socket |
| M3 | Medium | Deny-by-default still exposes all of `~/.config`, `~/.local`, `~/.cache` read-only |
| M4 | Medium | Legacy, learning and watch modes expose the host's `/run` sockets |
| M5 | Medium | greyproxy API reachable with `-f 43080`; allow-all bleeds to other sessions with the same name |
| M6 | Medium | The keyring `GH_TOKEN` is added after placeholder substitution: the real token is in the sandbox |
| M7 | Medium | A `.env` symlink makes the host read any file and mount it into the next sandbox |
| M8 | Medium | Seccomp, Landlock and the network namespace fail open with debug-only messages |
| M9 | Medium | Host SysV IPC, UTS and cgroup namespaces are shared |
| L1-L5 | Low | See "Low" |

## High

### H1. The host's whole `/dev` is bound into the sandbox

- **Where:** `internal/sandbox/linux.go:1305` (`--dev-bind /dev /dev`, every mode); Landlock then grants `/dev` read-write with `IOCTL_DEV` (`linux_landlock.go`, the `/dev` rule).
- **Path:** the agent opens `/dev/pts/N` of Theo's other terminals (same uid, mode 0620) and reads them: keystrokes, including passwords typed in an `ask-to-run` terminal. It can write escape sequences into them. `/dev/shm` and `/dev/mqueue` are the host's (Chromium, PipeWire segments). Devices with uaccess ACLs for the desktop user (`/dev/video*`, `/dev/snd/*`, `/dev/hidraw*`, `/dev/dri`) are open, bypassing `allowAudio`. Verified: the bind. Suspected: the reads, from kernel semantics.
- **Fix:** `--dev /dev` (private devpts, shm and the standard nodes), plus `--dev-bind /dev/net/tun` (already done when tun2socks runs), `/dev/snd` only with `allowAudio`, others only when configured. Narrow the Landlock `/dev` rule to those nodes (Landlock accepts rules on single files). Keep `--dev-bind` only as a fallback for setuid bwrap.
- **Check after the fix:** inside a sandbox, `ls /dev/pts` shows only the sandbox's own pty.

### H2. Learning and watch modes give the agent all of home, and the result is trusted

- **Where:** `linux.go:1271` (`--bind home home`), mandatory denies skipped in both modes; strace log bound read-write; `learning.go` `isSensitivePath` covers only rc files, `.ssh`, `.gnupg`, `.env`; `cmd/greywall/main.go:852` "Next run will auto-load this profile".
- **Path:** during a learning or watch run the agent writes `~/.config/systemd/user/*.service`, `~/.config/autostart`, `~/.local/bin/*`, `~/.config/greywall/learned/<cmd>.json` (with `allowWrite: ["~"]`), or appends forged `openat(...)` lines to the strace log so the generated profile grants those paths. The next normal run loads it silently. Verified in code.
- **Fix:** keep the mandatory denies, `~/.config/greywall` read-only and the greyproxy mask in both modes; run strace outside bwrap or give it a descriptor the child cannot reopen; add persistence directories to `isSensitivePath`; write the profile as pending and require an explicit approve step. Document that neither mode is a security boundary.

### H3. `.git` protection can be bypassed

- **Where:** `getMandatoryDenyPaths` (`linux.go`) protects only `cwd/.git/config` and `cwd/.git/hooks`, and only if they exist.
- **Paths:** `cwd/.git` as a file (worktree, `gitdir:`): nothing protected; `.git/modules/*/config` and `/hooks` (git recurses into submodules, `core.fsmonitor` runs on the host's next `git status`); a missing `.git/hooks` can be created; `core.hooksPath` inside cwd (`.husky/`) stays writable. Suspected: `mv .git .git.old` then a new `.git/config`, since `.git` itself is not a mount point. Verified: the code gaps.
- **Fix:** bind `cwd/.git` onto itself before the read-only sub-binds so it becomes a mount point (rename fails with EBUSY); resolve a `.git` file's `gitdir`/`commondir` and protect those; cover `modules/**/{config,hooks}` and `worktrees/*/config*`; read `core.hooksPath` on the host and bind it read-only; mount a read-only empty dir where `hooks` is missing. Add `.claude/settings*.json`, `.envrc`, `opencode.json`, `.opencode/`, `.zed/`, `.cursor/`, `.devcontainer/` to the protected list.
- **Check after the fix:** inside a sandbox, `mv .git .git.old` fails.

### H4. Symlinks planted in writable areas redirect the next run's allow paths

- **Where:** `NormalizePath` (`utils.go`) and `addPathRule` (`linux_landlock.go`) resolve symlinks; the claude profile makes `~/.claude` writable and puts `~/.claude/agents` and `~/.claude/skills` in `allowRead` (`profiles/base.go`, `agents/claude.go`).
- **Path:** `rm -rf ~/.claude/skills && ln -s ~/.aws ~/.claude/skills`. Next run, `~/.claude/skills` resolves to `~/.aws`, which is bound read-only and granted by Landlock. The same turns an allowWrite under a writable root into write access anywhere. Verified in code.
- **Fix:** resolve configured paths without following symlinks (`openat2` with `RESOLVE_NO_SYMLINKS`, or `Lstat` each component); refuse loudly when a configured path is a symlink or lies under another writable grant.

### H5. Built-in profiles grant write access to config the host executes later

- **Where:** `profiles/base.go` (`~/.agents`, `~/.skills`, `~/AGENTS.md`, `~/.config/gh`), `agents/claude.go` (`~/.claude`, `~/.claude.json`, `~/.mcp.json`), `agents/opencode.go` (`~/.config/opencode`), toolchain profiles (`~/.npmrc`, `~/.cargo`, `~/go`, `~/.nvm`, `~/.cache/pre-commit`, ...).
- **Path:** hooks in `~/.claude/settings.json`, `mcpServers` in `~/.claude.json`, opencode plugins and gh `!` aliases run in the next session or the next host command; `~/.agents` is imported into every session's instructions; a replaced `~/.cargo/bin/cargo` runs on the host. Verified: the grants. The agent-cockpit launcher's own config decides what is actually granted on this machine; cockpit plan 97b8d107 covers `~/.claude`.
- **Fix:** split grants into state (writable) and executables/config (read-only), and add a mandatory read-only list applied after the writable binds: `~/.claude/settings*.json`, `~/.claude.json` (or its `mcpServers`, via the launcher), `~/.config/opencode/plugin`, `~/.config/gh/config.yml`, `~/.npmrc`, `*/bin` of toolchains, `~/.agents`, `~/.skills`, `~/AGENTS.md`.

### H6. No network namespace: the sandbox silently gets the host network

- **Where:** `linux.go:1227-1231` drops `--unshare-net` when the probe fails, with a message only under `--debug`; tun2socks is skipped and the proxy becomes env vars only.
- **Path:** anything ignoring `HTTP_PROXY` reaches the internet, the LAN and every service on the host's loopback (including greyproxy's API), and abstract Unix sockets. Suspected: an agent in another sandbox can exhaust `user.max_net_namespaces` (seccomp does not block `unshare`) so the next sandbox's probe fails. Verified: the fallback.
- **Fix:** fail closed when a proxy is configured and the namespace is unavailable, with one named opt-out (`--allow-host-network`); always print the reason.

## Medium

- **M1. Seccomp gaps.** `linux_seccomp.go` never checks `seccomp_data.arch`, so i386 syscalls via `int 0x80` and x32 numbers bypass the denylist. TIOCSTI is not exploitable here: `dev.tty.legacy_tiocsti` is 0 on this kernel (checked), but the gap applies to every other blocked syscall. `unshare`/`clone(CLONE_NEWUSER)`, `setns`, `fsopen`/`open_tree`/`move_mount`, `io_uring_*` are allowed, and bwrap puts `CAP_NET_ADMIN` in the agent's ambient set (`linux.go:1434`), which opens nf_tables/tc to it (kernel privilege-escalation surface). Fix: arch check killing on mismatch and `nr >= 0x40000000`; block those syscalls (ENOSYS for `clone3`); `--unshare-user --disable-userns`; clear ambient capabilities in `runLandlockWrapper` before exec.
- **M2. Inbound port bridge (`-p`).** `linux.go:269` `TCP-LISTEN:%d,fork,reuseaddr` without `bind=`, so the host listens on all interfaces; its `UNIX-CONNECT` target lives in a directory the sandbox can write, so the agent can replace the socket with a symlink to `/run/docker.sock` or the user bus. Fix: `bind=127.0.0.1`; host-owned listening socket (swap roles) or a read-only directory; refuse symlinks.
- **M3. Wholesale home reads in deny-by-default.** `linux.go:1053` and the Landlock equivalent bind `~/.cache`, `~/.npm`, `~/.cargo`, `~/.rustup`, `~/.local`, `~/.config` read-only: `~/.config/gh/hosts.yml`, cloud credentials, keyrings in `~/.local/share/keyrings`, shell history, browser profiles. Fix: bind per-tool subpaths only, or at least ship default denyRead masks for known secret stores and histories.
- **M4. `/run` in other modes.** With `defaultDenyRead: false`, learning or watch, `--ro-bind / /` plus `dbusIsolationArgs` covers only `/run/user`; `/run/docker.sock`, `/run/podman`, the system bus stay connectable (suspected: bwrap binds recursively, despite the "non-recursive" comments). Fix: use `runIsolationArgs` in every mode.
- **M5. greyproxy API and name bleed.** `-f`/`forwardPorts` accept any port, so `-f 43080` gives the sandbox greyproxy's API directly, bypassing the own-listener block; the API token check is still off. Separately, allow-all from `--learning` and the match-all rule from `--watch` are registered under the client name, so a normal run with the same name (two `claude` sessions) inherits them. Fix: reject greyproxy's ports in forward ports; turn on `requireApiToken` (dotfiles step 4); tie session rules to the session's secret, or make names unique per run.
- **M6. Keyring token unprotected.** `cmd/greywall/main.go:772` appends `ResolveKeyringSecrets` after `SubstituteEnv` (line 657), so with the `gh` profile the real `GH_TOKEN` is in the sandbox. Fix: resolve keyring secrets before `DetectCredentials`.
- **M7. `.env` symlink.** `RewriteEnvFiles` follows symlinks: the agent creates `.env -> <any host file>`, the next run reads it on the host and mounts the rewritten copy into the sandbox; a FIFO hangs start-up. Fix: open with `O_NOFOLLOW`, require a regular file owned by the user, otherwise mask.
- **M8. Silent fail-open.** Seccomp generation failure (`linux.go`, seccomp block), Landlock failure (`ApplyLandlockFromConfig` returns nil, the wrapper ignores errors) and the missing network namespace (H6) only log under `--debug`. Fix: fail closed with one named opt-out (`--allow-degraded`), always warn.
- **M9. Shared IPC/UTS/cgroup.** No `--unshare-ipc`, `--unshare-uts`, `--unshare-cgroup-try`: host SysV shared memory (X11 MIT-SHM) is reachable. Fix: add them.

## Low

- **L1. Fixed paths in `/tmp`** (`/tmp/greywall/empty`, `/tmp/greywall-seccomp/...`, `/tmp/greywall/env-rewrite`) can be pre-created by another local user (not by the agent, whose `/tmp` is private). Fix: `MkdirTemp` under `$XDG_RUNTIME_DIR`, seccomp filter via a memfd, `/dev/null` as mask source. `CleanupFilter` is never called.
- **L2. Process lifetime.** No `Pdeathsig` on the sandbox or the socat bridges; the command is `exec 3<…; bwrap …` without `exec bwrap`; sandboxed processes share greywall's process group (suspected: `kill(0, SIGKILL)` reaches greywall and skips cleanup). Fix: `Pdeathsig`, `exec bwrap`.
- **L3. Proxy secret in arguments.** Since the per-run secret, the tun2socks URL with the secret is part of bwrap's arguments (`linux.go:1569`), visible in `ps` to the same user on the host. Fix: pass it by file or descriptor; strip userinfo from `GREYWALL_CONFIG_JSON`.
- **L4. Credential detection.** Detection is by variable name only (no `_KEY`, `_PAT`, `_PASS`, `_CREDENTIALS`, no `user:pass@` in URLs); registration failure leaves real values with a debug-only message.
- **L5. Bridge sockets** for proxy, DNS and D-Bus are created directly in `/tmp` (permissions depend on umask); multi-user machines only.

## Checked and fine

- No config is read from the project directory or parent directories; `extends` is never resolved.
- `GREYWALL_CONFIG_JSON` and `GREYWALL_MASKED_PATHS` are exported by greywall's inner script right before the wrapper; no agent code runs before Landlock.
- `/proc` is a fresh procfs in a new PID namespace; host processes are invisible.
- UDP and IPv6 fail closed through tun2socks; the DNS bridge has a fixed destination; the forward bridge cannot be redirected.
- The D-Bus proxy only allows `org.freedesktop.Notifications`.
- No secrets in git history (only a demo string in `examples/02-filesystem/demo.py`); four small direct dependencies (`govulncheck` not available in the sandbox).
- The command blocklist checks only the outer command: a convenience, not a boundary (document it).

## Suggested order

1. H1 (`--dev /dev`), H6 and M8 (fail closed): small, contained changes.
2. H3 and the protected-list additions; H4 (no-follow path resolution).
3. H2 (learning/watch), H5 together with cockpit plan 97b8d107.
4. M1 (seccomp), M2, M5 forward-port check, M6, M7.
5. M3 needs a decision on which home paths agents really read.

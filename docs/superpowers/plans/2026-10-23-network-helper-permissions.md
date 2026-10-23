# DNS and TUN helper permissions implementation plan

> **For agentic workers:** Use the executing-plans skill for inline implementation. Do not commit or deploy without separate authorization.

**Goal:** Restore DNS and transparent proxy startup without changing sandbox identity or exposing host devices.

**Architecture:** Keep bubblewrap's private devices and initial isolated network. After its final user-namespace transition, invoke resolved util-linux `unshare --net`, then `setpriv` to remove SYS_ADMIN before executing the setup shell. Start and verify network helpers in this correctly owned namespace; remove remaining ambient/inheritable capabilities before executing the user command.

**Tech stack:** Existing Go code, bubblewrap, util-linux (`unshare`, `setpriv`), iproute2 (`ip`, `ss`), socat, embedded tun2socks. No Go dependency changes.

**Spec:** Option A approved in this conversation. Host canary 51a7ef802a17 verified unchanged UID, private devices, successful TUN creation/DNS binding, no SYS_ADMIN in setup-shell permitted/effective/ambient sets, and zero permitted/effective/ambient capabilities after the final setpriv exec.

## Global constraints

- Preserve UID/GID mappings, private `/dev` and PTYs, mandatory network isolation, seccomp, Landlock and filesystem protections.
- SYS_ADMIN exists only for the direct namespace-creation executable, never the setup shell or user command.
- Missing tools, setup failures, dead helpers and readiness timeouts must prevent user-command startup with visible diagnostics.
- Do not change manifests, profiles, installed binaries, running sessions or existing untracked files.

## Review focus

- A capability bit alone is not proof the network namespace is owned by the final user namespace.
- DNS-only/fallback routing must not start against an unserved resolv.conf.
- Check actual listeners and TUN attachment, not just a fixed sleep or live process.
- Preserve user-command exit status and cleanup helpers on all startup failures.
- Keep learning/watch and library entry points working without a CLI-only helper.

## Task 1: Correct namespace ownership and verified startup

**Files:** Modify `internal/sandbox/linux.go`; add `internal/sandbox/network_helpers_linux_test.go`. Document new runtime tool requirements alongside existing Linux dependencies in `CLAUDE.md` and `README.md` if necessary.

**Interfaces:** Preserve `WrapCommandLinuxWithOptions` and callers unchanged. Use existing bridge types and feature detection; no public API additions.

- [x] Add runtime regressions through `WrapCommandLinuxWithOptions`: private devices/unchanged UID with working DNS relay and attached TUN; no setup capabilities reach the user command; failing network setup or helper exits never run the user command. Use local fixtures only, with bounded test deadlines.
- [x] Run new regressions against existing source on the host, demonstrating permission failures and fail-open startup before implementation.
- [x] Resolve required tools at command construction, add the namespace-local wrapper and capability transitions, and fail early if tools are absent.
- [x] Move cleanup registration before helper startup; check synchronous setup commands, keep helper stderr visible, and replace proxy startup's fixed delay with bounded listener/TUN-attachment checks.
- [x] Run targeted regressions, then `make test`, formatting and lint checks; report unavailable tools and all failures verbatim. Run namespace tests outside the enclosing sandbox using ask-to-run, not by weakening containment.
- [x] Review the diff for retained isolation, quote handling, exit status and cleanup; show diff stat. Mark todo e1fcfc71 done only after the fix is verified. Do not commit or deploy.

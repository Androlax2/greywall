# macOS Public CA Isolation Implementation Plan

> **For agentic workers:** Use the installed executing-plans skill after explicit plan confirmation. Do not delegate without separate authorization.

**Goal:** Make Greyproxy's public CA usable in a macOS sandbox without exposing private proxy state or allowing writes to the managed directory.

**Architecture:** Keep all existing managed-directory deny rules. On macOS, snapshot only validated public CA certificate data into a separate per-session directory, grant reads only to the snapshot, deny writes and moves to it, and point the existing CA environment variables there. Fail closed if an existing CA cannot be safely snapshotted. Prove the effective Seatbelt policy and TLS behavior in a real macOS sandbox; generated-profile assertions alone are insufficient.

**Tech Stack:** Go, macOS Seatbelt, Go standard-library TLS and X.509.

**Spec:** Androlax2/agent-cockpit#527 and todo `98078f11`; base commit `a9ccc58c4e57f7ad7aaf7c2ab3779d71cf485baf`.

## Global Constraints

- No live user services, global trust-store changes, installs, dependency or manifest changes, tags, releases, rollout, or pin updates.
- Preserve explicit user deny rules, managed-directory read and write denial, Linux behavior, and existing missing-CA behavior.
- Use temporary fixtures and a local test TLS endpoint only; no signed-in provider probes.
- A snapshot must contain public certificates only, not arbitrary source bytes; reject unsafe or malformed input rather than expose it.
- Do not claim macOS or Alpha acceptance without real macOS results. Publication requires separate approval.
- Do not run the existing unrestricted smoke suite against external services.

## Review Focus

- Missing, unreadable, malformed, or private-key-containing CA source: never expose private bytes; preserve missing-CA behavior and fail explicitly for unsafe existing sources.
- Symlinks and path aliases: prevent a source or destination path from exposing a different private file; exercise macOS `/var` and `/private/var` aliases.
- Denied parent, glob, and explicit certificate rules: never weaken the original deny; test rules alongside the snapshot.
- Destination modification, rename, deletion, and replacement: deny each through the real sandbox, including attempts through writable parents.
- Session cleanup, initialization errors, and repeated commands: no stale snapshot or silent fallback to the denied source.

## Task 1: Isolated CA snapshot and sandbox policy

**Files:** Modify `internal/sandbox/manager.go`, `internal/sandbox/macos.go`, and `internal/sandbox/utils.go` only as necessary; test through `internal/sandbox/macos_test.go`, `internal/sandbox/utils_test.go`, and `internal/sandbox/integration_macos_test.go`.

**Interfaces:** Preserve `WrapCommandMacOS` and `GenerateProxyEnvVars` behavior for callers that do not need the snapshot. The manager owns the snapshot's lifecycle; the macOS wrapper consumes its exact path and passes that path to the three existing CA environment variables.

- [ ] Add failing fixture tests through the wrapper/manager entry points. Assert the snapshot consists exclusively of parsed, re-encoded public CA certificate PEM; all three CA variables select it; no proxy or absent source retains existing behavior; invalid, key-bearing, unreadable, and symlinked sources fail closed. Assert all other read-deny rules and the entire managed-directory write deny remain present.
- [ ] Run those tests with `GOPROXY=off GOTOOLCHAIN=local go test ./internal/sandbox -run 'TestMacOS_.*CA|TestGenerateProxyEnvVars' -count=1`; record the pre-fix failure or the exact environmental blocker.
- [ ] Create a manager-owned private per-session directory separate from writable `TMPDIR`. Read only a regular, non-symlinked source; validate every PEM block as an X.509 CA certificate; reject keys, unparsed data, and malformed certificates; write only re-encoded certificate blocks. Ensure failure and cleanup remove the snapshot. Do not create a snapshot when no CA would currently be configured.
- [ ] Add a literal Seatbelt read grant for the snapshot and deny writes and moves to the entire snapshot directory, including normalized aliases. Keep every existing managed-directory deny unchanged. Set only `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, and `REQUESTS_CA_BUNDLE` to the snapshot for the macOS wrapper.
- [ ] Re-run the targeted tests and the relevant existing profile, path and Linux regression tests with network downloads disabled. Record exact commands and outcomes.

## Task 2: Real macOS enforcement and TLS proof

**Files:** `internal/sandbox/integration_macos_test.go`; reuse existing test helpers where safe.

- [ ] Add a macOS-only test that creates an isolated CA and local TLS server, temporary managed directory with a public certificate plus representative private files and a new nested secret, and a sandbox configured to deny reads and writes to the entire managed directory.
- [ ] Through the real manager and `sandbox-exec`, prove TLS succeeds using the exported CA path and fails with an unrelated CA. Verify each private file and nested secret is unreadable; managed-directory writes, creates, renames and deletes fail; snapshot writes, replacements, renames and deletes fail; test both deny-read modes and normalized aliases.
- [ ] Run the test on a macOS runner with `GOPROXY=off GOTOOLCHAIN=local go test ./internal/sandbox -run '^TestMacOS_.*CA' -count=1 -v`; record actual execution and distinguish skips from passes. If no authorized macOS runner exists, report this proof as missing and do not claim acceptance.

## Task 3: Verification and review

- [ ] Run safe, isolated project checks available without downloads; avoid tests that probe user services. Run `make fmt` and `make lint` before any commit only when their tools are already available and the commands are authorized; record missing tools and failures rather than installing.
- [ ] Apply the installed requesting-code-review workflow to the complete diff; resolve findings and re-run affected checks. Do not delegate unless separately authorized.
- [ ] Record exact commands, outcomes, platform limitations, branch and any authorized commit/PR in the todo summary and issue evidence. Do not mark the item done or claim Alpha acceptance while required proof is missing.

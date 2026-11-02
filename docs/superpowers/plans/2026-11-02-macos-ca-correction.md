# macOS CA Isolation Correction Plan

> **For agentic workers:** Use the installed executing-plans and test-driven-development workflows after explicit plan confirmation.

**Goal:** Correct the three macOS failures on merged `dotfiles` without weakening the managed-directory or snapshot protections.

**Evidence:** [Post-merge macOS job 125330115877](https://github.com/Androlax2/greywall/actions/runs/41461123530/job/125330115877) ran macOS 26.6.2 ARM64. `TestMacOS_PublicCATLSAndManagedDirectoryIsolation` and `TestMacOS_PublicCAReadableWhileProxyStateDenied` failed because `sandbox-exec` returned `unsupported syntax: kleene star`; `TestMacOS_PublicCARejectsSnapshotInsideManagedDirectory` accepted a forbidden overlap. Theo separately reports manual TLS and Seatbelt success; its command, configuration and coverage are unspecified.

**Constraints:** Base on `f03db18193359a562d5a0cf36652106eb25ff642`; keep all three failing entry points and their positive and negative assertions. No live user services, installs, manifests, tags, releases, pin updates or rollout. Local fixtures and GitHub-hosted PR tests only. Do not assume Linux profile tests prove macOS enforcement.

## Task 1: Capture the rejected expression

**Files:** `internal/sandbox/integration_macos_test.go` and, only if necessary, existing test helpers in `internal/sandbox/integration_test.go`.

- [ ] Add a bounded, macOS-only diagnostic using isolated fixture paths that reports the exact generated profile and identifies the smallest rejected expression. Compare a working no-proxy profile against the two existing proxy-enabled CA tests, including `(remote tcp "127.0.0.1:12345")`; do not infer the culprit from that difference alone. Any reduced diagnostic profile may run only a harmless command and must not replace or weaken the real regression tests.
- [ ] Run the three existing entry points and diagnostic on a hosted macOS runner through the corrective PR. Preserve all raw failure output and the runner OS/architecture. If the diagnostic cannot identify the expression, stop rather than inventing a regex change.

## Task 2: Resolve missing-path aliases without bypassing protected paths

**Files:** `internal/sandbox/macos.go` and `internal/sandbox/macos_test.go`, plus an existing path helper only if necessary.

- [ ] Add a portable regression using an existing symlinked ancestor and a nonexistent snapshot-root descendant. The protected path and descendant must refer to the same physical tree; assert the manager rejects overlap before creating the root.
- [ ] Run the regression and confirm the existing implementation fails for the alias mismatch. Preserve `TestMacOS_PublicCARejectsSnapshotInsideManagedDirectory` unchanged.
- [ ] Resolve existing ancestors for the comparison while preserving the nonexistent suffix, fail closed on unresolved errors, and retain all existing read/write denies. Run the new and existing overlap tests offline.

## Task 3: Evidence-supported Seatbelt correction

**Files:** determined by the Task 1 finding; preserve all three regression entry points.

- [ ] Add a targeted regression that fails on the actual rejected expression and checks the intended restriction, including negative private-read and directory-write behavior.
- [ ] Make the smallest change supported by the diagnostic evidence; do not broaden network or filesystem access, silently remove a deny, or change unrelated glob semantics.
- [ ] Run focused portable tests and actual hosted macOS TLS/Seatbelt tests. Record exact commands, OS/architecture, unexecuted or skipped tests, and failures.

## Task 4: Review and integration evidence

- [ ] Run the installed requesting-code-review workflow and a separate independent full-final-diff review after all corrections. Resolve findings using tests; do not treat either PR26 review as a review of this patch.
- [ ] Run the available project formatting and lint checks and isolated regressions. Preserve the previously copied tun2socks binary as unverified test-only material, never a release artifact.
- [ ] Update the Task 1 feature PR against `dotfiles`, follow required CI to an actual result, and report the PR/head and remaining fork-specific merge authorization boundary. Do not merge around failing checks.
- [ ] Preserve Theo's manual report alongside CI evidence; leave publication, pinning, rollout and #527 closure to their separately authorized requirements.

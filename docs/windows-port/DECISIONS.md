# Windows Port Decisions

## P0-D001 — Enforce phase isolation

- Status: Accepted
- Phase: P0
- Decision: Phase 0 changes only documentation and evidence. It does not modify application code, tests, dependencies, API behavior, configuration schema, UI, build, or release logic.
- Reason: The migration must retain a reviewable baseline and prevent later implementation choices from being mixed into evidence collection.
- Consequence: Known Windows failures remain intentionally unfixed at the P0 Gate.

## P0-D002 — Freeze one shared-codebase baseline

- Status: Accepted
- Phase: P0
- Decision: Use commit `a5c3adae1f1fa0bd9f0ac7b090ec422e285d0c0f` as the behavior baseline and keep a single macOS/Windows product codebase.
- Alternatives rejected: A Windows-only copy, an Electron/Tauri rewrite, or duplicating the HTTP/config/frontend core.
- Reason: The existing API, configuration recovery, security boundary, and frontend behavior are already product assets. Copying them would create drift and duplicate maintenance.
- Consequence: Later phases may extract operating-system boundaries but must preserve shared behavior unless the specification explicitly changes it.

## P0-D003 — Treat failing Windows tests as evidence, not P0 defects to patch

- Status: Accepted
- Phase: P0
- Decision: Record the native Windows import, file-mode, symlink-privilege, and missing-asset failures exactly. Do not add skips, weaken assertions, or patch around them in this phase.
- Reason: These failures identify the real portability seams. Hiding them would destroy the migration baseline.
- Consequence: `windowsTests` is `FAIL` while `phaseStatus` can be `PASS` because the P0 acceptance target is complete baseline evidence, not Windows runtime compatibility.

## P0-D004 — Do not fabricate missing release assets

- Status: Accepted
- Phase: P0
- Decision: Keep the two unmaterialized tracked macOS asset paths listed as a checkout blocker and do not generate placeholders.
- Reason: Replacement files would invalidate provenance and release reproducibility evidence.
- Consequence: Asset and release validation stays blocked until the original blobs are available.

## P0-D005 — Preserve destructive controls as unavailable until their gate

- Status: Accepted
- Phase: P0
- Decision: Do not expose Windows start, stop, restart, attach, or arbitrary process termination before the Phase 4 lifecycle and ownership checks pass.
- Reason: PID, port, name, or cwd alone is not ownership proof; premature controls could terminate unrelated user processes.
- Consequence: Earlier Windows phases may deliver safe observation and diagnostics only where the specification permits them.

## P0-D006 — Use current local evidence without overstating coverage

- Status: Accepted
- Phase: P0
- Decision: Count this machine only as a Windows 11 x64 non-admin baseline. Keep macOS, Windows 10, Python 3.12, clean-VM, packaged-runtime, and signed-release checks as `NOT_RUN`.
- Reason: WSL and historical assumptions are not substitutes for native target evidence.
- Consequence: `windowsBetaReady` remains `false` regardless of the P0 Gate result.

## P1-D001 — Extract only native boundaries

- Status: Accepted
- Phase: P1
- Decision: Add a typed `PlatformBackend` boundary and move native path, principal, lock, listener/process/cwd scan, launch, stop, picker, browser, launcher, and restart behavior behind adapters. Keep HTTP handlers, configuration, detection, logs, and frontend domain logic in place.
- Reason: This creates the seam required for Windows without duplicating or redesigning the existing product core.
- Consequence: `server.py` retains compatibility wrappers for existing callers and tests, while direct native process calls are rejected by `tools/check_platform_leaks.py`.

## P1-D002 — Model scan failures explicitly

- Status: Accepted
- Phase: P1
- Decision: Platform scans return `ok`, `partial`, or `failed` plus structured issues. Failed scans raise into the existing component isolation path; partial scans retain valid rows and add a degraded reason.
- Reason: An empty successful snapshot and an unavailable/denied scan have different user and safety meanings.
- Consequence: Later Windows monitoring can fail closed without claiming that the machine has no processes.

## P1-D003 — Keep Windows explicitly unsupported in P1

- Status: Accepted
- Phase: P1
- Decision: The Phase 1 loader uses an explicit `UnsupportedPlatform` outside macOS. It can expose safe metadata and preflight environment data, but all observation and control capabilities fail closed.
- Alternatives rejected: A provisional subprocess-based Windows scanner, POSIX emulation, WSL, or dummy lifecycle success.
- Reason: Windows storage/monitoring belongs to P2 and lifecycle belongs to P4.
- Consequence: Native Windows full regression remains red by design until the relevant phases are implemented.

## P1-D004 — Include the platform package in existing checks and release payload

- Status: Accepted
- Phase: P1
- Decision: Extend Python syntax discovery and the source release allowlist to include `localops/` and the platform leak checker.
- Reason: Extracted runtime code must not escape syntax or release verification.
- Consequence: The macOS source release continues to contain everything imported by `server.py`.

## P1-D005 — Stop at the macOS verification gate

- Status: Accepted
- Phase: P1
- Decision: Mark P1 `BLOCKED`, not `PASS`, until the complete existing suite passes on macOS with the original tracked assets.
- Reason: Contract tests and a POSIX surrogate cannot prove macOS zero regression.
- Consequence: No Phase 2, 3, or 4 implementation is started in this worktree.

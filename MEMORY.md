# Project Memory

## Project identity

- Repository: `songconmaisaix31-design/local-ops-windows`, forked from `laogou717/local-ops`.
- Product: a local-only operations console with a Python standard-library backend and a native HTML/CSS/JavaScript frontend.
- Baseline reviewed for the Windows port: `a5c3adae1f1fa0bd9f0ac7b090ec422e285d0c0f` on `main`.

## Durable decisions

- Keep one shared macOS/Windows codebase. Do not create a long-lived Windows-only copy or rewrite the product with Electron or Tauri.
- Extract only operating-system boundaries. Preserve the shared HTTP/API core, configuration domain, logs, project detection, and frontend wherever possible.
- Windows process control must fail closed. A port, PID, process name, or working directory alone never proves ownership.
- Preserve loopback-only HTTP binding, Host/Origin/token checks, atomic configuration writes, and protection against terminating unrelated processes.
- Native Windows support may add narrowly scoped `psutil` and `pywin32` runtime dependencies plus PyInstaller for packaging. When implementation begins, update `AGENTS.md` and installation/release documentation so the dependency policy matches reality.
- Do not claim Windows Beta readiness without real non-admin Windows 10/11 lifecycle tests and a self-contained package test on a clean machine.

## Current task state

- Status: Phase 1 platform extraction passed its full macOS CI and release gate on `windows-port/phases-1-4`; Phase 2–4 have not started.
- Source specification: `docs/specs/windows-native-port.md`.
- Execution plan: `docs/windows-port/PLAN.md`.
- Recovery source: `docs/windows-port/STATE.json`; obtain macOS test evidence before advancing beyond Phase 1.
- The local checkout was reconstructed as a verified shallow/partial checkout because GitHub large-object transfer was unavailable. Two macOS-only image blobs remain unmaterialized and must be fetched before macOS asset or release builds.
- Native Windows baseline import currently stops at the top-level `fcntl` dependency. Preserve this as a platform-extraction seam rather than hiding it with skips or weakening tests.
- The top-level `fcntl` blocker has been removed by the Phase 1 adapter boundary. Outside macOS, observation and control remain explicitly unsupported until their specified phases; never replace this fail-closed state with empty snapshots or fake lifecycle success.

## Memory hygiene

- Do not store tokens, credentials, private logs, user configuration, or user-specific absolute paths here.
- Update this file only with validated, long-lived project decisions or operational lessons.

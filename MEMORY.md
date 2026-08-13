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

- Status: Phase 1 platform extraction passed its full macOS CI and release gate on `windows-port/phases-1-4`. The current Windows 11 Phase 2 target is `PASS`: exact candidate `c5a31a8` passed a real non-admin source/browser flow plus Windows Python 3.12 and macOS regression/release jobs in CI run `31686699247`. Windows 10 is explicitly deferred, so the original cross-version Phase 2 gate remains open and `windowsBetaReady=false`. Phase 3–4 have not started.
- Source specification: `docs/specs/windows-native-port.md`.
- Execution plan: `docs/windows-port/PLAN.md`.
- Recovery source: `docs/windows-port/STATE.json`; obtain macOS test evidence before advancing beyond Phase 1.
- The local checkout was reconstructed as a verified shallow/partial checkout because GitHub large-object transfer was unavailable. Two macOS-only image blobs remain unmaterialized and must be fetched before macOS asset or release builds.
- The top-level `fcntl` blocker was removed by the Phase 1 adapter boundary. Windows Phase 2 now uses pinned `psutil` and `pywin32` for observation, Local AppData, SID/DACL, and Named Mutex behavior.
- Windows lifecycle remains fail closed: launch, managed stop, force stop, external kill, external attach, console restart, and console stop are disabled across capability metadata, HTTP route guards, and browser controls until the Phase 4 runner/Job Object identity gate passes.
- Full-machine Windows command-line ancestry was too slow for the first state response. Phase 2 queries PPID ancestry only for observed listeners and keeps Windows origin badges best-effort; do not reintroduce per-poll PowerShell/WMI or full process `cmdline` enumeration.
- A visible status banner is not connection truth. Windows partial scans legitimately return HTTP 200 plus a degraded notice, so the navigation connection indicator must follow the explicit connection state rather than banner visibility.

## Memory hygiene

- Do not store tokens, credentials, private logs, user configuration, or user-specific absolute paths here.
- Update this file only with validated, long-lived project decisions or operational lessons.

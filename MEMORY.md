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
- Schema v2 is additive: preserve legacy `command` for macOS/display compatibility, use `commandSpec` as the structured Windows compatibility contract, and never infer runtime ownership from migrated PID/port/token data.
- Phase 3 command preparation is data-only. Structured argv is never reconstructed from a display string; POSIX/raw shell text remains review-only, and local static preflight rejects UNC/device paths before any filesystem probe.
- Cross-platform config import is explicit and transactional: deterministic zero-write preview, explicit root mappings, selected-app validation, source/target hashes, target CAS, private receipts, idempotent retry, and post-hash rollback. Imported runtime identity is always cleared.
- Native Windows support may add narrowly scoped `psutil` and `pywin32` runtime dependencies plus PyInstaller for packaging. When implementation begins, update `AGENTS.md` and installation/release documentation so the dependency policy matches reality.
- Do not claim Windows Beta readiness without real non-admin Windows 10/11 lifecycle tests and a self-contained package test on a clean machine.
- Windows managed lifecycle uses one independent runner per app generation. The runner is the sole long-lived holder of a private, kill-on-close Job Object; the HTTP console owns config CAS and the runner writes only protected generation receipts.
- Windows runtime ownership requires the current SID, generation, runner/root PID create times, token digest plus HMAC challenge/receipt, and Job membership. Its public identity is an exact 11-field allowlist; raw tokens and private IPC/runtime paths are never public.
- Every Windows lifecycle mutation carries `expectedGeneration`. Graceful timeout retains identity and never auto-escalates; explicit force repeats validation and terminates only the verified Job. External attach/kill and console restart remain unsupported.
- Tests that exercise Windows process termination require `LOCALOPS_RUN_WINDOWS_LIFECYCLE_TESTS=1`, may run only inside an isolated fixture scope or hosted runner, and may control only fixture-created processes.
- Atomic Windows request/receipt writers apply and verify the private DACL on the temporary file before replacement. Reconnect and cleanup are verify-only; they never repair a widened record and then trust it.
- Windows assigns a new object's owner from the access token's `TokenOwner`. Accept only a default owner equal to the current user or Builtin Administrators. Only the creation-time apply path may normalize the Admin default owner to the current user while atomically applying the same protected DACL; verify-only existing records must already be current-user-owned and reject Admin ownership.
- Runtime cleanup is a two-stage protocol. Before release, the active generation must contain exactly the three private runtime records, have a valid signed terminal receipt, an empty Job, and no remaining runner; atomically renaming that directory to its strictly derived cleanup tombstone is the release commit. After commit, recovery may delete only a private, nonlink tombstone containing an allowlisted subset of those three records and performs no process observation or control. Unknown entries, widened ACLs, or links fail closed and leave the tombstone intact.

## Current task state

- Status: Phase 1 through Windows 11 Phase 4 passed. Historical Phase 3 implementation commit `97c417ef1491ac11fdb036c4e4102bfc190c88e6` passed CI run `31698371278`. Phase 4 implementation commit `06d9b1a37d4b775f4b01f822a021afb93513514c` passed exact-commit CI run `31768949592`: Windows Python 3.12 job `94670617580` and complete macOS regression/release job `94670617652` both passed. Its Windows build 26200/25H2 non-admin local gate passed real discovery 174/174 in 406.426s on Python 3.13.13, frontend 24/24, HTTP hardening 6/6 (30/30 combined), and Node 30/30, including `WIN-LIFE-001..012` (12/12), `WIN-SEC-001..014` (14/14), HTTP console subprocess terminate/reopen, and 100 full lifecycle cycles. Phase 5 packaging, Windows 10, and clean-machine validation remain open, so `windowsBetaReady=false`.
- Source specification: `docs/specs/windows-native-port.md`.
- Execution plan: `docs/windows-port/PLAN.md`.
- Recovery source: `docs/windows-port/STATE.json`; exact-commit CI evidence is required before closing each implemented phase.
- The local checkout was reconstructed as a verified shallow/partial checkout because GitHub large-object transfer was unavailable. Two macOS-only image blobs remain unmaterialized and must be fetched before macOS asset or release builds.
- The top-level `fcntl` blocker was removed by the Phase 1 adapter boundary. Windows Phase 2 now uses pinned `psutil` and `pywin32` for observation, Local AppData, SID/DACL, and Named Mutex behavior.
- Windows managed lifecycle remains fail closed whenever runner/Job/IPC/receipt/ACL/generation evidence is incomplete. Managed launch/stop/force are enabled only for authenticated Local Ops Jobs; external kill, external attach, console restart, and console stop remain disabled. Phase 4 exact-commit Windows Python 3.12 and complete macOS CI passed; Phase 5 must preserve these boundaries while adding packaging.
- Configure CLI diagnostic streams as UTF-8 with `backslashreplace` before any entry-point branch. Hosted Windows redirects standard streams through legacy code pages such as cp1252, and localized output must never terminate the HTTP console; PyInstaller windowed entry points still need an explicit file-backed logging path when standard streams are absent.
- Full-machine Windows command-line ancestry was too slow for the first state response. Phase 2 queries PPID ancestry only for observed listeners and keeps Windows origin badges best-effort; do not reintroduce per-poll PowerShell/WMI or full process `cmdline` enumeration.
- A visible status banner is not connection truth. Windows partial scans legitimately return HTTP 200 plus a degraded notice, so the navigation connection indicator must follow the explicit connection state rather than banner visibility.
- Import receipts must survive the atomic-write commit point. A failed final receipt/ACL verification cannot be modeled as if `os.replace` never happened; reconcile `prepared` state from the current config hash and keep memory/disk aligned before entering read-only protection.
- Import receipt hashes are deterministic over already-normalized snapshots. Idempotent commit retry and rollback must not re-run cwd, PATH, executable, or other environment probes; only a genuinely new commit performs dynamic preflight.

## Memory hygiene

- Do not store tokens, credentials, private logs, user configuration, or user-specific absolute paths here.
- Update this file only with validated, long-lived project decisions or operational lessons.

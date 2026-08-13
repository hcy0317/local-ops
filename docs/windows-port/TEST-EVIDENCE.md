# Phase 0 Test Evidence

## Evidence identity

- Baseline commit: `a5c3adae1f1fa0bd9f0ac7b090ec422e285d0c0f`
- Branch: `windows-port/phase-0-baseline`
- Date: `2026-08-13` (Asia/Shanghai)
- Host: Windows 11 Home x64, non-admin
- Python: 3.13.13
- Node.js: 24.16.0
- PowerShell: 7.6.3
- Git: 2.47.0.windows.1
- WSL: installed but not used as a Windows runtime

## Test inventory

Static source inventory contains 159 Python test methods and 7 Node.js tests:

| File | Declared tests |
| --- | ---: |
| `tests/test_server.py` | 83 |
| `tests/test_hardening.py` | 42 |
| `tests/test_frontend.py` | 14 |
| `tests/test_release.py` | 16 |
| `tests/test_project_checks.py` | 4 |
| `tests/js/ports.test.mjs` | 7 |

The native Windows Python discovery run executed only 36 cases because `test_server.py` and `test_hardening.py` failed during module import.

## Native Windows results

### Python unit discovery — FAIL

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m unittest discover -s tests -p 'test_*.py' -v
```

- Exit code: 1
- Ran: 36
- Passed: 31
- Failed assertions: 2
- Import errors: 3
- Skipped: 0 reported
- Final verification duration: 0.390 seconds

Failure summary:

1. `tests.test_hardening` cannot import `server.py`: `ModuleNotFoundError: No module named 'fcntl'`.
2. `tests.test_server` cannot import `server.py`: the same top-level `fcntl` failure.
3. The symlink-required-source release test cannot create a symlink under this non-admin Windows session: `[WinError 1314]`.
4. The frontend asset contract cannot find `static/assets/console-app-icon.png`; this is one of the two unmaterialized tracked blobs in the partial checkout.
5. The reproducible-release metadata test expects POSIX mode `0644`; the Windows filesystem reports `0666` for the output path (`438 != 420`).

The suite was run once for baseline capture and once after the P0 documentation was finalized. Both runs produced the same 36/31/2/3 outcome. No failure was retried until green, skipped, or weakened.

### Project checker without unit tests — FAIL

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python tools/check_project.py --skip-tests
```

- Exit code: 1
- Checks passed: 9
- Checks failed: 2
- Passed areas: required-file set (26), version, Python syntax (10 files), JavaScript syntax (8 files), JavaScript bindings (7 modules / 41 exports), locked dev dependencies, theme operations, static resources (8 resources / 16 imports), icon registry (56 icons).
- Failure 1: `/bin/bash` is unavailable on native Windows.
- Failure 2: `总控台.app/Contents/Resources/AppIcon.icns` is not materialized in the partial checkout.

### JavaScript port helpers — PASS

```powershell
node --test tests/js/ports.test.mjs
```

- Exit code: 0
- Passed: 7
- Failed: 0
- Skipped: 0

Covered contracts: port normalization, configured/actual port mapping, mismatch detection, preferred open port, displayed port order, and openability.

## Not-run matrix

| Environment / check | Status | Reason |
| --- | --- | --- |
| Current macOS authoritative suite (`make check`) | PASS | Run 31659571268 passed all project checks, including 170 Python tests |
| Exact-commit GitHub Actions run | PASS | Run 31659571268 passed checks, release verification, and reproducibility audit on commit 7768efaa1b805db5582c6867598f08d983a153f0 |
| Windows 10 x64 non-admin | NOT_RUN | Environment unavailable |
| Windows 11 Python 3.12 | NOT_RUN | Local interpreter is Python 3.13.13 |
| Clean Windows VM without Python | NOT_RUN | Environment unavailable; belongs to the packaging gate |
| Packaged Windows runtime | NOT_RUN | Packaging is Phase 5 work |
| Lifecycle/destructive security matrix | NOT_RUN | Windows lifecycle is intentionally unavailable before Phase 4 |
| macOS asset/release build | PASS | Run 31659571268 checked out the original assets and passed build, verification, and reproducibility |

## Baseline artifact hashes

SHA-256 hashes at the baseline commit/worktree:

| Artifact | SHA-256 |
| --- | --- |
| `server.py` | `14501E4B77725AF77F95A63A2A0940AF28745122641D63196FC5ED3CB26926DC` |
| `static/app.js` | `1EC7B4EF1714392E17BBA76B1564C8C9235C3F67ED248264C403E2F8AA775301` |
| `static/index.html` | `662B23F28A7849FBBFEB298AD8C69DD8C175D5165A0F7410D6F120CAF5659CA1` |
| `tests/test_server.py` | `1FAECB0B5D494E83489D7AD880E03C594E0BE4E327850D13967B86EA1C87E7A1` |
| `tests/test_hardening.py` | `95FC1747CF7DAB32605DFCEA7DB69404A8A9762D4168B7A803859FFF2888B665` |

## Manual evidence

- Native Windows environment and non-admin status were inspected directly in PowerShell.
- No browser, UI, notification, picker, process lifecycle, or package smoke test was performed in P0.
- No screenshots or generated binaries are claimed as evidence.

---

## Phase 1 evidence

### Focused platform contract and golden suite — PASS

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m unittest discover -s tests/contract -p 'test_*.py' -v
```

- Passed: 11
- Failed: 0
- Covered: configuration/state golden compatibility, fake success, permission denial, timeout, partial snapshot, degraded propagation, macOS listener parsing, missing-tool failure, partial process details, and shared-core platform leak detection.

### Shared-core native-call audit — PASS

```powershell
python tools/check_platform_leaks.py
```

- Result: `Shared-core platform boundary: OK`
- Checked: direct native imports, direct `os` process control, direct `webbrowser.open`, and direct `ps`/`lsof`/`osascript` subprocess calls in `server.py`.

### Lint and diff checks — PASS

```powershell
ruff check server.py localops tests/contract tests/test_server.py tools/check_platform_leaks.py tools/check_project.py tools/build_release.py
git diff --check
```

- Ruff: passed
- Whitespace/diff check: passed

### Incremental regression checks — PASS

```powershell
node --test tests/js/ports.test.mjs
python -m unittest tests.test_release.ProjectReleaseManifestTests tests.test_project_checks -v
python -m unittest tests.test_hardening.HttpSecurityTests -v
```

- Node port helpers: 7/7 passed
- Release manifest and JavaScript project bindings: 6/6 passed
- HTTP Host/Origin/cookie/Content-Type/CORS boundary: 6/6 passed

### Project checker — PARTIAL / expected host blockers

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python tools/check_project.py --skip-tests
```

- Passed: 9 checks
- Failed: 2 checks
- New platform package coverage: Python syntax now checks 20 files; required-file check covers 30 files.
- Existing blockers: native Windows has no `/bin/bash`; original `AppIcon.icns` blob is not materialized.

### Full native Windows Python discovery — FAIL

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m unittest discover -s tests -p 'test_*.py' -v
```

- Ran: 170
- Failed assertions: 22
- Errors: 11
- Duration: 25.552 seconds
- Primary causes: the P1 Windows adapter intentionally rejects monitoring/lifecycle operations; macOS/POSIX tests assume Bash, POSIX modes, signals, process groups, and symlink privileges; two tracked asset blobs are unavailable.
- Interpretation: this is valid Windows pre-P2 evidence, not a macOS regression result.

### Required macOS Phase 1 suite — PASS

- No local macOS host is available.
- GitHub Actions run `31659571268` executed on `macos-15` against commit `7768efaa1b805db5582c6867598f08d983a153f0`.
- `make check` passed, including all 170 Python tests and 7 Node tests.
- Release build and verification passed twice, and the two archives were byte-for-byte identical.
- The CI checkout materialized and verified the original tracked macOS assets; the local partial checkout remains unable to do so independently.
- P1 is `PASS`; P2–4 had not started at the time of that run.

---

## Phase 2 evidence

### Windows adapter and HTTP safety suite — PASS

```powershell
python -m unittest discover -s tests/windows -p 'test_*.py' -v
```

- Passed: 16
- Failed/errors/skipped: 0
- Latest combined Windows-suite duration: 10.888 seconds
- Covered: Local AppData, current SID, protected DACL, drive/UNC/equivalent/junction paths, Chinese and spaces, Named Mutex exclusion/recovery, current-process owner, IPv4/IPv6 listeners, listener failure, AccessDenied/NoSuchProcess races, mocked native picker, Windows exclusive socket, state capabilities, ACL read-only protection, console-stop rejection, destructive API rejection without process/config side effects, and keep-alive body consumption after a disabled attach request.

### Shared contracts — PASS

```powershell
python -m unittest discover -s tests/contract -p 'test_*.py' -v
```

- Passed: 12
- Failed/errors/skipped: 0
- The intentional state-contract delta is `platform` plus `capabilities`; schema remains v1.

### Real Windows source-process smoke — PASS

- Host: Windows 11 Home x64, non-admin, Python 3.13.13.
- Started `server.py --no-browser` in a temporary Chinese/space-containing data/log directory.
- Final isolated process smoke became ready on preferred port 9609 in 1.231 seconds; three repeated direct state builds completed in 1.360–1.773 seconds.
- The final smoke returned 20 current-user listener service rows; protected process access produced explicit degraded evidence without crashing state construction.
- A second process using the same data directory exited without becoming a writer; the first process remained live.
- All lifecycle/control capability flags were false. The test terminated only the server process it created and removed the temporary directory.

### Exact-candidate Windows 11 browser flow — PASS

- Candidate: `c5a31a860cb0d82a4abfc63aaf7e30eedb55556d`.
- A source process using an isolated Local AppData directory served `http://127.0.0.1:9609/` on Windows 11 non-admin. A real Chromium browser loaded the service-monitor view and rendered 22 current-user listener rows at the final capture.
- Protected-process limitations remained an explicit degraded health notice while the independent connection indicator stayed green and read `已连接`.
- Console restart and stop controls rendered disabled with `不可用` because `restart_console=false`.
- A same-origin browser write added a unique watch keyword, `/api/state` returned it, and the browser removed it. The final configuration hash matched the pre-test hash.
- External kill, managed start/stop/restart, external attach, console restart, and console stop all returned HTTP 409. The console process remained live and responsive after the probes.
- The isolated configuration file retained a protected DACL containing only the current user, SYSTEM, and Administrators.

### Supporting checks

- Node port helpers: 7/7 PASS.
- Shared HTTP Host/Origin/session/Content-Type/CORS security tests: 6/6 PASS.
- Release manifest and JavaScript binding tests: 6/6 PASS.
- Frontend contract: 15/16; the only failure is the pre-existing unmaterialized `static/assets/console-app-icon.png` blob.
- `ruff check`: PASS.
- `python -m compileall`: PASS.
- `python tools/check_platform_leaks.py`: PASS.
- `git diff --check`: PASS.
- `python tools/check_project.py --skip-tests`: 9 PASS / 2 FAIL; the existing host blockers are `/bin/bash` and the unmaterialized original `AppIcon.icns`.

### Phase 2 gate matrix

| Check | Status | Reason |
| --- | --- | --- |
| Windows 11 x64 non-admin | PASS | Real source process, browser UI, config round-trip, DACL, monitoring, and fail-closed controls passed on exact candidate `c5a31a8` |
| Windows 10 x64 non-admin | DEFERRED | Explicitly deferred until after the Windows 11 target is complete |
| Windows Python 3.12 branch CI | PASS | Run `31686699247`, job `94404329291`, implementation commit `c5a31a8` |
| Current Phase 2 macOS regression/release CI | PASS | Run `31686699247`, job `94404329372`; project checks, release build, and verification passed |
| Windows Phase 2 control gate | PASS | Lifecycle remains disabled until Phase 4; adapter, HTTP, browser controls, and no-side-effect tests agree |
| Windows package/clean VM | SKIPPED | Packaging belongs to Phase 5 |

The Windows 11 Phase 2 target was `PASS`. The original cross-version Phase 2 gate remains open because Windows 10 is deferred, not tested. Phase 3 began only after separate user authorization.

---

## Phase 3 evidence

### Windows Python 3.12 command, schema, import, and HTTP suite — PASS

```powershell
& "$env:TEMP\localops-phase3-win11\venv\Scripts\python.exe" -m unittest discover -s tests\windows -p 'test_*.py'
```

- Passed: 50
- Failed/errors/skipped: 0
- Duration: 6.676 seconds
- Covered: CommandSpec tagged-union validation, literal special-character argv, cmd/PowerShell isolation, PATHEXT/npm/pnpm shims, explicit Python 3.12 selection, static preflight, UNC/device zero-probe rejection, schema v2 migration, structured picker/project candidates, Windows adapter behavior, import HTTP preview/commit/rollback, and lifecycle 409/no-side-effect controls.

### Shared contract suite — PASS with one environment skip

```powershell
& "$env:TEMP\localops-phase3-win11\venv\Scripts\python.exe" -m unittest discover -s tests\contract -p 'test_*.py'
```

- Passed: 31
- Skipped: 1
- Failed/errors: 0
- Total: 32
- Duration: 0.584 seconds
- Skip: the non-admin Windows 11 session cannot create the source symlink needed for the explicit symlink rejection case (`WinError 1314`). Regular-file, oversize, malformed-field, UNC/device, conflict, identity clearing, CAS, prepared-state recovery, idempotency, and rollback tests all ran.

### Transaction failure recovery — PASS

- Injected final receipt failure plus compensation-CAS failure: a later identical commit reconciled the `prepared` receipt and returned idempotent success.
- Injected rollback CAS failure: `rollback_prepared` remained retryable and restored the exact pre-import target.
- Deleted private `before.json`: rollback returned the stable server-side `IMPORT_ROLLBACK_FAILED` code instead of a client path error.
- Injected post-`os.replace` ACL verification failure: in-memory and on-disk configuration stayed on the committed bytes, writes changed to read-only protection, and the import receipt remained recoverable.
- Changed cwd/PATH availability after commit: identical commit retry and rollback used deterministic hashes without re-running environment probes, while genuinely new commits still ran dynamic validation.
- Verified that receipt `postHash`, the in-memory snapshot, and the exact JSON written to disk remain identical even when dynamic preflight results could otherwise change.

### Real isolated Windows 11 API flow — PASS

- Source server: Python 3.12, non-admin Windows 11, isolated data/log directories, `http://127.0.0.1:9608/`.
- `/api/state`: `platform=windows`, `schemaVersion=2`, `launch_managed=false`.
- Preview classified the legacy POSIX app as `needs_review`, mapped `/Users/example/Projects/legacy app` to the explicit local Windows root, and created no target config or import record.
- Commit imported one selected app, retained `needs_review`, and cleared `lastPid`, `lastPgid`, `runToken`, `attached`, and `runtimeIdentity`; an identical retry returned the same `importId` with `idempotent=true`.
- `POST /api/apps/deadbeef/start` returned HTTP 409 with `CAPABILITY_DISABLED` and did not start a process.
- A UNC mapping preview returned HTTP 400 with `INVALID_PATH` before a network probe.
- Rollback succeeded and the final state contained zero imported apps.

### Frontend and supporting checks

- Frontend contract: 20/21 PASS. The sole failure is the pre-existing partial-checkout absence of `static/assets/console-app-icon.png`; no substitute was generated.
- JavaScript syntax: 8 files PASS.
- Node port helpers: 7/7 PASS.
- Shared HTTP security plus release/project bindings: 12/12 PASS.
- Ruff, Python compileall, shared-core platform leak audit, and `git diff --check`: PASS.
- Native `tools/check_project.py --skip-tests`: 9/11 PASS; Windows lacks `/bin/bash`, and the original tracked `AppIcon.icns` blob is not materialized.

### Visual and cross-platform gates

| Gate | Status | Evidence / limitation |
| --- | --- | --- |
| Phase 3 browser screenshot/click QA | NOT_RUN | `browser-harness --doctor` reports Chrome running but daemon/active CDP connections unavailable (0); no visual PASS is claimed |
| Windows 10 non-admin | DEFERRED | Explicit user scope; no Win10 claim |
| Phase 4 lifecycle | NOT_STARTED | No runner, Job Object, generation, runtime identity, or lifecycle side effect was added |
| Windows Python 3.12 exact-commit CI | PASS | Commit `97c417ef1491ac11fdb036c4e4102bfc190c88e6`, run `31698371278`, job `94441279178` |
| macOS complete regression/release CI | PASS | Commit `97c417ef1491ac11fdb036c4e4102bfc190c88e6`, run `31698371278`, job `94441279120`; project checks, release build/verify, and reproducibility passed |
| Windows package / clean VM | NOT_RUN | Phase 5 scope |

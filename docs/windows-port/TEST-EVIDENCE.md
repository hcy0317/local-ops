# Windows Port Test Evidence

## Phase 5 — IMPLEMENTED_UNVERIFIED

The exact-CI engineering candidate at implementation commit
`5daddece8a06d1fdd382d1814e58be7b777ceae4` passed CI run `31780819809`, so
`scopedTargetStatus=PASS`. The complete Phase 5 Gate is not accepted because
external environment and release checks remain open; therefore
`phaseStatus=IMPLEMENTED_UNVERIFIED`, `lastGreenPhase=P4`, and
`windowsBetaReady=false`. All lifecycle tests remained limited to their own
fixture processes.

### Full Windows Python 3.12 gate — PASS (local run)

```powershell
$env:LOCALOPS_RUN_WINDOWS_LIFECYCLE_TESTS = "1"
py -3.12 -B -m unittest discover -s tests -p "test_*.py" -v
```

- Ran: 207 tests
- Result: `OK`
- Skipped: 1 package-smoke test because the full discovery did not repeat the
  separate opt-in package gate
- Duration: 120.941 seconds

### Packaging and exact-CI artifact status — PASS

- Packaging unit module: 25 ran, 24 passed, one opt-in package-smoke gate
  skipped.
- Build form: Windows Python 3.12, PyInstaller 6.21.0,
  onedir/windowed/PE32+ x64, unsigned zip.
- Audit scope: version and architecture, embedded data, pinned runtime/build
  distributions, runtime licenses, unsafe paths, user data, logs,
  runtime/token/credential material, caches, and absolute-path leakage.
- Reproducible build A/B: PASS in exact-commit CI; two independent builds plus
  internal and independent audits passed, and both 18,649,468-byte archives
  were byte-identical.
- Archive SHA-256:
  `b227e6244bf18d337d0244cd032e58c20ed84afe7d56286b9f73cb59d408eebe`.
- Checksum sidecar: 107 bytes, SHA-256
  `347154c1cdafe03777a56bbda23e5ad37610d203823cc44105c54b28fec44009`.
- Manifest sidecar: 219,889 bytes, SHA-256
  `e78bb8bda187094689c7d78585f8c7c2c3855379b779c337c885050bb99bf0ae`.

### Audited package smoke — PASS (local run, 1/1)

- Duration: 24.209 seconds.
- Path/permissions: extracted under a read-only Chinese-and-space path.
- Runtime isolation: the packaged child's `PATH` contained no Python; the test
  harness still had Python and dependencies.
- Journey: real start → log marker → listener → controller close/reopen →
  explicit Force stop → generation release → app delete.
- Final state: fixture PIDs and ports were gone, runtime records were released,
  and every bundle-tree hash matched the pre-run tree.
- Safety boundary: only processes created by the isolated fixture were
  controlled.
- Limitation: stripped child `PATH` is not equivalent to an independent clean
  Windows VM without Python.

### Supporting local checks — PASS

- Focused Windows scope: 109/109.
- Shared contracts: 31 passed, one privileged symlink test skipped.
- Frontend + HTTP hardening: 30/30.
- Lifecycle Node contracts: 30/30.
- Common tests: 10/10.
- Project checks: 6/6.
- Compile discovery: 45 files.
- Ruff and `git diff --check`: PASS.

### Runner and frozen-runtime regression coverage — PASS (local run)

- Source venv redirector: base Python + `__PYVENV_LAUNCHER__` retains the venv
  while the persisted runner PID identifies the real long-lived interpreter.
- Console ownership: `FreeConsole` precedes private `AllocConsole` and target
  creation.
- Frozen child: same-executable runner launch sets
  `PYINSTALLER_RESET_ENVIRONMENT=1`.
- Dynamic runtime: `win32timezone` is an explicit hidden import.
- Launch resolution: the target executable is absolute before suspended
  creation.

### Exact-commit CI — PASS

- Accepted engineering-candidate commit:
  `5daddece8a06d1fdd382d1814e58be7b777ceae4`.
- Accepted run: `31780819809`, conclusion `SUCCESS`.
- Common job `94705997033`: `SUCCESS`.
- macOS full regression and source-release job `94705997092`: `SUCCESS`.
- Windows lifecycle, contracts, frontend/hardening, two-build reproduction,
  audit, package smoke, and upload job `94706274519`: `SUCCESS`.
- Uploaded GitHub artifact: id `9211730738`, name
  `local-ops-windows-x64-unsigned`, size 18,870,044 bytes, outer digest
  `sha256:a084fcc3794e9a57d5cd116992f2b42637df6f11ebd1d71f32568b6f8cff35c6`.
  This outer digest is distinct from the inner archive SHA-256 above.
- Historical failed Phase 5 attempt: commit `503401f`, run `31778658261`,
  source-test fixture path defect; not accepted evidence.
- Historical failed Phase 5 attempt: commit `52a2981`, run `31779137215`,
  Windows cp1252 CI stdio defect; not accepted evidence.
- Historical failed Phase 5 attempt: commit `12df546`, run `31779647391`,
  hosted-administrator package-smoke ACL defect; not accepted evidence.

### Phase 5 acceptance limitations

| Gate | Status | Evidence boundary |
| --- | --- | --- |
| Phase 5 exact-CI engineering candidate | PASS | Commit `5daddece8a06d1fdd382d1814e58be7b777ceae4`, run `31780819809`; this does not close external gates |
| Windows 10 x64 non-admin | SKIPPED | User explicitly deferred Win10 until Windows 11 work is stable |
| Independent clean VM without Python | NOT_RUN | Stripped child PATH does not substitute for this environment |
| Defender / SmartScreen | NOT_RUN | Current-tree artifact exists, but no OS reputation/security scan was run |
| Native Windows picker | NOT_RUN | Headless/API coverage is not an OS-dialog acceptance test |
| Windows Notification Center delivery | NOT_RUN | Notification object tests do not prove native delivery |
| Favicon brand approval | REVIEW_REQUIRED | Release owner must record a human brand decision |
| Signing | UNSIGNED | Current output is a development artifact, not a public signed release |
| Windows Beta | FALSE | Every required Phase 5 and Spec 3.2 gate must pass first |

---

## Phase 4 — PASS

The authorized local gate passed on 2026-08-14 on Windows NT build 26200
(DisplayVersion 25H2), x64, at medium integrity without administrator
membership. Local Python was 3.13.13 and Node.js was 24.16.0. All destructive
operations were restricted to processes created by the test fixtures.

Local evidence is closed by exact-commit CI for implementation commit
`06d9b1a37d4b775f4b01f822a021afb93513514c` and run `31768949592`.
Windows Python 3.12 job `94670617580` and complete macOS
regression/release/reproducibility job `94670617652` both passed.

### Gated real Windows discovery — PASS (174/174)

```powershell
$env:LOCALOPS_RUN_WINDOWS_LIFECYCLE_TESTS = "1"
python -B -m unittest discover -s tests\windows -p "test_*.py" -v
```

- Duration: 406.426 seconds
- Passed: 174
- Failed/errors/skipped: 0
- `WIN-LIFE-001..012`: 12/12 test methods passed.
- `WIN-SEC-001..014`: all 14 explicit cases passed.
- Accepted candidate commit: `06d9b1a37d4b775f4b01f822a021afb93513514c`
- Accepted CI run: `31768949592`

### WIN-LIFE mapping — PASS

| ID | Test module and method |
| --- | --- |
| `WIN-LIFE-001` | `tests/windows/test_windows_lifecycle.py::test_win_life_001_python_http_listener_log_and_job_state` |
| `WIN-LIFE-002` | `tests/windows/test_windows_lifecycle.py::test_win_life_002_node_npm_listener_log_and_state` |
| `WIN-LIFE-003` | `tests/windows/test_windows_lifecycle.py::test_win_life_003_background_child_survives_root_exit` |
| `WIN-LIFE-004` | `tests/windows/test_windows_lifecycle.py::test_win_life_004_005_console_close_and_reopen_reconnect` |
| `WIN-LIFE-005` | `tests/windows/test_windows_lifecycle.py::test_win_life_004_005_http_console_process_restart` |
| `WIN-LIFE-006` | `tests/windows/test_windows_lifecycle.py::test_win_life_006_graceful_success_and_generation_release` |
| `WIN-LIFE-007` | `tests/windows/test_windows_lifecycle.py::test_win_life_007_008_timeout_then_explicit_owned_job_force` |
| `WIN-LIFE-008` | `tests/windows/test_windows_lifecycle.py::test_win_life_007_008_timeout_then_explicit_owned_job_force` |
| `WIN-LIFE-009` | `tests/windows/test_windows_lifecycle.py::test_win_life_009_suspended_has_no_side_effect_before_resume` and `test_win_life_009_launch_failure_has_no_side_effect_or_runtime_records` |
| `WIN-LIFE-010` | `tests/windows/test_windows_lifecycle.py::test_win_life_010_runner_identity_mismatch_fails_closed` |
| `WIN-LIFE-011` | `tests/windows/test_windows_lifecycle.py::test_win_life_011_runner_crash_kills_only_its_job` |
| `WIN-LIFE-012` | `tests/windows/test_windows_lifecycle.py::test_win_life_012_one_hundred_cycles_leave_no_runtime_records` |

The two `WIN-LIFE-004/005` methods cover both a cold adapter reconnect after
the original controller exits and an actual HTTP console subprocess
termination/reopen while the managed service remains live. `WIN-LIFE-012`
performs 100 complete launch, activate, force-stop, and release cycles.

### WIN-SEC mapping — PASS

All cases are in `tests/windows/test_windows_security_matrix.py`.

| ID | Test method |
| --- | --- |
| `WIN-SEC-001` | `test_win_sec_001_pid_create_time_mismatch_refuses_control` |
| `WIN-SEC-002` | `test_win_sec_002_other_listener_is_not_claimed_or_stopped` |
| `WIN-SEC-003` | `test_win_sec_003_same_name_and_cwd_are_not_ownership_proof` |
| `WIN-SEC-004` | `test_win_sec_004_other_sid_rejected_before_cwd_or_control` |
| `WIN-SEC-005` | `test_win_sec_005_wrong_host_or_origin_is_rejected` |
| `WIN-SEC-006` | `test_win_sec_006_missing_or_wrong_cookie_and_hmac_are_rejected` |
| `WIN-SEC-007` | `test_win_sec_007_exclusive_socket_rejects_port_takeover` |
| `WIN-SEC-008` | `test_win_sec_008_widened_acl_is_verify_only_and_control_fails_closed` |
| `WIN-SEC-009` | `test_win_sec_009_junction_runtime_path_is_rejected` |
| `WIN-SEC-010` | `test_win_sec_010_cmd_and_powershell_special_args_do_not_inject` |
| `WIN-SEC-011` | `test_win_sec_011_concurrent_generation_cas_has_one_winner` |
| `WIN-SEC-012` | `test_win_sec_012_partial_scan_is_degraded_and_control_fails_closed` |
| `WIN-SEC-013` | `test_win_sec_013_stale_generation_cannot_stop_new_instance` |
| `WIN-SEC-014` | `test_win_sec_014_assign_or_persist_failure_never_resumes` |

### Frontend, HTTP hardening, contracts, and lint — PASS

- `python -B -m unittest tests.test_frontend -v`: 24/24 passed.
- `python -B -m unittest tests.test_hardening.HttpSecurityTests -v`: 6/6 passed (30/30 combined with frontend).
- `python -B -m unittest discover -s tests\contract -p "test_*.py" -v`: 31 passed, one privileged symlink case skipped because this non-admin session cannot create symlinks.
- `node --test tests\js\lifecycle.test.mjs`: 30/30 passed.
- Ruff: passed for the Phase 4 Python scope.
- Atomic request/receipt coverage proves the temporary file receives its
  private ACL before replacement becomes visible.
- Active-generation release requires exactly the three private runtime records,
  a valid signed terminal receipt, exact identity, an empty Job, and an absent
  runner. Atomic rename to the strictly derived cleanup tombstone is the
  release commit; a rename failure leaves the active generation intact.
- Committed tombstone recovery deletes only a private, nonlink allowlisted
  subset of the three runtime records and performs no process observation or
  control. Unknown entries, widened ACLs, links, and non-derived paths fail
  closed and remain untouched.

### Isolated Edge UI lifecycle flow — PASS (local run)

- Host/browser: isolated Windows 11 fixture, Edge 151, console port 9601, CDP
  port 9224. The existing user console and processes were outside the fixture.
- Core journey: add → start → log marker → HTTP 200 → graceful stop → bad-cwd
  diagnostic → restore → start → restart with a changed generation → final
  stop → delete.
- Final state: `runtimeIdentity` was `null`, runtime records were absent, and
  all fixture PIDs and ports were gone.
- Responsive checks: 1280 px and 360 px viewports had no horizontal overflow.
- Notifications: permission-denied and permission-granted paths passed; the
  granted path constructed and closed a `Notification` object.
- Compatibility-edit follow-up: a blocked app initially kept Save disabled;
  entering a valid cwd immediately enabled Save, cleared its disabled title
  and stale compatibility text, and preserved the structured command. A real
  save then returned backend compatibility `ready`, health `ok`, and the same
  direct command spec.
- Overlay follow-up: z-index order was banner 400, drawer mask 410, drawer 415,
  and toast 420. `elementFromPoint` at the prior overlap resolved to the drawer
  close control; a real click closed the drawer with `aria-hidden="true"`.
- Limitation: headless QA did not invoke the native OS picker or prove delivery
  through Windows Notification Center. Those native paths remain `NOT_RUN`.

### Exact-commit CI — PASS

- Accepted implementation commit:
  `06d9b1a37d4b775f4b01f822a021afb93513514c` (`06d9b1a`).
- Accepted run: `31768949592`, conclusion `SUCCESS`.
- Windows Python 3.12 job `94670617580`: `SUCCESS`.
- macOS regression/release/reproducibility job `94670617652`: `SUCCESS`.

- Historical failed attempt: exact commit
  `fc29e5637d93b95026a5dbca5e46c638c51b5439` (`fc29e56`), run
  `31766584905`, conclusion `FAILED`.
- Windows failure: the hosted administrator token demonstrated that Windows
  new-object ownership follows `TokenOwner`; the candidate incorrectly assumed
  the current user would always be the initial owner.
- macOS failure: Windows lifecycle fixtures did not isolate the fake platform
  principal globals from the host principal.
- Later historical failures were commit `c3a9fa9e83c6d4cfcf87b5310be0bd764ea58dc5`,
  run `31767880432`, and commit
  `b96b5c4293559b7cd17e855cfb055eba39495c02`, run `31768341494`.
  They exposed the eager non-Windows Job Object decorator, hosted-console
  diagnostics, and strict-cp1252 redirected output. They are not accepted
  evidence.
- The Windows workflow now runs Windows/lifecycle discovery, API contracts, and
  frontend/HTTP hardening as three independent fail-fast steps without
  `continue-on-error`.
- Phase 4 local Edge lifecycle QA: `PASS` (local evidence); native picker and Windows Notification Center delivery: `NOT_RUN`
- `lastGreenPhase`: `P4`

### Deferred beyond Phase 4

- Windows 10 non-admin validation: `SKIPPED` (explicit user scope)
- Self-contained package / clean VM without Python: `NOT_RUN` (Phase 5)
- `windowsBetaReady`: `false`

---

## Phase 0 evidence identity

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
| Lifecycle/destructive security matrix at the Phase 0 checkpoint | NOT_RUN | Windows lifecycle was intentionally unavailable before Phase 4 |
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
| Windows 10 x64 non-admin | SKIPPED | Explicit user scope; deferred until after the Windows 11 target is complete |
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
| Windows 10 non-admin | SKIPPED | Explicit user scope; no Win10 claim |
| Phase 4 lifecycle at the Phase 3 checkpoint | NOT_STARTED | No runner, Job Object, generation, runtime identity, or lifecycle side effect was present in the Phase 3 candidate |
| Phase 3 Windows Python 3.12 exact-commit CI | PASS | Historical Phase 3 commit `97c417ef1491ac11fdb036c4e4102bfc190c88e6`, run `31698371278`, job `94441279178`; not Phase 4 evidence |
| Phase 3 macOS complete regression/release CI | PASS | Historical Phase 3 commit `97c417ef1491ac11fdb036c4e4102bfc190c88e6`, run `31698371278`, job `94441279120`; not Phase 4 evidence |
| Windows package / clean VM | NOT_RUN | Phase 5 scope |

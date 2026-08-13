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
| Current macOS authoritative suite (`make check`) | PASS | Run 31659377461 passed all project checks, including 170 Python tests |
| Exact-commit GitHub Actions run | FAIL | Run 31659377461 failed in release validation on a literal home-path example; wording is fixed pending rerun |
| Windows 10 x64 non-admin | NOT_RUN | Environment unavailable |
| Windows 11 Python 3.12 | NOT_RUN | Local interpreter is Python 3.13.13 |
| Clean Windows VM without Python | NOT_RUN | Environment unavailable; belongs to the packaging gate |
| Packaged Windows runtime | NOT_RUN | Packaging is Phase 5 work |
| Lifecycle/destructive security matrix | NOT_RUN | Windows lifecycle is intentionally unavailable before Phase 4 |
| macOS asset/release build | NOT_RUN | macOS tools and two original asset blobs are unavailable |

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

### Required macOS Phase 1 suite — PASS / full workflow rerun pending

- No local macOS host is available.
- GitHub Actions run `31659377461` executed on `macos-15` against commit `7889fb67d578107559c2ac8f07eda29271d2357e`.
- `make check` passed, including all 170 Python tests and 7 Node tests.
- Release validation then rejected a literal macOS home-path example in the port specification; the wording is fixed without weakening path-leak detection.
- The focused release-path checks pass 2/2 locally and the specification now returns no path leak.
- The two original tracked macOS asset blobs are not materialized locally.
- P1 therefore remains `IMPLEMENTED_UNVERIFIED` until the full fixed workflow is green; P2–4 were not started.

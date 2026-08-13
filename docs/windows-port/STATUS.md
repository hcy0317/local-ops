# Windows Port Status

## Current result

**P1 BLOCKED — implementation is present, but the fork has no registered GitHub Actions workflow to run the required macOS regression gate.**

Phase 1 extracted the platform boundary and passed its focused contract, golden, lint, and platform-leak checks. Commit `3bd08e9c3b231c7fa2a282c4d6b2b382c2a4cf1a` was pushed to the phase branch, but the fork Actions API reports zero registered workflows and created no run. The workflow must be enabled in the fork before the `macos-15` gate can execute. Per the phase protocol, Phase 2–4 have not started.

## Phase 1 completed implementation

- Added typed platform contracts and structured scan states.
- Added a macOS adapter containing the original native path, lock, process, listener, cwd, launch, stop, picker, browser, launcher, and restart behavior.
- Added a fake platform covering success, permission denial, timeout, and partial snapshots.
- Added an explicit unsupported adapter so foreign-platform control paths fail closed during P1.
- Changed shared state assembly so partial/failed scan evidence becomes `degraded` rather than a false empty success.
- Added baseline-golden and direct-native-call checks.
- Added `localops/` to project syntax checks and the source release allowlist.

Focused evidence is green: 11/11 Python contract/golden tests, 7/7 Node port tests, 6/6 release-manifest/project-binding tests, 6/6 HTTP security tests, Ruff, platform-leak check, and `git diff --check`.

The full native Windows Python run is intentionally not green in P1: 170 tests ran with 22 failures and 11 errors. The failures are dominated by the explicitly unsupported Windows adapter, POSIX lifecycle/mode/symlink assumptions, and missing tracked assets. This is not a P1 macOS regression verdict.

## Phase 0 result

**P0 PASS — baseline frozen and risks registered.**

This result does not mean that the product runs on Windows. Native Windows tests currently fail, lifecycle controls remain unimplemented, and `windowsBetaReady` remains `false`. Phase 1 has not started.

## Scope completed

- Read the repository rules, port specification, implementation plan, source boundaries, and all six Python/JavaScript test files.
- Recorded the exact baseline commit, branch, worktree additions, environment capabilities, test outcomes, and artifact hashes.
- Frozen the existing API/state/config contract in `BASELINE-CONTRACTS.json`.
- Classified macOS/POSIX coupling across imports, storage, locking, discovery, lifecycle, commands, UI, build, and release.
- Made no business-code, dependency, API, schema, UI, build, or lifecycle change.

## Git and worktree baseline

| Item | Value |
| --- | --- |
| Baseline commit | `a5c3adae1f1fa0bd9f0ac7b090ec422e285d0c0f` |
| Phase branch | `windows-port/phase-0-baseline` |
| Tracked business-code changes | None |
| Preserved pre-existing additions | `MEMORY.md`, `docs/specs/windows-native-port.md`, `docs/windows-port/PLAN.md` |
| Phase 0 additions | `BASELINE-CONTRACTS.json`, `STATE.json`, `STATUS.md`, `DECISIONS.md`, `TEST-EVIDENCE.md` |
| Commit/push/PR | Not performed; not authorized for this phase |

The checkout is a verified shallow/partial reconstruction. Two tracked macOS brand assets are not materialized locally: `static/assets/console-app-icon.png` and `总控台.app/Contents/Resources/AppIcon.icns`. No placeholder was created.

## Available environment

| Capability | Observed result | Consequence |
| --- | --- | --- |
| OS | Windows 11 Home, x64, non-admin | Valid for native Win11 non-admin baseline only |
| Python | 3.13.13 | Does not replace the planned Python 3.12 CI target |
| Node.js | 24.16.0 | JavaScript contract tests are runnable |
| PowerShell | 7.6.3 | Native Windows shell available |
| Git | 2.47.0.windows.1 | Repository checks available |
| `bash` | WSL launcher only | Must not be treated as native Windows runtime |
| `make`, `lsof`, `osascript`, `plutil`, `iconutil` | Unavailable | macOS project/release checks cannot complete here |
| macOS host | Unavailable | Current macOS regression suite not run |
| Windows 10 / clean VM | Unavailable | No Beta claim is permitted |

## Existing behavior baseline

The machine-readable baseline is `docs/windows-port/BASELINE-CONTRACTS.json`. The protected behavior includes:

- schema v0→v1 migration, future-schema rejection, primary/backup recovery, atomic replacement, and read-only failure mode;
- stable `/api/state` keys and component-level degraded reporting;
- existing REST routes and response semantics;
- loopback binding, exact Host/port validation, same-origin browser control session, explicit CORS denial, and bounded request bodies;
- keep-alive body consumption and connection closure on rejected attacker-controlled bodies.

## Platform coupling inventory

| Category | Current anchors | Coupling and callers | Required boundary for later phases |
| --- | --- | --- | --- |
| Import and identity | `server.py:11`, `server.py:109` | Top-level `fcntl`; `os.getuid()` feeds ownership filtering and kill authorization | Platform identity and locking API |
| Storage paths | `server.py:38-39` | Hard-coded `~/Library/Application Support/总控台` and `~/Library/Logs/总控台` feed config, icons, logs, lock, and launcher | Platform directory provider |
| Privacy and atomic writes | `server.py:186-333`, `server.py:535`, `server.py:1515`, `server.py:2355-2358`, `server.py:4005` | `chmod`/`fchmod` assume POSIX modes for migration, config, logs, lock, and restart metadata | Platform privacy verifier; Windows must use ACL/SID semantics |
| Single instance | `server.py:538-574` | `fcntl.flock` protects one server per data directory | Platform instance lock; Windows later requires a named mutex |
| Listener discovery | `server.py:619-677` | `lsof` output is parsed by service, app, origin, attach, and port-conflict logic | Typed listener snapshot with explicit degraded errors |
| Process discovery | `server.py:682-739` | macOS `ps` columns, UID, `comm`, args, elapsed time, CPU, memory, and PGID support watched/services/apps | Typed process snapshot, partial-access errors preserved |
| Working directory discovery | `server.py:741-770` | `lsof -d cwd` is used by service grouping, app matching, attach, origin, and console-instance detection | Platform cwd lookup with access-denied state |
| Ownership and lifecycle | `server.py:1424-1623`, `server.py:2097-2302` | UID/PGID/run-token checks, `SIGTERM`/`SIGKILL`, `os.killpg`, `os.getpgid`, and process groups control kill/start/stop/restart/attach | Fail-closed platform lifecycle contract; unavailable controls stay disabled before Phase 4 |
| Command execution | `server.py:1506-1541`, `server.py:1652-1667`, `server.py:1988`, `server.py:2088-2094` | `/bin/bash`, shell strings, `shlex.quote`, `.command`/`.sh` candidates | Structured command specification; no automatic shell-string rewriting |
| Native picker | `server.py:1636-1650` | `osascript` implements directory/script selection and feeds `/api/pick` | Platform picker capability and cancellation result |
| Browser and console lifecycle | `server.py:3816-3920` | `lsof`, `osascript`, POSIX signals, launcher metadata, and detached helper semantics implement find/open/restart/stop | Platform console controller with explicit capabilities |
| Socket exclusivity | `server.py:2729` | `allow_reuse_address = True` is POSIX-oriented and insufficient against local Windows port preemption | Platform server socket policy; Windows later requires exclusive address use |
| Frontend path/command assumptions | `static/js/overlays.js:48,568-571` | `/bin/bash`, `/` splitting, and POSIX extensions shape picker and project forms | Platform capabilities and path helpers from the shared contract |
| Frontend platform copy | `static/app.js:283-355`, `static/index.html:118,371,498,609`, `static/js/widgets.js:317-338` | `.app`, `~/Library`, and Command-key instructions are user-visible | Capability/platform copy without changing shared API semantics |
| Project checks and release | `Makefile`, `tools/check_project.py:396-403`, `tools/build_release.py:47-109`, `tools/gen_brand_assets.py:4-65`, `.github/workflows/ci.yml` | Make/Bash/plist/iconutil, `.app`, POSIX modes, symlink behavior, and macOS-only CI block native Windows verification | Common and platform-specific checks split in Phase 5 |
| Documentation and launcher | `README.md`, `start.command`, `总控台.app` | Installation, recovery, logs, launch, and troubleshooting are macOS-only | Windows launcher/docs are Phase 4/5 work, not P0 work |

## Risk register

| Risk | Current evidence | P0 disposition |
| --- | --- | --- |
| Backend cannot import on Windows | Top-level `fcntl` raises `ModuleNotFoundError` | Recorded; no P1 fix attempted |
| Empty discovery could hide privilege/tool failures | Existing subprocess helpers can collapse unavailable commands into empty output | Must remain explicit in later platform contracts |
| Process ownership is POSIX-specific | UID/PGID/token and signals are embedded in lifecycle code | Lifecycle controls remain unavailable until Phase 4 Gate |
| Windows privacy cannot be proven with mode bits | Current checks rely on 0700/0600 | Future Windows ACL/SID evidence required |
| Release checks are host-sensitive | Windows reports archive output mode differently; symlink creation needs privilege | Split common/platform release checks later; do not weaken assertions in P0 |
| Local release source is incomplete | Two tracked asset blobs are not materialized | Fetch originals before asset/release validation; never synthesize substitutes |
| Coverage gap | No current macOS run, Win10 run, clean-VM run, or exact-commit CI run exists | Explicitly `NOT_RUN`; prevents Beta readiness |

## P0 Gate

- [x] Test commands, counts, outcomes, and failure causes recorded.
- [x] No business code changed.
- [x] Existing user work preserved.
- [x] Platform coupling covers imports, callers, API impact, UI, build, and release.
- [x] Actual environment capability and unavailable evidence are explicit.
- [x] `STATE.json` matches the branch, baseline, changed files, and test status.

Gate decision: **PASS for Phase 0 only**. The next authorized unit of work is Phase 1 platform-contract extraction; it has not started.

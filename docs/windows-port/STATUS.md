# Windows Port Status

## Phase 4 — PASS

The Phase 4 source candidate implements the runner/Job ownership model,
protected Named Pipe IPC and receipts, generation compare-and-swap, and the
lifecycle-aware UI/API contract. The authorized local gate passed on Windows
NT build 26200 (DisplayVersion 25H2), x64, at medium integrity without
administrator membership, using Python 3.13.13:

- gated real `tests/windows` discovery: 174/174 passed in 406.426s;
- `WIN-LIFE-001..012`: 12/12 passed, including actual HTTP console subprocess
  termination/reopen and 100 full launch/force/release cycles;
- `WIN-SEC-001..014`: 14/14 explicit cases passed;
- frontend: 24/24 passed; HTTP hardening: 6/6 passed (30/30 combined);
- lifecycle Node contracts: 30/30 passed;
- isolated headless Edge 151 UI flow passed at 1410x905 and 750x485;
- shared contracts: 31 passed and one privileged symlink case skipped;
- Ruff: passed.

The lifecycle gate controlled only fixture processes created by the tests.
Managed launch, graceful stop, and explicit force are enabled only for a fully
verified Local Ops Job. External attach/kill and console restart remain
disabled. Active-generation release requires exactly three private records, a
signed terminal receipt, an empty Job, and an absent runner. Atomic rename to a
strictly derived cleanup tombstone is the release commit; committed tombstone
recovery handles only a private, nonlink allowlisted record subset and performs
no process observation or control. The atomic request/receipt writers protect
their temporary files before replacement.

Phase 4 implementation commit
`06d9b1a37d4b775f4b01f822a021afb93513514c` (`06d9b1a`) passed exact-commit
CI run `31768949592`. Windows Python 3.12 job `94670617580` passed the
fixture-owned lifecycle, API contract, frontend, and HTTP hardening gates;
macOS job `94670617652` passed the complete regression, release, and
reproducibility audit. `lastGreenPhase` is P4.

Earlier runs remain historical failures, not accepted evidence. Run
`31766584905` exposed Windows `TokenOwner` semantics and macOS fake-principal
test isolation; run `31767880432` exposed an eager non-Windows Job Object test
decorator and insufficient hosted-console diagnostics; run `31768341494`
exposed localized startup crashing when redirected stdout used strict cp1252.
The accepted commit configures CLI diagnostic streams as UTF-8 before any
entry-point branch, so redirected output cannot terminate the service.

The current Windows workflow separates lifecycle/Windows discovery, API
contracts, and frontend/HTTP hardening into three independent fail-fast steps
with no `continue-on-error`, so a failing group is attributed directly and
later groups do not mask it.

The isolated Edge 151 flow completed add → start → log marker → HTTP 200 →
graceful stop → bad-cwd diagnostic → restore → start → restart with a changed
generation → final stop → delete. Final state had no runtime identity or runtime
records, and all fixture PIDs and ports were gone. The 1280 px and 360 px
viewports had no horizontal overflow. Notification permission-denied and
permission-granted paths both passed, including construction and close of the
notification object. Headless QA did not invoke the native OS picker or prove
delivery through Windows Notification Center, so those native paths remain
`NOT_RUN`.

The focused Edge follow-up closed both UI acceptance findings. Editing a
compatibility-blocked app initially kept Save disabled; entering a valid cwd
immediately enabled Save, cleared the disabled title and stale compatibility
copy, and left the structured command unchanged. After the real save, backend
state reported compatibility `ready` and health `ok` with the direct command
spec preserved. The verified overlay order is banner 400, drawer mask 410,
drawer 415, and toast 420. At the prior overlap point `elementFromPoint`
resolved to the drawer close control, and a real click closed the drawer and
set `aria-hidden="true"`.

Windows 10, self-contained packaging, a clean machine without Python, and Beta
readiness remain Phase 5 scope. `windowsBetaReady=false`.

## Current result

**P4 PASS / EXACT-COMMIT WINDOWS + MACOS CI PASS / WIN10 PHASE 5.**

Windows 10, self-contained packaging, and clean-machine Beta gates remain
Phase 5 work; therefore `windowsBetaReady=false`.

## Phase 3 last-green result

Phase 3 adds the frozen API Contract v2, additive schema v1→v2 migration, a non-executing `CommandSpec` model, Windows project detection/static preflight, explicit receipt-backed macOS configuration import, and platform/capability-driven UI. It does not add a runner, Job Object, generation, runtime identity, external attach, or any lifecycle side effect.

The Windows 11 non-admin local gate passed 50/50 Windows tests and ran 32 shared contract tests under Python 3.12: 31 passed and one symlink case was skipped because this non-admin session cannot create symlinks. An isolated real API flow on port 9608 proved schema v2 state, zero-write preview, explicit path mapping, runtime-identity clearing, atomic and idempotent commit, lifecycle HTTP 409, UNC rejection, and rollback to the original target. Ruff, compileall, JavaScript syntax, Node helpers, platform-leak audit, HTTP security checks, and diff checks pass.

Phase 3 visual browser interaction is `NOT_RUN`: `browser-harness --doctor` reports a running Chrome but no active CDP connection. Static frontend contracts pass 20/21; the only failure is the pre-existing unmaterialized `static/assets/console-app-icon.png` blob. This limitation is not presented as a visual PASS. Phase 2's exact-candidate Chromium evidence remains historical only.

Historical Phase 3 implementation commit `97c417ef1491ac11fdb036c4e4102bfc190c88e6` passed exact-commit CI run `31698371278`: Windows Python 3.12 job `94441279178` and macOS complete check/release/reproducibility job `94441279120` both passed. These IDs are not Phase 4 evidence.

The user explicitly deferred Windows 10. This did not fabricate the original cross-version or release gate: `windowsBetaReady=false`, packaging remains Phase 5, and Phase 4 had not started at this Phase 3 checkpoint.

## Phase 3 implemented scope

- Added schema v2 fields `commandSpec`, `runtimeIdentity`, and `importStatus` while preserving legacy `command` and macOS compatibility.
- Added direct/cmd/PowerShell/legacy-POSIX tagged command data, special-character-safe argv handling, PATHEXT/npm/pnpm/Python 3.12 selection, and local-only static preflight.
- Rejected UNC/device namespaces before PATH, cwd, executable, project, or import filesystem probes.
- Added explicit import preview/commit/rollback with a 1 MiB local regular-file limit, deterministic decisions, source/target hashes, target CAS, private before/source/receipt records, no-overwrite selection, identity clearing, idempotent retry, and recoverable prepared states.
- Added platform presentation metadata and removed browser POSIX quoting, slash parsing, and `/Users` inference.
- Gated Windows lifecycle/external-process actions at adapter, HTTP, rendered UI, and event-handler boundaries.
- Kept atomic configuration memory/disk state aligned when post-replace ACL verification fails, then entered read-only protection.

## Phase 2 implemented scope (historical checkpoint)

- Added `localops/platform/windows.py` with Known Folder paths, current SID identity, protected DACL application/verification, Named Mutex locking, read-only snapshots, native picker, and exclusive socket configuration.
- Added exact Windows runtime pins: `psutil==7.2.2` and `pywin32==312`.
- Added native owner matching in the shared core without changing macOS numeric UID behavior.
- Added `platform` and `capabilities` to the state contract as an intentional additive Phase 2 API change.
- At the Phase 2 checkpoint, Windows launch, managed stop, force stop, external kill, external attach, console restart, and console stop were disabled at capability, HTTP, and browser-control boundaries. Phase 4 now enables only authenticated Local Ops Job launch/stop/force; the external and console-control restrictions remain.
- Separated connection state from degraded/configuration notices so a healthy HTTP connection is not mislabeled as disconnected.
- Added Windows tests for roots/UNC/junctions, Chinese/spaces paths, DACL principals, mutex recovery, IPv4/IPv6, protected/racing processes, picker cancellation, exclusive address use, read-only ACL failure, and no-side-effect route rejection.
- Added a direct Windows CI job using Python 3.12 without Make/Bash.

Local evidence: 16/16 Windows tests, 12/12 shared contract tests, 6/6 HTTP security tests, 7/7 Node port tests, 6/6 release/module checks, Ruff, compileall, platform-leak audit, diff checks, and the exact-candidate Win11 browser flow pass. The frontend contract is 15/16 solely because the known partial checkout still lacks the original `console-app-icon.png`; the project checker remains 9/11 because native Windows lacks `/bin/bash` and the original `AppIcon.icns` is not materialized.

## Phase 1 result

**P1 PASS — the platform boundary, complete macOS checks, release build, release verification, and reproducibility audit are green.**

Phase 1 extracted the platform boundary and passed its focused contract, golden, lint, and platform-leak checks. macOS CI run `31659571268` passed the full `make check` gate, all 170 Python tests, the release build and verification, and a second byte-for-byte reproducibility build.

## Phase 1 completed implementation

- Added typed platform contracts and structured scan states.
- Added a macOS adapter containing the original native path, lock, process, listener, cwd, launch, stop, picker, browser, launcher, and restart behavior.
- Added a fake platform covering success, permission denial, timeout, and partial snapshots.
- Added an explicit unsupported adapter so foreign-platform control paths fail closed during P1.
- Changed shared state assembly so partial/failed scan evidence becomes `degraded` rather than a false empty success.
- Added baseline-golden and direct-native-call checks.
- Added `localops/` to project syntax checks and the source release allowlist.

Focused evidence is green: 12/12 Python contract/golden tests, 2/2 launch-environment tests, 7/7 Node port tests, 6/6 release-manifest/project-binding tests, 6/6 HTTP security tests, Ruff, platform-leak check, and `git diff --check`.

The full native Windows Python run is intentionally not green in P1: 170 tests ran with 22 failures and 11 errors. The failures are dominated by the explicitly unsupported Windows adapter, POSIX lifecycle/mode/symlink assumptions, and missing tracked assets. This is not a P1 macOS regression verdict.

## Phase 0 result

**P0 PASS — baseline frozen and risks registered.**

This result does not mean that the product runs on Windows. Native Windows tests currently fail, lifecycle controls remain unimplemented, and `windowsBetaReady` remains `false`.

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
| Coverage gap | At the P0 checkpoint no macOS run, Win10 run, clean-VM run, or exact-commit CI run existed | Explicitly `NOT_RUN`; prevented Beta readiness at that checkpoint |

## P0 Gate

- [x] Test commands, counts, outcomes, and failure causes recorded.
- [x] No business code changed.
- [x] Existing user work preserved.
- [x] Platform coupling covers imports, callers, API impact, UI, build, and release.
- [x] Actual environment capability and unavailable evidence are explicit.
- [x] `STATE.json` matches the branch, baseline, changed files, and test status.

Gate decision: **PASS for Phase 0 only**. The next authorized unit of work is Phase 1 platform-contract extraction; it has not started.

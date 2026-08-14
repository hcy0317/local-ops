# Windows Port Decisions

## P5-D001 — Build one audited unsigned onedir archive

- Status: Accepted for the exact-CI engineering candidate
- Phase: P5
- Decision: Build on Windows Python 3.12 with a pinned PyInstaller toolchain as a windowed PE32+ x64 onedir bundle, then emit a deterministically ordered unsigned zip plus canonical checksum and manifest sidecars. Audit the version resource, architecture, embedded data, runtime distributions, license files, unsigned marker, unsafe paths, user data, logs, runtime records, credentials, caches, and absolute-path leakage before accepting an artifact.
- Reason: A source checkout that runs is not a distributable Windows product, and a self-contained archive is safe only when its exact contents and provenance are reviewable.
- Consequence: Build-only dependencies stay separate from runtime dependencies. The development artifact remains explicitly unsigned, and its final hashes must come from the exact current tree.

## P5-D002 — Preserve the real runner PID across a source venv redirector

- Status: Accepted for the exact-CI engineering candidate
- Phase: P5
- Decision: When `sys.executable` is a Windows venv redirector, launch the runner with the resolved base Python executable and set `__PYVENV_LAUNCHER__` to the venv interpreter. Resolve every target executable to an absolute path before suspended creation.
- Reason: The venv redirector exits after handing off to base Python, so persisting its short-lived PID breaks runner identity and Job ownership. Relative executable lookup can also change between validation and launch.
- Consequence: The recorded runner PID belongs to the long-lived interpreter while imports still use the intended venv. Failure to resolve an absolute executable fails before user code is created.

## P5-D003 — Give every runner a private console group

- Status: Accepted for the exact-CI engineering candidate
- Phase: P5
- Decision: The runner first calls `FreeConsole`, then creates its own `AllocConsole`, and only afterwards creates the managed target suspended and assigns it to the private Job.
- Reason: A runner that inherits the controller or test console cannot provide a stable private console process group for graceful control and may couple fixture behavior to an unrelated console lifetime.
- Consequence: Graceful console control stays scoped to the runner-owned generation, while explicit Force remains the separately authenticated Job termination path.

## P5-D004 — Reset frozen child state and declare dynamic imports

- Status: Accepted for the exact-CI engineering candidate
- Phase: P5
- Decision: A frozen console that launches the same executable as its runner sets `PYINSTALLER_RESET_ENVIRONMENT=1`; the build declares `win32timezone` as a hidden import and uses the dedicated packaged entry point to dispatch console or runner mode.
- Reason: Reusing the parent PyInstaller extraction environment can corrupt same-executable child startup, and dynamically imported pywin32 modules are not reliably discovered by static collection.
- Consequence: The packaged runner starts from a fresh frozen environment with the required Windows runtime modules present. Missing frozen-state or import evidence fails package tests/audit rather than surfacing on a user machine.

## P5-D005 — Keep local package evidence separate from Beta acceptance

- Status: Accepted; external release acceptance pending
- Phase: P5
- Decision: Treat read-only Chinese-and-space-path package smoke with a stripped child `PATH` as local package evidence only. It does not prove an independent clean VM without Python. Exact-commit common/macOS/Windows/package CI may close the engineering-candidate target and populate `implementationCommit`/`ciRun`, but keep `phaseStatus=IMPLEMENTED_UNVERIFIED` and `windowsBetaReady=false` until the external Windows 10, clean-VM, Defender/SmartScreen, native picker/notification, asset-review, and signing gates are complete.
- Reason: The smoke harness still has Python and test dependencies, and headless API contracts cannot prove OS integration or release reputation checks.
- Consequence: The exact-CI engineering candidate may have `scopedTargetStatus=PASS` while Phase 5 remains `IMPLEMENTED_UNVERIFIED` and `lastGreenPhase=P4`. No local or hosted result may be relabeled as Windows 10, clean-machine, signed, or Beta evidence.

## P4-D001 — Bind every managed app generation to one runner-owned Job

- Status: Accepted
- Phase: P4
- Decision: Create the target suspended, assign it to a private named Job, persist the exact 11-field identity, and only then authenticate resume. The independent runner is the only long-lived Job handle owner and writes protected receipts, while the HTTP console alone writes config through generation CAS.
- Reason: Console lifetime, PID lifetime, and process ancestry do not prove ownership. The runner/Job boundary lets services survive console closure while ensuring runner failure cleans only its own process tree.
- Consequence: Any identity, ACL, receipt, IPC, or persistence failure is fail closed and user code must not execute before commit.

## P4-D002 — Separate graceful stop from explicit force

- Status: Accepted
- Phase: P4
- Decision: Graceful timeout retains the same runtime identity and never escalates. Force repeats SID, generation, PID create-time, HMAC/receipt, and Job validation before terminating only that Job. External attach/kill remains unsupported.
- Reason: A delayed or ambiguous stop must not affect a newer generation or an unrelated process.
- Consequence: Every lifecycle mutation carries `expectedGeneration`; stale requests return mismatch without retry.

## P4-D003 — Gate destructive tests to isolated fixtures

- Status: Accepted
- Phase: P4
- Decision: Tests that exercise Job termination require `LOCALOPS_RUN_WINDOWS_LIFECYCLE_TESTS=1`, run only inside an isolated fixture scope or hosted runner, and may control only processes spawned by their fixtures.
- Reason: Lifecycle verification needs real Win32 primitives, but development validation must never target existing user processes.
- Consequence: Local/mock results alone cannot close Phase 4. Exact-commit isolated Windows and full macOS CI evidence are required; Windows 10, packaging, and Beta stay in Phase 5.

## P4-D004 — Commit release by atomic rename, then recover strict tombstones

- Status: Accepted
- Phase: P4
- Decision: Use a two-stage cleanup protocol. Before release, the active generation must contain exactly the three protected request, token, and receipt records; token digest, signed terminal receipt, exact public identity, terminal state, and empty Job must agree, and the runner must be absent. An atomic same-volume rename to the strictly derived cleanup tombstone is the release commit. After commit, recovery may delete only a private, nonlink tombstone containing an allowlisted subset of those three records and performs no process observation or control. Atomic request/receipt writers protect the temporary file before replacement, and all reconnect/recovery paths verify existing ACLs without repairing them.
- Reason: Configuration CAS may complete before physical record removal, and unlink/rmdir can partially fail after release. A single atomic commit point prevents identity restoration from racing partial deletion, while a committed tombstone can be finalized without treating filesystem residue as process authority.
- Consequence: Failure before rename leaves the authenticated active generation intact. Failure after rename remains a committed release and is retryable. Unknown entries, widened ACLs, links/junctions, non-derived paths, live or ambiguous active generations, logs, and unrelated files remain untouched.

## P4-D005 — Normalize only the administrator token's creation-time owner

- Status: Accepted
- Phase: P4
- Decision: Read both `TokenUser` and `TokenOwner` at platform initialization and accept only a default owner equal to the current user or Builtin Administrators. Windows assigns a newly created object from `TokenOwner`; only the creation-time apply path may normalize the Admin default owner to `TokenUser`, in the same security-descriptor update that applies the protected current-user + SYSTEM + Administrators DACL. Verify-only paths require the existing owner to equal `TokenUser` and reject Admin-owned records without repair.
- Alternatives rejected: Assuming `TokenUser` is always the new-object owner, accepting Admin ownership as private ownership, or repairing an existing record before trusting it.
- Reason: Hosted administrator tokens may default new objects to Builtin Administrators, while persisted runtime records must remain bound to the exact current user. Creation must work under both token shapes without weakening reconnect or cleanup verification.
- Consequence: Unsupported token owners fail platform initialization; creation can converge to the same current-user-owned protected descriptor, and every existing record remains verify-only and fail closed.

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

## P2-D001 — Use pinned native libraries for observation and Windows security

- Status: Accepted
- Phase: P2
- Decision: Use `psutil==7.2.2` for listener/process observation and `pywin32==312` for Known Folder resolution, SID/DACL operations, and Named Mutex security.
- Reason: Both libraries directly cover the required Windows primitives; replacing them with polling PowerShell/WMI subprocesses or a large custom `ctypes` layer would add latency and security-sensitive code without product value.
- Consequence: macOS remains dependency-free at runtime, while Windows installs only `requirements-windows.txt`.

## P2-D002 — Keep Windows lifecycle disabled at both adapter and HTTP boundaries

- Status: Accepted
- Phase: P2
- Decision: Report observation and picker capabilities, but keep launch, managed stop, force stop, external kill, external attach, console restart, and console stop unavailable. Reject their HTTP routes before scanning, persisting configuration, invoking a control adapter, or shutting down the console; browser controls must follow the same capability state.
- Reason: Phase 2 has no Windows runner, Job Object, generation token, or verified runtime identity. Adapter-only failure is too late for attach/create and running-card mutations that can write state first.
- Consequence: Windows is useful for read-only monitoring without creating a hidden path into unfinished process control.

## P2-D003 — Make Windows storage security verifiable and fail read-only

- Status: Accepted
- Phase: P2
- Decision: Store data under the Local AppData Known Folder, apply a protected DACL containing only the current SID, SYSTEM, and Administrators, and verify owner, ACE type, access mask, principals, and DACL protection. ACL verification failure disables configuration writes and log maintenance.
- Reason: POSIX mode bits do not prove Windows privacy, and continuing to write after an ACL failure could expose commands or logs to another local user.
- Consequence: `--prepare-storage` fails nonzero on an ACL issue; interactive startup may still expose diagnostics but remains in read-only protection.

## P2-D004 — Use SID plus data-directory identity for one writer

- Status: Accepted
- Phase: P2
- Decision: Name a session-local Windows Mutex from SHA-256(current SID + canonical data directory) and protect it with the same private principals.
- Reason: A port is not a writer lock, and a lock file alone does not provide reliable Windows crash recovery or per-user object security.
- Consequence: The second instance for the same user/data directory is rejected, while closing or crashing releases the kernel object automatically.

## P2-D005 — Optimize only the Windows origin scan that blocked real state delivery

- Status: Accepted
- Phase: P2
- Decision: Query listener process details normally, but build Windows PPID ancestry only for observed current-user listeners and do not fetch every ancestor command line in Phase 2.
- Reason: Full-machine `cmdline` enumeration took about five seconds on the real non-admin host and caused the first `/api/state` request to time out. SID-first filtering plus targeted PPID ancestry reduced repeated real state builds to under two seconds while preserving the required current-user service rows.
- Consequence: Windows Phase 2 origin badges are best-effort and may be absent; macOS attribution behavior is unchanged.

## P2-D006 — Keep connection truth separate from health notices

- Status: Accepted
- Phase: P2
- Decision: Track loopback connection state independently from the shared status banner. Degraded scans, read-only protection, backup recovery, and schema notices may show the banner without changing the connection indicator.
- Reason: A protected-process partial snapshot is a successful but degraded response. Treating any visible notice as a disconnect hides the distinction users need to decide whether data is stale or merely incomplete.
- Consequence: Windows can truthfully display both `已连接` and a degraded notice; actual poll failures and console transitions still switch the connection indicator to disconnected.

## P3-D001 — Add schema v2 without replacing legacy command data

- Status: Accepted
- Phase: P3
- Decision: Add `commandSpec`, `runtimeIdentity`, and `importStatus` through an idempotent v1→v2 migration while preserving the existing `command` field and macOS behavior. Explicit cross-platform imports clear runtime identity; an in-place migration does not guess a Windows owner from legacy PID/token fields.
- Reason: Existing configuration is user data and the macOS command string remains a compatibility asset, but stale process identity is not portable ownership proof.
- Consequence: Older clients retain display data, Windows receives a structured compatibility model, and Phase 4 must create a new validated runtime identity.

## P3-D002 — Keep command preparation structured and non-executing

- Status: Accepted
- Phase: P3
- Decision: Represent direct, structured cmd, structured PowerShell, raw shell, and legacy POSIX commands as a fixed tagged union. Structured argv stays as separate values and is never reconstructed by parsing the display string. Phase 3 may stat local files and PATH entries but never spawn, probe a version, access the network, or execute a command.
- Reason: cmd and PowerShell have incompatible expansion rules; a universal quoting helper would create injection and corruption risks.
- Consequence: POSIX/raw shell text remains review-only, unsafe cmd values fail closed, and UNC/device paths are rejected before any filesystem probe.

## P3-D003 — Make configuration import explicit and receipt-backed

- Status: Accepted
- Phase: P3
- Decision: Import only from an explicit local regular JSON file through deterministic preview, explicit path mappings, selected-app validation, target-hash CAS commit, private source/before/receipt records, and post-hash CAS rollback. Never auto-discover, overwrite an existing app ID, or import logs/process identity.
- Reason: Cross-platform migration is a data transaction, not a best-effort file copy. Users need to see blocked/review decisions before anything changes and must not lose edits made after import.
- Consequence: Preview is zero-write; commit and rollback are retryable/idempotent, including recoverable `prepared` states after transient writer or receipt failures.

## P3-D004 — Treat platform presentation as backend state

- Status: Accepted
- Phase: P3
- Decision: Return shortcut modifier, data/log paths, console-log path, launch instruction, and lifecycle notice in `platformInfo`; the browser consumes native picker/project fields without POSIX quoting, `/` path splitting, or `/Users` home inference.
- Reason: The backend owns native path and capability truth. Reconstructing it in JavaScript creates divergent and unsafe platform behavior.
- Consequence: Windows shows Ctrl, native paths, and accurate disabled-operation copy while macOS keeps its existing command/data fields.

## P3-D005 — Preserve the Phase 4 lifecycle boundary

- Status: Accepted
- Phase: P3
- Decision: Do not add a Windows runner, Job Object, generation, IPC controller, runtime receipt, or lifecycle side effect in Phase 3. Adapter capabilities, HTTP routes, and UI handlers continue to reject or hide start/stop/restart/attach/kill/console-control paths.
- Reason: A structured command is not process ownership. Safe Windows control requires the Phase 4 identity and generation model.
- Consequence: Phase 3 can be accepted independently while every Windows lifecycle request still fails before configuration or process mutation.

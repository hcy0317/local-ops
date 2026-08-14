# Local Ops API Contract v3

Status: Frozen Phase 4 implementation contract; local gate passed, exact-commit CI pending

Scope: Windows managed runner, Job Object ownership, generation compare-and-swap, protected runtime receipts, and lifecycle UI

This contract extends `API-CONTRACT-v2.md`. Schema v2, CommandSpec, picker,
project detection, and configuration import remain unchanged unless this file
explicitly says otherwise.

Out of scope: external process attach/kill, Windows console restart/stop
controls, Windows packaging, Windows 10 validation, and Beta readiness. Tests
may terminate and reopen only the isolated HTTP console subprocess they create;
this does not enable the Windows console-control API.

## Security invariants

- Windows controls only a process tree created by Local Ops in a dedicated
  Named Job Object.
- The target root process is created suspended. It is assigned to the Job and
  its runtime identity is atomically persisted before its first instruction is
  resumed.
- The runner is the only long-lived Job handle owner. Closing the HTTP console
  does not close the Job. Unexpected runner exit closes the Job with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
- The runner never writes `config.json`. It only writes protected, generation-
  bound runtime receipts. The HTTP console owns configuration compare-and-swap.
- The raw control token is at least 192 random bits. It is stored only in the
  protected runtime directory and runner memory. It never appears in config,
  API responses, process arguments, logs, diagnostics, or errors.
- Every control validates owner SID, generation, token digest and HMAC, runner
  PID/create-time, root PID/create-time, Job identity, and protected receipt.
- A port, PID, executable name, cwd, or process ancestry is never ownership
  proof. Partial scan data is never used to authorize control.
- `attach_external`, `kill_external`, and `restart_console` remain `false` on
  Windows in Phase 4.
- `launch_managed`, `stop_managed`, and `force_stop_managed` are enabled only
  for a fully verified Local Ops Job. They do not authorize PID-, port-, name-,
  cwd-, or ancestry-based control.

## Persisted runtime identity

`runtimeIdentity` remains part of schema v2 and is either `null` or this exact
tagged object:

```json
{
  "platform": "windows",
  "kind": "job",
  "ownerSid": "S-1-5-21-example",
  "generationId": "3d6448f0-87a0-4ace-baad-3b80abca9e3e",
  "runnerPid": 1234,
  "runnerCreateTime": 1780000000.123,
  "rootPid": 5678,
  "rootCreateTime": 1780000001.456,
  "jobName": "Local\\LocalOps-deadbeef-3d6448f0-87a0-4ace-baad-3b80abca9e3e-0123456789abcdef",
  "tokenDigest": "sha256:0123456789abcdef000000000000000000000000000000000000000000000000",
  "startedAt": 1780000001456
}
```

The object has exactly these 11 public fields: `platform`, `kind`, `ownerSid`,
`generationId`, `runnerPid`, `runnerCreateTime`, `rootPid`, `rootCreateTime`,
`jobName`, `tokenDigest`, and `startedAt`. `jobName` contains the complete
canonical generation UUID followed by the first 16 hexadecimal characters of
the token digest. The raw token, pipe name, runtime directory, and receipt path
are never public identity fields.

Unknown fields, invalid types, non-UUID generations, non-current owner SIDs,
non-positive PIDs/times, unsafe Job names, and malformed digests are rejected.
Legacy PID/PGID/runToken fields remain for macOS compatibility but never prove
Windows ownership.

The protected runtime directory is derived from app ID and generation; it is
not stored in the public identity. It contains only bounded JSON/binary files:

- `request.json`: immutable structured invocation and non-secret launch data;
- `token.bin`: raw random token;
- `receipt.json`: runner state and non-secret identity/exit information.

Every directory/file must retain the current-user + SYSTEM + Administrators
protected DACL. A widened, unreadable, linked, junction-backed, or malformed
runtime record disables control.

Atomic `request.json` and `receipt.json` writes apply and verify the private
DACL on the temporary file before `os.replace` makes it visible. Existing
records are checked through verify-only paths; a widened ACL is never silently
repaired during reconnect or control.

Runtime release is a two-stage protocol:

1. Before release commit, the active generation directory must contain exactly
   the three private records above. The token digest, signed terminal receipt,
   exact public identity, terminal state, and empty Job must agree, and the
   runner must be absent. An atomic same-volume rename from the active
   generation path to the strictly derived cleanup tombstone is the release
   commit. Failure before that rename leaves the active generation intact and
   does not report release success.
2. After release commit, recovery may remove only a tombstone directly under
   the runtime root whose name is strictly derived from the validated app ID
   and generation UUID, whose directory and remaining entries are private and
   nonlink, and whose entries are a subset of `request.json`, `token.bin`, and
   `receipt.json`. Tombstone recovery performs no process observation or
   process control. Unknown entries, widened ACLs, links/junctions, or a path
   outside this derivation fail closed and leave the tombstone untouched.

Discovery of an active terminal generation may perform the ownership checks
required by stage 1. A committed tombstone is deletion evidence only; it never
becomes authority to open a Job, inspect a PID, or control a process.

## Runner receipt state machine

Receipt states are:

```text
prepared -> running -> stopping -> exited
    |          |          |
    +----------+----------+-> failed
```

- `prepared`: pipe and Job exist; root is suspended and assigned; config must
  persist the exact identity before `resume` is accepted.
- `running`: resume succeeded and the Job still has members.
- `stopping`: an authenticated graceful or force request is in progress.
- `exited`: the Job is empty; receipt contains an exit reason/code when known.
- `failed`: launch/control failed; receipt contains a bounded stable error code.

The runner writes receipts atomically. Receipt generation and identity must
exactly match config. A controller restart renders a matching `prepared`
generation as `starting` but does not resume it automatically; its bounded TTL
terminates the still-suspended Job, after which terminal reconciliation clears
the identity. User code never runs without the original authenticated resume.

## State response

Each `/api/state` app adds:

```json
{
  "runtimeIdentity": null,
  "lifecycleStatus": "stopped",
  "controlAvailable": true,
  "runtimeIssue": null
}
```

`lifecycleStatus` is one of:

- `stopped`: no runtime identity; start/delete may compare against `null`;
- `starting`: verified prepared generation; controls disabled;
- `running`: verified authenticated Job with members;
- `stopping`: verified stop operation in progress; controls disabled;
- `orphaned`: a runtime may exist but complete ownership proof failed;
- `unknown`: receipt/IPC/scan state is incomplete or temporarily unavailable.

`running` remains for older clients and is `true` only for verified `running`
or `stopping`. `controlAvailable` is `true` only for `stopped` or fully verified
`running`. `orphaned` and `unknown` must never be rendered as stopped or made
controllable. `runtimeIssue` exposes only a stable code and safe message.

## Generation compare-and-swap

On Windows, every start, stop, force, restart, running-config update, and delete
request must contain an `expectedGeneration` member. The member itself is
required; its value is:

- `null` when the user observed a stopped app;
- the exact generation UUID when the user observed a verified managed runtime.

Missing or malformed values fail before process, receipt, log, or config side
effects. A mismatch returns HTTP 409 `GENERATION_MISMATCH` and is never retried
automatically. The generation is frozen when user intent/confirmation begins;
the UI must not silently substitute a newer generation.

macOS accepts the additive member but preserves its existing lifecycle and
legacy clients.

## Lifecycle endpoints

### Start

`POST /api/apps/{id}/start`

```json
{"expectedGeneration": null}
```

Success:

```json
{
  "ok": true,
  "pid": 5678,
  "generationId": "3d6448f0-87a0-4ace-baad-3b80abca9e3e",
  "lifecycleStatus": "running"
}
```

Start performs static preflight, creates the protected request/token, launches
the runner, waits for `prepared`, persists the exact identity with a null-
generation CAS, authenticates `resume`, and verifies the resulting state.
Failure before persisted identity aborts the suspended Job. Failure after the
config commit reconciles from the protected receipt and never guesses success.

### Graceful stop and explicit force

`POST /api/apps/{id}/stop`

```json
{
  "expectedGeneration": "3d6448f0-87a0-4ace-baad-3b80abca9e3e",
  "force": false
}
```

`force` defaults to `false`. Graceful stop authenticates the runner, attempts
the compatible console protocol, waits a bounded interval, and clears identity
only after the verified Job is empty. Timeout returns HTTP 409 `STOP_TIMEOUT`,
keeps identity, and never escalates automatically.

`force:true` is a distinct explicit operation guarded by
`force_stop_managed`. It repeats every identity check, terminates only the
verified Job, confirms it is empty, and then clears the same generation.

### Restart

`POST /api/apps/{id}/restart`

```json
{"expectedGeneration": "3d6448f0-87a0-4ace-baad-3b80abca9e3e"}
```

Restart preflights before stopping, gracefully stops the expected generation,
and starts a new UUID generation only after the old identity is cleared. Stop
timeout or mismatch leaves the old generation intact and does not start.

### Update and delete

`PUT /api/apps/{id}` with `stopBeforeUpdate:true` must include the observed
`expectedGeneration`. A stopped lifecycle update includes
`expectedGeneration:null` when present but does not require a stop.

`DELETE /api/apps/{id}` consumes JSON:

```json
{"expectedGeneration": null}
```

or the exact running generation. Running delete uses graceful stop only; a
timeout cancels deletion. Force stop is an explicit prior action. The server
must consume the DELETE body before the next keep-alive request.

## Stable lifecycle errors

All errors keep the existing shape:

```json
{"ok": false, "error": "Safe message", "code": "GENERATION_MISMATCH"}
```

| Code | HTTP | Meaning |
| --- | ---: | --- |
| `GENERATION_REQUIRED` | 400 | `expectedGeneration` member is missing or malformed |
| `GENERATION_MISMATCH` | 409 | Observed generation no longer matches config |
| `APP_OPERATION_IN_PROGRESS` | 409 | Another serialized app mutation is active |
| `RUNTIME_IDENTITY_INVALID` | 409 | Stored identity does not match the tagged schema |
| `RUNTIME_IDENTITY_UNVERIFIED` | 409 | SID/PID-time/token/IPC/Job/receipt proof is incomplete |
| `RUNTIME_RECORD_INSECURE` | 409 | Runtime path or ACL verification failed |
| `LAUNCH_PREPARE_FAILED` | 500 | Runner could not prepare a suspended assigned Job |
| `LAUNCH_COMMIT_FAILED` | 409 | Identity could not be persisted before resume |
| `LAUNCH_ACTIVATE_FAILED` | 500 | Persisted prepared generation could not be resumed/reconciled |
| `STOP_TIMEOUT` | 409 | Graceful stop timed out; identity was retained |
| `RUNTIME_CONTROL_FAILED` | 500 | Authenticated runner control failed without proven completion |

Errors never expose raw tokens, HMACs, runtime paths, command output, stack
traces, or unbounded OS messages.

## UI contract

- Lifecycle actions require both the global capability and per-app
  `lifecycleStatus/controlAvailable` state.
- Generation mismatch, network ambiguity, and HTTP 5xx trigger one fresh state
  read and no mutation retry.
- Force is offered only after `STOP_TIMEOUT`, only if the same verified
  generation remains, and always requires a second explicit confirmation.
- Batch stop snapshots each app generation independently.
- External attach/kill controls remain hidden on Windows.

## Phase 4 acceptance boundary

- `WIN-LIFE-001..012` and `WIN-SEC-001..014` operate only processes created
  inside an isolated fixture scope or hosted runner; existing user processes
  are never valid test targets.
- Python and Node fixtures cover Job membership, background children, console
  closure/reopen, reconnect, timeout, force, runner crash, stale generation,
  transaction failure, atomic release commit, tombstone recovery, and repeated
  cleanup.
- No `taskkill /T`, bare-PID `TerminateProcess`, Windows `os.kill(pid, 0)`, or
  `psutil.children()` ownership proof exists.
- Node/frontend contracts cover every lifecycle caller and stale-state error.
- Exact-commit Windows Python 3.12 and complete macOS regression/release CI are
  required before Phase 4 PASS.
- `windowsBetaReady` remains `false`; packaging and Windows 10 are Phase 5.

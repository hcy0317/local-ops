# API Contract v2

Status: Phase 3 implementation contract

Scope: schema, command description, import, path selection, and compatible UI
Out of scope: Windows process start, stop, restart, attach, Job Objects, and runner IPC

## Compatibility rules

- Schema v2 is an additive change. Existing `command` fields and the
  `{ "ok": false, "error": "..." }` error envelope remain available.
- New errors add a stable `code` string. Clients must use `code` for behavior
  and may display `error` to the user.
- Existing macOS commands keep their legacy execution behavior. Windows never
  executes a legacy command string in Phase 3.
- Phase 3 exposes command data and static validation only. Windows lifecycle
  capabilities remain `false`, and lifecycle routes reject before changing
  configuration or process state.
- Unknown fields are ignored on input unless this contract explicitly rejects
  them. Existing response fields are not renamed or removed.

## Configuration schema v2

The top-level shape remains compatible with v1. Each normalized app adds three
fields:

```json
{
  "schemaVersion": 2,
  "apps": [
    {
      "id": "deadbeef",
      "name": "Example",
      "kind": "service",
      "cwd": "C:\\Projects\\example",
      "port": 3000,
      "command": "python -m http.server 3000",
      "commandSpec": {
        "version": 1,
        "mode": "direct",
        "executable": "python.exe",
        "args": ["-m", "http.server", "3000"],
        "shell": null,
        "text": null,
        "needsReview": false
      },
      "runtimeIdentity": null,
      "importStatus": "ready"
    }
  ]
}
```

`runtimeIdentity` is always `null` for newly migrated or imported records in
Phase 3. A future schema may store a validated runtime identity; Phase 3 must
not synthesize one from a PID, port, command, or legacy token.

`importStatus` is one of:

- `ready`: the structured command and mapped path pass static validation;
- `needs_review`: a human must confirm or replace a legacy/platform-specific
  command before it can become runnable on Windows;
- `blocked`: required command or path data is missing or invalid.

### Migration

- v1 to v2 is a pure, deterministic, version-by-version migration.
- Existing v1 `command` strings are preserved exactly.
- Existing macOS/POSIX strings become `legacy-posix` command specs with
  `needsReview: true`; migration never rewrites or executes them.
- `lastPid`, `lastPgid`, `runToken`, and `attached` remain unchanged for the
  normal in-place macOS migration so the existing macOS runtime can reconnect.
- Running the v2 normalizer or migration again is idempotent.
- A schema newer than v2 enters the existing read-only protection path and is
  never replaced by an older backup.
- Migration performs no network access and starts no command.

## CommandSpec v1

All modes use the same fixed keys:

```json
{
  "version": 1,
  "mode": "direct | cmd | powershell | legacy-posix",
  "executable": "string or null",
  "args": ["literal", "arguments"],
  "shell": "cmd.exe | powershell.exe | null",
  "text": "shell text or null",
  "needsReview": false
}
```

Validation rules:

| Mode | Required | Forbidden | Phase 3 Windows status |
| --- | --- | --- | --- |
| `direct` | non-empty `executable`, string `args` | `shell`, `text` | `ready` after static path checks |
| `cmd` | `shell=cmd.exe`; exactly one of a `.cmd/.bat` `executable` plus literal `args`, or non-empty raw `text` | mixing structured script data with raw `text` | structured scripts can be `ready`; raw text requires explicit review |
| `powershell` | `shell=powershell.exe`; exactly one of a `.ps1` `executable` plus literal `args`, or non-empty raw `text` | mixing structured script data with raw `text` | structured scripts can be `ready`; raw text requires explicit review |
| `legacy-posix` | string `text`, `needsReview=true` | Windows execution | `needs_review` |

Structured arguments are data. Spaces, Chinese text, and
`& | < > ^ ( ) % ! ' " ` $ ;` remain literal array elements and are never
round-tripped through a display string or POSIX quoting.

The future Windows runner will construct these fixed prefixes while preserving
the structured script and argument fields until the native quoting boundary:

- `cmd`: `%COMSPEC% /d /s /c <text>`;
- `powershell`: `powershell.exe -NoLogo -NoProfile -NonInteractive ...`.

Phase 3 may return a prepared direct argv or a structured shell invocation for
preflight diagnostics, but must not flatten a structured shell script into a
display string and parse it again, and must not spawn it. It must not add
PowerShell execution-policy bypass flags. Raw shell `text` never receives
interpolated path or argument data from the server.

## Platform compatibility

App state, picker results, and project-detection candidates may add:

```json
{
  "platformCompatibility": {
    "status": "ready | needs_review | blocked",
    "reasons": [
      {"code": "LEGACY_POSIX_COMMAND", "message": "Review this command for Windows."}
    ]
  }
}
```

`reasons` is an ordered list. Known reason codes are:

- `LEGACY_POSIX_COMMAND`
- `PATH_MAPPING_REQUIRED`
- `PATH_NOT_FOUND`
- `COMMAND_SPEC_INVALID`
- `UNSUPPORTED_SCRIPT_TYPE`

## State contract

`GET /api/state` keeps all existing fields and adds or preserves:

```json
{
  "schemaVersion": 2,
  "platform": "windows",
  "capabilities": {
    "monitor_processes": true,
    "launch_managed": false,
    "stop_managed": false,
    "force_stop_managed": false,
    "kill_external": false,
    "attach_external": false,
    "pick_path": true,
    "restart_console": false
  },
  "platformInfo": {
    "shortcutModifier": "Ctrl",
    "dataDir": "C:\\Users\\example\\AppData\\Local\\LocalOps",
    "logsDir": "C:\\Users\\example\\AppData\\Local\\LocalOps\\logs",
    "consoleLogPath": "C:\\Users\\example\\AppData\\Local\\LocalOps\\logs\\console.log",
    "launchInstruction": "Run the Windows source launcher.",
    "lifecycleNotice": "Process control is unavailable in this phase."
  },
  "apps": [
    {
      "command": "legacy display string",
      "commandSpec": {},
      "runtimeIdentity": null,
      "importStatus": "ready",
      "platformCompatibility": {"status": "ready", "reasons": []}
    }
  ]
}
```

These are the adapter's existing capability keys. Phase 3 does not rename or
alias them.

`platformInfo` contains presentation data that depends on native paths or the
source launcher. The browser must not recreate native paths or hard-code a
`.app`, `~/Library`, signal, or shell-specific instruction.

## Picker and project detection

`POST /api/pick` keeps the request `{ "what": "dir | script" }`.

A successful directory result is:

```json
{
  "ok": true,
  "canceled": false,
  "path": "C:\\Projects\\example",
  "dir": "C:\\Projects",
  "stem": "example"
}
```

A successful script result also includes the legacy display `command`, a
validated `commandSpec`, and `platformCompatibility`. Cancellation remains
`{ "ok": true, "canceled": true }` and has no side effect.

`POST /api/project/detect` keeps its existing response and adds
`commandSpec` and `platformCompatibility` to every candidate. The candidate's
`command` is display/legacy data only. Windows candidates include supported
`.cmd`, `.bat`, `.ps1`, native executable, Node shim, and explicit Python
launcher forms without executing them.

## Explicit macOS configuration import

Import never auto-discovers a source, never imports logs, and never overwrites
an existing target app. Browser requests require the existing same-origin
control session. Headerless loopback CLI JSON remains compatible and is still
subject to the existing Host, content-type, and bounded-body checks.

### Preview

`POST /api/config/import/preview`

```json
{
  "sourcePath": "D:\\Transfer\\config.json",
  "pathMappings": [
    {"sourceRoot": "/Volumes/Workspace/Projects", "targetRoot": "D:\\Projects"}
  ]
}
```

The source must be an explicit local regular JSON file no larger than 1 MiB.
UNC shares, device namespaces, directories, symlinks, and implicit discovery
are rejected before reading. Windows mapping targets must also be local
absolute paths. A preview:

- parses and validates the source without mutating the target configuration;
- computes `sourceHash` from the exact source bytes;
- maps each absolute macOS `cwd` only through an explicit root mapping;
- clears imported runtime/process identity in the preview;
- marks each app `ready`, `needs_review`, `blocked`, or `conflict`;
- returns a deterministic `previewId` bound to the source hash, normalized
  mappings, target-config hash, and previewed app decisions;
- writes no target config, staging file, receipt, source backup, or log.

```json
{
  "ok": true,
  "previewId": "sha256:...",
  "sourceHash": "sha256:...",
  "targetHash": "sha256:...",
  "apps": [],
  "summary": {"ready": 0, "needs_review": 0, "blocked": 0, "conflict": 0}
}
```

### Commit

`POST /api/config/import/commit`

```json
{
  "sourcePath": "D:\\Transfer\\config.json",
  "pathMappings": [],
  "previewId": "sha256:...",
  "selectedAppIds": ["deadbeef"]
}
```

Commit rebuilds the preview and rejects a changed source, mapping, target, or
selection. Only selected `ready` or `needs_review` apps that do not conflict
with an existing target ID are appended in source order. A commit:

1. copies the exact source bytes to a private, read-only import source record;
2. writes a private pre-import configuration backup and receipt;
3. creates and fully validates a staged v2 configuration;
4. atomically replaces the target through the existing configuration writer;
5. records pre/post hashes for rollback and idempotency.

Imported records preserve IDs, names, kind, ports, icons, theme/order metadata,
and other safe UI metadata. They clear `lastPid`, `lastPgid`, `runToken`,
`attached`, `runtimeIdentity`, and old running state. Top-level `hidden`,
`pinned`, and `promoted` entries are not imported because they may refer to old
process keys. POSIX commands are preserved as review-only data.

Recommitting an already committed `sourceHash` and selection returns the prior
`importId` with `idempotent: true` and does not append duplicate apps.
Receipt matching hashes the already-normalized target snapshot without
re-running cwd, executable, PATH, or other environment probes. Only a genuinely
new commit rebuilds the dynamically validated preview.
If the live config crossed its atomic replace point but receipt finalization
failed, a later identical request reconciles the `prepared` receipt against
the current config hash before returning idempotent success.

### Rollback

`POST /api/config/import/rollback`

```json
{"importId": "123e4567-e89b-42d3-a456-426614174000"}
```

Rollback restores the exact private pre-import backup only when the current
configuration hash equals the receipt's post-import hash. A later config edit
causes `IMPORT_ROLLBACK_CONFLICT`; the service never discards later user work.
Current and backup hashes are deterministic and do not re-run environment
preflight, so a PATH or filesystem availability change is not mistaken for a
configuration edit.
Repeating a completed rollback returns success with `idempotent: true`.
`rollback_prepared` remains retryable when the target still has the committed
post-import hash; a transient writer failure cannot permanently poison the
receipt.

## Stable error codes

All new Phase 3 failures use:

```json
{"ok": false, "error": "Human-readable message", "code": "INVALID_REQUEST"}
```

| Code | HTTP | Meaning |
| --- | ---: | --- |
| `INVALID_REQUEST` | 400 | Invalid JSON shape or field value |
| `INVALID_PATH` | 400 | Path is unsafe, unsupported, or not an explicit file |
| `PICKER_UNAVAILABLE` | 500 | Native picker failed before returning a path or cancellation |
| `COMMAND_SPEC_INVALID` | 400 | CommandSpec violates the tagged-union contract |
| `CAPABILITY_DISABLED` | 409 | The platform or current phase disables the operation |
| `CONFIG_READ_ONLY` | 409 | Protected config cannot be changed |
| `IMPORT_SOURCE_INVALID` | 400 | Source config cannot be parsed or normalized safely |
| `IMPORT_SOURCE_CHANGED` | 409 | Source bytes no longer match the preview |
| `IMPORT_PREVIEW_STALE` | 409 | Mapping or target config changed after preview |
| `IMPORT_SELECTION_INVALID` | 400 | Selection contains missing, blocked, or conflicting apps |
| `IMPORT_COMMIT_FAILED` | 500 | Staging, backup, validation, or atomic commit failed |
| `IMPORT_RECEIPT_NOT_FOUND` | 404 | Import receipt is absent or invalid |
| `IMPORT_ROLLBACK_CONFLICT` | 409 | Target changed after the import |
| `IMPORT_ROLLBACK_FAILED` | 500 | Validated rollback could not be committed atomically |

Internal paths, command output, stack traces, tokens, and runtime secrets are
never returned in an error.

## Generation semantics reserved for Phase 4

`generationId` identifies one managed runtime generation. In Phase 4, every
start, stop, restart, and delete operation for a running app will require the
caller's `expectedGeneration`, and a mismatch will fail without side effects.

Phase 3 does not create a generation, token, runner, Job Object,
runtime/lifecycle receipt, or runtime identity. Import transaction receipts
are configuration recovery metadata and do not establish process ownership.
This section reserves the meaning so Phase 3 configuration and UI cannot
accidentally assign weaker PID-only ownership semantics.

## Phase 3 acceptance boundary

- Schema and import code never run a command or access the network.
- Windows lifecycle and external-attach controls remain disabled in adapter,
  HTTP, and UI boundaries.
- Command generation has deterministic unit tests for spaces, Chinese text,
  and shell metacharacters.
- Import preview, commit, idempotency, and rollback use isolated test data.
- macOS legacy API fields and UI flows remain available.
- No Phase 4 runner or process-control module is added in this phase.

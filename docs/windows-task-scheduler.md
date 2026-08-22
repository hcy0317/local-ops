# Windows Task Scheduler monitoring

Local Ops can represent an existing Windows Task Scheduler registration as a launchpad card without taking ownership of the task's process tree.

## Configuration

An app may contain an optional canonical task path:

```json
{
  "kind": "service",
  "scheduledTaskPath": "\\Memos-Guard"
}
```

The server derives the display command and structured command from this path. `cwd` and `port` are `null`. A missing or disabled registration is a blocking card-health issue, but it is never treated as a stopped Local Ops Job.

Use `kind: "service"` for a continuously running Guard. Use `kind: "task"` for a one-shot import, synchronization, backup, or automation entry.

## Read API

`GET /api/windows/scheduled-tasks` returns non-Microsoft registrations by default. `?includeSystem=1` includes the `\\Microsoft\\` tree. The response contains the native task path, state, enabled flag, last and next run times, last result, run level, multiple-instance policy, actions, and running engine PIDs.

`GET /api/state` adds these fields to an associated app:

```json
{
  "runtimeSource": "windowsTaskScheduler",
  "scheduledTaskPath": "\\Memos-Guard",
  "scheduledTask": {
    "state": "running",
    "enabled": true,
    "runLevel": "highest",
    "multipleInstances": "ignoreNew",
    "enginePids": [1234]
  }
}
```

The state is one of `unknown`, `missing`, `disabled`, `queued`, `ready`, or `running`.

## Logs and run history

`GET /api/apps/{id}/logs?tail=300` combines three sources for a scheduled-task
card:

- Local Ops controller audit records for run, stop, enable, disable, and errors.
- Structured events from `Microsoft-Windows-TaskScheduler/Operational`, including
  trigger, task start, process creation, action start/completion, task completion,
  PID, timestamp, and result code when present.
- The current COM state, last run time, and last result.

Local Ops parses event XML directly and supplies its own stable labels. It does
not depend on localized rendered Event Log messages, so non-UTF console encodings
cannot corrupt the log drawer. The target task definition and action command are
never changed or wrapped, which means stdout/stderr still belong to the task's
own script or program when it writes them.

The response includes `taskHistory` metadata with `enabled`, `available`,
`partial`, `eventCount`, and structured issues. When the Operational channel is
disabled, the log drawer shows the retained historical records and an explicit
`启用任务历史` action. `POST /api/apps/{id}/scheduled-history` with
`{"enabled": true}` enables that Windows event channel using fixed `wevtutil`
arguments; it does not modify any task registration. Events that occurred while
history was disabled cannot be reconstructed, but future runs are recorded by
Windows even when Local Ops is closed.

## Lifecycle boundary

`POST /api/apps/{id}/start` with `{"expectedGeneration": null}` calls the Task Scheduler COM `Run` method. The registered task's security principal, run level, triggers, conditions, and multiple-instance policy remain authoritative.

`POST /api/apps/{id}/stop` with `{"expectedGeneration": null, "force": false}` calls the Task Scheduler COM `Stop(0)` method for that exact registration. It stops the task's current running instances without disabling, changing, or unregistering the task. Force-stop, restart, attach, and PID-based kill remain unsupported because these processes are external to the Local Ops Job Object.

`POST /api/apps/{id}/scheduled-enabled` with `{"enabled": true|false}` changes only the exact registration's `Enabled` property. It does not run or stop an instance and does not modify triggers, actions, principal, run level, conditions, or multiple-instance policy.

Deleting a card removes only Local Ops configuration and never stops, disables, or unregisters the Windows task. A completed Local Ops task whose authenticated runtime receipt is terminal may also be removed while protected runner-record cleanup continues in the background; this path never gains process-control authority.

Capabilities are advertised independently as `monitor_scheduled_tasks`,
`run_scheduled_tasks`, `stop_scheduled_tasks`, `toggle_scheduled_tasks`, and
`manage_scheduled_task_history`.

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

## Lifecycle boundary

`POST /api/apps/{id}/start` with `{"expectedGeneration": null}` calls the Task Scheduler COM `Run` method. The registered task's security principal, run level, triggers, conditions, and multiple-instance policy remain authoritative.

Scheduled-task cards do not support Local Ops stop, force-stop, restart, attach, or PID-based kill. Their processes are external to the Local Ops Job Object. Deleting a card removes only Local Ops configuration and never stops, disables, or unregisters the Windows task.

Capabilities are advertised independently as `monitor_scheduled_tasks` and `run_scheduled_tasks`.

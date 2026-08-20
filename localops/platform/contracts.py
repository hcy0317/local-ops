"""Typed operating-system boundary for the shared HTTP and domain core."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Mapping, Protocol, Sequence


class ScanStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class PlatformIssue:
    component: str
    code: str
    message: str
    degrades: bool = True


@dataclass(frozen=True)
class RuntimePaths:
    data_dir: str
    logs_dir: str
    runtime_dir: str


@dataclass(frozen=True)
class Principal:
    identifier: str
    numeric_id: int | None = None


class InstanceLock(Protocol):
    def release(self) -> None: ...


ListenerMap = dict[tuple[int, int], set[str]]
ProcessMap = dict[int, dict[str, object]]


@dataclass(frozen=True)
class ListenerSnapshot:
    status: ScanStatus
    listeners: ListenerMap = field(default_factory=dict)
    issues: tuple[PlatformIssue, ...] = ()


@dataclass(frozen=True)
class ProcessSnapshot:
    status: ScanStatus
    processes: ProcessMap = field(default_factory=dict)
    issues: tuple[PlatformIssue, ...] = ()


@dataclass(frozen=True)
class CwdSnapshot:
    status: ScanStatus
    cwds: dict[int, str | None] = field(default_factory=dict)
    issues: tuple[PlatformIssue, ...] = ()


@dataclass(frozen=True)
class ScheduledTaskSnapshot:
    status: ScanStatus
    tasks: dict[str, dict[str, object]] = field(default_factory=dict)
    issues: tuple[PlatformIssue, ...] = ()


@dataclass(frozen=True)
class ScheduledTaskRunResult:
    ok: bool
    task_path: str
    error: str | None = None
    code: str | None = None


@dataclass(frozen=True)
class PickResult:
    path: str | None = None
    canceled: bool = False
    issue: PlatformIssue | None = None


@dataclass(frozen=True)
class LaunchRequest:
    app_id: str
    command: str
    cwd: str
    log_path: str
    command_spec: Mapping[str, object] | None = None
    generation_id: str | None = None


@dataclass(frozen=True)
class ManagedRuntime:
    ok: bool
    error: str | None = None
    process: object | None = None
    process_id: int | None = None
    group_id: int | None = None
    token: str | None = None
    runtime_identity: RuntimeIdentity | None = None
    status: str | None = None
    code: str | None = None


@dataclass(frozen=True)
class RuntimeIdentity:
    platform: str
    kind: str
    identifier: int | str
    owner: str
    members: tuple[int, ...] = ()
    token: str | None = None
    app_id: str | None = None
    generation_id: str | None = None
    runner_pid: int | None = None
    runner_create_time: float | None = None
    root_pid: int | None = None
    root_create_time: float | None = None
    job_name: str | None = None
    token_digest: str | None = None
    started_at: int | None = None


WINDOWS_RUNTIME_IDENTITY_FIELDS = (
    "platform",
    "kind",
    "ownerSid",
    "generationId",
    "runnerPid",
    "runnerCreateTime",
    "rootPid",
    "rootCreateTime",
    "jobName",
    "tokenDigest",
    "startedAt",
)


def windows_runtime_identity_public(identity: RuntimeIdentity) -> dict[str, object]:
    """Return the exact public Windows identity; never serialize internal context."""
    if identity.platform != "windows" or identity.kind != "job":
        raise ValueError("not a Windows Job identity")
    if identity.token is not None:
        raise ValueError("Windows runtime identities must not contain raw tokens")
    values: dict[str, object | None] = {
        "platform": identity.platform,
        "kind": identity.kind,
        "ownerSid": identity.owner,
        "generationId": identity.generation_id,
        "runnerPid": identity.runner_pid,
        "runnerCreateTime": identity.runner_create_time,
        "rootPid": identity.root_pid,
        "rootCreateTime": identity.root_create_time,
        "jobName": identity.job_name,
        "tokenDigest": identity.token_digest,
        "startedAt": identity.started_at,
    }
    if any(value is None for value in values.values()):
        raise ValueError("Windows runtime identity is incomplete")
    return {name: values[name] for name in WINDOWS_RUNTIME_IDENTITY_FIELDS}


@dataclass(frozen=True)
class ManagedActivation:
    ok: bool
    error: str | None = None
    status: str | None = None
    code: str | None = None
    process_id: int | None = None


@dataclass(frozen=True)
class ManagedInspection:
    running: bool
    verified: bool
    members: tuple[int, ...] = ()
    issue: PlatformIssue | None = None
    status: str = "unknown"
    identity: RuntimeIdentity | None = None
    code: str | None = None
    exit_code: int | None = None
    updated_at: int | None = None


@dataclass(frozen=True)
class StopResult:
    ok: bool
    error: str | None = None
    still_running: bool = False
    status: str | None = None
    code: str | None = None


@dataclass(frozen=True)
class RestartResult:
    ok: bool
    helper_pid: int | None = None
    error: str | None = None


@dataclass(frozen=True)
class PlatformCapabilities:
    monitor_processes: bool = False
    launch_managed: bool = False
    stop_managed: bool = False
    force_stop_managed: bool = False
    kill_external: bool = False
    attach_external: bool = False
    pick_path: bool = False
    restart_console: bool = False
    monitor_scheduled_tasks: bool = False
    run_scheduled_tasks: bool = False
    stop_scheduled_tasks: bool = False


class PlatformUnavailable(RuntimeError):
    """The current adapter cannot safely perform the requested operation."""


class PlatformScanError(RuntimeError):
    def __init__(self, issues: Sequence[PlatformIssue]):
        self.issues = tuple(issues)
        message = "; ".join(issue.message for issue in self.issues)
        super().__init__(message or "platform scan failed")


class PlatformBackend(Protocol):
    name: str
    capabilities: PlatformCapabilities
    requires_verified_permissions: bool

    def runtime_paths(self) -> RuntimePaths: ...
    def current_principal(self) -> Principal: ...
    def validate_runtime_path(self, path: str, forbidden: set[str]) -> str: ...
    def ensure_private_directory(self, path: str) -> None: ...
    def ensure_private_file(self, path: str) -> None: ...
    def should_migrate_legacy_data(self) -> bool: ...
    def acquire_instance_lock(self, identity: str) -> InstanceLock | None: ...
    def scan_listeners(self) -> ListenerSnapshot: ...
    def process_snapshot(
        self, pids: set[int] | None = None, *, with_owner: bool = True,
    ) -> ProcessSnapshot: ...
    def processes_matching_keywords(self, keywords: Sequence[str]) -> ProcessSnapshot: ...
    def process_cwds(self, pids: set[int]) -> CwdSnapshot: ...
    def process_parents(self, pids: set[int] | None = None) -> ProcessSnapshot: ...
    def process_groups(self) -> ProcessSnapshot: ...
    def launch(self, app: LaunchRequest) -> ManagedRuntime: ...
    def activate_managed(self, identity: RuntimeIdentity) -> ManagedActivation: ...
    def abort_managed(self, identity: RuntimeIdentity) -> StopResult: ...
    def release_managed(self, identity: RuntimeIdentity) -> StopResult: ...
    def recover_managed_cleanups(self) -> tuple[RuntimeIdentity, ...]: ...
    def inspect_managed(self, identity: RuntimeIdentity) -> ManagedInspection: ...
    def stop_managed(
        self, identity: RuntimeIdentity, force: bool = False, timeout: float = 5.0,
    ) -> StopResult: ...
    def stop_external_process(self, pid: int, force: bool = False) -> StopResult: ...
    def process_group_id(self, pid: int) -> int | None: ...
    def current_process_group_id(self) -> int | None: ...
    def pid_alive(self, pid: int) -> bool: ...
    def scheduled_tasks(self, paths: set[str] | None = None) -> ScheduledTaskSnapshot: ...
    def run_scheduled_task(self, path: str) -> ScheduledTaskRunResult: ...
    def stop_scheduled_task(self, path: str) -> ScheduledTaskRunResult: ...
    def pick_path(self, kind: Literal["dir", "script"]) -> PickResult: ...
    def open_browser(self, url: str) -> None: ...
    def restart_console(self, preferred_port: int) -> RestartResult: ...
    def complete_console_restart(self, old_pid: int, preferred_port: int) -> int: ...
    def launcher_dialog(self, message: str) -> str | None: ...
    def launcher_alert(self, message: str) -> None: ...
    def configure_server_socket(self, sock: object) -> None: ...
    def platform_metadata(self) -> Mapping[str, object]: ...

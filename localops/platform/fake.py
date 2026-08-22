"""Deterministic platform implementation for shared-core contract tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Mapping

from .contracts import (
    CwdSnapshot,
    ElevationBrokerResult,
    ElevationBrokerStatus,
    ListenerSnapshot,
    ManagedActivation,
    ManagedInspection,
    ManagedRuntime,
    PickResult,
    PlatformCapabilities,
    Principal,
    ProcessSnapshot,
    RestartResult,
    RuntimeIdentity,
    RuntimePaths,
    ScanStatus,
    ScheduledTaskRunResult,
    ScheduledTaskSnapshot,
    StopResult,
)


@dataclass
class FakeInstanceLock:
    released: bool = False

    def release(self) -> None:
        self.released = True


@dataclass
class FakePlatform:
    name: str = "fake"
    requires_verified_permissions: bool = False
    capabilities: PlatformCapabilities = field(
        default_factory=lambda: PlatformCapabilities(
            monitor_processes=True,
            launch_managed=True,
            stop_managed=True,
            force_stop_managed=True,
            kill_external=True,
            attach_external=True,
            pick_path=True,
            restart_console=True,
            monitor_scheduled_tasks=False,
            run_scheduled_tasks=False,
            stop_scheduled_tasks=False,
            toggle_scheduled_tasks=False,
            monitor_docker=False,
            control_docker=False,
            manage_elevation_broker=False,
            launch_elevated=False,
        )
    )
    paths: RuntimePaths = field(
        default_factory=lambda: RuntimePaths("/fake/data", "/fake/logs", "/fake/runtime")
    )
    principal: Principal = field(default_factory=lambda: Principal("fake-user", 1000))
    listeners: ListenerSnapshot = field(
        default_factory=lambda: ListenerSnapshot(status=ScanStatus.OK)
    )
    processes: ProcessSnapshot = field(
        default_factory=lambda: ProcessSnapshot(status=ScanStatus.OK)
    )
    cwds: CwdSnapshot = field(
        default_factory=lambda: CwdSnapshot(status=ScanStatus.OK)
    )
    parents: ProcessSnapshot = field(
        default_factory=lambda: ProcessSnapshot(status=ScanStatus.OK)
    )
    groups: ProcessSnapshot = field(
        default_factory=lambda: ProcessSnapshot(status=ScanStatus.OK)
    )
    scheduled: ScheduledTaskSnapshot = field(
        default_factory=lambda: ScheduledTaskSnapshot(status=ScanStatus.OK)
    )
    scheduled_run_result: ScheduledTaskRunResult = field(
        default_factory=lambda: ScheduledTaskRunResult(False, "", "unsupported")
    )
    scheduled_stop_result: ScheduledTaskRunResult = field(
        default_factory=lambda: ScheduledTaskRunResult(False, "", "unsupported")
    )
    scheduled_toggle_result: ScheduledTaskRunResult = field(
        default_factory=lambda: ScheduledTaskRunResult(True, "")
    )
    elevation_status: ElevationBrokerStatus = field(
        default_factory=ElevationBrokerStatus
    )
    elevation_install_result: ElevationBrokerResult = field(
        default_factory=lambda: ElevationBrokerResult(False, "unsupported")
    )
    elevation_unlock_result: ElevationBrokerResult = field(
        default_factory=lambda: ElevationBrokerResult(False, "unsupported")
    )
    elevation_lock_result: ElevationBrokerResult = field(
        default_factory=lambda: ElevationBrokerResult(False, "unsupported")
    )
    elevation_launch_result: ElevationBrokerResult = field(
        default_factory=lambda: ElevationBrokerResult(False, "unsupported")
    )
    launch_result: ManagedRuntime = field(default_factory=lambda: ManagedRuntime(ok=True))
    activation_result: ManagedActivation = field(
        default_factory=lambda: ManagedActivation(ok=True)
    )
    inspection: ManagedInspection = field(
        default_factory=lambda: ManagedInspection(running=False, verified=True)
    )
    cleanup_recoveries: list[RuntimeIdentity] = field(default_factory=list)
    stop_result: StopResult = field(default_factory=lambda: StopResult(ok=True))
    pick_result: PickResult = field(default_factory=PickResult)
    restart_result: RestartResult = field(default_factory=lambda: RestartResult(ok=True))
    lock_available: bool = True
    alive_pids: set[int] = field(default_factory=set)
    calls: list[tuple[str, object]] = field(default_factory=list)

    def runtime_paths(self) -> RuntimePaths:
        return self.paths

    def current_principal(self) -> Principal:
        return self.principal

    def validate_runtime_path(self, path: str, forbidden: set[str]) -> str:
        if path in forbidden:
            raise ValueError("runtime path must be a dedicated subdirectory")
        return path

    def ensure_private_directory(self, path: str) -> None:
        self.calls.append(("ensure_private_directory", path))

    def ensure_private_file(self, path: str) -> None:
        self.calls.append(("ensure_private_file", path))

    @staticmethod
    def should_migrate_legacy_data() -> bool:
        return True

    def acquire_instance_lock(self, identity: str) -> FakeInstanceLock | None:
        self.calls.append(("acquire_instance_lock", identity))
        return FakeInstanceLock() if self.lock_available else None

    def scan_listeners(self) -> ListenerSnapshot:
        self.calls.append(("scan_listeners", None))
        return self.listeners

    def process_snapshot(
        self, pids: set[int] | None = None, *, with_owner: bool = True,
    ) -> ProcessSnapshot:
        self.calls.append(("process_snapshot", (pids, with_owner)))
        return self.processes

    def processes_matching_keywords(self, keywords: list[str]) -> ProcessSnapshot:
        normalized = tuple(str(value) for value in keywords)
        self.calls.append(("processes_matching_keywords", normalized))
        return self.processes

    def process_cwds(self, pids: set[int]) -> CwdSnapshot:
        self.calls.append(("process_cwds", pids))
        return self.cwds

    def process_parents(self, pids: set[int] | None = None) -> ProcessSnapshot:
        self.calls.append(("process_parents", pids))
        return self.parents

    def process_groups(self) -> ProcessSnapshot:
        return self.groups

    def launch(self, app: object) -> ManagedRuntime:
        self.calls.append(("launch", app))
        return self.launch_result

    def activate_managed(self, identity: RuntimeIdentity) -> ManagedActivation:
        self.calls.append(("activate_managed", identity))
        return self.activation_result

    def abort_managed(self, identity: RuntimeIdentity) -> StopResult:
        self.calls.append(("abort_managed", identity))
        return self.stop_result

    def release_managed(self, identity: RuntimeIdentity) -> StopResult:
        self.calls.append(("release_managed", identity))
        return self.stop_result

    def recover_managed_cleanups(self) -> tuple[RuntimeIdentity, ...]:
        self.calls.append(("recover_managed_cleanups", None))
        return tuple(self.cleanup_recoveries)

    def inspect_managed(self, identity: RuntimeIdentity) -> ManagedInspection:
        self.calls.append(("inspect_managed", identity))
        return self.inspection

    def stop_managed(
        self, identity: RuntimeIdentity, force: bool = False, timeout: float = 5.0,
    ) -> StopResult:
        self.calls.append(("stop_managed", (identity, force, timeout)))
        return self.stop_result

    def stop_external_process(self, pid: int, force: bool = False) -> StopResult:
        self.calls.append(("stop_external_process", (pid, force)))
        return self.stop_result

    def process_group_id(self, pid: int) -> int | None:
        return pid

    def current_process_group_id(self) -> int | None:
        return 1

    def pid_alive(self, pid: int) -> bool:
        return pid in self.alive_pids

    def scheduled_tasks(self, paths: set[str] | None = None) -> ScheduledTaskSnapshot:
        normalized = None if paths is None else frozenset(paths)
        self.calls.append(("scheduled_tasks", normalized))
        return self.scheduled

    def run_scheduled_task(self, path: str) -> ScheduledTaskRunResult:
        self.calls.append(("run_scheduled_task", path))
        result = self.scheduled_run_result
        if result.task_path:
            return result
        return ScheduledTaskRunResult(result.ok, path, result.error, result.code)

    def stop_scheduled_task(self, path: str) -> ScheduledTaskRunResult:
        self.calls.append(("stop_scheduled_task", path))
        result = self.scheduled_stop_result
        if result.task_path:
            return result
        return ScheduledTaskRunResult(result.ok, path, result.error, result.code)

    def set_scheduled_task_enabled(
            self, path: str, enabled: bool) -> ScheduledTaskRunResult:
        self.calls.append(("set_scheduled_task_enabled", (path, enabled)))
        result = self.scheduled_toggle_result
        if result.task_path:
            return result
        return ScheduledTaskRunResult(result.ok, path, result.error, result.code)

    def elevation_broker_status(self) -> ElevationBrokerStatus:
        self.calls.append(("elevation_broker_status", None))
        return self.elevation_status

    def install_elevation_broker(
            self, password_record: Mapping[str, object]) -> ElevationBrokerResult:
        self.calls.append(("install_elevation_broker", password_record))
        return self.elevation_install_result

    def unlock_elevation_broker(self, password: str) -> ElevationBrokerResult:
        self.calls.append(("unlock_elevation_broker", password))
        return self.elevation_unlock_result

    def lock_elevation_broker(self) -> ElevationBrokerResult:
        self.calls.append(("lock_elevation_broker", None))
        return self.elevation_lock_result

    def launch_elevated(
            self, command_spec: Mapping[str, object],
            cwd: str | None) -> ElevationBrokerResult:
        self.calls.append(("launch_elevated", (command_spec, cwd)))
        return self.elevation_launch_result

    def pick_path(self, kind: Literal["dir", "script"]) -> PickResult:
        self.calls.append(("pick_path", kind))
        return self.pick_result

    def open_browser(self, url: str) -> None:
        self.calls.append(("open_browser", url))

    def restart_console(self, preferred_port: int) -> RestartResult:
        self.calls.append(("restart_console", preferred_port))
        return self.restart_result

    def complete_console_restart(self, old_pid: int, preferred_port: int) -> int:
        self.calls.append(("complete_console_restart", (old_pid, preferred_port)))
        return 0

    def launcher_dialog(self, message: str) -> str | None:
        self.calls.append(("launcher_dialog", message))
        return None

    def launcher_alert(self, message: str) -> None:
        self.calls.append(("launcher_alert", message))

    def platform_metadata(self) -> Mapping[str, object]:
        return {"platform": self.name, "capabilities": self.capabilities.__dict__}

    def configure_server_socket(self, sock: object) -> None:
        self.calls.append(("configure_server_socket", sock))

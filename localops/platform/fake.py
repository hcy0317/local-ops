"""Deterministic platform implementation for shared-core contract tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Mapping

from .contracts import (
    CwdSnapshot,
    ListenerSnapshot,
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
    launch_result: ManagedRuntime = field(default_factory=lambda: ManagedRuntime(ok=True))
    inspection: ManagedInspection = field(
        default_factory=lambda: ManagedInspection(running=False, verified=True)
    )
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

    def process_cwds(self, pids: set[int]) -> CwdSnapshot:
        self.calls.append(("process_cwds", pids))
        return self.cwds

    def process_parents(self) -> ProcessSnapshot:
        return self.parents

    def process_groups(self) -> ProcessSnapshot:
        return self.groups

    def launch(self, app: object) -> ManagedRuntime:
        self.calls.append(("launch", app))
        return self.launch_result

    def inspect_managed(self, identity: RuntimeIdentity) -> ManagedInspection:
        self.calls.append(("inspect_managed", identity))
        return self.inspection

    def stop_managed(self, identity: RuntimeIdentity, force: bool = False) -> StopResult:
        self.calls.append(("stop_managed", (identity, force)))
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

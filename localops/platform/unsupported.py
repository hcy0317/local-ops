"""Explicit non-implementation used before a native adapter exists."""

from __future__ import annotations

import os
from typing import Literal, Mapping

from .contracts import (
    CwdSnapshot,
    ElevationBrokerResult,
    ElevationBrokerStatus,
    ListenerSnapshot,
    ManagedInspection,
    ManagedRuntime,
    PickResult,
    PlatformCapabilities,
    PlatformIssue,
    PlatformUnavailable,
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


class UnsupportedPlatform:
    capabilities = PlatformCapabilities()
    requires_verified_permissions = False

    def __init__(self, name: str):
        self.name = name
        self._issue = PlatformIssue(
            "platform", "unsupported_platform", f"{name} adapter is not implemented"
        )

    def runtime_paths(self) -> RuntimePaths:
        root = os.path.abspath(os.path.expanduser("~/.localops-unsupported"))
        return RuntimePaths(root, os.path.join(root, "logs"), os.path.join(root, "runtime"))

    def current_principal(self) -> Principal:
        return Principal(
            os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
            -1,
        )

    @staticmethod
    def validate_runtime_path(path: str, forbidden: set[str]) -> str:
        normalized = os.path.abspath(path)
        if normalized in forbidden:
            raise ValueError("runtime path must be a dedicated subdirectory")
        return normalized

    @staticmethod
    def ensure_private_directory(path: str) -> None:
        return None

    @staticmethod
    def ensure_private_file(path: str) -> None:
        return None

    @staticmethod
    def should_migrate_legacy_data() -> bool:
        return False

    @staticmethod
    def launch_environment(
        token: str, environ: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        env = dict(os.environ if environ is None else environ)
        env["CONSOLE_RUN_TOKEN"] = token
        return env

    def acquire_instance_lock(self, identity: str) -> None:
        raise PlatformUnavailable(self._issue.message)

    def scan_listeners(self) -> ListenerSnapshot:
        return ListenerSnapshot(ScanStatus.FAILED, issues=(self._issue,))

    def process_snapshot(
        self, pids: set[int] | None = None, *, with_owner: bool = True,
    ) -> ProcessSnapshot:
        return ProcessSnapshot(ScanStatus.FAILED, issues=(self._issue,))

    def processes_matching_keywords(self, keywords: list[str]) -> ProcessSnapshot:
        return ProcessSnapshot(ScanStatus.FAILED, issues=(self._issue,))

    def process_cwds(self, pids: set[int]) -> CwdSnapshot:
        return CwdSnapshot(ScanStatus.FAILED, issues=(self._issue,))

    def process_parents(self, pids: set[int] | None = None) -> ProcessSnapshot:
        return ProcessSnapshot(ScanStatus.FAILED, issues=(self._issue,))

    def process_groups(self) -> ProcessSnapshot:
        return ProcessSnapshot(ScanStatus.FAILED, issues=(self._issue,))

    def launch(self, app: object) -> ManagedRuntime:
        return ManagedRuntime(False, self._issue.message)

    def inspect_managed(self, identity: RuntimeIdentity) -> ManagedInspection:
        return ManagedInspection(False, False, issue=self._issue)

    def stop_managed(self, identity: RuntimeIdentity, force: bool = False) -> StopResult:
        return StopResult(False, self._issue.message)

    def stop_external_process(self, pid: int, force: bool = False) -> StopResult:
        return StopResult(False, self._issue.message)

    def process_group_id(self, pid: int) -> None:
        return None

    def current_process_group_id(self) -> None:
        return None

    def pid_alive(self, pid: int) -> bool:
        raise PlatformUnavailable(self._issue.message)

    def scheduled_tasks(self, paths: set[str] | None = None) -> ScheduledTaskSnapshot:
        return ScheduledTaskSnapshot(ScanStatus.FAILED, issues=(self._issue,))

    def run_scheduled_task(self, path: str) -> ScheduledTaskRunResult:
        return ScheduledTaskRunResult(
            False, path, self._issue.message, self._issue.code
        )

    def stop_scheduled_task(self, path: str) -> ScheduledTaskRunResult:
        return ScheduledTaskRunResult(
            False, path, self._issue.message, self._issue.code
        )

    def set_scheduled_task_enabled(
            self, path: str, enabled: bool) -> ScheduledTaskRunResult:
        return ScheduledTaskRunResult(
            False, path, self._issue.message, self._issue.code
        )

    @staticmethod
    def elevation_broker_status() -> ElevationBrokerStatus:
        return ElevationBrokerStatus()

    def install_elevation_broker(
            self, password_record: Mapping[str, object],
            package_executable: str | None = None) -> ElevationBrokerResult:
        return ElevationBrokerResult(False, self._issue.message, self._issue.code)

    def unlock_elevation_broker(self, password: str) -> ElevationBrokerResult:
        return ElevationBrokerResult(False, self._issue.message, self._issue.code)

    @staticmethod
    def lock_elevation_broker() -> ElevationBrokerResult:
        return ElevationBrokerResult(True)

    def launch_elevated(
            self, command_spec: Mapping[str, object], cwd: str | None,
    ) -> ElevationBrokerResult:
        return ElevationBrokerResult(False, self._issue.message, self._issue.code)

    def pick_path(self, kind: Literal["dir", "script", "exe"]) -> PickResult:
        return PickResult(issue=self._issue)

    def open_browser(self, url: str) -> None:
        raise PlatformUnavailable(self._issue.message)

    def restart_console(self, preferred_port: int) -> RestartResult:
        return RestartResult(False, error=self._issue.message)

    def complete_console_restart(self, old_pid: int, preferred_port: int) -> int:
        raise PlatformUnavailable(self._issue.message)

    def launcher_dialog(self, message: str) -> None:
        return None

    def launcher_alert(self, message: str) -> None:
        return None

    def platform_metadata(self) -> Mapping[str, object]:
        return {"platform": self.name, "capabilities": self.capabilities.__dict__}

    @staticmethod
    def configure_server_socket(sock: object) -> None:
        return None

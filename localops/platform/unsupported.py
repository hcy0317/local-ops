"""Explicit non-implementation used before a native adapter exists."""

from __future__ import annotations

import os
from typing import Literal, Mapping

from .contracts import (
    CwdSnapshot,
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
    StopResult,
)


class UnsupportedPlatform:
    capabilities = PlatformCapabilities()

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

    def process_cwds(self, pids: set[int]) -> CwdSnapshot:
        return CwdSnapshot(ScanStatus.FAILED, issues=(self._issue,))

    def process_parents(self) -> ProcessSnapshot:
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

    def pick_path(self, kind: Literal["dir", "script"]) -> PickResult:
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

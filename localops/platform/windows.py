"""Windows adapter for secure storage and read-only process monitoring."""

from __future__ import annotations

import hashlib
import os
import socket
import stat
import subprocess
import time
import webbrowser
from dataclasses import asdict
from typing import Literal, Mapping

import ntsecuritycon
import psutil
import pywintypes
import win32api
import win32con
import win32event
import win32security
import winerror
from win32com.shell import shell

from .contracts import (
    CwdSnapshot,
    LaunchRequest,
    ListenerSnapshot,
    ManagedInspection,
    ManagedRuntime,
    PickResult,
    PlatformCapabilities,
    PlatformIssue,
    Principal,
    ProcessSnapshot,
    RestartResult,
    RuntimeIdentity,
    RuntimePaths,
    ScanStatus,
    StopResult,
)


_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_JUNCTION_REPARSE_TAG = 0xA0000003


def _issue(component: str, code: str, message: str) -> PlatformIssue:
    return PlatformIssue(component, code, message)


class WindowsInstanceLock:
    def __init__(self, handle: object):
        self._handle = handle

    def release(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            win32api.CloseHandle(handle)


class WindowsPlatform:
    """Read-only Windows platform slice used until lifecycle support lands."""

    name = "windows"
    requires_verified_permissions = True
    capabilities = PlatformCapabilities(
        monitor_processes=True,
        launch_managed=False,
        stop_managed=False,
        force_stop_managed=False,
        kill_external=False,
        attach_external=False,
        pick_path=True,
        restart_console=False,
    )

    def __init__(self, base_dir: str, entrypoint: str):
        self.base_dir = os.path.abspath(base_dir)
        self.entrypoint = os.path.abspath(entrypoint)
        self.self_pid = os.getpid()
        self._sid = self._current_sid()
        self._principal = Principal(self._sid)

    @staticmethod
    def _current_sid() -> str:
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        try:
            sid = win32security.GetTokenInformation(
                token, win32security.TokenUser
            )[0]
            return win32security.ConvertSidToStringSid(sid)
        finally:
            token.Close()

    def runtime_paths(self) -> RuntimePaths:
        local_app_data = shell.SHGetKnownFolderPath(
            shell.FOLDERID_LocalAppData, 0, None
        )
        root = os.path.join(local_app_data, "LocalOps")
        return RuntimePaths(
            root,
            os.path.join(root, "logs"),
            os.path.join(root, "runtime"),
        )

    def current_principal(self) -> Principal:
        return self._principal

    @staticmethod
    def _canonical_path(path: str) -> str:
        normalized = os.path.realpath(os.path.abspath(path))
        if os.path.exists(normalized):
            try:
                import win32file

                normalized = win32file.GetLongPathName(normalized)
            except pywintypes.error:
                pass
        return os.path.normcase(os.path.normpath(normalized))

    @staticmethod
    def _has_junction_component(path: str) -> bool:
        drive, tail = os.path.splitdrive(os.path.abspath(path))
        current = drive + os.sep
        for part in (item for item in tail.replace("/", "\\").split("\\") if item):
            current = os.path.join(current, part)
            if not os.path.lexists(current):
                continue
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode):
                return True
            attributes = getattr(info, "st_file_attributes", 0)
            reparse_tag = getattr(info, "st_reparse_tag", 0)
            if (attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
                    and reparse_tag == _JUNCTION_REPARSE_TAG):
                return True
        return False

    def validate_runtime_path(self, path: str, forbidden: set[str]) -> str:
        normalized = os.path.abspath(path)
        drive, tail = os.path.splitdrive(normalized)
        if drive and not tail.strip("\\/"):
            raise ValueError("runtime path cannot be a drive or UNC share root")
        if self._has_junction_component(normalized):
            raise ValueError("runtime path cannot contain a symlink or junction")
        canonical = self._canonical_path(normalized)
        if canonical in {self._canonical_path(item) for item in forbidden}:
            raise ValueError("runtime path must be a dedicated subdirectory")
        return normalized

    def _private_acl(self, inherit: bool) -> object:
        flags = (
            win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE
            if inherit else 0
        )
        acl = win32security.ACL()
        for sid_text in (self._sid, _SYSTEM_SID, _ADMINISTRATORS_SID):
            sid = win32security.ConvertStringSidToSid(sid_text)
            acl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                ntsecuritycon.FILE_ALL_ACCESS,
                sid,
            )
        return acl

    def _apply_and_verify_acl(self, path: str, *, directory: bool) -> None:
        try:
            acl = self._private_acl(directory)
            owner = win32security.ConvertStringSidToSid(self._sid)
            win32security.SetNamedSecurityInfo(
                path,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION
                | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                None,
                acl,
                None,
            )
            descriptor = win32security.GetNamedSecurityInfo(
                path,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
        except pywintypes.error as exc:
            raise PermissionError("cannot apply or inspect private Windows ACL") from exc
        actual_owner = win32security.ConvertSidToStringSid(
            descriptor.GetSecurityDescriptorOwner()
        )
        dacl = descriptor.GetSecurityDescriptorDacl()
        allowed = {self._sid, _SYSTEM_SID, _ADMINISTRATORS_SID}
        aces = (
            [dacl.GetAce(index) for index in range(dacl.GetAceCount())]
            if dacl is not None else []
        )
        principals = {
            win32security.ConvertSidToStringSid(ace[2]) for ace in aces
        }
        allowed_only = all(
            ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
            and ace[1] & ntsecuritycon.FILE_ALL_ACCESS
            == ntsecuritycon.FILE_ALL_ACCESS
            for ace in aces
        )
        control = descriptor.GetSecurityDescriptorControl()[0]
        if (actual_owner != self._sid or principals != allowed
                or not allowed_only
                or not control & win32security.SE_DACL_PROTECTED):
            raise PermissionError("private Windows ACL verification failed")

    def ensure_private_directory(self, path: str) -> None:
        if self._has_junction_component(path) or not os.path.isdir(path):
            raise OSError("private runtime path is not a safe directory")
        self._apply_and_verify_acl(path, directory=True)

    def ensure_private_file(self, path: str) -> None:
        if self._has_junction_component(path) or not os.path.isfile(path):
            raise OSError("private runtime path is not a regular file")
        self._apply_and_verify_acl(path, directory=False)

    @staticmethod
    def should_migrate_legacy_data() -> bool:
        return False

    def _security_attributes(self) -> object:
        descriptor = win32security.SECURITY_DESCRIPTOR()
        descriptor.SetSecurityDescriptorDacl(True, self._private_acl(False), False)
        attributes = win32security.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = descriptor
        return attributes

    def acquire_instance_lock(self, identity: str) -> WindowsInstanceLock | None:
        data_dir = self._canonical_path(os.path.dirname(identity))
        digest = hashlib.sha256(
            (self._sid + "\0" + data_dir).encode("utf-8")
        ).hexdigest()[:32]
        handle = win32event.CreateMutex(
            self._security_attributes(), False, "Local\\LocalOps-" + digest
        )
        if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
            win32api.CloseHandle(handle)
            return None
        return WindowsInstanceLock(handle)

    @staticmethod
    def _process_owner_sid(pid: int) -> str:
        handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid)
        )
        try:
            token = win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)
            try:
                sid = win32security.GetTokenInformation(
                    token, win32security.TokenUser
                )[0]
                return win32security.ConvertSidToStringSid(sid)
            finally:
                token.Close()
        finally:
            handle.Close()

    def scan_listeners(self) -> ListenerSnapshot:
        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, OSError) as exc:
            return ListenerSnapshot(ScanStatus.FAILED, issues=(
                _issue("listeners", "access_denied", str(exc)),
            ))
        listeners: dict[tuple[int, int], set[str]] = {}
        missing_owner = False
        for connection in connections:
            if connection.status != psutil.CONN_LISTEN or not connection.laddr:
                continue
            if connection.pid is None:
                missing_owner = True
                continue
            address = connection.laddr
            host = address.ip if hasattr(address, "ip") else address[0]
            port = address.port if hasattr(address, "port") else address[1]
            listeners.setdefault((int(connection.pid), int(port)), set()).add(str(host))
        issues = (() if not missing_owner else (
            _issue(
                "listeners",
                "owner_unavailable",
                "one or more Windows listeners did not expose an owning PID",
            ),
        ))
        return ListenerSnapshot(
            ScanStatus.PARTIAL if issues else ScanStatus.OK,
            listeners,
            issues,
        )

    def process_snapshot(
        self, pids: set[int] | None = None, *, with_owner: bool = True,
    ) -> ProcessSnapshot:
        issues: list[PlatformIssue] = []
        processes: dict[int, dict[str, object]] = {}
        access_denied = False
        try:
            if pids is None:
                candidates = list(psutil.process_iter())
            else:
                candidates = []
                for pid in sorted(pids):
                    try:
                        candidates.append(psutil.Process(int(pid)))
                    except psutil.NoSuchProcess:
                        continue
                    except psutil.AccessDenied:
                        access_denied = True
        except (psutil.Error, OSError) as exc:
            return ProcessSnapshot(ScanStatus.FAILED, issues=(
                _issue("processes", "scan_failed", str(exc)),
            ))
        now = time.time()
        for process in candidates:
            try:
                pid = int(process.pid)
                owner = None
                if with_owner:
                    try:
                        owner = self._process_owner_sid(pid)
                    except (psutil.AccessDenied, pywintypes.error, OSError):
                        access_denied = True
                        continue
                    if owner != self._sid:
                        continue
                info = process.as_dict(
                    attrs=("pid", "name", "exe", "cmdline", "cpu_percent",
                           "memory_percent", "create_time", "ppid"),
                    ad_value=None,
                )
                command = info.get("cmdline") or []
                processes[pid] = {
                    "owner": owner,
                    "uid": None,
                    "etime": max(0, int(now - (info.get("create_time") or now))),
                    "cpu": float(info.get("cpu_percent") or 0.0),
                    "mem": float(info.get("memory_percent") or 0.0),
                    "comm": info.get("exe") or info.get("name") or "",
                    "args": subprocess.list2cmdline(command) if command else "",
                    "ppid": int(info.get("ppid") or 0),
                }
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                access_denied = True
                continue
            except (OSError, ValueError, TypeError) as exc:
                issues.append(_issue("processes", "snapshot_error", str(exc)))
        if access_denied:
            issues.append(_issue(
                "processes",
                "access_denied",
                "one or more protected Windows processes were not readable",
            ))
        deduplicated = tuple(dict.fromkeys(issues))
        return ProcessSnapshot(
            ScanStatus.PARTIAL if deduplicated else ScanStatus.OK,
            processes,
            deduplicated,
        )

    def process_cwds(self, pids: set[int]) -> CwdSnapshot:
        cwds: dict[int, str | None] = {}
        access_denied = False
        for pid in sorted(int(value) for value in pids):
            try:
                cwds[pid] = psutil.Process(pid).cwd()
            except psutil.NoSuchProcess:
                continue
            except (psutil.AccessDenied, OSError):
                cwds[pid] = None
                access_denied = True
        issues = (() if not access_denied else (
            _issue(
                "process_cwds",
                "access_denied",
                "one or more Windows process directories were not readable",
            ),
        ))
        return CwdSnapshot(
            ScanStatus.PARTIAL if issues else ScanStatus.OK,
            cwds,
            issues,
        )

    def process_parents(self, pids: set[int] | None = None) -> ProcessSnapshot:
        parents: dict[int, dict[str, object]] = {}
        access_denied = False
        try:
            if pids is None:
                candidates = psutil.process_iter(attrs=("pid", "ppid"))
                for process in candidates:
                    try:
                        info = process.info
                        parents[int(info["pid"])] = {
                            "ppid": int(info.get("ppid") or 0),
                            "args": "",
                        }
                    except psutil.NoSuchProcess:
                        continue
                    except psutil.AccessDenied:
                        access_denied = True
            else:
                pending = list(int(pid) for pid in pids)
                while pending:
                    pid = pending.pop()
                    if pid <= 0 or pid in parents:
                        continue
                    try:
                        parent = int(psutil.Process(pid).ppid())
                    except psutil.NoSuchProcess:
                        continue
                    except (psutil.AccessDenied, OSError):
                        access_denied = True
                        continue
                    parents[pid] = {"ppid": parent, "args": ""}
                    if parent > 1:
                        pending.append(parent)
        except (psutil.Error, OSError) as exc:
            return ProcessSnapshot(ScanStatus.FAILED, issues=(
                _issue("process_parents", "scan_failed", str(exc)),
            ))
        issues = (() if not access_denied else (
            _issue(
                "process_parents",
                "access_denied",
                "one or more Windows process parent records were not readable",
            ),
        ))
        return ProcessSnapshot(
            ScanStatus.PARTIAL if issues else ScanStatus.OK,
            parents,
            issues,
        )

    @staticmethod
    def process_groups() -> ProcessSnapshot:
        problem = _issue(
            "process_groups",
            "not_supported",
            "POSIX process groups are unavailable on Windows",
        )
        return ProcessSnapshot(ScanStatus.FAILED, issues=(problem,))

    @staticmethod
    def launch(app: LaunchRequest) -> ManagedRuntime:
        return ManagedRuntime(False, "Windows process launch is disabled in Phase 2")

    @staticmethod
    def inspect_managed(identity: RuntimeIdentity) -> ManagedInspection:
        return ManagedInspection(False, False, issue=_issue(
            "managed", "disabled", "Windows managed lifecycle is disabled in Phase 2"
        ))

    @staticmethod
    def stop_managed(identity: RuntimeIdentity, force: bool = False) -> StopResult:
        return StopResult(False, "Windows process control is disabled in Phase 2")

    @staticmethod
    def stop_external_process(pid: int, force: bool = False) -> StopResult:
        return StopResult(False, "Windows external process control is disabled in Phase 2")

    @staticmethod
    def process_group_id(pid: int) -> None:
        return None

    @staticmethod
    def current_process_group_id() -> None:
        return None

    @staticmethod
    def pid_alive(pid: int) -> bool:
        try:
            return psutil.pid_exists(int(pid))
        except (TypeError, ValueError):
            return False

    @staticmethod
    def pick_path(kind: Literal["dir", "script"]) -> PickResult:
        try:
            import tkinter
            from tkinter import filedialog

            root = tkinter.Tk()
            root.withdraw()
            try:
                path = (
                    filedialog.askdirectory(title="选择工作目录", mustexist=True)
                    if kind == "dir"
                    else filedialog.askopenfilename(title="选择批处理脚本")
                )
            finally:
                root.destroy()
        except Exception as exc:
            return PickResult(issue=_issue("picker", "os_error", str(exc)))
        return PickResult(path=os.path.abspath(path) if path else None, canceled=not bool(path))

    @staticmethod
    def open_browser(url: str) -> None:
        webbrowser.open(url)

    @staticmethod
    def restart_console(preferred_port: int) -> RestartResult:
        return RestartResult(False, error="Windows console restart is disabled in Phase 2")

    @staticmethod
    def complete_console_restart(old_pid: int, preferred_port: int) -> int:
        return 1

    @staticmethod
    def launcher_dialog(message: str) -> None:
        return None

    @staticmethod
    def launcher_alert(message: str) -> None:
        return None

    @staticmethod
    def configure_server_socket(sock: object) -> None:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)

    def platform_metadata(self) -> Mapping[str, object]:
        return {"platform": self.name, "capabilities": asdict(self.capabilities)}

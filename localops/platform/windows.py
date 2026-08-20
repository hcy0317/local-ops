"""Windows adapter for secure storage, monitoring, and owned-Job lifecycle."""

from __future__ import annotations

import gc
import hashlib
import os
import socket
import stat
import subprocess
import sys
import time
import webbrowser
from dataclasses import asdict, dataclass
from typing import Literal, Mapping

import ntsecuritycon
import pythoncom
import psutil
import pywintypes
import win32api
import win32con
import win32event
import win32file
import win32pipe
import win32process
import win32security
import winerror
import win32com.client
from win32com.shell import shell

from localops.command_spec import (
    CommandSpecError,
    prepared_invocation,
    resolve_windows_executable,
)
from localops.windows.runner_protocol import (
    PIPE_BUFFER_BYTES,
    ProtocolError,
    decode_message,
    encode_message,
    make_launch_request,
    make_request,
    new_token,
    pipe_name,
    read_json,
    reconnect_observations_valid,
    runner_command,
    runtime_directory,
    terminal_observations_valid,
    token_digest,
    validate_app_id,
    validate_generation_id,
    validate_public_identity,
    validate_receipt,
    verify_response,
    write_json_atomic,
)

from .contracts import (
    CwdSnapshot,
    LaunchRequest,
    ListenerSnapshot,
    ManagedActivation,
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
    ScheduledTaskRunResult,
    ScheduledTaskSnapshot,
    StopResult,
    windows_runtime_identity_public,
)


_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_JUNCTION_REPARSE_TAG = 0xA0000003
_RUNNER_PREPARE_TIMEOUT = 10.0
_MAX_CLEANUP_RECOVERY_ENTRIES = 256
_RUNTIME_RECORD_NAMES = frozenset({"request.json", "token.bin", "receipt.json"})
_CLEANUP_TOMBSTONE_PREFIX = ".cleanup-"


@dataclass(frozen=True)
class _WindowsRuntimeContext:
    identity: RuntimeIdentity
    token: bytes
    receipt: dict[str, object]
    members: tuple[int, ...]
    state: str


def _issue(
    component: str, code: str, message: str, *, degrades: bool = True,
) -> PlatformIssue:
    return PlatformIssue(component, code, message, degrades=degrades)


def _runner_process_settings() -> tuple[str, dict[str, str] | None]:
    """Return a runner executable whose PID is the long-lived interpreter."""
    executable = sys.executable
    environment: dict[str, str] | None = None
    if bool(getattr(sys, "frozen", False)):
        environment = dict(os.environ)
        environment["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        return executable, environment

    base_executable = getattr(sys, "_base_executable", executable)
    if (
        isinstance(base_executable, str)
        and base_executable
        and os.path.normcase(os.path.abspath(base_executable))
        != os.path.normcase(os.path.abspath(executable))
    ):
        resolved = resolve_windows_executable(
            base_executable, env=os.environ, cwd=os.getcwd()
        )
        if resolved is None:
            raise CommandSpecError("Python base executable is unavailable")
        executable = resolved
        environment = dict(os.environ)
        environment["__PYVENV_LAUNCHER__"] = sys.executable
    return executable, environment


class WindowsInstanceLock:
    def __init__(self, handle: object):
        self._handle = handle

    def release(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            win32api.CloseHandle(handle)


class WindowsPlatform:
    """Windows backend that controls only authenticated Local Ops Jobs."""

    name = "windows"
    requires_verified_permissions = True
    capabilities = PlatformCapabilities(
        monitor_processes=True,
        launch_managed=True,
        stop_managed=True,
        force_stop_managed=True,
        kill_external=False,
        attach_external=False,
        pick_path=True,
        restart_console=False,
        monitor_scheduled_tasks=True,
        run_scheduled_tasks=True,
        stop_scheduled_tasks=True,
    )

    def __init__(self, base_dir: str, entrypoint: str):
        self.base_dir = os.path.abspath(base_dir)
        self.entrypoint = os.path.abspath(entrypoint)
        self.self_pid = os.getpid()
        self._sid, self._default_owner_sid = self._current_token_sids()
        if self._default_owner_sid not in {self._sid, _ADMINISTRATORS_SID}:
            raise PermissionError("current Windows token has an unsupported default owner")
        self._principal = Principal(self._sid)

    @staticmethod
    def _current_token_sids() -> tuple[str, str]:
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        try:
            user_sid = win32security.GetTokenInformation(
                token, win32security.TokenUser
            )[0]
            owner_sid = win32security.GetTokenInformation(
                token, win32security.TokenOwner
            )
            return (
                win32security.ConvertSidToStringSid(user_sid),
                win32security.ConvertSidToStringSid(owner_sid),
            )
        finally:
            token.Close()

    def runtime_paths(self) -> RuntimePaths:
        local_app_data = shell.SHGetKnownFolderPath(
            shell.FOLDERID_LocalAppData, 0, None
        )
        default_root = os.path.join(local_app_data, "LocalOps")
        root_value = os.environ.get("CONSOLE_DATA_DIR")
        logs_value = os.environ.get("CONSOLE_LOG_DIR")
        if root_value is not None and not os.path.isabs(os.path.expanduser(root_value)):
            raise ValueError("CONSOLE_DATA_DIR must be absolute")
        if logs_value is not None and not os.path.isabs(os.path.expanduser(logs_value)):
            raise ValueError("CONSOLE_LOG_DIR must be absolute")
        root = os.path.abspath(os.path.expanduser(root_value or default_root))
        logs = os.path.abspath(os.path.expanduser(
            logs_value or os.path.join(root, "logs")
        ))
        return RuntimePaths(
            root,
            logs,
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
            before = win32security.GetNamedSecurityInfo(
                path,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
            existing_owner = win32security.ConvertSidToStringSid(
                before.GetSecurityDescriptorOwner()
            )
            owner = None
            security_information = (
                win32security.DACL_SECURITY_INFORMATION
                | win32security.PROTECTED_DACL_SECURITY_INFORMATION
            )
            if existing_owner != self._sid:
                # Administrator tokens default new objects to the group owner.
                # Normalize only that creation case; verification stays user-owned.
                if (existing_owner != self._default_owner_sid
                        or existing_owner != _ADMINISTRATORS_SID):
                    raise PermissionError("private Windows path has an unexpected owner")
                owner = win32security.ConvertStringSidToSid(self._sid)
                security_information |= win32security.OWNER_SECURITY_INFORMATION
            acl = self._private_acl(directory)
            win32security.SetNamedSecurityInfo(
                path,
                win32security.SE_FILE_OBJECT,
                security_information,
                owner,
                None,
                acl,
                None,
            )
        except pywintypes.error as exc:
            raise PermissionError("cannot apply or inspect private Windows ACL") from exc
        self._verify_private_acl(path)

    def _verify_private_acl(self, path: str) -> None:
        try:
            descriptor = win32security.GetNamedSecurityInfo(
                path,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
        except pywintypes.error as exc:
            raise PermissionError("cannot inspect private Windows ACL") from exc
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

    def verify_private_directory(self, path: str) -> None:
        if self._has_junction_component(path) or not os.path.isdir(path):
            raise OSError("private runtime path is not a safe directory")
        self._verify_private_acl(path)

    def verify_private_file(self, path: str) -> None:
        if self._has_junction_component(path) or not os.path.isfile(path):
            raise OSError("private runtime path is not a regular file")
        self._verify_private_acl(path)

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
                degrades=False,
            ))
        deduplicated = tuple(dict.fromkeys(issues))
        return ProcessSnapshot(
            ScanStatus.PARTIAL if deduplicated else ScanStatus.OK,
            processes,
            deduplicated,
        )

    @staticmethod
    def _wql_like_literal(value: str) -> str:
        """Escape one substring for a WQL LIKE expression.

        WMI performs the indexed/native filtering; Python still rechecks the
        exact substring before returning a row.
        """
        return (value.replace("[", "[[]")
                .replace("%", "[%]")
                .replace("_", "[_]")
                .replace("'", "''"))

    def _query_process_keyword_rows(
        self, keywords: tuple[str, ...],
    ) -> list[dict[str, object]]:
        clauses = []
        for keyword in keywords:
            escaped = self._wql_like_literal(keyword)
            clauses.append("CommandLine LIKE '%%%s%%'" % escaped)
            clauses.append("Name LIKE '%%%s%%'" % escaped)
        if not clauses:
            return []
        query = (
            "SELECT ProcessId, Name, CommandLine FROM Win32_Process WHERE "
            + " OR ".join(clauses)
        )
        pythoncom.CoInitialize()
        locator = services = rows = item = None
        try:
            locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            services = locator.ConnectServer(".", r"root\cimv2")
            rows = services.ExecQuery(query)
            result = []
            for item in rows:
                try:
                    result.append({
                        "pid": int(item.ProcessId),
                        "name": str(item.Name or ""),
                        "command_line": str(item.CommandLine or ""),
                    })
                except (AttributeError, TypeError, ValueError, pywintypes.error):
                    continue
            return result
        finally:
            item = rows = services = locator = None
            gc.collect()
            pythoncom.CoUninitialize()

    def processes_matching_keywords(self, keywords: list[str]) -> ProcessSnapshot:
        normalized = tuple(dict.fromkeys(
            value.strip() for value in keywords
            if isinstance(value, str) and value.strip()
        ))
        if not normalized:
            return ProcessSnapshot(ScanStatus.OK)
        try:
            candidates = self._query_process_keyword_rows(normalized)
        except (OSError, pywintypes.error, pythoncom.com_error) as exc:
            return ProcessSnapshot(ScanStatus.FAILED, issues=(
                _issue("processes", "wmi_query_failed", str(exc)),
            ))

        lowered = tuple(value.casefold() for value in normalized)
        processes: dict[int, dict[str, object]] = {}
        access_denied = False
        now = time.time()
        for row in candidates:
            try:
                pid = int(row.get("pid") or 0)
                command_line = str(row.get("command_line") or "")
                name = str(row.get("name") or "")
                haystack = (name + "\0" + command_line).casefold()
                if pid <= 0 or not any(value in haystack for value in lowered):
                    continue
                owner = self._process_owner_sid(pid)
                if owner != self._sid:
                    continue
                process = psutil.Process(pid)
                info = process.as_dict(
                    attrs=("name", "exe", "cpu_percent", "memory_percent",
                           "create_time", "ppid"),
                    ad_value=None,
                )
                processes[pid] = {
                    "owner": owner,
                    "uid": None,
                    "etime": max(0, int(now - (info.get("create_time") or now))),
                    "cpu": float(info.get("cpu_percent") or 0.0),
                    "mem": float(info.get("memory_percent") or 0.0),
                    "comm": info.get("exe") or info.get("name") or name,
                    "args": command_line,
                    "ppid": int(info.get("ppid") or 0),
                }
            except psutil.NoSuchProcess:
                continue
            except (psutil.AccessDenied, pywintypes.error, OSError):
                access_denied = True
                continue
            except (TypeError, ValueError) as exc:
                return ProcessSnapshot(ScanStatus.FAILED, issues=(
                    _issue("processes", "snapshot_error", str(exc)),
                ))
        issues = (() if not access_denied else (
            _issue(
                "processes", "access_denied",
                "one or more matching Windows processes were not readable",
                degrades=False,
            ),
        ))
        return ProcessSnapshot(
            ScanStatus.PARTIAL if issues else ScanStatus.OK,
            processes,
            issues,
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
                degrades=False,
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
    def _scheduled_task_parts(path: str) -> tuple[str, str, str]:
        normalized = "\\" + str(path).strip().replace("/", "\\").lstrip("\\")
        folder, _, name = normalized.rpartition("\\")
        return normalized, folder or "\\", name

    @staticmethod
    def _task_timestamp(value: object) -> int | None:
        if value is None:
            return None
        try:
            timestamp = int(value.timestamp())
            return timestamp if timestamp > 0 else None
        except (AttributeError, OSError, OverflowError, TypeError, ValueError):
            return None

    @staticmethod
    def _com_collection(collection: object) -> list[object]:
        try:
            return [collection.Item(index)
                    for index in range(1, int(collection.Count) + 1)]
        except (AttributeError, TypeError, ValueError, pywintypes.error):
            try:
                return list(collection)
            except (TypeError, pywintypes.error):
                return []

    def _scheduled_task_row(self, task: object) -> dict[str, object]:
        state_value = int(getattr(task, "State", 0) or 0)
        state = {
            0: "unknown",
            1: "disabled",
            2: "queued",
            3: "ready",
            4: "running",
        }.get(state_value, "unknown")
        actions: list[str] = []
        run_level = "limited"
        multiple_instances = "parallel"
        try:
            definition = task.Definition
            run_level = (
                "highest" if int(definition.Principal.RunLevel or 0) == 1
                else "limited"
            )
            multiple_instances = {
                0: "parallel",
                1: "queue",
                2: "ignoreNew",
                3: "stopExisting",
            }.get(int(definition.Settings.MultipleInstances or 0), "unknown")
            for action in self._com_collection(definition.Actions):
                if int(getattr(action, "Type", -1)) != 0:
                    continue
                executable = str(getattr(action, "Path", "") or "")
                arguments = str(getattr(action, "Arguments", "") or "")
                display = (executable + (" " + arguments if arguments else "")).strip()
                if display:
                    actions.append(display)
        except (AttributeError, TypeError, ValueError, pywintypes.error):
            pass
        engine_pids = []
        try:
            for instance in self._com_collection(task.GetInstances(0)):
                pid = int(getattr(instance, "EnginePID", 0) or 0)
                if pid > 0:
                    engine_pids.append(pid)
        except (AttributeError, TypeError, ValueError, pywintypes.error):
            pass
        path = str(getattr(task, "Path", "") or "")
        return {
            "path": path,
            "name": str(getattr(task, "Name", "") or ""),
            "state": state,
            "enabled": bool(getattr(task, "Enabled", False)),
            "lastRunAt": self._task_timestamp(getattr(task, "LastRunTime", None)),
            "nextRunAt": self._task_timestamp(getattr(task, "NextRunTime", None)),
            "lastResult": int(getattr(task, "LastTaskResult", 0) or 0),
            "runLevel": run_level,
            "multipleInstances": multiple_instances,
            "actions": actions,
            "enginePids": sorted(set(engine_pids)),
        }

    def scheduled_tasks(self, paths: set[str] | None = None) -> ScheduledTaskSnapshot:
        pythoncom.CoInitialize()
        service = task = folder = registered = children = None
        pending: list[object] = []
        try:
            service = win32com.client.Dispatch("Schedule.Service")
            service.Connect()
            tasks: dict[str, dict[str, object]] = {}
            issues: list[PlatformIssue] = []
            if paths is not None:
                for requested in sorted(paths, key=str.casefold):
                    normalized, folder_path, name = self._scheduled_task_parts(requested)
                    try:
                        task = service.GetFolder(folder_path).GetTask(name)
                        row = self._scheduled_task_row(task)
                    except (AttributeError, TypeError, ValueError, pywintypes.error) as exc:
                        row = {
                            "path": normalized,
                            "name": name,
                            "state": "missing",
                            "enabled": False,
                            "lastRunAt": None,
                            "nextRunAt": None,
                            "lastResult": None,
                            "runLevel": "unknown",
                            "multipleInstances": "unknown",
                            "actions": [],
                            "enginePids": [],
                            "error": str(exc),
                        }
                    tasks[normalized.casefold()] = row
            else:
                pending = [service.GetFolder("\\")]
                while pending:
                    folder = pending.pop()
                    try:
                        registered = folder.GetTasks(1)
                        children = folder.GetFolders(0)
                    except (AttributeError, pywintypes.error) as exc:
                        issues.append(_issue(
                            "scheduled_tasks", "folder_access_denied", str(exc),
                            degrades=False,
                        ))
                        continue
                    for task in self._com_collection(registered):
                        row = self._scheduled_task_row(task)
                        if row["path"]:
                            tasks[str(row["path"]).casefold()] = row
                    pending.extend(self._com_collection(children))
            deduplicated = tuple(dict.fromkeys(issues))
            return ScheduledTaskSnapshot(
                ScanStatus.PARTIAL if deduplicated else ScanStatus.OK,
                tasks,
                deduplicated,
            )
        except (OSError, AttributeError, pywintypes.error, pythoncom.com_error) as exc:
            return ScheduledTaskSnapshot(ScanStatus.FAILED, issues=(
                _issue("scheduled_tasks", "query_failed", str(exc)),
            ))
        finally:
            pending.clear()
            task = folder = registered = children = service = None
            gc.collect()
            pythoncom.CoUninitialize()

    def run_scheduled_task(self, path: str) -> ScheduledTaskRunResult:
        normalized, folder_path, name = self._scheduled_task_parts(path)
        pythoncom.CoInitialize()
        service = task = None
        try:
            service = win32com.client.Dispatch("Schedule.Service")
            service.Connect()
            task = service.GetFolder(folder_path).GetTask(name)
            if not bool(task.Enabled):
                return ScheduledTaskRunResult(
                    False, normalized, "Windows scheduled task is disabled",
                    "SCHEDULED_TASK_DISABLED",
                )
            task.Run("")
            return ScheduledTaskRunResult(True, normalized)
        except (OSError, AttributeError, pywintypes.error, pythoncom.com_error) as exc:
            return ScheduledTaskRunResult(
                False, normalized, str(exc), "SCHEDULED_TASK_RUN_FAILED"
            )
        finally:
            task = service = None
            gc.collect()
            pythoncom.CoUninitialize()

    def stop_scheduled_task(self, path: str) -> ScheduledTaskRunResult:
        """Stop all running instances of one exact registered task.

        This leaves the registration, enabled state, triggers, principal, and
        multiple-instance policy unchanged.
        """
        normalized, folder_path, name = self._scheduled_task_parts(path)
        pythoncom.CoInitialize()
        service = task = instances = None
        try:
            service = win32com.client.Dispatch("Schedule.Service")
            service.Connect()
            task = service.GetFolder(folder_path).GetTask(name)
            instances = self._com_collection(task.GetInstances(0))
            if not instances:
                return ScheduledTaskRunResult(True, normalized)
            task.Stop(0)
            return ScheduledTaskRunResult(True, normalized)
        except (OSError, AttributeError, pywintypes.error, pythoncom.com_error) as exc:
            return ScheduledTaskRunResult(
                False, normalized, str(exc), "SCHEDULED_TASK_STOP_FAILED"
            )
        finally:
            instances = task = service = None
            gc.collect()
            pythoncom.CoUninitialize()

    @staticmethod
    def process_groups() -> ProcessSnapshot:
        problem = _issue(
            "process_groups",
            "not_supported",
            "POSIX process groups are unavailable on Windows",
        )
        return ProcessSnapshot(ScanStatus.FAILED, issues=(problem,))

    @staticmethod
    def _create_private_file(path: str, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _ensure_runtime_parent(self, path: str) -> None:
        created = False
        try:
            os.mkdir(path)
            created = True
        except FileExistsError:
            pass
        if created:
            self.ensure_private_directory(path)
        else:
            self.verify_private_directory(path)

    def _runtime_files(self, app_id: str, generation_id: str) -> tuple[str, ...]:
        paths = self.runtime_paths()
        directory = runtime_directory(paths.runtime_dir, app_id, generation_id)
        return (
            directory,
            os.path.join(directory, "request.json"),
            os.path.join(directory, "token.bin"),
            os.path.join(directory, "receipt.json"),
            os.path.join(paths.logs_dir, app_id + ".log"),
        )

    def _cleanup_tombstone_path(self, app_id: str, generation_id: str) -> str:
        validated_app_id = validate_app_id(app_id)
        validated_generation = validate_generation_id(generation_id)
        return os.path.join(
            self.runtime_paths().runtime_dir,
            f"{_CLEANUP_TOMBSTONE_PREFIX}{validated_app_id}-{validated_generation}",
        )

    @staticmethod
    def _parse_cleanup_tombstone(name: str) -> tuple[str, str] | None:
        if not name.startswith(_CLEANUP_TOMBSTONE_PREFIX):
            return None
        payload = name[len(_CLEANUP_TOMBSTONE_PREFIX):]
        if len(payload) != 45 or payload[8:9] != "-":
            return None
        app_id, generation_id = payload[:8], payload[9:]
        try:
            if (validate_app_id(app_id) != app_id
                    or validate_generation_id(generation_id) != generation_id):
                return None
        except (TypeError, ValueError, ProtocolError):
            return None
        return app_id, generation_id

    def _verify_runtime_record_directory(
        self, directory: str, *, exact: bool,
    ) -> tuple[str, ...]:
        self.verify_private_directory(directory)
        names: list[str] = []
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(names) >= 4 or not entry.is_file(follow_symlinks=False):
                    raise ProtocolError(
                        "RUNTIME_RECORD_INSECURE",
                        "runtime directory has unexpected records",
                    )
                names.append(entry.name)
        present = set(names)
        if (exact and present != _RUNTIME_RECORD_NAMES) or (
                not exact and not present.issubset(_RUNTIME_RECORD_NAMES)):
            raise ProtocolError(
                "RUNTIME_RECORD_INSECURE", "runtime directory has unexpected records"
            )
        for name in names:
            self.verify_private_file(os.path.join(directory, name))
        return tuple(sorted(names))

    def _stage_exact_runtime_records(self, app_id: str, generation_id: str) -> str:
        directory, request_path, token_path, receipt_path, _ = self._runtime_files(
            app_id, generation_id
        )
        runtime_root = self.runtime_paths().runtime_dir
        app_directory = os.path.dirname(directory)
        self.verify_private_directory(runtime_root)
        self.verify_private_directory(app_directory)
        self._verify_runtime_record_directory(directory, exact=True)
        # Keep these bindings explicit: the rename is the cleanup commit point,
        # and every credential must still be the verified exact source record.
        for path in (request_path, token_path, receipt_path):
            self.verify_private_file(path)
        tombstone = self._cleanup_tombstone_path(app_id, generation_id)
        if os.path.lexists(tombstone):
            raise ProtocolError(
                "RUNTIME_RECORD_INSECURE", "runtime cleanup tombstone already exists"
            )
        # Same-volume directory rename is atomic. Before it returns, failure
        # leaves the authenticated generation intact; after it returns, the
        # active runtime path is gone and config identity may stay cleared.
        os.rename(directory, tombstone)
        return tombstone

    def _discard_unpublished_runtime_records(
        self, app_id: str, generation_id: str,
    ) -> None:
        """Remove only records created by this failed, never-persisted launch."""
        directory, _, _, _, _ = self._runtime_files(app_id, generation_id)
        runtime_root = self.runtime_paths().runtime_dir
        self.verify_private_directory(runtime_root)
        self.verify_private_directory(os.path.dirname(directory))
        # Preparation can fail before receipt publication, so a strict subset
        # is valid here. Unexpected entries or ACL/link failures remain untouched.
        self._verify_runtime_record_directory(directory, exact=False)
        tombstone = self._cleanup_tombstone_path(app_id, generation_id)
        if os.path.lexists(tombstone):
            raise ProtocolError(
                "RUNTIME_RECORD_INSECURE", "runtime cleanup tombstone already exists"
            )
        os.rename(directory, tombstone)
        try:
            self._delete_cleanup_tombstone(tombstone)
        except (OSError, ProtocolError, pywintypes.error):
            pass

    def _delete_cleanup_tombstone(self, tombstone: str) -> None:
        runtime_root = self.runtime_paths().runtime_dir
        expected_parent = os.path.normcase(os.path.abspath(runtime_root))
        if os.path.normcase(os.path.dirname(os.path.abspath(tombstone))) != expected_parent:
            raise ProtocolError(
                "RUNTIME_RECORD_INSECURE", "cleanup tombstone escaped runtime root"
            )
        parsed = self._parse_cleanup_tombstone(os.path.basename(tombstone))
        if parsed is None:
            raise ProtocolError(
                "RUNTIME_RECORD_INSECURE", "cleanup tombstone name is invalid"
            )
        self.verify_private_directory(runtime_root)
        names = self._verify_runtime_record_directory(tombstone, exact=False)
        for name in names:
            os.unlink(os.path.join(tombstone, name))
        os.rmdir(tombstone)
        app_directory = os.path.join(runtime_root, parsed[0])
        try:
            self.verify_private_directory(app_directory)
            os.rmdir(app_directory)
        except OSError:
            pass

    def release_managed(self, identity: RuntimeIdentity) -> StopResult:
        """Delete one cleared generation after terminal ownership is proven."""
        try:
            self._runtime_context(identity, require_runner=False)
            inspection = self.inspect_managed(identity)
            if (not inspection.verified or inspection.status not in {"exited", "failed"}
                    or inspection.members):
                raise ProtocolError(
                    "RUNTIME_IDENTITY_UNVERIFIED", "runtime is not safely terminal"
                )
            self._wake_terminal_runner(identity)
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                observation = self._observe_process(int(identity.runner_pid or 0))
                if (observation is None or observation[0] != identity.owner
                        or abs(observation[1] - float(identity.runner_create_time or 0)) > 0.1):
                    break
                time.sleep(0.05)
            else:
                raise ProtocolError(
                    "RUNTIME_CONTROL_FAILED", "runner did not release runtime records"
                )
            tombstone = self._stage_exact_runtime_records(
                str(identity.app_id), str(identity.generation_id)
            )
            # The atomic rename above commits release. Record deletion is
            # intentionally best effort and recoverable after controller restart.
            try:
                self._delete_cleanup_tombstone(tombstone)
            except (OSError, ProtocolError, pywintypes.error):
                pass
            return StopResult(True, still_running=False, status=inspection.status)
        except (OSError, ProtocolError, pywintypes.error) as exc:
            return StopResult(
                False, str(exc), still_running=False, status="unknown",
                code=getattr(exc, "code", "RUNTIME_CONTROL_FAILED"),
            )

    def _wake_terminal_runner(self, identity: RuntimeIdentity) -> None:
        """Release a runner whose pipe thread is still waiting after Job exit."""
        try:
            pipe = self._connect_pipe(identity, timeout=0.5)
        except ProtocolError:
            return
        try:
            # A terminal runner accepts no more work. Connecting and closing an
            # authenticated-identity-bound pipe only releases ConnectNamedPipe;
            # the server observes EOF and completes its existing shutdown path.
            pass
        finally:
            pipe.Close()

    @staticmethod
    def _bounded_directory_names(path: str, limit: int) -> tuple[str, ...]:
        names: list[str] = []
        with os.scandir(path) as entries:
            for index, entry in enumerate(entries):
                if index >= limit:
                    break
                try:
                    if entry.is_dir(follow_symlinks=False):
                        names.append(entry.name)
                except OSError:
                    continue
        return tuple(sorted(names))

    def recover_managed_cleanups(self) -> tuple[RuntimeIdentity, ...]:
        """Finalize committed tombstones, then discover signed terminal generations."""
        runtime_root = self.runtime_paths().runtime_dir
        try:
            self.verify_private_directory(runtime_root)
            runtime_names = self._bounded_directory_names(
                runtime_root, _MAX_CLEANUP_RECOVERY_ENTRIES
            )
        except (OSError, ProtocolError, pywintypes.error):
            return ()

        # Tombstones are created only by the authenticated release transaction.
        # Recovery deletes only strict private directories with a derived name
        # and the bounded allowlisted record subset; it never opens a Job or PID.
        for name in runtime_names:
            if self._parse_cleanup_tombstone(name) is None:
                continue
            try:
                self._delete_cleanup_tombstone(os.path.join(runtime_root, name))
            except (OSError, ProtocolError, pywintypes.error):
                continue

        app_names = tuple(
            name for name in runtime_names
            if self._parse_cleanup_tombstone(name) is None
        )

        recovered: list[RuntimeIdentity] = []
        scanned_generations = 0
        for app_id in app_names:
            if scanned_generations >= _MAX_CLEANUP_RECOVERY_ENTRIES:
                break
            try:
                if validate_app_id(app_id) != app_id:
                    continue
                app_directory = os.path.join(runtime_root, app_id)
                self.verify_private_directory(app_directory)
                generation_names = self._bounded_directory_names(
                    app_directory,
                    _MAX_CLEANUP_RECOVERY_ENTRIES - scanned_generations,
                )
            except (OSError, ProtocolError, pywintypes.error):
                continue
            for generation_id in generation_names:
                scanned_generations += 1
                try:
                    if validate_generation_id(generation_id) != generation_id:
                        continue
                    directory, request_path, token_path, receipt_path, _ = (
                        self._runtime_files(app_id, generation_id)
                    )
                    self.verify_private_directory(directory)
                    record_names: list[str] = []
                    with os.scandir(directory) as records:
                        for record in records:
                            if len(record_names) >= 4:
                                break
                            record_names.append(record.name)
                    if set(record_names) != {
                        "request.json", "token.bin", "receipt.json"
                    }:
                        continue
                    self.verify_private_file(request_path)
                    self.verify_private_file(token_path)
                    self.verify_private_file(receipt_path)
                    with open(token_path, "rb") as stream:
                        token = stream.read(33)
                    if len(token) != 32:
                        continue
                    receipt = validate_receipt(
                        read_json(receipt_path),
                        token,
                        app_id=app_id,
                        generation_id=generation_id,
                        owner_sid=self._sid,
                    )
                    if receipt["state"] not in {"exited", "failed"}:
                        continue
                    members = tuple(sorted(int(pid) for pid in receipt["members"]))
                    if members:
                        continue
                    public = receipt["identity"]
                    identity = self._identity_from_public(public, app_id, members)
                    if windows_runtime_identity_public(identity) != public:
                        continue
                    if not terminal_observations_valid(
                        public,
                        runner_observation=self._observe_process(
                            int(public["runnerPid"])
                        ),
                        root_observation=self._observe_process(int(public["rootPid"])),
                        members=members,
                    ):
                        continue
                    recovered.append(identity)
                except (OSError, ValueError, ProtocolError, pywintypes.error):
                    continue
        return tuple(recovered)

    @staticmethod
    def _process_create_time(pid: int) -> float:
        handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid)
        )
        try:
            return float(
                win32process.GetProcessTimes(handle)["CreationTime"].timestamp()
            )
        finally:
            handle.Close()

    def _observe_process(self, pid: int) -> tuple[str, float] | None:
        try:
            process = psutil.Process(int(pid))
            create_time = float(process.create_time())
        except psutil.NoSuchProcess:
            return None
        except (psutil.AccessDenied, OSError) as exc:
            raise ProtocolError(
                "RUNTIME_IDENTITY_UNVERIFIED", "runtime process is not observable"
            ) from exc
        try:
            owner = self._process_owner_sid(pid)
            handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid)
            )
            try:
                if int(win32process.GetExitCodeProcess(handle)) != win32con.STILL_ACTIVE:
                    return None
            finally:
                handle.Close()
            return owner, create_time
        except pywintypes.error as exc:
            if exc.winerror in {winerror.ERROR_INVALID_PARAMETER,
                                winerror.ERROR_FILE_NOT_FOUND}:
                return None
            raise ProtocolError(
                "RUNTIME_IDENTITY_UNVERIFIED", "runtime process owner is not observable"
            ) from exc

    @staticmethod
    def _identity_from_public(
        public: Mapping[str, object], app_id: str, members: tuple[int, ...] = (),
    ) -> RuntimeIdentity:
        return RuntimeIdentity(
            platform="windows",
            kind="job",
            identifier=str(public["jobName"]),
            owner=str(public["ownerSid"]),
            members=members,
            app_id=app_id,
            generation_id=str(public["generationId"]),
            runner_pid=int(public["runnerPid"]),
            runner_create_time=float(public["runnerCreateTime"]),
            root_pid=int(public["rootPid"]),
            root_create_time=float(public["rootCreateTime"]),
            job_name=str(public["jobName"]),
            token_digest=str(public["tokenDigest"]),
            started_at=int(public["startedAt"]),
        )

    def _validate_identity(self, identity: RuntimeIdentity, token: bytes) -> dict[str, object]:
        if identity.app_id is None or identity.generation_id is None:
            raise ProtocolError("RUNTIME_IDENTITY_INVALID", "runtime identity is incomplete")
        public = windows_runtime_identity_public(identity)
        return validate_public_identity(
            public,
            app_id=identity.app_id,
            generation_id=identity.generation_id,
            owner_sid=self._sid,
            digest=token_digest(token),
        )

    @staticmethod
    def _receipt_previous_state(state: object) -> str | None:
        return {
            "prepared": None,
            "running": "prepared",
            "stopping": "running",
            "exited": "running",
            "failed": "prepared",
        }.get(state)  # type: ignore[arg-type]

    def _runtime_context(
        self, identity: RuntimeIdentity, *, require_runner: bool,
        allow_stale_root: bool = False,
    ) -> _WindowsRuntimeContext:
        if identity.app_id is None or identity.generation_id is None:
            raise ProtocolError("RUNTIME_IDENTITY_INVALID", "runtime identity is incomplete")
        directory, request_path, token_path, receipt_path, _ = self._runtime_files(
            identity.app_id, identity.generation_id
        )
        self.verify_private_directory(directory)
        self.verify_private_file(request_path)
        self.verify_private_file(token_path)
        self.verify_private_file(receipt_path)
        with open(token_path, "rb") as stream:
            token = stream.read(33)
        if len(token) != 32:
            raise ProtocolError("RUNTIME_RECORD_INSECURE", "invalid runtime token")
        expected = self._validate_identity(identity, token)
        raw_receipt = read_json(receipt_path)
        unsigned = dict(raw_receipt)
        unsigned.pop("hmac", None)
        previous = self._receipt_previous_state(unsigned.get("state"))
        if previous is None and unsigned.get("state") not in {"prepared", "failed"}:
            raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid current runner state")
        receipt = validate_receipt(
            raw_receipt,
            token,
            app_id=identity.app_id,
            generation_id=identity.generation_id,
            owner_sid=self._sid,
            previous_state=previous,
        )
        if receipt["identity"] != expected:
            raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "receipt identity mismatch")
        members = tuple(sorted(int(pid) for pid in receipt["members"]))
        state = str(receipt["state"])
        if state in {"exited", "failed"}:
            if members:
                raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "terminal Job is not empty")
            if not terminal_observations_valid(
                expected,
                runner_observation=self._observe_process(int(expected["runnerPid"])),
                root_observation=self._observe_process(int(expected["rootPid"])),
                members=members,
            ):
                raise ProtocolError(
                    "RUNTIME_IDENTITY_UNVERIFIED", "terminal process evidence mismatch"
                )
        elif require_runner:
            runner_observation = self._observe_process(int(expected["runnerPid"]))
            root_observation = (
                self._observe_process(int(expected["rootPid"]))
                if int(expected["rootPid"]) in members else None
            )
            valid = reconnect_observations_valid(
                expected,
                runner_observation=runner_observation,
                root_observation=root_observation,
                members=members,
            )
            if (not valid and allow_stale_root and runner_observation is not None
                    and runner_observation[0] == expected["ownerSid"]
                    and abs(
                        runner_observation[1] - float(expected["runnerCreateTime"])
                    ) <= 0.1
                    and root_observation is None):
                valid = True
            if not valid:
                raise ProtocolError(
                    "RUNTIME_IDENTITY_UNVERIFIED", "runtime process evidence mismatch"
                )
        return _WindowsRuntimeContext(identity, token, receipt, members, state)

    def _connect_pipe(self, identity: RuntimeIdentity, timeout: float) -> object:
        if identity.app_id is None or identity.generation_id is None:
            raise ProtocolError("RUNTIME_IDENTITY_INVALID", "runtime identity is incomplete")
        name = pipe_name(identity.app_id, identity.generation_id)
        deadline = time.monotonic() + max(0.1, float(timeout))
        while True:
            try:
                handle = win32file.CreateFile(
                    name,
                    win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                    0,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None,
                )
                win32pipe.SetNamedPipeHandleState(
                    handle, win32pipe.PIPE_READMODE_MESSAGE, None, None
                )
                if int(win32pipe.GetNamedPipeServerProcessId(handle)) != identity.runner_pid:
                    handle.Close()
                    raise ProtocolError(
                        "RUNTIME_IDENTITY_UNVERIFIED", "named pipe runner mismatch"
                    )
                observation = self._observe_process(int(identity.runner_pid))
                if (observation is None or observation[0] != identity.owner
                        or abs(
                            observation[1] - float(identity.runner_create_time or 0)
                        ) > 0.1):
                    handle.Close()
                    raise ProtocolError(
                        "RUNTIME_IDENTITY_UNVERIFIED",
                        "named pipe runner identity changed",
                    )
                return handle
            except pywintypes.error as exc:
                if (exc.winerror not in {winerror.ERROR_FILE_NOT_FOUND,
                                         winerror.ERROR_PIPE_BUSY}
                        or time.monotonic() >= deadline):
                    raise ProtocolError(
                        "RUNTIME_CONTROL_FAILED", "runner control channel unavailable"
                    ) from exc
                try:
                    win32pipe.WaitNamedPipe(name, 100)
                except pywintypes.error:
                    pass

    def _control(
        self,
        identity: RuntimeIdentity,
        action: str,
        *,
        payload: Mapping[str, object] | None = None,
        timeout: float = 5.0,
    ) -> tuple[dict[str, object], _WindowsRuntimeContext]:
        context = self._runtime_context(
            identity,
            require_runner=True,
            allow_stale_root=action == "inspect",
        )
        request = make_request(
            action, str(identity.generation_id), context.token, payload
        )
        pipe = self._connect_pipe(identity, timeout)
        try:
            win32file.WriteFile(pipe, encode_message(request))
            _, data = win32file.ReadFile(pipe, PIPE_BUFFER_BYTES)
        except pywintypes.error as exc:
            raise ProtocolError(
                "RUNTIME_CONTROL_FAILED", "runner control exchange failed"
            ) from exc
        finally:
            pipe.Close()
        response = verify_response(decode_message(bytes(data)), context.token, request)
        response_payload = response["payload"]
        if set(response_payload) != {"identity", "members", "exitCode"}:
            raise ProtocolError("RUNTIME_CONTROL_FAILED", "invalid runner response payload")
        expected = self._validate_identity(identity, context.token)
        actual = validate_public_identity(
            response_payload["identity"],
            app_id=str(identity.app_id),
            generation_id=str(identity.generation_id),
            owner_sid=self._sid,
            digest=token_digest(context.token),
        )
        if actual != expected:
            raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "runner identity mismatch")
        members = response_payload["members"]
        if (not isinstance(members, list)
                or any(not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0
                       for pid in members)
                or len(members) != len(set(members))):
            raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "invalid Job members")
        refreshed = self._runtime_context(
            identity,
            require_runner=str(response["status"]) not in {"exited", "failed"},
        )
        if refreshed.state != response["status"]:
            raise ProtocolError(
                "RUNTIME_IDENTITY_UNVERIFIED",
                "runner receipt state mismatch",
            )
        return response, refreshed

    def launch(self, app: LaunchRequest) -> ManagedRuntime:
        if app.command_spec is None or app.generation_id is None:
            return ManagedRuntime(
                False,
                "Windows launch requires a reviewed command and generation",
                code="LAUNCH_PREPARE_FAILED",
            )
        process: subprocess.Popen[bytes] | None = None
        identity: RuntimeIdentity | None = None
        directory_created = False
        try:
            invocation = prepared_invocation(app.command_spec)
            if isinstance(invocation, list):
                executable = invocation[0]
                resolved = resolve_windows_executable(
                    executable, env=os.environ, cwd=app.cwd
                )
                if resolved is None:
                    raise CommandSpecError("Windows executable is unavailable")
                invocation = [resolved, *invocation[1:]]
            else:
                executable = str(invocation["executable"])
                resolved = resolve_windows_executable(
                    executable, env=os.environ, cwd=app.cwd
                )
                if resolved is None:
                    raise CommandSpecError("Windows executable is unavailable")
                invocation = {**invocation, "executable": resolved}
            runner_executable, runner_environment = _runner_process_settings()
            if (
                isinstance(invocation, list)
                and runner_environment is not None
                and runner_environment.get("__PYVENV_LAUNCHER__") == sys.executable
                and os.path.normcase(os.path.abspath(invocation[0]))
                == os.path.normcase(os.path.abspath(sys.executable))
            ):
                # The Windows venv redirector exits after spawning base Python,
                # which would make rootPid and its console group stale. The
                # runner already carries the venv launcher marker, so invoking
                # base Python directly preserves the venv with one stable root.
                invocation = [runner_executable, *invocation[1:]]
            directory, request_path, token_path, receipt_path, expected_log = (
                self._runtime_files(app.app_id, app.generation_id)
            )
            if os.path.normcase(os.path.abspath(app.log_path)) != os.path.normcase(
                os.path.abspath(expected_log)
            ):
                raise ProtocolError("RUNTIME_RECORD_INSECURE", "unexpected log path")
            paths = self.runtime_paths()
            for parent in (paths.data_dir, paths.logs_dir, paths.runtime_dir):
                try:
                    os.mkdir(parent)
                except FileExistsError:
                    pass
                # These are controller-owned storage parents, not token-bearing
                # generation records. Reapply the exact private DACL because
                # Windows inheritance can mutate their inherited ACE flags.
                self.ensure_private_directory(parent)
            app_directory = os.path.dirname(directory)
            if os.path.isdir(app_directory):
                if os.listdir(app_directory):
                    self.verify_private_directory(app_directory)
                else:
                    os.rmdir(app_directory)
                    os.mkdir(app_directory)
                    self.ensure_private_directory(app_directory)
            else:
                os.mkdir(app_directory)
                self.ensure_private_directory(app_directory)
            os.mkdir(directory)
            directory_created = True
            self.ensure_private_directory(directory)
            if not os.path.isfile(expected_log):
                self._create_private_file(expected_log, b"")
            self.ensure_private_file(expected_log)
            token = new_token()
            self._create_private_file(token_path, token)
            self.ensure_private_file(token_path)
            request = make_launch_request(
                app_id=app.app_id,
                generation_id=app.generation_id,
                owner_sid=self._sid,
                invocation=invocation,
                cwd=os.path.abspath(app.cwd),
                log_path=expected_log,
                token=token,
            )
            write_json_atomic(request_path, request, self.ensure_private_file)
            self.ensure_private_file(request_path)
            flags = (
                win32process.DETACHED_PROCESS
                | win32process.CREATE_NEW_PROCESS_GROUP
                | win32process.CREATE_UNICODE_ENVIRONMENT
            )
            with open(expected_log, "ab", buffering=0) as runner_log:
                self.verify_private_file(expected_log)
                process = subprocess.Popen(
                    runner_command(
                        runner_executable, app.app_id, app.generation_id
                    ),
                    cwd=self.base_dir,
                    env=runner_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=runner_log,
                    stderr=runner_log,
                    close_fds=True,
                    creationflags=flags,
                )
            deadline = time.monotonic() + _RUNNER_PREPARE_TIMEOUT
            while time.monotonic() < deadline:
                if os.path.isfile(receipt_path):
                    self.verify_private_file(receipt_path)
                    receipt = validate_receipt(
                        read_json(receipt_path),
                        token,
                        app_id=app.app_id,
                        generation_id=app.generation_id,
                        owner_sid=self._sid,
                    )
                    public = receipt["identity"]
                    if int(public["runnerPid"]) != process.pid:
                        raise ProtocolError(
                            "RUNTIME_IDENTITY_UNVERIFIED", "unexpected runner process"
                        )
                    identity = self._identity_from_public(
                        public, app.app_id,
                        tuple(sorted(int(pid) for pid in receipt["members"])),
                    )
                    self._runtime_context(identity, require_runner=True)
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.05)
            if identity is None:
                raise ProtocolError("LAUNCH_PREPARE_FAILED", "runner did not prepare")
            response, _ = self._control(identity, "inspect", timeout=2.0)
            if not response["ok"] or response["status"] != "prepared":
                raise ProtocolError("LAUNCH_PREPARE_FAILED", "runner is not prepared")
            return ManagedRuntime(
                True,
                process=process,
                process_id=identity.root_pid,
                runtime_identity=identity,
                status="prepared",
            )
        except (CommandSpecError, OSError, ProtocolError, pywintypes.error) as exc:
            code = getattr(exc, "code", "LAUNCH_PREPARE_FAILED")
            if identity is not None:
                aborted = self.abort_managed(identity)
                if aborted.ok:
                    released = self.release_managed(identity)
                    if released.ok:
                        identity = None
            elif process is not None:
                try:
                    process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    # This is the exact runner just created by this call. It owns
                    # only this still-uncommitted generation.
                    process.terminate()
                    try:
                        process.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        pass
                if process.poll() is not None and directory_created:
                    try:
                        self._discard_unpublished_runtime_records(
                            app.app_id, app.generation_id
                        )
                    except (OSError, ProtocolError, pywintypes.error):
                        pass
            elif directory_created:
                try:
                    self._discard_unpublished_runtime_records(
                        app.app_id, app.generation_id
                    )
                except (OSError, ProtocolError, pywintypes.error):
                    pass
            return ManagedRuntime(
                False,
                str(exc),
                runtime_identity=identity,
                status="failed",
                code=code,
            )

    def activate_managed(self, identity: RuntimeIdentity) -> ManagedActivation:
        try:
            response, _ = self._control(identity, "resume", timeout=5.0)
            if not response["ok"] or response["status"] != "running":
                return ManagedActivation(
                    False,
                    str(response.get("error") or "runner activation failed"),
                    status=str(response["status"]),
                    code=str(response.get("code") or "LAUNCH_ACTIVATE_FAILED"),
                )
            return ManagedActivation(True, status="running", process_id=identity.root_pid)
        except (OSError, ProtocolError, pywintypes.error) as exc:
            return ManagedActivation(
                False, str(exc), status="prepared",
                code=getattr(exc, "code", "LAUNCH_ACTIVATE_FAILED"),
            )

    def abort_managed(self, identity: RuntimeIdentity) -> StopResult:
        try:
            response, context = self._control(identity, "abort", timeout=5.0)
            return StopResult(
                bool(response["ok"] and not context.members),
                None if response["ok"] else str(response.get("error") or "abort failed"),
                still_running=bool(context.members),
                status=context.state,
                code=None if response["ok"] else str(
                    response.get("code") or "RUNTIME_CONTROL_FAILED"
                ),
            )
        except (OSError, ProtocolError, pywintypes.error) as exc:
            return StopResult(
                False, str(exc), still_running=True, status="unknown",
                code=getattr(exc, "code", "RUNTIME_CONTROL_FAILED"),
            )

    def inspect_managed(self, identity: RuntimeIdentity) -> ManagedInspection:
        try:
            context = self._runtime_context(identity, require_runner=False)
            if context.state in {"exited", "failed"}:
                return ManagedInspection(
                    False,
                    True,
                    members=(),
                    status=context.state,
                    identity=identity,
                    code=context.receipt.get("code"),
                    exit_code=context.receipt.get("exitCode"),
                    updated_at=int(context.receipt["updatedAt"]),
                )
            runner_observation = self._observe_process(int(identity.runner_pid or 0))
            if runner_observation is None or (
                runner_observation[0] != identity.owner
                or abs(runner_observation[1] - float(identity.runner_create_time or 0))
                > 0.1
            ):
                root_observation = self._observe_process(int(identity.root_pid or 0))
                original_root_alive = bool(
                    root_observation is not None
                    and root_observation[0] == identity.owner
                    and abs(
                        root_observation[1] - float(identity.root_create_time or 0)
                    ) <= 0.1
                )
                if original_root_alive:
                    raise ProtocolError(
                        "RUNTIME_IDENTITY_UNVERIFIED",
                        "runner exited before Job cleanup completed",
                    )
                # The signed receipt binds this generation to a kill-on-close Job
                # whose runner is its sole handle owner. Proven runner absence/PID
                # reuse therefore proves kernel cleanup without reopening the Job.
                return ManagedInspection(
                    False,
                    True,
                    members=(),
                    status="failed",
                    identity=identity,
                    code="RUNTIME_CONTROL_FAILED",
                    exit_code=None,
                    updated_at=int(time.time() * 1000),
                )
            response, refreshed = self._control(identity, "inspect", timeout=2.0)
            return ManagedInspection(
                running=bool(refreshed.members),
                verified=bool(response["ok"]),
                members=refreshed.members,
                status=refreshed.state,
                identity=self._identity_from_public(
                    refreshed.receipt["identity"], str(identity.app_id), refreshed.members
                ),
                code=response.get("code"),
                exit_code=refreshed.receipt.get("exitCode"),
                updated_at=int(refreshed.receipt["updatedAt"]),
            )
        except (OSError, ProtocolError, pywintypes.error) as exc:
            code = getattr(exc, "code", "RUNTIME_IDENTITY_UNVERIFIED")
            return ManagedInspection(
                False,
                False,
                issue=_issue("managed", code, str(exc)),
                status="unknown",
                code=code,
            )

    def stop_managed(
        self, identity: RuntimeIdentity, force: bool = False, timeout: float = 5.0,
    ) -> StopResult:
        action = "force" if force else "stop"
        try:
            inspection = self.inspect_managed(identity)
            if not inspection.verified:
                return StopResult(
                    False,
                    inspection.issue.message if inspection.issue else
                    "runtime identity could not be verified",
                    still_running=True,
                    status=inspection.status,
                    code=inspection.code or "RUNTIME_IDENTITY_UNVERIFIED",
                )
            if inspection.status in {"exited", "failed"} and not inspection.members:
                return StopResult(True, still_running=False, status=inspection.status)
            response, context = self._control(
                identity, action, payload={"timeout": float(timeout)},
                timeout=max(2.0, float(timeout) + 2.0),
            )
            return StopResult(
                bool(response["ok"] and not context.members),
                None if response["ok"] else str(response.get("error") or "stop failed"),
                still_running=bool(context.members),
                status=context.state,
                code=None if response["ok"] else str(
                    response.get("code") or "RUNTIME_CONTROL_FAILED"
                ),
            )
        except (OSError, ProtocolError, pywintypes.error) as exc:
            return StopResult(
                False, str(exc), still_running=True, status="unknown",
                code=getattr(exc, "code", "RUNTIME_CONTROL_FAILED"),
            )

    @staticmethod
    def stop_external_process(pid: int, force: bool = False) -> StopResult:
        return StopResult(False, "Windows external process control is disabled")

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
        return RestartResult(False, error="Windows console restart is disabled")

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

"""Elevated broker installer and fixed Named Pipe server for Windows."""

from __future__ import annotations

import hashlib
import hmac
import json
import ntpath
import os
from pathlib import Path
import re
import shutil
import secrets
import subprocess
import sys
import threading
import time
import uuid
from typing import Mapping, Sequence

import ntsecuritycon
import pythoncom
import psutil
import pywintypes
import win32api
import win32con
import win32file
import win32pipe
import win32process
import win32security
import winerror
import win32com.client
from win32com.shell import shell

from localops.elevation_broker import (
    BROKER_INSTALL_SCHEMA,
    BROKER_PUBLIC_SCHEMA,
    BROKER_TASK_PATH,
    ElevationBrokerProtocol,
    broker_install_request_digest,
    broker_pipe_name,
    broker_task_spec,
    normalize_elevated_launch,
    normalize_elevated_stop,
    normalize_scheduled_request,
    normalize_elevated_task_command_spec,
    make_keepalive_registry,
    validate_keepalive_registry,
)
from localops.command_spec import (
    is_local_windows_path,
    prepared_invocation,
    resolve_windows_executable,
)
from localops.windows.job_object import OwnedJob
from localops.windows.runner_protocol import (
    decode_message,
    encode_message,
    native_process_command,
    validate_app_id,
)


_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_USERS_SID = "S-1-5-32-545"
_EVERYONE_SID = "S-1-1-0"
_AUTHENTICATED_USERS_SID = "S-1-5-11"
_CREATOR_OWNER_SID = "S-1-3-0"
_TRUSTED_INSTALLER_SID = (
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)
_MAX_MESSAGE = 1024 * 1024
_CAPABILITY_TEMP_RE = re.compile(
    r"(?:key\.bin|grants\.json)\.tmp-[0-9a-f]{32}\Z"
)
_KEEP_ALIVE_ATTESTATION_TTL = 30.0
_KEEP_ALIVE_RESOURCE_VERIFY_TTL = 30.0


def _program_data_dir() -> Path:
    root = os.environ.get("ProgramData") or r"C:\ProgramData"
    return Path(root) / "LocalOps"


def _verify_broker_data_ancestors(*, require_localops: bool) -> None:
    raw_root = Path(os.environ.get("ProgramData") or r"C:\ProgramData")
    root = Path(os.path.abspath(raw_root))
    if (not root.is_dir() or root.is_symlink()
            or win32api.GetFileAttributes(
                str(root)) & win32con.FILE_ATTRIBUTE_REPARSE_POINT
            or os.path.normcase(os.path.realpath(root))
            != os.path.normcase(os.path.abspath(root))):
        raise OSError("ProgramData root is not a trusted canonical directory")
    expected_localops = Path(os.path.abspath(root / "LocalOps"))
    if expected_localops.exists():
        if (not expected_localops.is_dir() or expected_localops.is_symlink()
                or win32api.GetFileAttributes(
                    str(expected_localops)) & win32con.FILE_ATTRIBUTE_REPARSE_POINT
                or os.path.normcase(os.path.realpath(expected_localops))
                != os.path.normcase(os.path.abspath(expected_localops))):
            raise OSError("LocalOps ProgramData directory is not canonical")
    elif require_localops:
        raise OSError("LocalOps ProgramData directory is missing")
    expected_capabilities = expected_localops / "capabilities"
    if expected_capabilities.exists() and (
            not expected_capabilities.is_dir()
            or expected_capabilities.is_symlink()
            or win32api.GetFileAttributes(
                str(expected_capabilities)) & win32con.FILE_ATTRIBUTE_REPARSE_POINT
            or os.path.normcase(os.path.realpath(expected_capabilities))
            != os.path.normcase(os.path.abspath(expected_capabilities))):
        raise OSError("capability directory is not canonical")


def _program_files_broker_dir() -> Path:
    root = os.environ.get("ProgramFiles") or r"C:\Program Files"
    return Path(root) / "LocalOps" / "Broker"


def public_config_path() -> Path:
    return _program_data_dir() / "elevation-broker.json"


def secret_config_path() -> Path:
    return _program_data_dir() / "elevation-password.json"


def capability_dir() -> Path:
    return _program_data_dir() / "capabilities"


def capability_key_path() -> Path:
    return capability_dir() / "key.bin"


def capability_registry_path() -> Path:
    return capability_dir() / "grants.json"


def _acl(owner_sid: str, *, user_access: int, inherit: bool) -> object:
    flags = (
        win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE
        if inherit else 0
    )
    acl = win32security.ACL()
    for sid_text, access in (
        (_SYSTEM_SID, ntsecuritycon.FILE_ALL_ACCESS),
        (_ADMINISTRATORS_SID, ntsecuritycon.FILE_ALL_ACCESS),
        (owner_sid, user_access),
    ):
        if access:
            acl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                flags,
                access,
                win32security.ConvertStringSidToSid(sid_text),
            )
    return acl


def _protect_path(
        path: Path, owner_sid: str, *, directory: bool,
        user_access: int) -> None:
    if path.is_symlink() or (directory and not path.is_dir()) or (
            not directory and not path.is_file()):
        raise OSError("broker path is not a safe expected object")
    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        _acl(owner_sid, user_access=user_access, inherit=directory),
        None,
    )


def _write_json(path: Path, payload: Mapping[str, object], owner_sid: str, *, secret: bool):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    data = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    try:
        with open(temporary, "xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        access = 0 if secret else (
            ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_EXECUTE
        )
        _protect_path(temporary, owner_sid, directory=False, user_access=access)
        os.replace(temporary, path)
        _protect_path(path, owner_sid, directory=False, user_access=access)
    finally:
        temporary.unlink(missing_ok=True)


def _write_secret_bytes(path: Path, payload: bytes, owner_sid: str) -> None:
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    try:
        with open(temporary, "xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _protect_path(temporary, owner_sid, directory=False, user_access=0)
        os.replace(temporary, path)
        _protect_path(path, owner_sid, directory=False, user_access=0)
    finally:
        temporary.unlink(missing_ok=True)


def _verify_broker_only_path(
        path: Path, *, directory: bool, allow_inherited: bool = False) -> None:
    if (path.is_symlink() or (directory and not path.is_dir())
            or (not directory and not path.is_file())):
        raise OSError("broker-only path is not a safe expected object")
    attributes = win32api.GetFileAttributes(str(path))
    if attributes & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
        raise OSError("broker-only path cannot be a reparse point")
    descriptor = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION,
    )
    owner = win32security.ConvertSidToStringSid(
        descriptor.GetSecurityDescriptorOwner()
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    aces = [
        dacl.GetAce(index) for index in range(dacl.GetAceCount())
    ] if dacl is not None else []
    principals = {
        win32security.ConvertSidToStringSid(ace[2]) for ace in aces
    }
    allowed = {_SYSTEM_SID, _ADMINISTRATORS_SID}
    control = descriptor.GetSecurityDescriptorControl()[0]
    if (owner not in allowed or principals != allowed
            or not aces
            or not all(
                ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
                and ace[1] & ntsecuritycon.FILE_ALL_ACCESS
                == ntsecuritycon.FILE_ALL_ACCESS
                for ace in aces
            ) or (
                not allow_inherited
                and not control & win32security.SE_DACL_PROTECTED
            )):
        raise PermissionError("broker-only ACL verification failed")


def _verify_broker_public_directory(path: Path, owner_sid: str) -> None:
    if (path.is_symlink() or not path.is_dir()
            or win32api.GetFileAttributes(
                str(path)) & win32con.FILE_ATTRIBUTE_REPARSE_POINT):
        raise OSError("broker public directory is not a safe directory")
    descriptor = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION,
    )
    owner = win32security.ConvertSidToStringSid(
        descriptor.GetSecurityDescriptorOwner()
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    aces = [
        dacl.GetAce(index) for index in range(dacl.GetAceCount())
    ] if dacl is not None else []
    expected = {
        _SYSTEM_SID: ntsecuritycon.FILE_ALL_ACCESS,
        _ADMINISTRATORS_SID: ntsecuritycon.FILE_ALL_ACCESS,
        owner_sid: (
            ntsecuritycon.FILE_GENERIC_READ
            | ntsecuritycon.FILE_GENERIC_EXECUTE
        ),
    }
    actual = {
        win32security.ConvertSidToStringSid(ace[2]): int(ace[1])
        for ace in aces
        if ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
    }
    control = descriptor.GetSecurityDescriptorControl()[0]
    if (owner not in {_SYSTEM_SID, _ADMINISTRATORS_SID}
            or set(actual) != set(expected)
            or any(actual[sid] & ~mask for sid, mask in expected.items())
            or not control & win32security.SE_DACL_PROTECTED):
        raise PermissionError("broker public directory ACL verification failed")


def _verify_broker_public_file(path: Path, owner_sid: str) -> None:
    if (path.is_symlink() or not path.is_file()
            or win32api.GetFileAttributes(
                str(path)) & win32con.FILE_ATTRIBUTE_REPARSE_POINT):
        raise OSError("broker public file is not a safe regular file")
    descriptor = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION,
    )
    owner = win32security.ConvertSidToStringSid(
        descriptor.GetSecurityDescriptorOwner()
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    aces = [
        dacl.GetAce(index) for index in range(dacl.GetAceCount())
    ] if dacl is not None else []
    expected = {
        _SYSTEM_SID: ntsecuritycon.FILE_ALL_ACCESS,
        _ADMINISTRATORS_SID: ntsecuritycon.FILE_ALL_ACCESS,
        owner_sid: (
            ntsecuritycon.FILE_GENERIC_READ
            | ntsecuritycon.FILE_GENERIC_EXECUTE
        ),
    }
    actual = {
        win32security.ConvertSidToStringSid(ace[2]): int(ace[1])
        for ace in aces
        if ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
    }
    control = descriptor.GetSecurityDescriptorControl()[0]
    if (owner not in {_SYSTEM_SID, _ADMINISTRATORS_SID}
            or set(actual) != set(expected)
            or any(actual[sid] & ~mask for sid, mask in expected.items())
            or not control & win32security.SE_DACL_PROTECTED):
        raise PermissionError("broker public file ACL verification failed")


def _cleanup_capability_temporaries(directory: Path) -> None:
    for item in directory.iterdir():
        if item.name in {"key.bin", "grants.json"}:
            continue
        if not _CAPABILITY_TEMP_RE.fullmatch(item.name):
            raise OSError("capability store contains unknown entries")
        # The directory was already verified broker-only. A crash between raw
        # file creation and explicit protection can leave the exact inherited
        # SYSTEM/Administrators ACL without SE_DACL_PROTECTED; that remains
        # safe to remove, but no additional principal or right is accepted.
        _verify_broker_only_path(
            item, directory=False, allow_inherited=True
        )
        item.unlink()


def _load_capability_registry(
        owner_sid: str, *, create: bool
        ) -> tuple[bytes, str, int, dict[str, object]]:
    _verify_broker_data_ancestors(require_localops=True)
    directory = capability_dir()
    directory_created = False
    if directory.exists():
        if directory.is_symlink() or not directory.is_dir():
            raise OSError("capability store is not a safe directory")
    elif create:
        directory.mkdir(parents=False)
        directory_created = True
    else:
        raise OSError("capability store is missing")
    if directory_created:
        _protect_path(directory, owner_sid, directory=True, user_access=0)
    _verify_broker_only_path(directory, directory=True)
    _cleanup_capability_temporaries(directory)
    key_path = capability_key_path()
    registry_path = capability_registry_path()
    if key_path.exists():
        _verify_broker_only_path(key_path, directory=False)
        key = key_path.read_bytes()
    elif create:
        key = secrets.token_bytes(32)
        _write_secret_bytes(key_path, key, owner_sid)
    else:
        raise OSError("capability key is missing")
    if len(key) != 32:
        raise OSError("capability key length is invalid")
    _verify_broker_only_path(key_path, directory=False)
    key_id = hashlib.sha256(key).hexdigest()[:32]
    if registry_path.exists():
        _verify_broker_only_path(registry_path, directory=False)
        registry = _read_json(registry_path)
        revision, grants = validate_keepalive_registry(
            registry, key, owner_sid=owner_sid, key_id=key_id
        )
    elif create:
        revision, grants = 0, {}
        _write_json(
            registry_path,
            make_keepalive_registry(owner_sid, key_id, revision, grants, key),
            owner_sid,
            secret=True,
        )
    else:
        raise OSError("capability registry is missing")
    _verify_broker_only_path(registry_path, directory=False)
    _verify_broker_data_ancestors(require_localops=True)
    _verify_broker_only_path(directory, directory=True)
    return key, key_id, revision, grants


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _protect_bundle(root: Path, owner_sid: str) -> None:
    user_rx = ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_EXECUTE
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        if current_path.is_symlink():
            raise OSError("broker bundle contains a link")
        _protect_path(current_path, owner_sid, directory=True, user_access=user_rx)
        for name in [*dirs, *files]:
            candidate = current_path / name
            if candidate.is_symlink():
                raise OSError("broker bundle contains a link")
            _protect_path(
                candidate, owner_sid, directory=candidate.is_dir(), user_access=user_rx
            )


def _register_task(spec: Mapping[str, str]) -> None:
    pythoncom.CoInitialize()
    service = folder = definition = action = registered = None
    try:
        service = win32com.client.Dispatch("Schedule.Service")
        service.Connect()
        folder = service.GetFolder("\\")
        definition = service.NewTask(0)
        definition.RegistrationInfo.Description = (
            "Local Ops fixed elevation broker. No dynamic command is stored in this task."
        )
        definition.Principal.UserId = spec["ownerSid"]
        definition.Principal.LogonType = 3
        definition.Principal.RunLevel = 1
        definition.Settings.Enabled = True
        definition.Settings.AllowDemandStart = True
        definition.Settings.MultipleInstances = 2
        definition.Settings.ExecutionTimeLimit = "PT0S"
        definition.Settings.DisallowStartIfOnBatteries = False
        definition.Settings.StopIfGoingOnBatteries = False
        action = definition.Actions.Create(0)
        action.Path = spec["executable"]
        action.Arguments = spec["arguments"]
        action.WorkingDirectory = spec["workingDirectory"]
        registered = folder.RegisterTaskDefinition(
            BROKER_TASK_PATH.lstrip("\\"), definition, 6,
            spec["ownerSid"], None, 3, spec["sddl"],
        )
        if int(registered.State or 0) == 4:
            registered.Stop(0)
            deadline = time.monotonic() + 10.0
            while (int(registered.State or 0) == 4
                   and time.monotonic() < deadline):
                time.sleep(0.05)
            if int(registered.State or 0) == 4:
                raise TimeoutError(
                    "previous elevation broker instance did not stop"
                )
    finally:
        registered = action = definition = folder = service = None
        pythoncom.CoUninitialize()


def install(request: Mapping[str, object]) -> dict[str, object]:
    if (not isinstance(request, Mapping)
            or request.get("schema") != BROKER_INSTALL_SCHEMA
            or set(request) != {
                "schema", "ownerSid", "passwordRecord",
                "bundleSource", "executableName",
            }):
        raise ValueError("broker install request is invalid")
    if not bool(getattr(sys, "frozen", False)):
        raise ValueError("broker installation requires the packaged Windows build")
    owner_sid = str(request["ownerSid"])
    source = Path(str(request["bundleSource"])).resolve()
    executable_name = str(request["executableName"])
    if source != Path(sys.executable).resolve().parent:
        raise ValueError("broker bundle source does not match the elevated package")
    source_executable = source / executable_name
    if source_executable.resolve() != Path(sys.executable).resolve():
        raise ValueError("broker executable does not match the elevated package")
    fingerprint = _sha256(source_executable)
    broker_root = _program_files_broker_dir()
    broker_root.mkdir(parents=True, exist_ok=True)
    target = broker_root / fingerprint[:16]
    target_executable = target / executable_name
    if not target.exists():
        staging = broker_root / (".install-" + uuid.uuid4().hex)
        try:
            shutil.copytree(source, staging, symlinks=False)
            _protect_bundle(staging, owner_sid)
            os.replace(staging, target)
        finally:
            if staging.exists() and staging.parent == broker_root:
                shutil.rmtree(staging)
    if not target_executable.is_file() or _sha256(target_executable) != fingerprint:
        raise OSError("installed broker executable hash mismatch")
    _protect_bundle(target, owner_sid)
    spec = broker_task_spec(str(target_executable), owner_sid)
    pipe_name = broker_pipe_name(owner_sid)
    public = {
        "schema": BROKER_PUBLIC_SCHEMA,
        "ownerSid": owner_sid,
        "executable": str(target_executable),
        "workingDirectory": str(target),
        "taskPath": BROKER_TASK_PATH,
        "pipeName": pipe_name,
        "executableSha256": fingerprint,
    }
    secret = {
        "schema": BROKER_PUBLIC_SCHEMA,
        "ownerSid": owner_sid,
        "passwordRecord": request["passwordRecord"],
    }
    data_dir = _program_data_dir()
    _verify_broker_data_ancestors(require_localops=False)
    data_created = not data_dir.exists()
    if data_created:
        data_dir.mkdir(parents=True, exist_ok=False)
        _protect_path(
            data_dir, owner_sid, directory=True,
            user_access=ntsecuritycon.FILE_GENERIC_READ
            | ntsecuritycon.FILE_GENERIC_EXECUTE,
        )
    _verify_broker_public_directory(data_dir, owner_sid)
    _write_json(public_config_path(), public, owner_sid, secret=False)
    _write_json(secret_config_path(), secret, owner_sid, secret=True)
    _load_capability_registry(owner_sid, create=True)
    _register_task(spec)
    return {"ok": True, "taskPath": BROKER_TASK_PATH}


def _read_json(path: Path) -> dict[str, object]:
    with open(path, "r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("broker configuration must be an object")
    return value


def _owner_sid(pid: int) -> str:
    process = win32api.OpenProcess(
        win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    try:
        token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
        try:
            sid = win32security.GetTokenInformation(
                token, win32security.TokenUser
            )[0]
            return win32security.ConvertSidToStringSid(sid)
        finally:
            token.Close()
    finally:
        process.Close()


def _launch(request: dict[str, object]) -> int:
    normalized = normalize_elevated_launch(request)
    process = subprocess.Popen(
        [normalized["executable"], *normalized["args"]],
        cwd=normalized["cwd"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=(
            win32process.DETACHED_PROCESS | win32process.CREATE_NEW_PROCESS_GROUP
        ),
    )
    return int(process.pid)


def _observe(request: dict[str, object], owner_sid: str) -> dict[str, object]:
    normalized = normalize_elevated_launch(request)
    favorite = os.path.normcase(os.path.realpath(normalized["executable"]))
    favorite_dir = os.path.dirname(favorite)
    favorite_name = os.path.basename(favorite)
    expected_args = list(normalized["args"])
    now = time.time()
    matches = []
    for process in psutil.process_iter(("pid", "name")):
        try:
            pid = int(process.pid)
            if (pid == os.getpid()
                    or os.path.normcase(process.name()) != favorite_name):
                continue
            executable = os.path.normcase(os.path.realpath(process.exe()))
            if (executable != favorite
                    and os.path.commonpath(
                        [favorite_dir, executable]
                    ) != favorite_dir):
                continue
            if _owner_sid(pid).casefold() != owner_sid.casefold():
                continue
            command = process.cmdline()
            if expected_args and command[-len(expected_args):] != expected_args:
                continue
            created = float(process.create_time())
            matches.append({
                "pid": pid,
                "createTime": created,
                "executable": executable,
                "commandLine": subprocess.list2cmdline(command),
                "etime": max(0, int(now - created)),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError,
                pywintypes.error):
            continue
    matches.sort(key=lambda row: int(row["pid"]))
    return {"ok": True, "processes": matches}


def _stop(request: dict[str, object], owner_sid: str) -> dict[str, object]:
    normalized = normalize_elevated_stop(request)
    validated = []
    stopped = []
    for row in normalized["processes"]:
        pid = int(row["pid"])
        if pid == os.getpid():
            return {
                "ok": False, "code": "BROKER_STOP_IDENTITY_MISMATCH",
                "error": "broker cannot stop itself", "running": True,
            }
        try:
            process = psutil.Process(pid)
            if _owner_sid(pid).casefold() != owner_sid.casefold():
                raise ValueError("process owner changed")
            actual_executable = os.path.normcase(os.path.realpath(process.exe()))
            expected_executable = os.path.normcase(
                os.path.realpath(str(row["executable"]))
            )
            if actual_executable != expected_executable:
                raise ValueError("process executable changed")
            if abs(float(process.create_time()) - float(row["createTime"])) > 0.001:
                raise ValueError("process creation time changed")
            validated.append((pid, process))
        except psutil.NoSuchProcess:
            stopped.append(pid)
        except (psutil.AccessDenied, OSError, ValueError, pywintypes.error) as exc:
            return {
                "ok": False, "code": "BROKER_STOP_IDENTITY_MISMATCH",
                "error": str(exc), "running": True,
            }

    running = []
    for pid, process in validated:
        try:
            process.terminate()
            process.wait(timeout=5.0)
            stopped.append(pid)
        except psutil.NoSuchProcess:
            stopped.append(pid)
        except psutil.TimeoutExpired:
            running.append(pid)
        except (psutil.AccessDenied, OSError) as exc:
            return {
                "ok": False, "code": "BROKER_STOP_FAILED",
                "error": str(exc), "stopped": stopped,
                "running": [pid, *running],
            }
    if running:
        return {
            "ok": False, "code": "STOP_TIMEOUT",
            "error": "one or more programs did not exit before timeout",
            "stopped": stopped, "running": running,
        }
    return {"ok": True, "stopped": stopped, "running": []}


def _scheduled(request: dict[str, object], owner_sid: str) -> dict[str, object]:
    normalized = normalize_scheduled_request(request)
    from localops.platform.windows import WindowsPlatform

    platform = WindowsPlatform(os.getcwd(), sys.executable)
    if platform.current_principal().identifier.casefold() != owner_sid.casefold():
        return {
            "ok": False, "code": "BROKER_SCHEDULED_OWNER_MISMATCH",
            "error": "scheduled task owner SID changed",
        }
    operation = str(normalized["operation"])
    if operation in {"list", "query"}:
        snapshot = platform.scheduled_tasks(
            None if operation == "list" else set(normalized["paths"])
        )
        return {
            "ok": snapshot.status.value != "failed",
            "operation": operation,
            "status": snapshot.status.value,
            "tasks": snapshot.tasks,
            "issues": [{
                "component": issue.component,
                "code": issue.code,
                "message": issue.message,
                "degrades": issue.degrades,
            } for issue in snapshot.issues],
        }
    if operation == "run":
        result = platform.run_scheduled_task(str(normalized["path"]))
    elif operation == "stop":
        result = platform.stop_scheduled_task(str(normalized["path"]))
    elif operation == "toggle":
        result = platform.set_scheduled_task_enabled(
            str(normalized["path"]), bool(normalized["enabled"])
        )
    else:
        result = platform.set_scheduled_task_history_enabled(
            bool(normalized["enabled"])
        )
    return {
        "ok": result.ok,
        "operation": operation,
        "path": getattr(result, "task_path", None),
        "enabled": getattr(result, "enabled", None),
        "error": result.error,
        "code": result.code,
    }


def _scheduled_runtime(path: str, owner_sid: str) -> dict[str, object]:
    normalized = normalize_scheduled_request({
        "operation": "query", "paths": [path]
    })["paths"][0]
    from localops.platform.windows import WindowsPlatform

    platform = WindowsPlatform(os.getcwd(), sys.executable)
    if platform.current_principal().identifier.casefold() != owner_sid.casefold():
        raise PermissionError("scheduled task owner SID changed")
    row = platform.scheduled_task_runtime(str(normalized))
    return {
        "ok": True,
        "operation": "query",
        "status": "ok",
        "tasks": {str(normalized).casefold(): row},
        "issues": [],
    }


def _pipe_security(owner_sid: str) -> object:
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorDacl(
        True,
        _acl(
            owner_sid,
            user_access=ntsecuritycon.FILE_ALL_ACCESS,
            inherit=False,
        ),
        False,
    )
    attributes = win32security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


def _canonical_digest(value: Mapping[str, object]) -> str:
    payload = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _task_security_record(
        task: Mapping[str, object], owner_sid: str) -> dict[str, object]:
    action_types = list(task.get("actionTypes") or [])
    action_details = list(task.get("actionDetails") or [])
    definition_fingerprint = task.get("definitionFingerprint")
    security_fingerprint = task.get("securityDescriptorFingerprint")
    principal_sid = str(task.get("principalSid") or "")
    run_level = str(task.get("runLevel") or "")
    security_locked = task.get("securityLocked")
    # A mutable task is safe only when Task Scheduler will execute it with the
    # broker owner's limited token. Highest/foreign tasks still require a
    # privileged-writer-only descriptor so the grant cannot become elevation.
    limited_to_owner = (
        run_level == "limited"
        and principal_sid.casefold() == owner_sid.casefold()
    )
    if (task.get("actionCount") != 1 or len(action_details) != 1
            or action_details[0].get("type") != "exec"
            or action_types not in ([0], ["Exec"])
            or not isinstance(definition_fingerprint, str)
            or not isinstance(security_fingerprint, str)
            or (security_locked is not True and security_locked is not False)
            or (security_locked is not True and not limited_to_owner)
            or not principal_sid):
        raise ValueError(
            "persistent scheduled keep-alive requires one fully verified Exec task"
        )
    return {
        "path": str(task.get("path") or ""),
        "principalSid": principal_sid,
        "runLevel": run_level,
        "multipleInstances": str(task.get("multipleInstances") or ""),
        "triggerCount": int(task.get("triggerCount") or 0),
        "principalLogonType": task.get("principalLogonType"),
        "actionDetails": action_details,
        "actionTypes": action_types,
        "definitionFingerprint": definition_fingerprint,
        "securityDescriptorFingerprint": security_fingerprint,
        "securityLocked": security_locked is True,
    }


def _program_files_roots() -> tuple[str, ...]:
    roots = []
    for name in ("ProgramFiles", "ProgramFiles(x86)"):
        value = os.environ.get(name)
        if value:
            roots.append(os.path.normcase(os.path.realpath(value)))
    return tuple(dict.fromkeys(roots))


def _reject_user_writable(
        path: Path, owner_sid: str, *, directory: bool,
        allow_root_creator_owner: bool = False) -> None:
    descriptor = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION,
    )
    owner = win32security.ConvertSidToStringSid(
        descriptor.GetSecurityDescriptorOwner()
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    write_mask = (
        win32con.GENERIC_WRITE
        | ntsecuritycon.FILE_WRITE_DATA
        | ntsecuritycon.FILE_APPEND_DATA
        | ntsecuritycon.FILE_ADD_FILE
        | ntsecuritycon.FILE_ADD_SUBDIRECTORY
        | ntsecuritycon.FILE_DELETE_CHILD
        | ntsecuritycon.DELETE
        | ntsecuritycon.WRITE_DAC
        | ntsecuritycon.WRITE_OWNER
    )
    trusted_writers = {
        _SYSTEM_SID.casefold(),
        _ADMINISTRATORS_SID.casefold(),
        _TRUSTED_INSTALLER_SID.casefold(),
    }
    if owner.casefold() not in trusted_writers:
        raise PermissionError(
            "persistent elevated keep-alive target has an untrusted owner"
        )
    for ace in (
            dacl.GetAce(index) for index in range(dacl.GetAceCount())
            ) if dacl is not None else ():
        sid = win32security.ConvertSidToStringSid(ace[2]).casefold()
        inherit_only = bool(ace[0][1] & win32con.INHERIT_ONLY_ACE)
        if (inherit_only and directory and allow_root_creator_owner
                and sid == _CREATOR_OWNER_SID.casefold()):
            continue
        if (ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
                and (directory or not inherit_only)
                and sid not in trusted_writers and ace[1] & write_mask):
            raise PermissionError(
                "persistent elevated keep-alive target is user-writable"
            )


def _protected_program_fingerprint(
        executable: object, owner_sid: str) -> tuple[str, str]:
    if not isinstance(executable, str):
        raise ValueError("keep-alive executable is invalid")
    path = Path(executable)
    if not path.is_file() or path.is_symlink():
        raise ValueError("keep-alive executable is not a regular protected file")
    resolved = os.path.normcase(os.path.realpath(path))
    if not any(
            os.path.commonpath([root, resolved]) == root
            for root in _program_files_roots()):
        raise ValueError("keep-alive executable must be installed under Program Files")
    _reject_user_writable(
        Path(resolved), owner_sid, directory=False
    )
    return resolved, _sha256(Path(resolved))


def _protected_program_request(
        value: object, owner_sid: str) -> tuple[dict[str, object], str]:
    launch = normalize_elevated_launch(value)
    executable, digest = _protected_program_fingerprint(
        launch["executable"], owner_sid
    )
    cwd_path = Path(str(launch["cwd"]))
    if not cwd_path.is_dir() or cwd_path.is_symlink():
        raise ValueError("keep-alive working directory is not protected")
    cwd = os.path.normcase(os.path.realpath(cwd_path))
    if cwd != os.path.dirname(executable):
        raise ValueError(
            "persistent elevated keep-alive requires the executable directory"
        )
    matching_roots = [
        root for root in _program_files_roots()
        if os.path.commonpath([root, cwd]) == root
    ]
    if len(matching_roots) != 1:
        raise ValueError("persistent elevated keep-alive root is ambiguous")
    root = matching_roots[0]
    cursor = Path(cwd)
    while True:
        if (cursor.is_symlink()
                or win32api.GetFileAttributes(
                    str(cursor)) & win32con.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError(
                "persistent elevated keep-alive path contains a reparse point"
            )
        _reject_user_writable(
            cursor,
            owner_sid,
            directory=True,
            allow_root_creator_owner=(
                os.path.normcase(os.path.realpath(cursor)) == root
            ),
        )
        if os.path.normcase(os.path.realpath(cursor)) == root:
            break
        if cursor.parent == cursor:
            raise ValueError("persistent elevated keep-alive path escaped its root")
        cursor = cursor.parent
    launch["executable"] = executable
    launch["cwd"] = cwd
    return launch, digest


def _prepare_keepalive_grant(
        request: Mapping[str, object], owner_sid: str) -> dict[str, object]:
    app_id = request.get("appId")
    kind = request.get("kind")
    if (not isinstance(app_id, str) or len(app_id) != 8
            or any(char not in "0123456789abcdefABCDEF" for char in app_id)):
        raise ValueError("keep-alive app id is invalid")
    if kind == "elevatedProgram" and set(request) == {
            "appId", "kind", "request"}:
        launch, digest = _protected_program_request(
            request.get("request"), owner_sid
        )
        return {
            "appId": app_id.lower(),
            "kind": kind,
            "request": launch,
            "executableSha256": digest,
        }
    if kind == "scheduledService" and set(request) == {
            "appId", "kind", "path"}:
        path = normalize_scheduled_request({
            "operation": "query", "paths": [request.get("path")]
        })["paths"][0]
        response = _scheduled({"operation": "query", "paths": [path]}, owner_sid)
        task = (response.get("tasks") or {}).get(path.casefold())
        if not response.get("ok") or not isinstance(task, Mapping):
            raise ValueError("scheduled keep-alive target is unavailable")
        return {
            "appId": app_id.lower(),
            "kind": kind,
            "path": path,
            "taskFingerprint": _canonical_digest(
                _task_security_record(task, owner_sid)
            ),
        }
    raise ValueError("keep-alive grant resource is invalid")


class _KeepAliveGrantExecutor:
    def __init__(self, owner_sid: str, *, clock=time.monotonic):
        self.owner_sid = owner_sid
        self.clock = clock
        self._verified: dict[tuple[str, ...], float] = {}

    def _cached(self, key: tuple[str, ...], now: float) -> bool:
        self._verified = {
            item: expiry for item, expiry in self._verified.items()
            if expiry >= now
        }
        expiry = self._verified.get(key)
        return expiry is not None and expiry >= now

    def _remember(self, key: tuple[str, ...], now: float) -> None:
        self._verified[key] = now + _KEEP_ALIVE_RESOURCE_VERIFY_TTL

    def __call__(
            self, operation: str, record: Mapping[str, object]
            ) -> dict[str, object]:
        now = self.clock()
        if record.get("kind") == "elevatedProgram":
            request = record.get("request")
            key = (
                "program",
                str(record.get("executableSha256") or ""),
                _canonical_digest(request if isinstance(request, Mapping) else {}),
            )
            if self._cached(key, now):
                launch = normalize_elevated_launch(request)
            else:
                launch, digest = _protected_program_request(
                    request, self.owner_sid
                )
                if digest != record.get("executableSha256"):
                    raise ValueError("keep-alive executable identity changed")
                self._remember(key, now)
            if operation == "observe":
                return _observe(launch, self.owner_sid)
            observed = _observe(launch, self.owner_sid)
            if not observed.get("ok"):
                return observed
            if observed.get("processes"):
                return {
                    "ok": False,
                    "code": "BROKER_KEEPALIVE_ALREADY_RUNNING",
                    "error": "the exact elevated program is already running",
                }
            return {"ok": True, "pid": _launch(launch)}

        if record.get("kind") == "scheduledService":
            path = str(record.get("path") or "")
            key = (
                "scheduled",
                path.casefold(),
                str(record.get("taskFingerprint") or ""),
            )
            if self._cached(key, now):
                queried = _scheduled_runtime(path, self.owner_sid)
            else:
                queried = _scheduled(
                    {"operation": "query", "paths": [path]}, self.owner_sid
                )
                task = (queried.get("tasks") or {}).get(path.casefold())
                if not queried.get("ok") or not isinstance(task, Mapping):
                    raise ValueError("scheduled keep-alive target is unavailable")
                task_fingerprint = _canonical_digest(
                    _task_security_record(task, self.owner_sid)
                )
                if task_fingerprint != record.get("taskFingerprint"):
                    raise ValueError("scheduled keep-alive task definition changed")
                self._remember(key, now)
            task = (queried.get("tasks") or {}).get(path.casefold())
            if not queried.get("ok") or not isinstance(task, Mapping):
                self._verified.pop(key, None)
                raise ValueError("scheduled keep-alive target is unavailable")
            if operation == "query":
                return queried
            if task.get("state") != "ready" or task.get("enabled") is not True:
                return {
                    "ok": False,
                    "code": "BROKER_KEEPALIVE_TASK_NOT_READY",
                    "error": "scheduled keep-alive task is not ready",
                }
            # A run attempt changes volatile task state and forces the next
            # observation through a complete XML/SDDL verification.
            self._verified.pop(key, None)
            return _scheduled(
                {"operation": "run", "path": path}, self.owner_sid
            )
        raise ValueError("keep-alive grant kind is invalid")


def _execute_keepalive_grant(
        operation: str, record: Mapping[str, object], owner_sid: str
        ) -> dict[str, object]:
    return _KeepAliveGrantExecutor(owner_sid)(operation, record)


class _BoundedClientImageAttestation:
    def __init__(
            self, owner_sid: str, executable_sha256: str, *,
            verify=None, clock=time.monotonic):
        self.owner_sid = owner_sid
        self.executable_sha256 = executable_sha256
        self.verify = verify or _keepalive_client_image_valid
        self.clock = clock
        self._verified: dict[tuple[object, ...], float] = {}

    def __call__(self, executable: Path) -> bool:
        try:
            if not executable.is_file() or executable.is_symlink():
                return False
            info = executable.stat(follow_symlinks=False)
            key = (
                os.path.normcase(os.path.realpath(executable)),
                int(info.st_dev), int(info.st_ino), int(info.st_size),
                int(info.st_mtime_ns), self.owner_sid.casefold(),
                self.executable_sha256,
            )
        except (OSError, ValueError):
            return False
        now = self.clock()
        self._verified = {
            item: expiry for item, expiry in self._verified.items()
            if expiry >= now
        }
        expiry = self._verified.get(key)
        if expiry is not None and expiry >= now:
            return True
        valid = bool(self.verify(
            executable, self.owner_sid, self.executable_sha256
        ))
        if valid:
            self._verified[key] = now + _KEEP_ALIVE_ATTESTATION_TTL
        return valid


def _keepalive_client_image_valid(
        executable: Path, owner_sid: str, executable_sha256: str) -> bool:
    try:
        resolved = os.path.normcase(os.path.realpath(executable))
        local_ops_root = os.path.normcase(os.path.realpath(
            Path(os.environ.get("ProgramFiles") or r"C:\Program Files") / "LocalOps"
        ))
        if (not executable.is_file() or executable.is_symlink()
                or os.path.commonpath([local_ops_root, resolved]) != local_ops_root
                or not hmac.compare_digest(_sha256(executable), executable_sha256)):
            return False
        cursor = executable.parent
        root_path = Path(local_ops_root)
        while True:
            if win32api.GetFileAttributes(
                    str(cursor)) & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
                return False
            if os.path.normcase(os.path.realpath(cursor)) == local_ops_root:
                break
            if cursor.parent == cursor or root_path not in cursor.parents:
                return False
            cursor = cursor.parent
        descriptor = win32security.GetNamedSecurityInfo(
            str(executable), win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION,
        )
        file_owner = win32security.ConvertSidToStringSid(
            descriptor.GetSecurityDescriptorOwner()
        )
        dacl = descriptor.GetSecurityDescriptorDacl()
        aces = [
            dacl.GetAce(index) for index in range(dacl.GetAceCount())
        ] if dacl is not None else []
        masks = {
            _SYSTEM_SID: ntsecuritycon.FILE_ALL_ACCESS,
            _ADMINISTRATORS_SID: ntsecuritycon.FILE_ALL_ACCESS,
            owner_sid: (
                ntsecuritycon.FILE_GENERIC_READ
                | ntsecuritycon.FILE_GENERIC_EXECUTE
            ),
        }
        control = descriptor.GetSecurityDescriptorControl()[0]
        return bool(
            file_owner in {_SYSTEM_SID, _ADMINISTRATORS_SID}
            and {
                win32security.ConvertSidToStringSid(ace[2]) for ace in aces
            } == set(masks)
            and all(
                ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE
                and ace[1] & ~masks[
                    win32security.ConvertSidToStringSid(ace[2])
                ] == 0
                for ace in aces
            )
            and control & win32security.SE_DACL_PROTECTED
        )
    except (OSError, psutil.Error, pywintypes.error, ValueError):
        return False


def _keepalive_client_valid(
        pid: int, created: float, owner_sid: str,
        executable_sha256: str, *, image_valid=None) -> bool:
    try:
        process = psutil.Process(pid)
        # These identity facts are intentionally never cached: the PID comes
        # from the Named Pipe kernel and clientCreateTime is untrusted input.
        if (_owner_sid(pid).casefold() != owner_sid.casefold()
                or abs(float(process.create_time()) - float(created)) > 0.01):
            return False
        executable = Path(process.exe())
        process_handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        try:
            token = win32security.OpenProcessToken(
                process_handle, win32con.TOKEN_QUERY
            )
            try:
                if bool(win32security.GetTokenInformation(
                        token, win32security.TokenElevation)):
                    return False
            finally:
                token.Close()
        finally:
            process_handle.Close()
        verifier = image_valid or (
            lambda path: _keepalive_client_image_valid(
                path, owner_sid, executable_sha256
            )
        )
        return bool(verifier(executable))
    except (OSError, psutil.Error, pywintypes.error, ValueError):
        return False


def _trusted_system_interpreter(mode: str, owner_sid: str) -> str:
    if mode == "cmd":
        relative = ("System32", "cmd.exe")
    elif mode == "powershell":
        relative = (
            "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
        )
    else:
        raise ValueError("elevated task interpreter mode is invalid")
    windows = Path(win32api.GetWindowsDirectory())
    expected = windows.joinpath(*relative)
    expected_absolute = os.path.normcase(os.path.abspath(expected))
    resolved = os.path.normcase(os.path.realpath(expected))
    if (not expected.is_file() or expected.is_symlink()
            or resolved != expected_absolute):
        raise ValueError("elevated task system interpreter is unavailable")
    cursor = windows
    if (cursor.is_symlink()
            or win32api.GetFileAttributes(
                str(cursor)) & win32con.FILE_ATTRIBUTE_REPARSE_POINT):
        raise ValueError(
            "elevated task system interpreter path contains a reparse point"
        )
    _reject_user_writable(
        cursor,
        owner_sid,
        directory=True,
        allow_root_creator_owner=True,
    )
    for part in relative:
        cursor /= part
        if (cursor.is_symlink()
                or win32api.GetFileAttributes(
                    str(cursor)) & win32con.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError(
                "elevated task system interpreter path contains a reparse point"
            )
        _reject_user_writable(
            cursor,
            owner_sid,
            directory=cursor != expected,
            allow_root_creator_owner=cursor != expected,
        )
    return os.path.abspath(expected)


def _prepare_elevated_task_request(
        value: Mapping[str, object],
        owner_sid: str) -> tuple[str, object, str]:
    if set(value) != {"appId", "commandSpec", "cwd"}:
        raise ValueError("elevated task request shape is invalid")
    app_id = validate_app_id(value.get("appId"))
    cwd_value = value.get("cwd")
    if (not isinstance(cwd_value, str) or not ntpath.isabs(cwd_value)
            or not is_local_windows_path(cwd_value)
            or not os.path.isdir(cwd_value)):
        raise ValueError("elevated task working directory is invalid")
    cwd = os.path.abspath(cwd_value)
    spec = normalize_elevated_task_command_spec(value.get("commandSpec"))
    if spec.get("mode") in {"cmd", "powershell"}:
        script = spec.get("executable")
        if (not isinstance(script, str) or not ntpath.isabs(script)
                or not is_local_windows_path(script) or not os.path.isfile(script)):
            raise ValueError("elevated task script is unavailable")
    mode = str(spec.get("mode") or "")
    if mode in {"cmd", "powershell"}:
        interpreter = _trusted_system_interpreter(mode, owner_sid)
        environment = dict(os.environ)
        if mode == "cmd":
            environment["COMSPEC"] = interpreter
        invocation = prepared_invocation(spec, env=environment)
        if not isinstance(invocation, Mapping):
            raise ValueError("elevated task structured invocation is invalid")
        invocation = {**invocation, "executable": interpreter}
    else:
        invocation = prepared_invocation(spec)
        executable = str(invocation[0])
        resolved = resolve_windows_executable(
            executable, env=os.environ, cwd=cwd
        )
        if resolved is None:
            raise ValueError("elevated task executable is unavailable")
        invocation = [resolved, *invocation[1:]]
    native_process_command(invocation)
    return app_id, invocation, cwd


class _ElevatedBatchRun:
    def __init__(
            self, app_id: str, run_id: str, owner_sid: str,
            invocation: object, cwd: str):
        self.app_id = app_id
        self.run_id = run_id
        self.owner_sid = owner_sid
        self.started_at = int(time.time() * 1000)
        self.completed_at: int | None = None
        self.exit_code: int | None = None
        self.manually_stopped = False
        self.process_handle = None
        self.process_id: int | None = None
        self.create_time: float | None = None
        self.job: OwnedJob | None = None
        self._start(invocation, cwd)

    def _start(self, invocation: object, cwd: str) -> None:
        application, command_line = native_process_command(invocation)
        input_stream = output_stream = None
        input_handle = output_handle = None
        input_inheritable = output_inheritable = False
        process_handle = thread_handle = None
        job = None
        try:
            input_stream = open(os.devnull, "rb", buffering=0)
            output_stream = open(os.devnull, "ab", buffering=0)
            msvcrt = __import__("msvcrt")
            input_handle = int(msvcrt.get_osfhandle(input_stream.fileno()))
            output_handle = int(msvcrt.get_osfhandle(output_stream.fileno()))
            os.set_handle_inheritable(input_handle, True)
            input_inheritable = True
            os.set_handle_inheritable(output_handle, True)
            output_inheritable = True
            startup = win32process.STARTUPINFO()
            startup.dwFlags = (
                win32con.STARTF_USESTDHANDLES
                | win32con.STARTF_USESHOWWINDOW
            )
            startup.wShowWindow = win32con.SW_HIDE
            startup.hStdInput = input_handle
            startup.hStdOutput = output_handle
            startup.hStdError = output_handle
            process_handle, thread_handle, pid, _ = win32process.CreateProcess(
                application,
                command_line,
                None,
                None,
                True,
                win32process.CREATE_SUSPENDED
                | win32process.CREATE_NEW_PROCESS_GROUP
                | win32process.CREATE_UNICODE_ENVIRONMENT
                | getattr(subprocess, "CREATE_NO_WINDOW", 0),
                None,
                cwd,
                startup,
            )
            job = OwnedJob(
                "Local\\LocalOps-ElevatedBatch-" + self.run_id,
                self.owner_sid,
            )
            job.assign(process_handle)
            created = float(
                win32process.GetProcessTimes(process_handle)["CreationTime"].timestamp()
            )
            previous = int(win32process.ResumeThread(thread_handle))
            if previous != 1:
                raise OSError("elevated task suspended count is invalid")
            win32api.CloseHandle(thread_handle)
            thread_handle = None
            self.process_handle = process_handle
            self.process_id = int(pid)
            self.create_time = created
            self.job = job
        except Exception:
            if process_handle is not None:
                try:
                    win32process.TerminateProcess(process_handle, 1)
                except pywintypes.error:
                    pass
            if job is not None:
                try:
                    job.terminate(1)
                except Exception:
                    pass
                job.close()
            if thread_handle is not None:
                win32api.CloseHandle(thread_handle)
            if process_handle is not None:
                win32api.CloseHandle(process_handle)
            raise
        finally:
            if input_inheritable and input_handle is not None:
                try:
                    os.set_handle_inheritable(input_handle, False)
                except OSError:
                    pass
            if output_inheritable and output_handle is not None:
                try:
                    os.set_handle_inheritable(output_handle, False)
                except OSError:
                    pass
            if input_stream is not None:
                input_stream.close()
            if output_stream is not None:
                output_stream.close()

    def _refresh(self) -> None:
        if self.completed_at is not None or self.job is None:
            return
        if self.job.members():
            return
        code = None
        if self.process_handle is not None:
            try:
                code = int(win32process.GetExitCodeProcess(self.process_handle))
            except pywintypes.error:
                code = None
            win32api.CloseHandle(self.process_handle)
            self.process_handle = None
        self.job.close()
        self.job = None
        self.exit_code = None if code == win32con.STILL_ACTIVE else code
        self.completed_at = int(time.time() * 1000)

    def result(self) -> dict[str, object]:
        self._refresh()
        return {
            "ok": True,
            "appId": self.app_id,
            "found": True,
            "running": self.completed_at is None,
            "pid": self.process_id,
            "createTime": self.create_time,
            "startedAt": self.started_at,
            "completedAt": self.completed_at,
            "exitCode": self.exit_code,
            "manuallyStopped": self.manually_stopped,
        }

    def stop(self) -> dict[str, object]:
        self._refresh()
        if self.job is not None:
            self.job.terminate(130)
            if not self.job.wait_empty(5.0):
                raise OSError("elevated task Job did not stop")
            self.exit_code = 130
            self.manually_stopped = True
            self.completed_at = int(time.time() * 1000)
            if self.process_handle is not None:
                win32api.CloseHandle(self.process_handle)
                self.process_handle = None
            self.job.close()
            self.job = None
        return self.result()

    def close(self) -> None:
        if self.job is not None:
            self.job.close()
            self.job = None
        if self.process_handle is not None:
            win32api.CloseHandle(self.process_handle)
            self.process_handle = None


class _ElevatedBatchTaskManager:
    def __init__(self, owner_sid: str, *, run_factory=None):
        self.owner_sid = owner_sid
        self.run_factory = run_factory or _ElevatedBatchRun
        self.runs: dict[str, object] = {}
        self.lock = threading.RLock()

    def _prune(self, maximum: int) -> None:
        terminal = []
        for app_id, run in self.runs.items():
            result = run.result()
            if not result["running"]:
                terminal.append((int(result.get("completedAt") or 0), app_id))
        while len(self.runs) > maximum and terminal:
            _, app_id = min(terminal)
            terminal = [item for item in terminal if item[1] != app_id]
            old = self.runs.pop(app_id)
            old.close()

    def launch(self, request: Mapping[str, object]) -> dict[str, object]:
        app_id, invocation, cwd = _prepare_elevated_task_request(
            request, self.owner_sid
        )
        with self.lock:
            previous = self.runs.get(app_id)
            if previous is not None and previous.result()["running"]:
                return {
                    "ok": False,
                    "code": "BROKER_ELEVATED_TASK_ALREADY_RUNNING",
                    "error": "the elevated batch task is already running",
                }
            if previous is None:
                self._prune(255)
                if len(self.runs) >= 256:
                    return {
                        "ok": False,
                        "code": "BROKER_ELEVATED_TASK_CAPACITY",
                        "error": "too many elevated batch task records",
                    }
            if previous is not None:
                previous.close()
            run_id = uuid.uuid4().hex
            run = self.run_factory(
                app_id, run_id, self.owner_sid, invocation, cwd
            )
            self.runs[app_id] = run
            return run.result()

    def query(self, app_id: str) -> dict[str, object]:
        app_id = validate_app_id(app_id)
        with self.lock:
            run = self.runs.get(app_id)
            if run is None:
                return {
                    "ok": True, "appId": app_id,
                    "found": False, "running": False,
                }
            return run.result()

    def stop(self, app_id: str) -> dict[str, object]:
        app_id = validate_app_id(app_id)
        with self.lock:
            run = self.runs.get(app_id)
            if run is None:
                return {
                    "ok": True, "appId": app_id,
                    "found": False, "running": False,
                }
            return run.stop()


def serve() -> int:
    _verify_broker_data_ancestors(require_localops=True)
    expected_owner_sid = _owner_sid(os.getpid())
    _verify_broker_public_directory(
        _program_data_dir(), expected_owner_sid
    )
    _verify_broker_public_file(public_config_path(), expected_owner_sid)
    _verify_broker_only_path(secret_config_path(), directory=False)
    public = _read_json(public_config_path())
    secret = _read_json(secret_config_path())
    owner_sid = str(public.get("ownerSid") or "")
    if owner_sid.casefold() != expected_owner_sid.casefold():
        return 2
    if (secret.get("schema") != BROKER_PUBLIC_SCHEMA
            or secret.get("ownerSid") != owner_sid):
        return 2
    capability_key, key_id, revision, grants = _load_capability_registry(
        owner_sid, create=False
    )
    revision_box = [revision]
    grant_executor = _KeepAliveGrantExecutor(owner_sid)
    elevated_task_manager = _ElevatedBatchTaskManager(owner_sid)
    executable_sha256 = str(public.get("executableSha256") or "")
    client_image_attestation = _BoundedClientImageAttestation(
        owner_sid, executable_sha256
    )

    def persist_grants(records: Mapping[str, object]) -> None:
        next_revision = revision_box[0] + 1
        signed = make_keepalive_registry(
            owner_sid, key_id, next_revision, records, capability_key
        )
        _write_json(
            capability_registry_path(), signed, owner_sid, secret=True
        )
        _verify_broker_only_path(
            capability_registry_path(), directory=False
        )
        revision_box[0] = next_revision

    protocol = ElevationBrokerProtocol(
        secret.get("passwordRecord"),
        owner_sid=owner_sid,
        process_matches=lambda pid, created, owner: (
            _owner_sid(pid).casefold() == owner.casefold()
            and abs(psutil.Process(pid).create_time() - created) <= 0.01
        ),
        launch=_launch,
        observe=lambda request: _observe(request, owner_sid),
        stop=lambda request: _stop(request, owner_sid),
        scheduled=lambda request: _scheduled(request, owner_sid),
        grant_prepare=lambda request: _prepare_keepalive_grant(
            request, owner_sid
        ),
        grant_execute=grant_executor,
        grant_client_valid=lambda pid, created: _keepalive_client_valid(
            pid, created, owner_sid, executable_sha256,
            image_valid=client_image_attestation,
        ),
        elevated_task_launch=elevated_task_manager.launch,
        elevated_task_query=elevated_task_manager.query,
        elevated_task_stop=elevated_task_manager.stop,
        grant_records=grants,
        persist_grants=persist_grants,
    )
    pipe_name = broker_pipe_name(owner_sid)
    failed_unlocks = 0
    while True:
        pipe = win32pipe.CreateNamedPipe(
            pipe_name,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE
            | win32pipe.PIPE_WAIT,
            8,
            _MAX_MESSAGE,
            _MAX_MESSAGE,
            0,
            _pipe_security(owner_sid),
        )
        try:
            try:
                win32pipe.ConnectNamedPipe(pipe, None)
            except pywintypes.error as exc:
                if exc.winerror != winerror.ERROR_PIPE_CONNECTED:
                    raise
            client_pid = int(win32pipe.GetNamedPipeClientProcessId(pipe))
            _, raw = win32file.ReadFile(pipe, _MAX_MESSAGE)
            message = decode_message(bytes(raw))
            response = protocol.handle(message, client_pid=client_pid)
            if message.get("action") == "unlock" and not response.get("ok"):
                failed_unlocks += 1
                time.sleep(min(5.0, 0.25 * (2 ** min(failed_unlocks, 4))))
            elif response.get("ok"):
                failed_unlocks = 0
            win32file.WriteFile(pipe, encode_message(response))
            win32file.FlushFileBuffers(pipe)
        except (OSError, psutil.Error, pywintypes.error, ValueError):
            try:
                win32file.WriteFile(
                    pipe, encode_message({
                        "ok": False, "code": "BROKER_REQUEST_FAILED"
                    })
                )
            except pywintypes.error:
                pass
        finally:
            try:
                win32pipe.DisconnectNamedPipe(pipe)
            except pywintypes.error:
                pass
            win32file.CloseHandle(pipe)


def _write_install_response(
        path: Path, payload: Mapping[str, object], owner_sid: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "x", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=True, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    _protect_path(
        path, owner_sid, directory=False,
        user_access=ntsecuritycon.FILE_ALL_ACCESS,
    )
    win32security.SetNamedSecurityInfo(
        str(path),
        win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION,
        win32security.ConvertStringSidToSid(owner_sid),
        None, None, None,
    )


def _validate_install_paths(request_path: Path, response_path: Path) -> None:
    local_app_data = shell.SHGetKnownFolderPath(
        shell.FOLDERID_LocalAppData, 0, None
    )
    # ShellExecuteEx("runas") does not preserve process-local data overrides
    # reliably. Broker installation therefore uses one fixed current-user
    # transaction root even when the controller stores normal data elsewhere.
    data_root = (Path(local_app_data) / "LocalOps").resolve()
    expected_root = (data_root / "runtime" / "elevation-install").resolve()
    parent = request_path.resolve().parent
    if (response_path.resolve().parent != parent
            or request_path.name != "request.json"
            or response_path.name != "response.json"
            or parent.parent != expected_root
            or len(parent.name) != 32
            or any(char not in "0123456789abcdef" for char in parent.name.casefold())
            or request_path.is_symlink() or response_path.is_symlink()):
        raise ValueError("broker install paths are outside the fixed transaction root")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["serve"]:
        return serve()
    if len(args) == 4 and args[0] == "install":
        request_path = Path(args[1])
        response_path = Path(args[2])
        expected_digest = args[3]
        request: dict[str, object] = {}
        try:
            _validate_install_paths(request_path, response_path)
            request = _read_json(request_path)
            if not hmac.compare_digest(
                    broker_install_request_digest(request), expected_digest):
                raise ValueError("broker install request digest mismatch")
            owner_sid = str(request.get("ownerSid") or "")
            result = install(request)
            _write_install_response(response_path, result, owner_sid)
            return 0
        except Exception as exc:
            try:
                owner_sid = str(request.get("ownerSid") or "")
                _write_install_response(response_path, {
                    "ok": False, "code": "BROKER_INSTALL_FAILED",
                    "error": str(exc),
                }, owner_sid)
            except Exception:
                pass
            return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

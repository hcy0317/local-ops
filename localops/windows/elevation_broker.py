"""Elevated broker installer and fixed Named Pipe server for Windows."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
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
)
from localops.windows.runner_protocol import decode_message, encode_message


_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_MAX_MESSAGE = 1024 * 1024


def _program_data_dir() -> Path:
    root = os.environ.get("ProgramData") or r"C:\ProgramData"
    return Path(root) / "LocalOps"


def _program_files_broker_dir() -> Path:
    root = os.environ.get("ProgramFiles") or r"C:\Program Files"
    return Path(root) / "LocalOps" / "Broker"


def public_config_path() -> Path:
    return _program_data_dir() / "elevation-broker.json"


def secret_config_path() -> Path:
    return _program_data_dir() / "elevation-password.json"


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
    service = folder = definition = action = None
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
        folder.RegisterTaskDefinition(
            BROKER_TASK_PATH.lstrip("\\"), definition, 6,
            spec["ownerSid"], None, 3, spec["sddl"],
        )
    finally:
        action = definition = folder = service = None
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
    data_dir.mkdir(parents=True, exist_ok=True)
    _protect_path(
        data_dir, owner_sid, directory=True,
        user_access=ntsecuritycon.FILE_GENERIC_READ
        | ntsecuritycon.FILE_GENERIC_EXECUTE,
    )
    _write_json(public_config_path(), public, owner_sid, secret=False)
    _write_json(secret_config_path(), secret, owner_sid, secret=True)
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


def serve() -> int:
    public = _read_json(public_config_path())
    secret = _read_json(secret_config_path())
    owner_sid = str(public.get("ownerSid") or "")
    if (secret.get("schema") != BROKER_PUBLIC_SCHEMA
            or secret.get("ownerSid") != owner_sid):
        return 2
    protocol = ElevationBrokerProtocol(
        secret.get("passwordRecord"),
        owner_sid=owner_sid,
        process_matches=lambda pid, created, owner: (
            _owner_sid(pid).casefold() == owner.casefold()
            and abs(psutil.Process(pid).create_time() - created) <= 0.01
        ),
        launch=_launch,
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
    data_root = Path(os.environ.get("CONSOLE_DATA_DIR") or (
        Path(local_app_data) / "LocalOps"
    )).resolve()
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

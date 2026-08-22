"""Password and protocol contract for the Windows elevation broker."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import ntpath
import re
import secrets
import subprocess
from typing import Callable, Mapping


PASSWORD_RECORD_SCHEMA = "localops-elevation-password.v1"
DEFAULT_PBKDF2_ITERATIONS = 600_000
BROKER_TASK_PATH = r"\LocalOps-ElevationBroker"
BROKER_MODULE = "localops.windows.elevation_broker"
BROKER_PUBLIC_SCHEMA = "localops-elevation-broker.v1"
BROKER_INSTALL_SCHEMA = "localops-elevation-install.v1"
_SID_RE = re.compile(r"^S-\d(?:-\d+)+$", re.IGNORECASE)


def broker_install_request_digest(request: Mapping[str, object]) -> str:
    encoded = json.dumps(
        request, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def broker_pipe_name(owner_sid: str) -> str:
    if not isinstance(owner_sid, str) or not _SID_RE.fullmatch(owner_sid):
        raise ValueError("owner SID is invalid")
    digest = hashlib.sha256(owner_sid.encode("ascii")).hexdigest()[:24]
    return r"\\.\pipe\LocalOps-Elevation-" + digest


def broker_task_sddl(owner_sid: str) -> str:
    if not isinstance(owner_sid, str) or not _SID_RE.fullmatch(owner_sid):
        raise ValueError("owner SID is invalid")
    return "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;%s)" % owner_sid


def broker_task_spec(executable: object, owner_sid: str) -> dict[str, str]:
    if (not isinstance(executable, str) or not ntpath.isabs(executable)
            or not executable.casefold().endswith(".exe")):
        raise ValueError("broker executable must be an absolute .exe path")
    normalized = ntpath.normpath(executable)
    return {
        "taskPath": BROKER_TASK_PATH,
        "executable": normalized,
        "arguments": subprocess.list2cmdline(["-m", BROKER_MODULE, "serve"]),
        "workingDirectory": ntpath.dirname(normalized),
        "ownerSid": owner_sid,
        "sddl": broker_task_sddl(owner_sid),
    }


def _same_windows_path(left: object, right: object) -> bool:
    return (
        isinstance(left, str) and isinstance(right, str)
        and ntpath.normcase(ntpath.normpath(left))
        == ntpath.normcase(ntpath.normpath(right))
    )


def verify_broker_task(
        task: object, spec: Mapping[str, str]) -> tuple[bool, str | None]:
    if not isinstance(task, Mapping) or task.get("state") == "missing":
        return False, "BROKER_TASK_MISSING"
    actions = task.get("actionDetails")
    principal_sid = task.get("principalSid") or task.get("principalUserId")
    valid = (
        str(task.get("path") or "").casefold()
        == str(spec["taskPath"]).casefold()
        and task.get("enabled") is True
        and task.get("runLevel") == "highest"
        and str(principal_sid or "").casefold()
        == str(spec["ownerSid"]).casefold()
        and task.get("multipleInstances") == "ignoreNew"
        and task.get("triggerCount") == 0
        and task.get("securityLocked") is True
        and isinstance(actions, list) and len(actions) == 1
    )
    if not valid:
        return False, "BROKER_TASK_MISMATCH"
    action = actions[0]
    if (not isinstance(action, Mapping) or action.get("type") != "exec"
            or not _same_windows_path(action.get("path"), spec["executable"])
            or action.get("arguments") != spec["arguments"]
            or not _same_windows_path(
                action.get("workingDirectory"), spec["workingDirectory"]
            )):
        return False, "BROKER_TASK_MISMATCH"
    return True, None


def _password_bytes(password: object) -> bytes:
    if not isinstance(password, str) or len(password) < 8 or len(password) > 1024:
        raise ValueError("password must contain 8 to 1024 characters")
    if "\x00" in password:
        raise ValueError("password contains an invalid character")
    return password.encode("utf-8")


def new_password_record(
        password: object, *, salt: bytes | None = None,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> dict[str, object]:
    secret = _password_bytes(password)
    if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 10_000:
        raise ValueError("PBKDF2 iterations are too low")
    material = secrets.token_bytes(16) if salt is None else salt
    if not isinstance(material, bytes) or len(material) < 16:
        raise ValueError("password salt must contain at least 16 bytes")
    verifier = hashlib.pbkdf2_hmac("sha256", secret, material, iterations)
    return {
        "schema": PASSWORD_RECORD_SCHEMA,
        "algorithm": "pbkdf2-hmac-sha256",
        "iterations": iterations,
        "salt": base64.b64encode(material).decode("ascii"),
        "verifier": base64.b64encode(verifier).decode("ascii"),
    }


def _record_values(record: object) -> tuple[int, bytes, bytes]:
    if not isinstance(record, Mapping):
        raise ValueError("password record must be an object")
    if (set(record) != {
            "schema", "algorithm", "iterations", "salt", "verifier"
        } or record.get("schema") != PASSWORD_RECORD_SCHEMA
            or record.get("algorithm") != "pbkdf2-hmac-sha256"):
        raise ValueError("password record schema is invalid")
    iterations = record.get("iterations")
    if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 10_000:
        raise ValueError("password record iterations are invalid")
    try:
        salt = base64.b64decode(str(record["salt"]), validate=True)
        verifier = base64.b64decode(str(record["verifier"]), validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("password record encoding is invalid") from exc
    if len(salt) < 16 or len(verifier) != 32:
        raise ValueError("password record material is invalid")
    return iterations, salt, verifier


def verify_password(password: object, record: object) -> bool:
    try:
        secret = _password_bytes(password)
        iterations, salt, expected = _record_values(record)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", secret, salt, iterations)
    return hmac.compare_digest(actual, expected)


def normalize_elevated_launch(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"executable", "args", "cwd"}:
        raise ValueError("launch request must contain executable, args, and cwd only")
    executable = value.get("executable")
    if (not isinstance(executable, str) or not executable
            or "\x00" in executable or len(executable) > 32767
            or not ntpath.isabs(executable)
            or not executable.casefold().endswith(".exe")):
        raise ValueError("executable must be an absolute .exe path")
    args = value.get("args")
    if (not isinstance(args, list) or len(args) > 128
            or not all(isinstance(arg, str) and "\x00" not in arg
                       and len(arg) <= 4096 for arg in args)
            or sum(len(arg) for arg in args) > 32767):
        raise ValueError("args must be a bounded string array")
    cwd = value.get("cwd")
    if (not isinstance(cwd, str) or not cwd or "\x00" in cwd
            or len(cwd) > 32767 or not ntpath.isabs(cwd)):
        raise ValueError("cwd must be an absolute Windows path")
    return {
        "executable": ntpath.normpath(executable),
        "args": list(args),
        "cwd": ntpath.normpath(cwd),
    }


class ElevationBrokerProtocol:
    def __init__(
            self, password_record: object, *, owner_sid: str,
            process_matches: Callable[[int, float, str], bool],
            launch: Callable[[dict[str, object]], int],
            token_factory: Callable[[], str] | None = None):
        _record_values(password_record)
        if not isinstance(owner_sid, str) or not owner_sid:
            raise ValueError("owner SID is required")
        self._record = dict(password_record)
        self._owner_sid = owner_sid
        self._process_matches = process_matches
        self._launch = launch
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._console_pid: int | None = None
        self._console_create_time: float | None = None
        self._token: str | None = None

    @property
    def unlocked(self) -> bool:
        return self._session_valid(self._console_pid)

    def _clear_session(self) -> None:
        self._console_pid = None
        self._console_create_time = None
        self._token = None

    def _session_valid(self, client_pid: int | None) -> bool:
        valid = (
            isinstance(client_pid, int) and not isinstance(client_pid, bool)
            and client_pid == self._console_pid
            and self._console_create_time is not None
            and self._token is not None
            and self._process_matches(
                client_pid, self._console_create_time, self._owner_sid
            )
        )
        if not valid and self._token is not None:
            self._clear_session()
        return bool(valid)

    def _authorized(self, message: Mapping[str, object], client_pid: int) -> bool:
        token = message.get("token")
        return (
            self._session_valid(client_pid)
            and isinstance(token, str)
            and self._token is not None
            and hmac.compare_digest(token, self._token)
        )

    def handle(self, message: object, *, client_pid: int) -> dict[str, object]:
        if not isinstance(message, Mapping):
            return {"ok": False, "code": "BROKER_REQUEST_INVALID"}
        action = message.get("action")
        if action == "unlock":
            console_pid = message.get("consolePid")
            created = message.get("consoleCreateTime")
            if (not isinstance(console_pid, int) or isinstance(console_pid, bool)
                    or console_pid != client_pid
                    or not isinstance(created, (int, float))
                    or isinstance(created, bool)
                    or not self._process_matches(
                        console_pid, float(created), self._owner_sid
                    )):
                return {"ok": False, "code": "BROKER_CLIENT_INVALID"}
            if not verify_password(message.get("password"), self._record):
                return {"ok": False, "code": "BROKER_PASSWORD_INVALID"}
            self._console_pid = console_pid
            self._console_create_time = float(created)
            self._token = self._token_factory()
            return {"ok": True, "token": self._token, "unlocked": True}
        if action == "lock":
            if not self._authorized(message, client_pid):
                return {"ok": False, "code": "BROKER_SESSION_INVALID"}
            self._clear_session()
            return {"ok": True, "unlocked": False}
        if not self._authorized(message, client_pid):
            return {"ok": False, "code": "BROKER_SESSION_INVALID"}
        if action == "status":
            return {"ok": True, "unlocked": True}
        if action == "launch":
            try:
                request = normalize_elevated_launch(message.get("request"))
                pid = self._launch(request)
            except (OSError, TypeError, ValueError) as exc:
                return {
                    "ok": False, "code": "BROKER_LAUNCH_FAILED",
                    "error": str(exc),
                }
            return {"ok": True, "pid": int(pid)}
        return {"ok": False, "code": "BROKER_REQUEST_INVALID"}

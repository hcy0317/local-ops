"""Password and protocol contract for the Windows elevation broker."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import ntpath
import re
import secrets
import subprocess
import time
from typing import Callable, Mapping

from localops.command_spec import (
    CommandSpecError,
    is_local_windows_path,
    normalize_command_spec,
)


PASSWORD_RECORD_SCHEMA = "localops-elevation-password.v1"
DEFAULT_PBKDF2_ITERATIONS = 600_000
BROKER_TASK_PATH = r"\LocalOps-ElevationBroker"
BROKER_MODULE = "localops.windows.elevation_broker"
BROKER_PUBLIC_SCHEMA = "localops-elevation-broker.v1"
BROKER_INSTALL_SCHEMA = "localops-elevation-install.v1"
KEEPALIVE_REGISTRY_SCHEMA = "localops-elevation-keepalive-registry.v1"
_SID_RE = re.compile(r"^S-\d(?:-\d+)+$", re.IGNORECASE)
_ELEVATED_TASK_DENIED_DIRECT = re.compile(
    r"(?:cmd|powershell(?:_ise)?|pwsh|(?:ba|z|c|k)?sh|wsl|busybox|"
    r"py|pythonw?(?:\d+(?:\.\d+)*)?|node|ruby|perl|php|"
    r"wscript|cscript|mshta|rundll32)\.exe\Z",
    re.IGNORECASE,
)


def normalize_elevated_task_command_spec(value: object) -> dict[str, object]:
    spec = normalize_command_spec(value)
    mode = spec.get("mode")
    executable = spec.get("executable")
    if (spec.get("needsReview") is True or mode == "legacy-posix"
            or spec.get("text") is not None or mode not in {
                "direct", "cmd", "powershell",
            } or not isinstance(executable, str)):
        raise CommandSpecError(
            "elevated task requires a reviewed structured command"
        )
    if (mode in {"cmd", "powershell"}
            and (not ntpath.isabs(executable)
                 or not is_local_windows_path(executable))):
        raise CommandSpecError(
            "elevated task script must use an absolute local path"
        )
    if mode == "direct":
        if (ntpath.splitext(executable)[1].casefold() not in {".exe", ".com"}
                or spec.get("args") or not ntpath.isabs(executable)
                or not is_local_windows_path(executable)):
            raise CommandSpecError(
                "elevated task direct mode requires an absolute local EXE or "
                "COM without arguments"
            )
        if _ELEVATED_TASK_DENIED_DIRECT.fullmatch(ntpath.basename(executable)):
            raise CommandSpecError(
                "elevated task direct mode cannot use a command interpreter"
            )
    return spec


def broker_install_request_digest(request: Mapping[str, object]) -> str:
    encoded = json.dumps(
        request, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def make_keepalive_registry(
        owner_sid: str, key_id: str, revision: int,
        grants: Mapping[str, object], key: bytes) -> dict[str, object]:
    if (not isinstance(key, bytes) or len(key) != 32
            or not isinstance(key_id, str) or not re.fullmatch(r"[0-9a-f]{32}", key_id)
            or not isinstance(revision, int) or isinstance(revision, bool)
            or revision < 0 or not isinstance(grants, Mapping)
            or len(grants) > 256):
        raise ValueError("keep-alive registry input is invalid")
    unsigned = {
        "schema": KEEPALIVE_REGISTRY_SCHEMA,
        "ownerSid": owner_sid,
        "keyId": key_id,
        "revision": revision,
        "grants": json.loads(json.dumps(grants, ensure_ascii=True)),
    }
    encoded = json.dumps(
        unsigned, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    signature = hmac.new(
        key, b"localops-keepalive-registry-v1\0" + encoded, hashlib.sha256
    ).digest()
    return {
        **unsigned,
        "hmac": base64.b64encode(signature).decode("ascii"),
    }


def validate_keepalive_registry(
        value: object, key: bytes, *, owner_sid: str,
        key_id: str) -> tuple[int, dict[str, object]]:
    if (not isinstance(value, Mapping) or set(value) != {
            "schema", "ownerSid", "keyId", "revision", "grants", "hmac"
        } or value.get("schema") != KEEPALIVE_REGISTRY_SCHEMA
            or value.get("ownerSid") != owner_sid
            or value.get("keyId") != key_id):
        raise ValueError("keep-alive registry schema is invalid")
    revision = value.get("revision")
    grants = value.get("grants")
    if (not isinstance(revision, int) or isinstance(revision, bool)
            or revision < 0 or not isinstance(grants, Mapping)
            or len(grants) > 256):
        raise ValueError("keep-alive registry content is invalid")
    try:
        actual = base64.b64decode(str(value.get("hmac") or ""), validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("keep-alive registry HMAC is invalid") from exc
    expected_record = make_keepalive_registry(
        owner_sid, key_id, revision, grants, key
    )
    expected = base64.b64decode(expected_record["hmac"], validate=True)
    if len(actual) != 32 or not hmac.compare_digest(actual, expected):
        raise ValueError("keep-alive registry integrity check failed")
    return revision, json.loads(json.dumps(grants, ensure_ascii=True))


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


def normalize_elevated_stop(value: object) -> dict[str, object]:
    if (not isinstance(value, Mapping)
            or set(value) != {"favoriteExecutable", "processes"}):
        raise ValueError(
            "stop request must contain favoriteExecutable and processes only"
        )
    favorite = value.get("favoriteExecutable")
    if (not isinstance(favorite, str) or not favorite
            or "\x00" in favorite or len(favorite) > 32767
            or not ntpath.isabs(favorite)
            or not favorite.casefold().endswith(".exe")):
        raise ValueError("favoriteExecutable must be an absolute .exe path")
    favorite = ntpath.normpath(favorite)
    favorite_dir = ntpath.dirname(favorite)
    rows = value.get("processes")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 64:
        raise ValueError("processes must be a bounded non-empty array")
    normalized = []
    seen = set()
    for row in rows:
        if (not isinstance(row, Mapping)
                or set(row) != {"pid", "createTime", "executable"}):
            raise ValueError("process identity fields are invalid")
        pid = row.get("pid")
        created = row.get("createTime")
        executable = row.get("executable")
        if (not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0
                or pid in seen):
            raise ValueError("process pid must be unique and positive")
        if (not isinstance(created, (int, float)) or isinstance(created, bool)
                or not math.isfinite(float(created)) or float(created) <= 0):
            raise ValueError("process createTime is invalid")
        if (not isinstance(executable, str) or not executable
                or "\x00" in executable or len(executable) > 32767
                or not ntpath.isabs(executable)
                or not executable.casefold().endswith(".exe")):
            raise ValueError("process executable must be an absolute .exe path")
        executable = ntpath.normpath(executable)
        try:
            inside = ntpath.commonpath(
                [favorite_dir, executable]
            ).casefold() == favorite_dir.casefold()
        except ValueError:
            inside = False
        if (ntpath.basename(executable).casefold()
                != ntpath.basename(favorite).casefold()):
            raise ValueError("process executable name changed")
        if executable.casefold() != favorite.casefold() and not inside:
            raise ValueError("process executable is outside the favorite directory")
        seen.add(pid)
        normalized.append({
            "pid": pid,
            "createTime": float(created),
            "executable": executable,
        })
    return {
        "favoriteExecutable": favorite,
        "processes": normalized,
    }


def _normalize_scheduled_path(value: object) -> str:
    if (not isinstance(value, str) or not value or len(value) > 1024
            or any(ord(char) < 32 for char in value)):
        raise ValueError("scheduled task path is invalid")
    parts = [
        part for part in value.strip().replace("/", "\\").split("\\")
        if part
    ]
    if (not parts or any(part in {".", ".."} for part in parts)
            or any(len(part) > 255 for part in parts)):
        raise ValueError("scheduled task path is invalid")
    return "\\" + "\\".join(parts)


def normalize_scheduled_request(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("scheduled request must be an object")
    operation = value.get("operation")
    if operation == "list" and set(value) == {"operation"}:
        return {"operation": operation}
    if operation == "query" and set(value) == {"operation", "paths"}:
        paths = value.get("paths")
        if not isinstance(paths, list) or not 1 <= len(paths) <= 64:
            raise ValueError("scheduled query paths must be bounded")
        normalized = [_normalize_scheduled_path(path) for path in paths]
        if len(normalized) != len(set(path.casefold() for path in normalized)):
            raise ValueError("scheduled query paths must be unique")
        return {"operation": operation, "paths": normalized}
    if operation in {"run", "stop"} and set(value) == {"operation", "path"}:
        return {
            "operation": operation,
            "path": _normalize_scheduled_path(value.get("path")),
        }
    if operation == "toggle" and set(value) == {
            "operation", "path", "enabled"}:
        enabled = value.get("enabled")
        if not isinstance(enabled, bool):
            raise ValueError("scheduled toggle enabled must be boolean")
        return {
            "operation": operation,
            "path": _normalize_scheduled_path(value.get("path")),
            "enabled": enabled,
        }
    if operation == "history" and set(value) == {"operation", "enabled"}:
        enabled = value.get("enabled")
        if not isinstance(enabled, bool):
            raise ValueError("scheduled history enabled must be boolean")
        return {"operation": operation, "enabled": enabled}
    raise ValueError("scheduled request operation is invalid")


class ElevationBrokerProtocol:
    def __init__(
            self, password_record: object, *, owner_sid: str,
            process_matches: Callable[[int, float, str], bool],
            launch: Callable[[dict[str, object]], int],
            observe: Callable[[dict[str, object]], dict[str, object]],
            stop: Callable[[dict[str, object]], dict[str, object]],
            scheduled: Callable[[dict[str, object]], dict[str, object]],
            token_factory: Callable[[], str] | None = None,
            grant_id_factory: Callable[[], str] | None = None,
            grant_prepare: Callable[[Mapping[str, object]], dict[str, object]] | None = None,
            grant_execute: Callable[[str, Mapping[str, object]], dict[str, object]] | None = None,
            grant_client_valid: Callable[[int, float], bool] | None = None,
            elevated_task_launch: Callable[[Mapping[str, object]], dict[str, object]] | None = None,
            elevated_task_query: Callable[[str], dict[str, object]] | None = None,
            elevated_task_stop: Callable[[str], dict[str, object]] | None = None,
            grant_records: Mapping[str, object] | None = None,
            persist_grants: Callable[[Mapping[str, object]], None] | None = None):
        _record_values(password_record)
        if not isinstance(owner_sid, str) or not owner_sid:
            raise ValueError("owner SID is required")
        self._record = dict(password_record)
        self._owner_sid = owner_sid
        self._process_matches = process_matches
        self._launch = launch
        self._observe = observe
        self._stop = stop
        self._scheduled = scheduled
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._grant_id_factory = grant_id_factory or (lambda: secrets.token_urlsafe(24))
        self._grant_prepare = grant_prepare
        self._grant_execute = grant_execute
        self._grant_client_valid = grant_client_valid or (
            lambda _pid, _created: False
        )
        self._elevated_task_launch = elevated_task_launch
        self._elevated_task_query = elevated_task_query
        self._elevated_task_stop = elevated_task_stop
        self._persist_grants = persist_grants or (lambda _records: None)
        self._grants = self._normalize_grants(grant_records or {})
        pending_cutoff = time.time() - 3600.0
        retained = {
            grant_id: record for grant_id, record in self._grants.items()
            if record.get("active") is True
            or float(record.get("issuedAt") or 0) >= pending_cutoff
        }
        if len(retained) != len(self._grants):
            self._grants = retained
            self._persist_grants(self._grants)
        self._leases: dict[str, dict[str, object]] = {}
        self._console_pid: int | None = None
        self._console_create_time: float | None = None
        self._token: str | None = None

    @staticmethod
    def _normalize_grants(records: object) -> dict[str, dict[str, object]]:
        if not isinstance(records, Mapping) or len(records) > 256:
            raise ValueError("keep-alive grant registry is invalid")
        normalized = {}
        for grant_id, raw in records.items():
            if (not isinstance(grant_id, str) or not 16 <= len(grant_id) <= 128
                    or not isinstance(raw, Mapping)):
                raise ValueError("keep-alive grant record is invalid")
            record = json.loads(json.dumps(raw, ensure_ascii=True))
            if (not isinstance(record.get("appId"), str)
                    or not re.fullmatch(r"[0-9a-fA-F]{8}", record["appId"])
                    or record.get("kind") not in {
                        "elevatedProgram", "scheduledService"
                    }):
                raise ValueError("keep-alive grant resource is invalid")
            record["active"] = record.get("active") is True
            issued_at = record.get("issuedAt")
            record["issuedAt"] = (
                float(issued_at)
                if isinstance(issued_at, (int, float))
                and not isinstance(issued_at, bool) and issued_at > 0
                else None
            )
            normalized[grant_id] = record
        return normalized

    @staticmethod
    def _grant_digest(record: Mapping[str, object]) -> str:
        binding = {
            key: value for key, value in record.items()
            if key not in {"active", "issuedAt"}
        }
        payload = json.dumps(
            binding, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def _grant_caller_valid(
            self, message: Mapping[str, object], client_pid: int) -> bool:
        created = message.get("clientCreateTime")
        if (not isinstance(created, (int, float)) or isinstance(created, bool)
                or float(created) <= 0):
            return False
        try:
            return bool(self._grant_client_valid(client_pid, float(created)))
        except (OSError, TypeError, ValueError):
            return False

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
        if action == "keepalive-grant-issue":
            if not self._authorized(message, client_pid):
                return {"ok": False, "code": "BROKER_SESSION_INVALID"}
            if self._grant_prepare is None:
                return {"ok": False, "code": "BROKER_KEEPALIVE_UNSUPPORTED"}
            try:
                request = message.get("request")
                if not isinstance(request, Mapping):
                    raise ValueError("keep-alive grant request is invalid")
                record = self._grant_prepare(request)
                record = dict(record)
                record["active"] = False
                record["issuedAt"] = time.time()
                validated = self._normalize_grants({"x" * 16: record})["x" * 16]
                validated["active"] = False
                grant_id = self._grant_id_factory()
                if (not isinstance(grant_id, str) or not 16 <= len(grant_id) <= 128
                        or grant_id in self._grants):
                    raise ValueError("keep-alive grant id is invalid")
                self._grants[grant_id] = validated
                try:
                    self._persist_grants(self._grants)
                except Exception:
                    self._grants.pop(grant_id, None)
                    raise
            except (OSError, TypeError, ValueError) as exc:
                return {
                    "ok": False, "code": "BROKER_KEEPALIVE_GRANT_FAILED",
                    "error": str(exc),
                }
            return {
                "ok": True,
                "grantId": grant_id,
                "resourceDigest": self._grant_digest(validated),
            }
        if action == "keepalive-grant-activate":
            if not self._authorized(message, client_pid):
                return {"ok": False, "code": "BROKER_SESSION_INVALID"}
            grant_id = message.get("grantId")
            record = self._grants.get(grant_id) if isinstance(grant_id, str) else None
            if record is None:
                return {"ok": False, "code": "BROKER_KEEPALIVE_GRANT_INVALID"}
            if (message.get("appId") != record.get("appId")
                    or message.get("bindingDigest") != self._grant_digest(record)):
                return {"ok": False, "code": "BROKER_KEEPALIVE_BINDING_MISMATCH"}
            previous = bool(record.get("active"))
            record["active"] = True
            try:
                self._persist_grants(self._grants)
            except Exception as exc:
                record["active"] = previous
                return {
                    "ok": False, "code": "BROKER_KEEPALIVE_ACTIVATE_FAILED",
                    "error": str(exc),
                }
            return {"ok": True, "active": True}
        if action in {"keepalive-grant-use", "keepalive-grant-revoke"}:
            if not self._grant_caller_valid(message, client_pid):
                return {"ok": False, "code": "BROKER_KEEPALIVE_CLIENT_INVALID"}
            grant_id = message.get("grantId")
            record = self._grants.get(grant_id) if isinstance(grant_id, str) else None
            if record is None:
                if action == "keepalive-grant-revoke":
                    return {
                        "ok": True, "revoked": True, "alreadyAbsent": True
                    }
                return {"ok": False, "code": "BROKER_KEEPALIVE_GRANT_INVALID"}
            if (message.get("appId") != record.get("appId")
                    or message.get("bindingDigest") != self._grant_digest(record)):
                return {"ok": False, "code": "BROKER_KEEPALIVE_BINDING_MISMATCH"}
            if action == "keepalive-grant-revoke":
                removed = self._grants.pop(grant_id)
                try:
                    self._persist_grants(self._grants)
                except Exception as exc:
                    self._grants[grant_id] = removed
                    return {
                        "ok": False, "code": "BROKER_KEEPALIVE_REVOKE_FAILED",
                        "error": str(exc),
                    }
                return {"ok": True, "revoked": True}
            if record.get("active") is not True:
                return {"ok": False, "code": "BROKER_KEEPALIVE_GRANT_INACTIVE"}
            operation = message.get("operation")
            allowed = (
                {"observe", "launch"}
                if record.get("kind") == "elevatedProgram"
                else {"query", "run"}
            )
            if operation not in allowed or self._grant_execute is None:
                return {"ok": False, "code": "BROKER_KEEPALIVE_OPERATION_DENIED"}
            created = float(message["clientCreateTime"])
            lease_now = time.monotonic()
            self._leases = {
                lease_id: lease for lease_id, lease in self._leases.items()
                if float(lease.get("expiresAt") or 0) >= lease_now
            }
            if operation in {"launch", "run"}:
                lease_id = message.get("leaseId")
                lease = self._leases.pop(lease_id, None) if isinstance(
                    lease_id, str) else None
                expected_action = "launch" if operation == "launch" else "run"
                if (not isinstance(lease, Mapping)
                        or lease.get("grantId") != grant_id
                        or lease.get("action") != expected_action
                        or lease.get("clientPid") != client_pid
                        or lease.get("clientCreateTime") != created
                        or float(lease.get("expiresAt") or 0) < time.monotonic()):
                    return {
                        "ok": False, "code": "BROKER_KEEPALIVE_LEASE_INVALID"
                    }
            try:
                response = self._grant_execute(str(operation), record)
                if not isinstance(response, dict) or "ok" not in response:
                    raise ValueError("keep-alive grant response is invalid")
                eligible = False
                lease_action = None
                if operation == "observe":
                    eligible = response.get("ok") is True and not (
                        response.get("processes") or []
                    )
                    lease_action = "launch"
                elif operation == "query":
                    path = str(record.get("path") or "").casefold()
                    task = (response.get("tasks") or {}).get(path)
                    eligible = bool(
                        response.get("ok") and isinstance(task, Mapping)
                        and task.get("state") == "ready"
                        and task.get("enabled") is True
                    )
                    lease_action = "run"
                if eligible and lease_action:
                    if len(self._leases) >= 256:
                        oldest = min(
                            self._leases,
                            key=lambda item: float(
                                self._leases[item].get("expiresAt") or 0
                            ),
                        )
                        self._leases.pop(oldest, None)
                    lease_id = secrets.token_urlsafe(24)
                    self._leases[lease_id] = {
                        "grantId": grant_id,
                        "action": lease_action,
                        "clientPid": client_pid,
                        "clientCreateTime": created,
                        "expiresAt": time.monotonic() + 10.0,
                    }
                    response = dict(response)
                    response["leaseId"] = lease_id
                return response
            except (OSError, TypeError, ValueError) as exc:
                return {
                    "ok": False, "code": "BROKER_KEEPALIVE_ACTION_FAILED",
                    "error": str(exc),
                }
        if action == "elevated-task-query":
            if not self._grant_caller_valid(message, client_pid):
                return {"ok": False, "code": "BROKER_ELEVATED_TASK_CLIENT_INVALID"}
            app_id = message.get("appId")
            if (not isinstance(app_id, str)
                    or not re.fullmatch(r"[0-9a-fA-F]{8}", app_id)
                    or self._elevated_task_query is None):
                return {"ok": False, "code": "BROKER_ELEVATED_TASK_INVALID"}
            try:
                response = self._elevated_task_query(app_id.lower())
                if not isinstance(response, dict) or "ok" not in response:
                    raise ValueError("elevated task query response is invalid")
                return response
            except (OSError, TypeError, ValueError) as exc:
                return {
                    "ok": False, "code": "BROKER_ELEVATED_TASK_QUERY_FAILED",
                    "error": str(exc),
                }
        if not self._authorized(message, client_pid):
            return {"ok": False, "code": "BROKER_SESSION_INVALID"}
        if action == "elevated-task-launch":
            if self._elevated_task_launch is None:
                return {"ok": False, "code": "BROKER_ELEVATED_TASK_UNSUPPORTED"}
            try:
                request = message.get("request")
                if not isinstance(request, Mapping):
                    raise ValueError("elevated task launch request is invalid")
                response = self._elevated_task_launch(request)
                if not isinstance(response, dict) or "ok" not in response:
                    raise ValueError("elevated task launch response is invalid")
                return response
            except (OSError, TypeError, ValueError) as exc:
                return {
                    "ok": False, "code": "BROKER_ELEVATED_TASK_LAUNCH_FAILED",
                    "error": str(exc),
                }
        if action == "elevated-task-stop":
            app_id = message.get("appId")
            if (not isinstance(app_id, str)
                    or not re.fullmatch(r"[0-9a-fA-F]{8}", app_id)
                    or self._elevated_task_stop is None):
                return {"ok": False, "code": "BROKER_ELEVATED_TASK_INVALID"}
            try:
                response = self._elevated_task_stop(app_id.lower())
                if not isinstance(response, dict) or "ok" not in response:
                    raise ValueError("elevated task stop response is invalid")
                return response
            except (OSError, TypeError, ValueError) as exc:
                return {
                    "ok": False, "code": "BROKER_ELEVATED_TASK_STOP_FAILED",
                    "error": str(exc),
                }
        if action == "status":
            return {
                "ok": True,
                "unlocked": True,
                "protocolVersion": 5,
                "capabilities": [
                    "launch", "observe", "stop", "scheduled",
                    "keepalive-grants", "elevated-batch-tasks",
                ],
            }
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
        if action == "observe":
            try:
                request = normalize_elevated_launch(message.get("request"))
                response = self._observe(request)
                if (not isinstance(response, dict)
                        or response.get("ok") is not True
                        or not isinstance(response.get("processes"), list)):
                    raise ValueError("observe response is invalid")
            except (OSError, TypeError, ValueError) as exc:
                return {
                    "ok": False, "code": "BROKER_OBSERVE_FAILED",
                    "error": str(exc),
                }
            return response
        if action == "stop":
            try:
                request = normalize_elevated_stop(message.get("request"))
                response = self._stop(request)
                if not isinstance(response, dict) or "ok" not in response:
                    raise ValueError("stop response is invalid")
            except (OSError, TypeError, ValueError) as exc:
                return {
                    "ok": False, "code": "BROKER_STOP_FAILED",
                    "error": str(exc),
                }
            return response
        if action == "scheduled":
            try:
                request = normalize_scheduled_request(message.get("request"))
                response = self._scheduled(request)
                if not isinstance(response, dict) or "ok" not in response:
                    raise ValueError("scheduled response is invalid")
            except (OSError, TypeError, ValueError) as exc:
                return {
                    "ok": False, "code": "BROKER_SCHEDULED_FAILED",
                    "error": str(exc),
                }
            return response
        return {"ok": False, "code": "BROKER_REQUEST_INVALID"}

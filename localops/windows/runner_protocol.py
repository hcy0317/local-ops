"""Pure protocol and record helpers shared by the controller and runner."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import subprocess
import uuid
from collections.abc import Callable, Mapping, Sequence

PROTOCOL_VERSION = 1
TOKEN_BYTES = 32
MAX_RECORD_BYTES = 64 * 1024
PIPE_BUFFER_BYTES = 64 * 1024
ALLOWED_ACTIONS = frozenset({"inspect", "resume", "stop", "force", "abort"})
ALLOWED_STATES = frozenset({"prepared", "running", "stopping", "exited", "failed"})
_TRANSITIONS = {
    "prepared": frozenset({"running", "failed"}),
    "running": frozenset({"stopping", "exited", "failed"}),
    "stopping": frozenset({"running", "exited", "failed"}),
    "exited": frozenset(),
    "failed": frozenset(),
}
_APP_ID = re.compile(r"^[0-9a-f]{8}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SID = re.compile(r"^S-1-(?:\d+-)+\d+$")
PUBLIC_IDENTITY_FIELDS = frozenset({
    "platform", "kind", "ownerSid", "generationId", "runnerPid",
    "runnerCreateTime", "rootPid", "rootCreateTime", "jobName",
    "tokenDigest", "startedAt",
})
LAUNCH_REQUEST_FIELDS = frozenset({
    "version", "appId", "generationId", "ownerSid", "invocation", "cwd",
    "logPath",
})


class ProtocolError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class NonceCache:
    """Small per-runner replay cache for authenticated control messages."""

    def __init__(self, capacity: int = 256):
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._values: list[str] = []
        self._seen: set[str] = set()

    def remember(self, nonce: str) -> bool:
        if nonce in self._seen:
            return False
        self._seen.add(nonce)
        self._values.append(nonce)
        if len(self._values) > self._capacity:
            self._seen.remove(self._values.pop(0))
        return True


def validate_app_id(value: str) -> str:
    value = str(value).lower()
    if not _APP_ID.fullmatch(value):
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid app id")
    return value


def validate_generation_id(value: str) -> str:
    try:
        parsed = str(uuid.UUID(str(value))).lower()
    except (ValueError, AttributeError, TypeError) as exc:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid generation id") from exc
    if parsed != str(value).lower():
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "non-canonical generation id")
    return parsed


def runtime_directory(runtime_root: str, app_id: str, generation_id: str) -> str:
    root = os.path.abspath(runtime_root)
    child = os.path.abspath(
        os.path.join(root, validate_app_id(app_id), validate_generation_id(generation_id))
    )
    if os.path.normcase(os.path.commonpath((root, child))) != os.path.normcase(root):
        raise ProtocolError("RUNTIME_RECORD_INSECURE", "runtime path escaped its root")
    return child


def pipe_name(app_id: str, generation_id: str) -> str:
    return rf"\\.\pipe\LocalOps-{validate_app_id(app_id)}-{validate_generation_id(generation_id)}"


def token_digest(token: bytes) -> str:
    if not isinstance(token, bytes) or len(token) < 24:
        raise ProtocolError("RUNTIME_RECORD_INSECURE", "runtime token is too short")
    return "sha256:" + hashlib.sha256(token).hexdigest()


def job_name(app_id: str, generation_id: str, digest: str) -> str:
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid token digest")
    digest_hex = digest[7:].lower()
    if not _HEX_64.fullmatch(digest_hex):
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid token digest")
    return "Local\\LocalOps-%s-%s-%s" % (
        validate_app_id(app_id), validate_generation_id(generation_id), digest_hex[:16]
    )


def new_token() -> bytes:
    return secrets.token_bytes(TOKEN_BYTES)


def runner_command(executable: str, app_id: str, generation_id: str) -> list[str]:
    """Build the non-secret runner CLI; runtime paths are derived in the child."""
    if not isinstance(executable, str) or not executable:
        raise ProtocolError("LAUNCH_PREPARE_FAILED", "runner executable is invalid")
    return [
        executable,
        "-m",
        "localops.windows.runner",
        "--app-id",
        validate_app_id(app_id),
        "--generation-id",
        validate_generation_id(generation_id),
    ]


def make_launch_request(
    *,
    app_id: str,
    generation_id: str,
    owner_sid: str,
    invocation: object,
    cwd: str,
    log_path: str,
    token: bytes,
) -> dict[str, object]:
    """Create the protected launch record consumed by the independent runner."""
    if not isinstance(owner_sid, str) or not _SID.fullmatch(owner_sid):
        raise ProtocolError("LAUNCH_PREPARE_FAILED", "invalid launch owner")
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        raise ProtocolError("LAUNCH_PREPARE_FAILED", "launch cwd must be absolute")
    if not isinstance(log_path, str) or not os.path.isabs(log_path):
        raise ProtocolError("LAUNCH_PREPARE_FAILED", "launch log path must be absolute")
    # Validate the execution boundary before any record is committed.
    native_process_command(invocation)
    return sign_record({
        "version": PROTOCOL_VERSION,
        "appId": validate_app_id(app_id),
        "generationId": validate_generation_id(generation_id),
        "ownerSid": owner_sid,
        "invocation": invocation,
        "cwd": cwd,
        "logPath": log_path,
    }, token, "launch-request")


def validate_launch_request(
    value: object,
    token: bytes,
    *,
    app_id: str,
    generation_id: str,
    owner_sid: str,
    expected_log_path: str,
) -> dict[str, object]:
    request = verify_record(value, token, "launch-request")
    if set(request) != LAUNCH_REQUEST_FIELDS or request["version"] != PROTOCOL_VERSION:
        raise ProtocolError("LAUNCH_PREPARE_FAILED", "invalid launch request shape")
    if request["appId"] != validate_app_id(app_id):
        raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "launch app mismatch")
    if request["generationId"] != validate_generation_id(generation_id):
        raise ProtocolError("GENERATION_MISMATCH", "launch generation mismatch")
    if request["ownerSid"] != owner_sid:
        raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "launch owner mismatch")
    cwd = request["cwd"]
    log_path = request["logPath"]
    if not isinstance(cwd, str) or not os.path.isabs(cwd) or not os.path.isdir(cwd):
        raise ProtocolError("LAUNCH_PREPARE_FAILED", "launch cwd is unavailable")
    if (not isinstance(log_path, str) or not os.path.isabs(log_path)
            or os.path.normcase(os.path.abspath(log_path))
            != os.path.normcase(os.path.abspath(expected_log_path))):
        raise ProtocolError("RUNTIME_RECORD_INSECURE", "launch log path mismatch")
    native_process_command(request["invocation"])
    return request


def validate_public_identity(
    value: object,
    *,
    app_id: str,
    generation_id: str,
    owner_sid: str,
    digest: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != PUBLIC_IDENTITY_FIELDS:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid runtime identity shape")
    generation_id = validate_generation_id(generation_id)
    if (value["platform"], value["kind"]) != ("windows", "job"):
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid runtime identity kind")
    if (not isinstance(value["ownerSid"], str)
            or not _SID.fullmatch(value["ownerSid"])
            or value["ownerSid"] != owner_sid):
        raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "runtime owner mismatch")
    if value["generationId"] != generation_id:
        raise ProtocolError("GENERATION_MISMATCH", "runtime generation mismatch")
    if value["tokenDigest"] != digest:
        raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "runtime token mismatch")
    for name in ("runnerPid", "rootPid", "startedAt"):
        item = value[name]
        if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
            raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid runtime identity value")
    for name in ("runnerCreateTime", "rootCreateTime"):
        item = value[name]
        if (not isinstance(item, (int, float)) or isinstance(item, bool)
                or not math.isfinite(float(item)) or float(item) <= 0):
            raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid runtime identity value")
    if value["jobName"] != job_name(app_id, generation_id, digest):
        raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "runtime Job mismatch")
    return dict(value)


def validate_receipt(
    value: object,
    token: bytes,
    *,
    app_id: str,
    generation_id: str,
    owner_sid: str,
    previous_state: str | None = None,
) -> dict[str, object]:
    receipt = verify_record(value, token, "receipt")
    expected = {
        "version", "sequence", "state", "identity", "members", "updatedAt",
        "code", "error", "exitCode",
    }
    if set(receipt) != expected or receipt["version"] != PROTOCOL_VERSION:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid runner receipt shape")
    state = receipt["state"]
    if not isinstance(state, str) or state not in ALLOWED_STATES:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid runner state")
    # A controller may reconnect with only the latest signed snapshot. Transition
    # validation is applied only when the caller actually observed a prior state.
    if previous_state is not None:
        validate_transition(previous_state, state)
    for name in ("sequence", "updatedAt"):
        item = receipt[name]
        if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
            raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid runner receipt value")
    members = receipt["members"]
    if (not isinstance(members, list)
            or any(not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0
                   for pid in members)
            or len(set(members)) != len(members)):
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid Job member list")
    identity = validate_public_identity(
        receipt["identity"], app_id=app_id, generation_id=generation_id,
        owner_sid=owner_sid, digest=token_digest(token),
    )
    if state == "prepared" and identity["rootPid"] not in members:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "prepared Job has no root")
    if state in {"running", "stopping"} and not members:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "active Job is empty")
    if state in {"exited", "failed"} and members:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "terminal Job is not empty")
    for name in ("code", "error"):
        item = receipt[name]
        if item is not None and (not isinstance(item, str) or len(item) > 1024):
            raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid receipt diagnostic")
    exit_code = receipt["exitCode"]
    if (exit_code is not None
            and (not isinstance(exit_code, int) or isinstance(exit_code, bool))):
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid process exit code")
    return receipt


def reconnect_observations_valid(
    identity: Mapping[str, object],
    *,
    runner_observation: tuple[str, float] | None,
    root_observation: tuple[str, float] | None,
    members: Sequence[int],
) -> bool:
    """Validate live evidence while allowing a completed root wrapper to disappear."""
    owner = identity.get("ownerSid")
    runner_time = identity.get("runnerCreateTime")
    root_time = identity.get("rootCreateTime")
    root_pid = identity.get("rootPid")
    if (not isinstance(owner, str) or not isinstance(runner_time, (int, float))
            or not isinstance(root_time, (int, float)) or not isinstance(root_pid, int)):
        return False
    if runner_observation is None:
        return False
    if (runner_observation[0] != owner
            or abs(float(runner_observation[1]) - float(runner_time)) > 0.1):
        return False
    if root_pid not in members:
        return True
    return bool(
        root_observation is not None
        and root_observation[0] == owner
        and abs(float(root_observation[1]) - float(root_time)) <= 0.1
    )


def terminal_observations_valid(
    identity: Mapping[str, object],
    *,
    runner_observation: tuple[str, float] | None,
    root_observation: tuple[str, float] | None,
    members: Sequence[int],
) -> bool:
    """Validate a signed empty terminal snapshot without reopening its Job."""
    if members:
        return False
    owner = identity.get("ownerSid")
    runner_time = identity.get("runnerCreateTime")
    root_time = identity.get("rootCreateTime")
    if (not isinstance(owner, str) or not isinstance(runner_time, (int, float))
            or not isinstance(root_time, (int, float))):
        return False
    # The runner may still be alive briefly to serve its terminal receipt. Any
    # other process at that PID is harmless only when PID reuse is proven.
    if (runner_observation is not None
            and runner_observation[0] == owner
            and abs(float(runner_observation[1]) - float(runner_time)) > 0.01):
        pass
    # The original root cannot still exist after its runner-owned Job is empty.
    if (root_observation is not None
            and root_observation[0] == owner
            and abs(float(root_observation[1]) - float(root_time)) <= 0.01):
        return False
    return True


def _canonical_json(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value, ensure_ascii=True, allow_nan=False,
            separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "record is not JSON-safe") from exc
    if len(encoded) > MAX_RECORD_BYTES:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "record is too large")
    return encoded


def _mac(token: bytes, purpose: str, value: Mapping[str, object]) -> str:
    return hmac.new(
        token, purpose.encode("ascii") + b"\0" + _canonical_json(value), hashlib.sha256
    ).hexdigest()


def sign_record(value: Mapping[str, object], token: bytes, purpose: str) -> dict[str, object]:
    if "hmac" in value:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "record already has an HMAC")
    result = dict(value)
    result["hmac"] = _mac(token, purpose, result)
    return result


def verify_record(value: object, token: bytes, purpose: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "record must be an object")
    unsigned = dict(value)
    signature = unsigned.pop("hmac", None)
    if not isinstance(signature, str) or not _HEX_64.fullmatch(signature):
        raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "record HMAC is missing")
    if not hmac.compare_digest(signature, _mac(token, purpose, unsigned)):
        raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "record HMAC is invalid")
    return unsigned


def make_request(action: str, generation_id: str, token: bytes,
                 payload: Mapping[str, object] | None = None) -> dict[str, object]:
    if action not in ALLOWED_ACTIONS:
        raise ProtocolError("RUNTIME_CONTROL_FAILED", "unsupported control action")
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(24)).rstrip(b"=").decode("ascii")
    return sign_record({
        "version": PROTOCOL_VERSION,
        "action": action,
        "generationId": validate_generation_id(generation_id),
        "nonce": nonce,
        "payload": dict(payload or {}),
    }, token, "request")


def verify_request(value: object, token: bytes, generation_id: str,
                   nonces: NonceCache) -> dict[str, object]:
    request = verify_record(value, token, "request")
    if set(request) != {"version", "action", "generationId", "nonce", "payload"}:
        raise ProtocolError("RUNTIME_CONTROL_FAILED", "invalid request shape")
    if request["version"] != PROTOCOL_VERSION:
        raise ProtocolError("RUNTIME_CONTROL_FAILED", "unsupported protocol version")
    if request["generationId"] != validate_generation_id(generation_id):
        raise ProtocolError("GENERATION_MISMATCH", "runtime generation mismatch")
    if request["action"] not in ALLOWED_ACTIONS:
        raise ProtocolError("RUNTIME_CONTROL_FAILED", "unsupported control action")
    nonce = request["nonce"]
    if not isinstance(nonce, str) or not (30 <= len(nonce) <= 64):
        raise ProtocolError("RUNTIME_CONTROL_FAILED", "invalid request nonce")
    if not nonces.remember(nonce):
        raise ProtocolError("RUNTIME_CONTROL_FAILED", "replayed request")
    if not isinstance(request["payload"], dict):
        raise ProtocolError("RUNTIME_CONTROL_FAILED", "invalid request payload")
    return request


def make_response(request: Mapping[str, object], token: bytes, *, ok: bool,
                  status: str, payload: Mapping[str, object] | None = None,
                  code: str | None = None, error: str | None = None) -> dict[str, object]:
    return sign_record({
        "version": PROTOCOL_VERSION, "nonce": request["nonce"], "ok": bool(ok),
        "status": status, "payload": dict(payload or {}), "code": code, "error": error,
    }, token, "response")


def verify_response(value: object, token: bytes,
                    request: Mapping[str, object]) -> dict[str, object]:
    response = verify_record(value, token, "response")
    expected = {"version", "nonce", "ok", "status", "payload", "code", "error"}
    if set(response) != expected or response["version"] != PROTOCOL_VERSION:
        raise ProtocolError("RUNTIME_CONTROL_FAILED", "invalid response shape")
    if response["nonce"] != request.get("nonce"):
        raise ProtocolError("RUNTIME_IDENTITY_UNVERIFIED", "response nonce mismatch")
    if not isinstance(response["ok"], bool) or not isinstance(response["payload"], dict):
        raise ProtocolError("RUNTIME_CONTROL_FAILED", "invalid response values")
    return response


def validate_transition(previous: str | None, current: str) -> None:
    if current not in ALLOWED_STATES:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid runner state")
    if previous is None:
        if current not in {"prepared", "failed"}:
            raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid initial runner state")
    elif current != previous and current not in _TRANSITIONS.get(previous, frozenset()):
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid runner state transition")


def _structured_invocation(
    invocation: object,
) -> tuple[str, str, list[str], str, list[str]]:
    if not isinstance(invocation, dict) or set(invocation) != {
        "mode", "executable", "prefixArgs", "script", "args"
    }:
        raise ProtocolError("LAUNCH_PREPARE_FAILED", "invalid structured invocation")
    mode, executable = invocation["mode"], invocation["executable"]
    prefix, script, args = invocation["prefixArgs"], invocation["script"], invocation["args"]
    if (mode not in {"cmd", "powershell"} or not isinstance(executable, str)
            or not isinstance(script, str) or not isinstance(prefix, list)
            or not isinstance(args, list)
            or not all(isinstance(part, str) for part in [*prefix, *args])):
        raise ProtocolError("LAUNCH_PREPARE_FAILED", "invalid structured invocation")
    return mode, executable, prefix, script, args


def _cmd_literal(value: str) -> str:
    # Phase 3 rejects expansion/quote controls. Check again at the execution boundary.
    if any(character in value for character in ('"', "%", "!", "\0", "\r", "\n")):
        raise ProtocolError("LAUNCH_PREPARE_FAILED", "unsafe structured cmd value")
    return '"' + value + '"'


def invocation_argv(invocation: object) -> list[str]:
    if isinstance(invocation, list):
        if not invocation or not all(isinstance(part, str) for part in invocation):
            raise ProtocolError("LAUNCH_PREPARE_FAILED", "invalid direct invocation")
        return list(invocation)
    mode, executable, prefix, script, args = _structured_invocation(invocation)
    if mode == "cmd":
        raise ProtocolError(
            "LAUNCH_PREPARE_FAILED",
            "structured cmd requires the native quoting boundary",
        )
    return [executable, *prefix, script, *args]


def command_line(argv: Sequence[str]) -> str:
    if not argv or not all(isinstance(part, str) for part in argv):
        raise ProtocolError("LAUNCH_PREPARE_FAILED", "invalid process arguments")
    return subprocess.list2cmdline(list(argv))


def native_process_command(invocation: object) -> tuple[str, str]:
    """Return CreateProcess applicationName/commandLine without shell re-parsing."""
    if isinstance(invocation, list):
        argv = invocation_argv(invocation)
        return argv[0], command_line(argv)
    mode, executable, prefix, script, args = _structured_invocation(invocation)
    if mode == "powershell":
        argv = [executable, *prefix, script, *args]
        return executable, command_line(argv)
    if prefix != ["/d", "/s", "/c"]:
        raise ProtocolError("LAUNCH_PREPARE_FAILED", "invalid structured cmd prefix")
    literal_command = " ".join(_cmd_literal(value) for value in [script, *args])
    fixed_prefix = subprocess.list2cmdline([executable, *prefix])
    # /s strips this outer pair. Every data value remains separately quoted, so
    # &|<>^() cannot become cmd syntax.
    return executable, fixed_prefix + ' "' + literal_command + '"'


def encode_message(value: Mapping[str, object]) -> bytes:
    return _canonical_json(value)


def decode_message(data: bytes) -> dict[str, object]:
    if not isinstance(data, bytes) or len(data) > MAX_RECORD_BYTES:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "message is too large")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "invalid JSON message") from exc
    if not isinstance(value, dict):
        raise ProtocolError("RUNTIME_IDENTITY_INVALID", "message must be an object")
    return value


def read_json(path: str) -> dict[str, object]:
    with open(path, "rb") as stream:
        return decode_message(stream.read(MAX_RECORD_BYTES + 1))


def write_json_atomic(
    path: str,
    value: Mapping[str, object],
    prepare_file: Callable[[str], None] | None = None,
) -> None:
    data = _canonical_json(value)
    temporary = path + ".tmp-" + secrets.token_hex(8)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if prepare_file is not None:
            # The replacement must already carry its private ACL when it first
            # becomes visible to a verify-only reader.
            prepare_file(temporary)
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass

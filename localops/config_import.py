"""Explicit, preview-first macOS configuration import for Windows.

The module is intentionally limited to JSON and filesystem operations.  It
never discovers a source, starts a command, accesses the network, or writes the
live configuration directly.  Callers provide the existing atomic Config
writer through ``replace_target(expected_hash, replacement)``.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import posixpath
import re
import shutil
import stat
import uuid
from collections.abc import Callable, Mapping, Sequence

from localops.command_spec import (
    CommandSpecError,
    is_local_windows_path,
    normalize_command_spec,
    platform_compatibility,
)


MAX_SOURCE_BYTES = 1 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024
SUPPORTED_SCHEMA_VERSION = 5
_HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_PREVIEW_PATTERN = re.compile(
    r"sha256:([0-9a-f]{64})\.([0-9a-f]{64})"
)
_RUNTIME_FIELDS = (
    "lastPid",
    "lastPgid",
    "runToken",
    "runtimeIdentity",
    "lastExit",
)


class ConfigImportError(ValueError):
    """A safe, stable import failure for the HTTP error envelope."""

    def __init__(self, code: str, http_status: int, message: str):
        super().__init__(message)
        self.code = code
        self.http_status = http_status
        self.message = message


def _error(code: str, status: int, message: str) -> ConfigImportError:
    return ConfigImportError(code, status, message)


def _clone(value: object) -> object:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def config_hash(config: Mapping[str, object]) -> str:
    """Hash an already-normalized configuration for compare-and-swap."""
    if not isinstance(config, Mapping):
        raise TypeError("config must be an object")
    return _sha256(_canonical_bytes(config))


def _validated_snapshot_hash(
    value: object,
    code: str,
    message: str,
) -> tuple[dict[str, object], str]:
    """Validate an already-normalized current snapshot without probes."""
    try:
        snapshot = _clone(value)
    except Exception:
        raise _error(code, 500, message) from None
    if (not isinstance(snapshot, dict)
            or type(snapshot.get("schemaVersion")) is not int
            or snapshot["schemaVersion"] != SUPPORTED_SCHEMA_VERSION
            or not isinstance(snapshot.get("apps"), list)
            or any(not isinstance(app, dict) for app in snapshot["apps"])):
        raise _error(code, 500, message)
    return snapshot, config_hash(snapshot)


def _read_regular_file(path: object, limit: int) -> tuple[str, bytes]:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise _error("INVALID_PATH", 400, "The source path is invalid.")
    if not os.path.isabs(path):
        raise _error("INVALID_PATH", 400, "The source path must be absolute.")
    if os.name == "nt" and path.startswith(("\\\\", "//")):
        raise _error(
            "INVALID_PATH", 400, "The source must be a local regular file."
        )
    normalized = os.path.abspath(path)
    try:
        path_metadata = os.lstat(normalized)
    except OSError:
        raise _error(
            "INVALID_PATH", 400, "The source must be an explicit regular file."
        ) from None
    if (stat.S_ISLNK(path_metadata.st_mode)
            or not stat.S_ISREG(path_metadata.st_mode)):
        raise _error(
            "INVALID_PATH", 400, "The source must be an explicit regular file."
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(normalized, flags)
    except OSError:
        raise _error(
            "INVALID_PATH", 400, "The source must be an explicit regular file."
        ) from None
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode)
                or (path_metadata.st_dev, path_metadata.st_ino)
                != (metadata.st_dev, metadata.st_ino)):
            raise _error(
                "INVALID_PATH", 400,
                "The source must be an explicit regular file."
            )
        if metadata.st_size > limit:
            raise _error("IMPORT_SOURCE_INVALID", 400, "The source is too large.")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > limit:
            raise _error("IMPORT_SOURCE_INVALID", 400, "The source is too large.")
        return normalized, payload
    finally:
        os.close(fd)


def _decode_json(payload: bytes, *, receipt: bool = False) -> dict[str, object]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        code = "IMPORT_RECEIPT_NOT_FOUND" if receipt else "IMPORT_SOURCE_INVALID"
        status = 404 if receipt else 400
        message = "The import receipt is missing or invalid." if receipt else (
            "The source configuration is not valid UTF-8 JSON."
        )
        raise _error(code, status, message) from None
    if not isinstance(value, dict):
        code = "IMPORT_RECEIPT_NOT_FOUND" if receipt else "IMPORT_SOURCE_INVALID"
        status = 404 if receipt else 400
        message = "The import receipt is missing or invalid." if receipt else (
            "The source configuration must be a JSON object."
        )
        raise _error(code, status, message)
    return value


def _validate_source_shape(raw: Mapping[str, object]) -> list[dict[str, object]]:
    version = raw.get("schemaVersion", 0)
    if type(version) is not int or version < 0 or version > SUPPORTED_SCHEMA_VERSION:
        raise _error(
            "IMPORT_SOURCE_INVALID", 400,
            "The source schema version is not supported."
        )
    apps = raw.get("apps", [])
    if not isinstance(apps, list):
        raise _error(
            "IMPORT_SOURCE_INVALID", 400,
            "The source apps field must be an array."
        )
    validated = []
    seen = set()
    for app in apps:
        if not isinstance(app, dict):
            raise _error(
                "IMPORT_SOURCE_INVALID", 400,
                "Every source app must be an object."
            )
        app_id = app.get("id")
        if (not isinstance(app_id, str)
                or not re.fullmatch(r"[0-9a-f]{8}", app_id)):
            raise _error(
                "IMPORT_SOURCE_INVALID", 400,
                "Every source app must have a valid string id."
            )
        if app_id in seen:
            raise _error(
                "IMPORT_SOURCE_INVALID", 400,
                "Source app ids must be unique."
            )
        seen.add(app_id)
        for key in ("name", "command"):
            value = app.get(key)
            if (not isinstance(value, str) or not value.strip()
                    or "\x00" in value):
                raise _error(
                    "IMPORT_SOURCE_INVALID", 400,
                    f"Every source app must have a valid {key}."
                )
        cwd = app.get("cwd")
        if cwd is not None and (not isinstance(cwd, str) or "\x00" in cwd):
            raise _error(
                "IMPORT_SOURCE_INVALID", 400,
                "Every source app cwd must be a string or null."
            )
        kind = app.get("kind", "service")
        if kind not in ("service", "task"):
            raise _error(
                "IMPORT_SOURCE_INVALID", 400,
                "Every source app kind must be service or task."
            )
        port = app.get("port")
        if (port is not None
                and (type(port) is not int or not 1 <= port <= 65535)):
            raise _error(
                "IMPORT_SOURCE_INVALID", 400,
                "Every source app port must be null or an integer from 1 to 65535."
            )
        for key in ("emoji", "glyph", "icon", "favicon"):
            value = app.get(key)
            if value is not None and (
                    not isinstance(value, str) or "\x00" in value):
                raise _error(
                    "IMPORT_SOURCE_INVALID", 400,
                    f"Every source app {key} must be a string or null."
                )
        if "commandSpec" in app and app["commandSpec"] is not None:
            try:
                normalize_command_spec(app["commandSpec"])
            except CommandSpecError:
                # Keep the app visible in preview, but never let normalization
                # silently turn an invalid v2 command into a selectable record.
                app = dict(app)
                app["__invalidCommandSpec"] = True
        validated.append(app)
    return validated


def _normalize_config(
    raw: Mapping[str, object],
    normalize_config: Callable[[Mapping[str, object]], Mapping[str, object]],
    *,
    source: bool,
) -> dict[str, object]:
    try:
        normalized = normalize_config(_clone(raw))
    except ConfigImportError:
        raise
    except Exception:
        if source:
            raise _error(
                "IMPORT_SOURCE_INVALID", 400,
                "The source configuration could not be normalized."
            ) from None
        raise _error(
            "IMPORT_COMMIT_FAILED", 500,
            "The target configuration could not be validated."
        ) from None
    version = normalized.get("schemaVersion") if isinstance(normalized, dict) else None
    if type(version) is not int or version < 2:
        if source:
            raise _error(
                "IMPORT_SOURCE_INVALID", 400,
                "The source configuration could not be normalized to a supported schema."
            )
        raise _error(
            "IMPORT_COMMIT_FAILED", 500,
            "The target configuration could not be validated."
        )
    if not isinstance(normalized.get("apps"), list):
        if source:
            raise _error(
                "IMPORT_SOURCE_INVALID", 400,
                "The normalized source apps field is invalid."
            )
        raise _error(
            "IMPORT_COMMIT_FAILED", 500,
            "The normalized target apps field is invalid."
        )
    return normalized


def _normalize_mappings(path_mappings: object) -> list[dict[str, str]]:
    if not isinstance(path_mappings, list):
        raise _error("INVALID_REQUEST", 400, "pathMappings must be an array.")
    normalized = []
    seen = set()
    for mapping in path_mappings:
        if not isinstance(mapping, Mapping):
            raise _error(
                "INVALID_REQUEST", 400,
                "Every path mapping must be an object."
            )
        source_root = mapping.get("sourceRoot")
        target_root = mapping.get("targetRoot")
        if not isinstance(source_root, str) or not isinstance(target_root, str):
            raise _error(
                "INVALID_REQUEST", 400,
                "Path mapping roots must be strings."
            )
        if (not source_root or not target_root or "\x00" in source_root
                or "\x00" in target_root):
            raise _error("INVALID_PATH", 400, "A path mapping root is invalid.")
        if not is_local_windows_path(target_root):
            raise _error(
                "INVALID_PATH", 400,
                "A Windows mapping root must be a local path."
            )
        source_root = posixpath.normpath(source_root)
        target_root = ntpath.normpath(target_root)
        drive, tail = ntpath.splitdrive(target_root)
        if (not posixpath.isabs(source_root) or source_root.startswith("//")
                or not drive or not tail.startswith(("\\", "/"))):
            raise _error(
                "INVALID_PATH", 400,
                "Mappings require absolute macOS and Windows roots."
            )
        if source_root in seen:
            raise _error(
                "INVALID_REQUEST", 400,
                "A source root may only be mapped once."
            )
        seen.add(source_root)
        normalized.append({
            "sourceRoot": source_root,
            "targetRoot": target_root,
        })
    normalized.sort(key=lambda item: item["sourceRoot"])
    return normalized


def _map_cwd(
    cwd: object,
    mappings: Sequence[Mapping[str, str]],
) -> tuple[str | None, dict[str, str] | None]:
    if not isinstance(cwd, str) or not cwd or "\x00" in cwd:
        return None, {
            "code": "PATH_MAPPING_REQUIRED",
            "message": "The app does not have a mappable macOS working directory.",
        }
    normalized_cwd = posixpath.normpath(cwd)
    if not posixpath.isabs(normalized_cwd) or normalized_cwd.startswith("//"):
        return None, {
            "code": "PATH_MAPPING_REQUIRED",
            "message": "The app working directory is not an absolute macOS path.",
        }
    matches = [
        mapping for mapping in mappings
        if normalized_cwd == mapping["sourceRoot"]
        or normalized_cwd.startswith(mapping["sourceRoot"].rstrip("/") + "/")
    ]
    if not matches:
        return None, {
            "code": "PATH_MAPPING_REQUIRED",
            "message": "Add an explicit path mapping for this working directory.",
        }
    mapping = max(matches, key=lambda item: len(item["sourceRoot"]))
    relative = posixpath.relpath(normalized_cwd, mapping["sourceRoot"])
    parts = [] if relative == "." else relative.split("/")
    mapped = ntpath.normpath(ntpath.join(mapping["targetRoot"], *parts))
    try:
        within_root = ntpath.commonpath((mapping["targetRoot"], mapped))
    except ValueError:
        within_root = ""
    if ntpath.normcase(within_root) != ntpath.normcase(mapping["targetRoot"]):
        return None, {
            "code": "PATH_MAPPING_REQUIRED",
            "message": "The mapped path escapes its Windows root.",
        }
    return mapped, None


def _command_status(
    raw_app: Mapping[str, object],
    normalized_app: Mapping[str, object],
    cwd: str | None,
) -> tuple[str, list[dict[str, str]]]:
    if raw_app.get("__invalidCommandSpec"):
        return "blocked", [{
            "code": "COMMAND_SPEC_INVALID",
            "message": "The source commandSpec is invalid.",
        }]
    try:
        command_spec = normalize_command_spec(normalized_app.get("commandSpec"))
    except CommandSpecError:
        return "blocked", [{
            "code": "COMMAND_SPEC_INVALID",
            "message": "The source command cannot be represented safely.",
        }]
    compatibility = platform_compatibility(command_spec, cwd, "windows")
    status = compatibility.get("status")
    reasons = compatibility.get("reasons")
    return (
        status if status in ("ready", "needs_review", "blocked") else "blocked",
        list(reasons) if isinstance(reasons, list) else [],
    )


def _clear_runtime(app: Mapping[str, object]) -> dict[str, object]:
    imported = dict(_clone(app))
    for field in _RUNTIME_FIELDS:
        imported[field] = None
    imported["attached"] = False
    imported["keepAlive"] = False
    imported["desiredRunning"] = False
    imported["keepAliveGrant"] = None
    return imported


def _build_preview(
    source_path: object,
    path_mappings: object,
    target_config: Mapping[str, object],
    *,
    normalize_config: Callable[[Mapping[str, object]], Mapping[str, object]],
    path_exists: Callable[[str], bool],
) -> tuple[dict[str, object], bytes, dict[str, object], list[dict[str, str]]]:
    _normalized_path, source_bytes = _read_regular_file(
        source_path, MAX_SOURCE_BYTES
    )
    raw = _decode_json(source_bytes)
    raw_apps = _validate_source_shape(raw)
    mappings = _normalize_mappings(path_mappings)
    source = _normalize_config(raw, normalize_config, source=True)
    target = _normalize_config(target_config, normalize_config, source=False)

    source_apps = source["apps"]
    normalized_by_id = {
        app.get("id"): app for app in source_apps if isinstance(app, dict)
    }
    if len(normalized_by_id) != len(raw_apps):
        raise _error(
            "IMPORT_SOURCE_INVALID", 400,
            "Normalization discarded or duplicated a source app."
        )
    target_ids = {
        app.get("id") for app in target["apps"] if isinstance(app, dict)
    }
    preview_apps = []
    summary = {key: 0 for key in (
        "ready", "needs_review", "blocked", "conflict"
    )}
    for raw_app in raw_apps:
        app_id = raw_app["id"]
        normalized_app = normalized_by_id.get(app_id)
        if not isinstance(normalized_app, dict):
            raise _error(
                "IMPORT_SOURCE_INVALID", 400,
                "Normalization changed a source app id."
            )
        imported = _clear_runtime(normalized_app)
        source_cwd = raw_app.get("cwd")
        mapped_cwd, path_reason = _map_cwd(source_cwd, mappings)
        command_status, reasons = _command_status(
            raw_app, imported, mapped_cwd)
        if mapped_cwd is not None:
            imported["cwd"] = mapped_cwd
            try:
                exists = bool(path_exists(mapped_cwd))
            except OSError:
                exists = False
            if not exists:
                path_reason = {
                    "code": "PATH_NOT_FOUND",
                    "message": "The mapped Windows working directory was not found.",
                }
        if path_reason:
            status = "blocked"
            reasons = [path_reason, *reasons]
        else:
            status = command_status
        if app_id in target_ids:
            status = "conflict"
            reasons = [{
                "code": "APP_ID_CONFLICT",
                "message": "An app with this id already exists in the target.",
            }, *reasons]
        imported["importStatus"] = (
            status if status in ("ready", "needs_review", "blocked")
            else command_status
        )
        public_app = dict(imported)
        public_app["status"] = status
        public_app["reasons"] = reasons
        public_app["sourceCwd"] = source_cwd
        preview_apps.append(public_app)
        summary[status] += 1

    source_hash = _sha256(source_bytes)
    target_hash = config_hash(target)
    decision = {
        "sourceHash": source_hash,
        "pathMappings": mappings,
        "targetHash": target_hash,
        "apps": preview_apps,
    }
    decision_hash = hashlib.sha256(_canonical_bytes(decision)).hexdigest()
    preview_id = "sha256:" + source_hash.removeprefix("sha256:") + "." + decision_hash
    preview = {
        "ok": True,
        "previewId": preview_id,
        "sourceHash": source_hash,
        "targetHash": target_hash,
        "apps": preview_apps,
        "summary": summary,
    }
    return preview, source_bytes, target, mappings


def preview_import(
    source_path: object,
    path_mappings: object,
    target_config: Mapping[str, object],
    *,
    normalize_config: Callable[[Mapping[str, object]], Mapping[str, object]],
    path_exists: Callable[[str], bool] = os.path.isdir,
) -> dict[str, object]:
    """Validate and classify an explicit import without writing any file."""
    preview, _source_bytes, _target, _mappings = _build_preview(
        source_path,
        path_mappings,
        target_config,
        normalize_config=normalize_config,
        path_exists=path_exists,
    )
    return preview


def _selection(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        raise _error(
            "IMPORT_SELECTION_INVALID", 400,
            "Select at least one importable app."
        )
    result = []
    seen = set()
    for app_id in value:
        if (not isinstance(app_id, str) or not app_id or "\x00" in app_id
                or app_id in seen):
            raise _error(
                "IMPORT_SELECTION_INVALID", 400,
                "selectedAppIds must contain unique valid string ids."
            )
        seen.add(app_id)
        result.append(app_id)
    return result


def _validate_preview_id(value: object) -> re.Match[str]:
    if not isinstance(value, str):
        raise _error("INVALID_REQUEST", 400, "previewId must be a string.")
    match = _PREVIEW_PATTERN.fullmatch(value)
    if not match:
        raise _error("INVALID_REQUEST", 400, "previewId is invalid.")
    return match


def _json_record(value: Mapping[str, object]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _ensure_directory(path: str, *, create: bool) -> None:
    try:
        if create:
            os.makedirs(path, mode=0o700, exist_ok=True)
        if not os.path.isdir(path) or os.path.islink(path):
            raise OSError("not a safe directory")
        if os.name != "nt":
            os.chmod(path, 0o700)
    except OSError:
        raise _error(
            "IMPORT_COMMIT_FAILED", 500,
            "The private import record directory is unavailable."
        ) from None


def _write_private(
    path: str,
    payload: bytes,
    ensure_private_file: Callable[[str], None] | None,
    *,
    read_only: bool = False,
) -> None:
    temporary = path + ".tmp-" + uuid.uuid4().hex
    fd = -1
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        if ensure_private_file:
            ensure_private_file(temporary)
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        if ensure_private_file:
            ensure_private_file(path)
        if read_only:
            os.chmod(path, stat.S_IREAD)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _cleanup_record(path: str) -> None:
    if not os.path.isdir(path) or os.path.islink(path):
        return
    for root, _directories, files in os.walk(path):
        for name in files:
            try:
                os.chmod(os.path.join(root, name), stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
    try:
        shutil.rmtree(path)
    except OSError:
        pass


def _load_receipt(record_dir: str) -> dict[str, object]:
    path = os.path.join(record_dir, "receipt.json")
    try:
        _normalized, payload = _read_regular_file(path, MAX_RECORD_BYTES)
        receipt = _decode_json(payload, receipt=True)
    except ConfigImportError:
        raise _error(
            "IMPORT_RECEIPT_NOT_FOUND", 404,
            "The import receipt is missing or invalid."
        ) from None
    required = {
        "version", "importId", "status", "previewId", "sourceHash",
        "targetHash", "postHash", "pathMappings", "selectedAppIds",
    }
    if (not required.issubset(receipt)
            or receipt.get("version") != 1
            or not _HASH_PATTERN.fullmatch(str(receipt.get("sourceHash", "")))
            or not _HASH_PATTERN.fullmatch(str(receipt.get("targetHash", "")))
            or not _HASH_PATTERN.fullmatch(str(receipt.get("postHash", "")))):
        raise _error(
            "IMPORT_RECEIPT_NOT_FOUND", 404,
            "The import receipt is missing or invalid."
        )
    return receipt


def _find_idempotent_receipt(
    records_dir: str,
    *,
    source_hash: str,
    mappings: list[dict[str, str]],
    preview_id: str,
    selected: list[str],
    current_hash: str,
    ensure_private_file: Callable[[str], None] | None,
) -> dict[str, object] | None:
    if not os.path.isdir(records_dir) or os.path.islink(records_dir):
        return None
    selection_key = sorted(selected)
    try:
        entries = list(os.scandir(records_dir))
    except OSError:
        return None
    for entry in entries:
        if not entry.is_dir(follow_symlinks=False):
            continue
        try:
            receipt = _load_receipt(entry.path)
        except ConfigImportError:
            continue
        if (receipt.get("sourceHash") == source_hash
                and receipt.get("pathMappings") == mappings
                and receipt.get("previewId") == preview_id
                and sorted(receipt.get("selectedAppIds", [])) == selection_key):
            if (receipt.get("status") == "committed"
                    and receipt.get("postHash") == current_hash):
                return receipt
            if receipt.get("status") == "prepared":
                if receipt.get("postHash") == current_hash:
                    receipt["status"] = "committed"
                    try:
                        _write_private(
                            os.path.join(entry.path, "receipt.json"),
                            _json_record(receipt),
                            ensure_private_file,
                        )
                    except Exception:
                        raise _error(
                            "IMPORT_COMMIT_FAILED", 500,
                            "The import receipt could not be finalized."
                        ) from None
                    return receipt
                if receipt.get("targetHash") == current_hash:
                    _cleanup_record(entry.path)
    return None


def _replace(
    replace_target: Callable[[str, Mapping[str, object]], object],
    expected_hash: str,
    replacement: Mapping[str, object],
    *,
    rollback: bool,
) -> None:
    try:
        replaced = replace_target(expected_hash, _clone(replacement))
    except ConfigImportError:
        raise
    except Exception:
        code = "IMPORT_ROLLBACK_FAILED" if rollback else "IMPORT_COMMIT_FAILED"
        raise _error(
            code, 500,
            "The configuration could not be replaced atomically."
        ) from None
    if replaced is False:
        code = "IMPORT_ROLLBACK_CONFLICT" if rollback else "IMPORT_PREVIEW_STALE"
        message = (
            "The target changed after this import."
            if rollback else "The target changed after the preview."
        )
        raise _error(code, 409, message)


def commit_import(
    source_path: object,
    path_mappings: object,
    preview_id: object,
    selected_app_ids: object,
    *,
    records_dir: str,
    get_target: Callable[[], Mapping[str, object]],
    replace_target: Callable[[str, Mapping[str, object]], object],
    normalize_config: Callable[[Mapping[str, object]], Mapping[str, object]],
    ensure_private_file: Callable[[str], None] | None = None,
    path_exists: Callable[[str], bool] = os.path.isdir,
) -> dict[str, object]:
    """Commit selected preview apps with target-hash compare-and-swap."""
    preview_match = _validate_preview_id(preview_id)
    selected = _selection(selected_app_ids)
    mappings = _normalize_mappings(path_mappings)
    _normalized_path, source_bytes = _read_regular_file(
        source_path, MAX_SOURCE_BYTES
    )
    source_hash = _sha256(source_bytes)
    if source_hash.removeprefix("sha256:") != preview_match.group(1):
        raise _error(
            "IMPORT_SOURCE_CHANGED", 409,
            "The source file changed after the preview."
        )
    target_snapshot = get_target()
    _target, target_hash = _validated_snapshot_hash(
        target_snapshot,
        "IMPORT_COMMIT_FAILED",
        "The target configuration could not be validated.",
    )
    prior = _find_idempotent_receipt(
        records_dir,
        source_hash=source_hash,
        mappings=mappings,
        preview_id=str(preview_id),
        selected=selected,
        current_hash=target_hash,
        ensure_private_file=ensure_private_file,
    )
    if prior:
        return {
            "ok": True,
            "importId": prior["importId"],
            "importedAppIds": list(prior["selectedAppIds"]),
            "idempotent": True,
        }

    preview, rebuilt_source, target, rebuilt_mappings = _build_preview(
        source_path,
        path_mappings,
        target_snapshot,
        normalize_config=normalize_config,
        path_exists=path_exists,
    )
    if rebuilt_source != source_bytes:
        raise _error(
            "IMPORT_SOURCE_CHANGED", 409,
            "The source file changed after the preview."
        )
    if rebuilt_mappings != mappings or preview["previewId"] != preview_id:
        raise _error(
            "IMPORT_PREVIEW_STALE", 409,
            "The mapping or target configuration changed after the preview."
        )
    decisions = {app["id"]: app for app in preview["apps"]}
    invalid = [
        app_id for app_id in selected
        if app_id not in decisions
        or decisions[app_id]["status"] not in ("ready", "needs_review")
    ]
    if invalid:
        raise _error(
            "IMPORT_SELECTION_INVALID", 400,
            "The selection contains a missing, blocked, or conflicting app."
        )
    selected_set = set(selected)
    selected_in_source_order = [
        app["id"] for app in preview["apps"] if app["id"] in selected_set
    ]
    staged = dict(_clone(target))
    staged_apps = list(staged["apps"])
    statuses = {}
    for app in preview["apps"]:
        if app["id"] not in selected_set:
            continue
        imported = {
            key: _clone(value)
            for key, value in app.items()
            if key not in ("status", "reasons", "sourceCwd")
        }
        imported["importStatus"] = app["status"]
        imported = _clear_runtime(imported)
        statuses[imported["id"]] = app["status"]
        staged_apps.append(imported)
    staged["apps"] = staged_apps
    staged["schemaVersion"] = target["schemaVersion"]
    staged = _normalize_config(staged, normalize_config, source=False)
    staged_by_id = {
        app.get("id"): app for app in staged["apps"] if isinstance(app, dict)
    }
    if any(app_id not in staged_by_id for app_id in selected_in_source_order):
        raise _error(
            "IMPORT_COMMIT_FAILED", 500,
            "The staged configuration did not retain every selected app."
        )
    for app_id, status_value in statuses.items():
        staged_by_id[app_id].update(_clear_runtime(staged_by_id[app_id]))
        staged_by_id[app_id]["importStatus"] = status_value
    post_hash = config_hash(staged)

    import_id = str(uuid.uuid4())
    _ensure_directory(records_dir, create=True)
    record_dir = os.path.join(records_dir, import_id)
    target_replaced = False
    try:
        os.mkdir(record_dir, 0o700)
        if os.name != "nt":
            os.chmod(record_dir, 0o700)
        source_record = os.path.join(record_dir, "source.json")
        before_record = os.path.join(record_dir, "before.json")
        receipt_path = os.path.join(record_dir, "receipt.json")
        receipt = {
            "version": 1,
            "importId": import_id,
            "status": "prepared",
            "previewId": preview_id,
            "sourceHash": source_hash,
            "targetHash": preview["targetHash"],
            "postHash": post_hash,
            "pathMappings": mappings,
            "selectedAppIds": selected_in_source_order,
            "sourceRecord": "source.json",
            "beforeRecord": "before.json",
        }
        _write_private(
            source_record, source_bytes, ensure_private_file, read_only=True
        )
        _write_private(
            before_record, _json_record(target), ensure_private_file
        )
        _write_private(receipt_path, _json_record(receipt), ensure_private_file)
        _replace(
            replace_target,
            str(preview["targetHash"]),
            staged,
            rollback=False,
        )
        target_replaced = True
        receipt["status"] = "committed"
        try:
            _write_private(
                receipt_path, _json_record(receipt), ensure_private_file
            )
        except Exception:
            try:
                _replace(
                    replace_target, post_hash, target, rollback=True
                )
                target_replaced = False
                _cleanup_record(record_dir)
            except ConfigImportError:
                pass
            raise _error(
                "IMPORT_COMMIT_FAILED", 500,
                "The import receipt could not be finalized."
            ) from None
    except ConfigImportError:
        if os.path.isdir(record_dir):
            try:
                current = _normalize_config(
                    get_target(), normalize_config, source=False
                )
            except ConfigImportError:
                current = None
            if not target_replaced and (
                    current is None or config_hash(current) != post_hash):
                _cleanup_record(record_dir)
        raise
    except Exception:
        _cleanup_record(record_dir)
        raise _error(
            "IMPORT_COMMIT_FAILED", 500,
            "The private import records could not be written."
        ) from None
    return {
        "ok": True,
        "importId": import_id,
        "importedAppIds": selected_in_source_order,
        "idempotent": False,
    }


def _validated_import_id(value: object) -> str:
    if not isinstance(value, str):
        raise _error(
            "IMPORT_RECEIPT_NOT_FOUND", 404,
            "The import receipt is missing or invalid."
        )
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise _error(
            "IMPORT_RECEIPT_NOT_FOUND", 404,
            "The import receipt is missing or invalid."
        ) from None
    canonical = str(parsed)
    if canonical != value:
        raise _error(
            "IMPORT_RECEIPT_NOT_FOUND", 404,
            "The import receipt is missing or invalid."
        )
    return canonical


def rollback_import(
    import_id: object,
    *,
    records_dir: str,
    get_target: Callable[[], Mapping[str, object]],
    replace_target: Callable[[str, Mapping[str, object]], object],
    normalize_config: Callable[[Mapping[str, object]], Mapping[str, object]],
    ensure_private_file: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Restore the private pre-import backup when postHash still matches."""
    canonical_id = _validated_import_id(import_id)
    record_dir = os.path.join(records_dir, canonical_id)
    if os.path.islink(record_dir) or not os.path.isdir(record_dir):
        raise _error(
            "IMPORT_RECEIPT_NOT_FOUND", 404,
            "The import receipt is missing or invalid."
        )
    receipt = _load_receipt(record_dir)
    if receipt.get("importId") != canonical_id:
        raise _error(
            "IMPORT_RECEIPT_NOT_FOUND", 404,
            "The import receipt is missing or invalid."
        )
    _current, current_hash = _validated_snapshot_hash(
        get_target(),
        "IMPORT_ROLLBACK_FAILED",
        "The current configuration could not be validated.",
    )
    if receipt.get("status") == "rolled_back":
        return {"ok": True, "importId": canonical_id, "idempotent": True}
    if (receipt.get("status") == "rollback_prepared"
            and current_hash == receipt["targetHash"]):
        receipt["status"] = "rolled_back"
        try:
            _write_private(
                os.path.join(record_dir, "receipt.json"),
                _json_record(receipt),
                ensure_private_file,
            )
        except Exception:
            raise _error(
                "IMPORT_ROLLBACK_FAILED", 500,
                "The rollback receipt could not be finalized."
            ) from None
        return {"ok": True, "importId": canonical_id, "idempotent": True}
    status = receipt.get("status")
    if status == "prepared" and current_hash == receipt["targetHash"]:
        _cleanup_record(record_dir)
        raise _error(
            "IMPORT_RECEIPT_NOT_FOUND", 404,
            "The import receipt is missing or invalid."
        )
    if status not in ("committed", "prepared", "rollback_prepared"):
        raise _error(
            "IMPORT_RECEIPT_NOT_FOUND", 404,
            "The import receipt is missing or invalid."
        )
    if current_hash != receipt["postHash"]:
        raise _error(
            "IMPORT_ROLLBACK_CONFLICT", 409,
            "The target changed after this import."
        )
    try:
        _normalized, before_bytes = _read_regular_file(
            os.path.join(record_dir, "before.json"), MAX_RECORD_BYTES
        )
        before_raw = _decode_json(before_bytes, receipt=True)
        before, before_hash = _validated_snapshot_hash(
            before_raw,
            "IMPORT_ROLLBACK_FAILED",
            "The pre-import backup could not be validated.",
        )
    except ConfigImportError:
        raise _error(
            "IMPORT_ROLLBACK_FAILED", 500,
            "The pre-import backup could not be validated."
        ) from None
    if before_hash != receipt["targetHash"]:
        raise _error(
            "IMPORT_ROLLBACK_FAILED", 500,
            "The pre-import backup does not match the receipt."
        )
    receipt["status"] = "rollback_prepared"
    try:
        _write_private(
            os.path.join(record_dir, "receipt.json"),
            _json_record(receipt),
            ensure_private_file,
        )
    except Exception:
        raise _error(
            "IMPORT_ROLLBACK_FAILED", 500,
            "The rollback receipt could not be prepared."
        ) from None
    _replace(
        replace_target,
        str(receipt["postHash"]),
        before,
        rollback=True,
    )
    receipt["status"] = "rolled_back"
    try:
        _write_private(
            os.path.join(record_dir, "receipt.json"),
            _json_record(receipt),
            ensure_private_file,
        )
    except Exception:
        raise _error(
            "IMPORT_ROLLBACK_FAILED", 500,
            "The rollback receipt could not be finalized."
        ) from None
    return {"ok": True, "importId": canonical_id, "idempotent": False}

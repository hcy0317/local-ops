#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""总控台后端（单文件，仅 Python 3 标准库）。

本地服务监控 + 快速启动台：
    python3 server.py  →  绑定 127.0.0.1，端口 9600 起（被占 +1，最多 10 个）
API 契约与实现要点见 AGENTS.md。
"""

import functools
import hashlib
import errno
import json
import logging
import ntpath
import os
import random
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from localops.platform.contracts import (
    ElevatedTaskResult,
    LaunchRequest,
    PlatformScanError,
    RuntimeIdentity,
    ScanStatus,
)
from localops.platform.loader import load_platform
from localops.command_spec import (
    CommandSpecError,
    command_spec_for_executable,
    command_spec_for_script,
    direct_command_spec,
    display_command,
    is_local_windows_path,
    legacy_command_spec,
    normalize_command_spec,
    platform_compatibility,
    prepared_invocation,
    python_command_spec,
    select_python_executable,
    static_preflight,
)
from localops.config_import import (
    ConfigImportError,
    commit_import,
    config_hash,
    preview_import,
    rollback_import,
)
from localops.docker_resources import (
    DockerController,
    DockerSnapshot,
    normalize_docker_resource,
)
from localops.elevation_broker import (
    new_password_record,
    normalize_elevated_task_command_spec,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_PATH = os.path.join(BASE_DIR, "VERSION")
LEGACY_DATA_DIR = os.path.join(BASE_DIR, "data")
PLATFORM = load_platform(BASE_DIR, __file__)
DOCKER = DockerController()
PLATFORM_PATHS = PLATFORM.runtime_paths()
DEFAULT_DATA_DIR = PLATFORM_PATHS.data_dir
DEFAULT_LOGS_DIR = PLATFORM_PATHS.logs_dir


def resolve_runtime_dir(name, default):
    """解析专用运行目录，拒绝空值、相对路径和过宽目标。"""
    overridden = name in os.environ
    raw = (os.environ.get(name) or "").strip() if overridden else default
    if not raw:
        raise RuntimeError("%s 不能为空" % name)
    expanded = os.path.expanduser(raw)
    if overridden and not os.path.isabs(expanded):
        raise RuntimeError("%s 必须是绝对路径" % name)
    path = os.path.abspath(expanded)
    forbidden = {os.path.abspath(os.sep), os.path.abspath(os.path.expanduser("~")),
                 os.path.abspath(BASE_DIR)}
    try:
        path = PLATFORM.validate_runtime_path(path, forbidden)
    except ValueError as exc:
        raise RuntimeError("%s 必须指向安全的专用子目录: %s" %
                           (name, exc)) from exc
    return path, overridden


DATA_DIR, DATA_DIR_OVERRIDDEN = resolve_runtime_dir(
    "CONSOLE_DATA_DIR", DEFAULT_DATA_DIR)
ICONS_DIR = os.path.join(DATA_DIR, "icons")
LOGS_DIR, LOGS_DIR_OVERRIDDEN = resolve_runtime_dir(
    "CONSOLE_LOG_DIR", DEFAULT_LOGS_DIR)
STATIC_DIR = os.path.join(BASE_DIR, "static")
THEMES_DIR = os.path.join(STATIC_DIR, "themes")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
INSTANCE_LOCK_PATH = os.path.join(DATA_DIR, "console.lock")
IMPORT_RECORDS_DIR = os.path.join(DATA_DIR, "imports")
CONTROL_CREDENTIAL_PATH = os.path.join(DATA_DIR, "control-credential.json")
TAILSCALE_PROXY_CREDENTIAL_PATH = os.path.join(
    DATA_DIR, "tailscale-proxy-secret"
)

CURRENT_SCHEMA_VERSION = 5

# 默认 UI 主题：新安装与无偏好回退均使用它，主题清单中固定排首位。
DEFAULT_UI_THEME = "ops"


def read_project_version(path=VERSION_PATH):
    """读取根目录 VERSION。失败时保持服务可诊断，但标记为降级。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = f.read(128).strip()
        if not re.fullmatch(
                r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
                r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", value):
            raise ValueError("VERSION 不是合法的 SemVer")
        return value, None
    except (OSError, UnicodeError, ValueError) as e:
        return "0.0.0+unknown", str(e)


APP_VERSION, VERSION_LOAD_ERROR = read_project_version()

HOST = "127.0.0.1"
PORT_START = 9600
PORT_TRIES = 10
SUBPROCESS_TIMEOUT = 5          # lsof/ps 等子进程超时（秒）
MAX_ICON_BYTES = 5 * 1024 * 1024
MAX_JSON_BYTES = 1 * 1024 * 1024
MAX_DETECT_FILE_BYTES = 2 * 1024 * 1024
MAX_LOG_BYTES = 10 * 1024 * 1024
LOG_BACKUPS = 3
LOG_MAINTENANCE_SEC = 30
BROWSER_BOOTSTRAP_TTL_SEC = 60.0
CONTROL_SESSION_IDLE_SEC = 8 * 60 * 60
TAILSCALE_PROXY_AUTH_HEADER = "X-LocalOps-Tailscale-Proxy-Authorization"
TAILSCALE_USER_LOGIN_HEADER = "Tailscale-User-Login"
TAILSCALE_LOGIN_RE = re.compile(r"^[^\s@]+@[^\s@]+$")
TAILSCALE_PROXY_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
STARTUP_PROBE_SEC = 0.25
APP_STOP_TIMEOUT_SEC = 5.0
RUN_TOKEN_ENV = "CONSOLE_RUN_TOKEN"
RUN_TOKEN_ARG_PREFIX = "console-run:"
TASK_CANCELED_EXIT_CODE = 130

SELF_PID = os.getpid()
SELF_PRINCIPAL = PLATFORM.current_principal()
# Compatibility name used throughout the macOS domain model and existing tests.
SELF_UID = SELF_PRINCIPAL.numeric_id
ICON_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".ico")
LOG = logging.getLogger("console")
LOG_LOCK = threading.RLock()
MANUAL_STOP_LOCK = threading.RLock()
MANUAL_STOP_TOKENS = set()
_PLATFORM_SCAN_STATE = threading.local()
# One terminal generation clear is a single transaction: config CAS, runtime
# record release, and any identity restore must not race state reconciliation.
# A global lock keeps this uncommon path simple and also serializes recovery
# scans with release I/O; normal process inspection and lifecycle control do
# not take it.
_WINDOWS_RELEASE_LOCK = threading.RLock()
_WINDOWS_PENDING_RELEASES = {}


def process_owned_by_current(info):
    """Match native process ownership without assuming a POSIX numeric UID."""
    if not info:
        return False
    owner = info.get("owner")
    if owner is not None:
        return owner == SELF_PRINCIPAL.identifier
    return SELF_UID is not None and info.get("uid") == SELF_UID


def process_owner_value(info):
    if not info:
        return None
    owner = info.get("owner")
    return owner if owner is not None else info.get("uid")


def _begin_platform_scan_cycle():
    _PLATFORM_SCAN_STATE.issues = []


def _record_platform_issues(status, issues):
    current = getattr(_PLATFORM_SCAN_STATE, "issues", None)
    if current is not None:
        current.extend(issue for issue in issues if issue not in current)
    if status is ScanStatus.FAILED:
        raise PlatformScanError(issues)


def _consume_platform_scan_issues():
    issues = list(getattr(_PLATFORM_SCAN_STATE, "issues", []))
    _PLATFORM_SCAN_STATE.issues = []
    return issues


def classify_task_exit(code):
    """把一次性任务的退出码归一为稳定的产品语义。"""
    if code == 0:
        return "succeeded"
    if code == TASK_CANCELED_EXIT_CODE:
        return "canceled"
    return "failed"


def public_last_exit(app):
    """兼容旧配置：只在 API 输出时补齐任务状态，不改写磁盘。"""
    value = app.get("lastExit")
    if not isinstance(value, dict):
        return value
    result = dict(value)
    if (app.get("kind") or "service") == "task":
        # 旧版把“总控台按钮停止”记作 canceled + null；新协议中它是 stopped。
        if result.get("status") == "canceled" and result.get("code") is None:
            result["status"] = "stopped"
        elif (result.get("status") not in
              {"succeeded", "canceled", "failed", "stopped"}
              and isinstance(result.get("code"), int)):
            result["status"] = classify_task_exit(result["code"])
    return result


STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".otf": "font/otf",
    ".woff2": "font/woff2",
}

PLACEHOLDER_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>总控台</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f5f5f7;color:#1d1d1f}
.card{background:#fff;border:1px solid rgba(0,0,0,.06);border-radius:14px;padding:36px 44px;box-shadow:0 8px 30px rgba(0,0,0,.08);max-width:540px;text-align:center}
h1{font-size:20px;margin:0 0 14px}p{color:#6e6e73;font-size:14px;line-height:1.8;margin:6px 0}
code{background:#f5f5f7;border:1px solid rgba(0,0,0,.05);border-radius:6px;padding:2px 7px;font-family:ui-monospace,Menlo,monospace;font-size:13px}
</style></head>
<body><div class="card">
<h1>🖥 总控台后端运行中</h1>
<p>前端文件 <code>static/index.html</code> 尚未提供，界面暂不可用。</p>
<p>API 已就绪：<code>GET /api/state</code></p>
</div></body></html>"""

APP_ROUTE_RE = re.compile(
    r"^/api/apps/([0-9a-fA-F]{8})(?:/(start|stop|restart|icon|logs|favicon|"
    r"diagnose|attach|keep-alive|scheduled-enabled|scheduled-history))?$")


# ---------------------------------------------------------------- 运行目录

def _ensure_private_dir(path):
    if os.path.islink(path):
        raise OSError("私有运行目录不能是符号链接: %s" % path)
    os.makedirs(path, mode=0o700, exist_ok=True)
    if os.path.islink(path) or not os.path.isdir(path):
        raise OSError("私有运行路径不是安全目录: %s" % path)
    try:
        PLATFORM.ensure_private_directory(path)
    except OSError:
        if PLATFORM.requires_verified_permissions:
            raise
        LOG.warning("无法收紧目录权限: %s", path)


def _copy_private_regular_file(source, target):
    """不跟随符号链接地复制普通文件，目标权限固定为 0600。"""
    try:
        source_stat = os.lstat(source)
    except OSError:
        return False
    if not stat.S_ISREG(source_stat.st_mode):
        return False
    source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(source, source_flags)
    try:
        target_fd = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            PLATFORM.ensure_private_file(target)
            with os.fdopen(os.dup(source_fd), "rb") as src, \
                    os.fdopen(target_fd, "wb") as dst:
                target_fd = -1
                shutil.copyfileobj(src, dst, length=1024 * 1024)
                dst.flush()
                os.fsync(dst.fileno())
        finally:
            if target_fd >= 0:
                os.close(target_fd)
    finally:
        os.close(source_fd)
    PLATFORM.ensure_private_file(target)
    return True


def write_control_credential(path, console_server):
    """Publish the current-process CLI bearer in current-user-only storage."""
    _ensure_private_dir(os.path.dirname(path) or ".")
    payload = json.dumps({
        "schema": "localops-control.v1",
        "pid": SELF_PID,
        "port": int(console_server.console_port),
        "token": console_server.cli_token,
    }, ensure_ascii=True, sort_keys=True)
    tmp = "%s.%s.tmp" % (path, secrets.token_hex(8))
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(tmp, flags, 0o600)
    try:
        PLATFORM.ensure_private_file(tmp)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        PLATFORM.ensure_private_file(path)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.lexists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def read_control_credential(path, expected_port=None):
    """Read a previously verified private CLI bearer without repairing ACLs."""
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            return None
        verifier = getattr(PLATFORM, "verify_private_file", None)
        if verifier is not None:
            verifier(path)
        else:
            PLATFORM.ensure_private_file(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            raw = os.read(fd, 4097)
        finally:
            os.close(fd)
        if len(raw) > 4096:
            return None
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return None
    if (not isinstance(payload, dict)
            or set(payload) != {"schema", "pid", "port", "token"}
            or payload.get("schema") != "localops-control.v1"
            or not isinstance(payload.get("pid"), int)
            or isinstance(payload.get("pid"), bool)
            or not isinstance(payload.get("port"), int)
            or isinstance(payload.get("port"), bool)
            or not isinstance(payload.get("token"), str)
            or len(payload["token"]) < 32):
        return None
    if expected_port is not None and payload["port"] != int(expected_port):
        return None
    return payload


def remove_control_credential(path, console_server):
    payload = read_control_credential(path, console_server.console_port)
    if (payload is None or payload["pid"] != SELF_PID
            or not secrets.compare_digest(
                payload["token"], console_server.cli_token)):
        return False
    try:
        os.unlink(path)
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def read_tailscale_proxy_credential(path):
    """Read the stable proxy-only bearer without repairing an existing ACL."""
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            return None
        verifier = getattr(PLATFORM, "verify_private_file", None)
        if verifier is not None:
            verifier(path)
        else:
            PLATFORM.ensure_private_file(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            raw = os.read(fd, 257)
        finally:
            os.close(fd)
        if len(raw) > 256:
            return None
        token = raw.decode("ascii")
    except (OSError, UnicodeError, ValueError, TypeError):
        return None
    return token if TAILSCALE_PROXY_TOKEN_RE.fullmatch(token) else None


def ensure_tailscale_proxy_credential(path):
    token = read_tailscale_proxy_credential(path)
    if token is not None:
        return token
    if os.path.lexists(path):
        raise OSError("Tailscale proxy credential is invalid or insecure")
    _ensure_private_dir(os.path.dirname(path) or ".")
    token = secrets.token_urlsafe(48)
    tmp = "%s.%s.tmp" % (path, secrets.token_hex(8))
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(tmp, flags, 0o600)
    try:
        PLATFORM.ensure_private_file(tmp)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            fd = -1
            stream.write(token)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        PLATFORM.ensure_private_file(path)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.lexists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return token


def _install_migrated_directory(target, populate):
    """在目标不存在时原子安装一份迁移副本。"""
    if os.path.lexists(target):
        return False
    parent = os.path.dirname(target) or "."
    # parent 可能是用户共用的 ~/Library/Application Support，
    # 只确保存在，不擅自改它的现有权限。
    os.makedirs(parent, mode=0o700, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".console-migration-", dir=parent)
    installed = False
    try:
        PLATFORM.ensure_private_directory(staging)
        populate(staging)
        try:
            os.rename(staging, target)
            installed = True
        except OSError as e:
            # 另一个同时启动的实例可能已经完成迁移。
            if not os.path.lexists(target) or e.errno not in (
                    errno.EEXIST, errno.ENOTEMPTY):
                raise
        return installed
    finally:
        if not installed and os.path.isdir(staging):
            shutil.rmtree(staging)


def migrate_legacy_runtime_data(
        data_dir=DATA_DIR, logs_dir=LOGS_DIR,
        legacy_data_dir=LEGACY_DATA_DIR,
        data_overridden=DATA_DIR_OVERRIDDEN,
        logs_overridden=LOGS_DIR_OVERRIDDEN):
    """首次运行时将项目内旧数据复制到 macOS 用户目录。

    只在对应目标完全不存在且没有显式环境变量覆盖时执行。
    旧文件不会被删除或改权限。
    """
    result = {"dataMigrated": False, "logsMigrated": False}
    if not PLATFORM.should_migrate_legacy_data():
        return result
    legacy_data_dir = os.path.abspath(legacy_data_dir)
    data_dir = os.path.abspath(data_dir)
    logs_dir = os.path.abspath(logs_dir)

    if (not data_overridden and data_dir != legacy_data_dir
            and os.path.isdir(legacy_data_dir)
            and not os.path.lexists(data_dir)):
        def populate_data(staging):
            for name in ("config.json", "config.json.bak"):
                _copy_private_regular_file(
                    os.path.join(legacy_data_dir, name),
                    os.path.join(staging, name))
            source_icons = os.path.join(legacy_data_dir, "icons")
            if os.path.isdir(source_icons) and not os.path.islink(source_icons):
                target_icons = os.path.join(staging, "icons")
                os.mkdir(target_icons, 0o700)
                for name in os.listdir(source_icons):
                    if os.path.basename(name) != name:
                        continue
                    _copy_private_regular_file(
                        os.path.join(source_icons, name),
                        os.path.join(target_icons, name))

        result["dataMigrated"] = _install_migrated_directory(
            data_dir, populate_data)

    legacy_logs = os.path.join(legacy_data_dir, "logs")
    if (not logs_overridden and logs_dir != legacy_logs
            and os.path.isdir(legacy_logs) and not os.path.islink(legacy_logs)
            and not os.path.lexists(logs_dir)):
        def populate_logs(staging):
            for name in os.listdir(legacy_logs):
                if os.path.basename(name) != name:
                    continue
                _copy_private_regular_file(
                    os.path.join(legacy_logs, name),
                    os.path.join(staging, name))

        result["logsMigrated"] = _install_migrated_directory(
            logs_dir, populate_logs)
    return result


def prepare_runtime_storage():
    migration = migrate_legacy_runtime_data()
    security_issues = []
    for private_dir in (DATA_DIR, ICONS_DIR, LOGS_DIR):
        try:
            _ensure_private_dir(private_dir)
        except PermissionError as exc:
            security_issues.append("运行目录 ACL 验证失败: %s" % exc)
    for path in (CONFIG_PATH, CONFIG_PATH + ".bak", INSTANCE_LOCK_PATH):
        try:
            if stat.S_ISREG(os.lstat(path).st_mode):
                PLATFORM.ensure_private_file(path)
        except PermissionError as exc:
            security_issues.append("运行文件 ACL 验证失败: %s" % exc)
        except OSError:
            pass
    for directory in (ICONS_DIR, LOGS_DIR):
        try:
            entries = os.scandir(directory)
        except OSError:
            continue
        with entries:
            for entry in entries:
                try:
                    if entry.is_file(follow_symlinks=False):
                        PLATFORM.ensure_private_file(entry.path)
                except PermissionError as exc:
                    security_issues.append("运行文件 ACL 验证失败: %s" % exc)
                except OSError:
                    LOG.warning("无法收紧文件权限: %s", entry.path)
    migration["securityIssues"] = list(dict.fromkeys(security_issues))
    return migration


def write_private_bytes(path, payload):
    """以 0600 权限写入用户数据文件。"""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        PLATFORM.ensure_private_file(path)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
    PLATFORM.ensure_private_file(path)


# ---------------------------------------------------------------- 配置


class ConfigSchemaError(ValueError):
    pass


class FutureConfigSchemaError(ConfigSchemaError):
    pass


_WINDOWS_RUNTIME_IDENTITY_FIELDS = {
    "platform",
    "kind",
    "ownerSid",
    "generationId",
    "runnerPid",
    "runnerCreateTime",
    "rootPid",
    "rootCreateTime",
    "jobName",
    "tokenDigest",
    "startedAt",
}
_WINDOWS_SID_RE = re.compile(r"^S-1-(?:\d+-){1,14}\d+$")
_TOKEN_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_LIFECYCLE_ERROR_MESSAGES = {
    "GENERATION_REQUIRED": "请求缺少有效的运行代次",
    "GENERATION_MISMATCH": "应用运行代次已变化，请刷新状态后重试",
    "RUNTIME_IDENTITY_INVALID": "保存的运行身份无效，已禁止控制",
    "RUNTIME_IDENTITY_UNVERIFIED": "无法完整验证受管运行身份，已禁止控制",
    "RUNTIME_RECORD_INSECURE": "运行记录安全验证失败，已禁止控制",
    "LAUNCH_PREPARE_FAILED": "无法安全准备受管进程",
    "LAUNCH_COMMIT_FAILED": "无法在启动前保存运行身份",
    "LAUNCH_ACTIVATE_FAILED": "运行身份已保存，但进程未能安全恢复",
    "STOP_TIMEOUT": "应用未在限定时间内退出，仍保留管理身份",
    "RUNTIME_CONTROL_FAILED": "受管进程控制失败，仍保留管理身份",
}


def runtime_generation(app):
    """Return the persisted managed generation, never a legacy PID token."""
    identity = app.get("runtimeIdentity") if isinstance(app, dict) else None
    return identity.get("generationId") if isinstance(identity, dict) else None


def normalize_expected_generation(data, *, required):
    """Validate the observed generation carried by a lifecycle request."""
    if "expectedGeneration" not in data:
        if required:
            return None, "请求缺少 expectedGeneration"
        return None, None
    value = data.get("expectedGeneration")
    if value is None:
        return None, None
    if not isinstance(value, str):
        return None, "expectedGeneration 必须是 UUID 字符串或 null"
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None, "expectedGeneration 必须是 UUID 字符串或 null"
    if str(parsed) != value:
        return None, "expectedGeneration 必须使用规范的小写 UUID"
    return value, None


def normalize_runtime_identity(value, app_id, *, current_owner=None):
    """Validate the exact public Windows Job identity stored in schema v2."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != _WINDOWS_RUNTIME_IDENTITY_FIELDS:
        raise ConfigSchemaError("runtimeIdentity 必须是受支持的完整 Windows Job 身份")
    if value.get("platform") != "windows" or value.get("kind") != "job":
        raise ConfigSchemaError("runtimeIdentity 平台或类型无效")

    owner_sid = value.get("ownerSid")
    if not isinstance(owner_sid, str) or not _WINDOWS_SID_RE.fullmatch(owner_sid):
        raise ConfigSchemaError("runtimeIdentity ownerSid 无效")
    if current_owner is not None and owner_sid != current_owner:
        raise ConfigSchemaError("runtimeIdentity 不属于当前 Windows 用户")

    generation = value.get("generationId")
    try:
        parsed_generation = uuid.UUID(generation) if isinstance(generation, str) else None
    except (ValueError, AttributeError):
        parsed_generation = None
    if parsed_generation is None or str(parsed_generation) != generation:
        raise ConfigSchemaError("runtimeIdentity generationId 无效")

    for field in ("runnerPid", "rootPid", "startedAt"):
        field_value = value.get(field)
        if isinstance(field_value, bool) or not isinstance(field_value, int) or field_value <= 0:
            raise ConfigSchemaError("runtimeIdentity %s 无效" % field)
    for field in ("runnerCreateTime", "rootCreateTime"):
        field_value = value.get(field)
        if (isinstance(field_value, bool)
                or not isinstance(field_value, (int, float))
                or not (0 < field_value < float("inf"))):
            raise ConfigSchemaError("runtimeIdentity %s 无效" % field)

    prefix = "Local\\LocalOps-%s-%s-" % (app_id, generation)
    job_name = value.get("jobName")
    token_digest = value.get("tokenDigest")
    if (not isinstance(token_digest, str)
            or not _TOKEN_DIGEST_RE.fullmatch(token_digest)):
        raise ConfigSchemaError("runtimeIdentity tokenDigest 无效")
    expected_job_name = prefix + token_digest[7:23]
    if job_name != expected_job_name:
        raise ConfigSchemaError("runtimeIdentity jobName 无效")
    return json.loads(json.dumps(value, ensure_ascii=False))


def public_runtime_identity(identity, app_id):
    """Serialize only the non-secret v3 identity fields."""
    if identity is None or identity.app_id != app_id:
        raise ConfigSchemaError("runner 返回的 runtimeIdentity 未绑定当前应用")
    public = {
        "platform": identity.platform,
        "kind": identity.kind,
        "ownerSid": identity.owner,
        "generationId": identity.generation_id,
        "runnerPid": identity.runner_pid,
        "runnerCreateTime": identity.runner_create_time,
        "rootPid": identity.root_pid,
        "rootCreateTime": identity.root_create_time,
        "jobName": identity.job_name,
        "tokenDigest": identity.token_digest,
        "startedAt": identity.started_at,
    }
    return normalize_runtime_identity(
        public,
        app_id,
        current_owner=(
            SELF_PRINCIPAL.identifier if PLATFORM.name == "windows" else None
        ),
    )


def native_runtime_identity(app):
    """Rehydrate internal adapter context without exposing runtime paths/secrets."""
    app_id = app.get("id")
    public = normalize_runtime_identity(
        app.get("runtimeIdentity"),
        app_id,
        current_owner=(
            SELF_PRINCIPAL.identifier if PLATFORM.name == "windows" else None
        ),
    )
    if public is None:
        return None
    return RuntimeIdentity(
        platform=public["platform"],
        kind=public["kind"],
        identifier=public["jobName"],
        owner=public["ownerSid"],
        members=(public["rootPid"],),
        app_id=app_id,
        generation_id=public["generationId"],
        runner_pid=public["runnerPid"],
        runner_create_time=public["runnerCreateTime"],
        root_pid=public["rootPid"],
        root_create_time=public["rootCreateTime"],
        job_name=public["jobName"],
        token_digest=public["tokenDigest"],
        started_at=public["startedAt"],
    )


def lifecycle_error(code, fallback="RUNTIME_IDENTITY_UNVERIFIED"):
    stable = code if code in _LIFECYCLE_ERROR_MESSAGES else fallback
    return {"code": stable, "message": _LIFECYCLE_ERROR_MESSAGES[stable]}


def inspect_windows_runtime(app):
    """Return fail-closed lifecycle presentation for one Windows app."""
    identity = app.get("runtimeIdentity")
    if identity is None:
        return {
            "status": "stopped",
            "running": False,
            "controlAvailable": True,
            "deleteAvailable": True,
            "issue": None,
            "members": (),
            "verified": True,
        }
    try:
        native = native_runtime_identity(app)
        inspection = PLATFORM.inspect_managed(native)
    except (ConfigSchemaError, OSError, ValueError, TypeError):
        return {
            "status": "orphaned",
            "running": False,
            "controlAvailable": False,
            "deleteAvailable": False,
            "issue": lifecycle_error("RUNTIME_IDENTITY_INVALID"),
            "members": (),
            "verified": False,
        }
    except Exception:
        LOG.exception("检查 Windows 受管运行身份失败: %s", app.get("id"))
        return {
            "status": "unknown",
            "running": False,
            "controlAvailable": False,
            "deleteAvailable": False,
            "issue": lifecycle_error("RUNTIME_IDENTITY_UNVERIFIED"),
            "members": (),
            "verified": False,
        }

    raw_status = getattr(inspection, "status", None) or "unknown"
    status_map = {
        "prepared": "starting",
        "starting": "starting",
        "running": "running",
        "stopping": "stopping",
    }
    status = status_map.get(raw_status)
    verified = bool(getattr(inspection, "verified", False))
    if not verified:
        raw_code = getattr(inspection, "code", None)
        issue_code = getattr(getattr(inspection, "issue", None), "code", None)
        code = raw_code if raw_code in _LIFECYCLE_ERROR_MESSAGES else issue_code
        insecure = code in {
            "RUNTIME_IDENTITY_INVALID",
            "RUNTIME_RECORD_INSECURE",
        }
        return {
            "status": "orphaned" if insecure else "unknown",
            "running": False,
            "controlAvailable": False,
            "deleteAvailable": False,
            "issue": lifecycle_error(code),
            "members": (),
            "verified": False,
        }
    if not _windows_inspection_matches(native, inspection):
        return {
            "status": "unknown",
            "running": False,
            "controlAvailable": False,
            "deleteAvailable": False,
            "issue": lifecycle_error("RUNTIME_IDENTITY_UNVERIFIED"),
            "members": (),
            "verified": False,
        }
    members = tuple(getattr(inspection, "members", ()) or ())
    inspection_running = bool(getattr(inspection, "running", False))
    if (status in ("running", "stopping")
            and (not inspection_running or not members)):
        return {
            "status": "unknown",
            "running": False,
            "controlAvailable": False,
            "deleteAvailable": False,
            "issue": lifecycle_error("RUNTIME_IDENTITY_UNVERIFIED"),
            "members": (),
            "verified": False,
        }
    if status is None:
        terminal = (
            raw_status in ("exited", "failed")
            and not inspection_running
            and not members
        )
        return {
            "status": "unknown",
            "running": False,
            "controlAvailable": False,
            "deleteAvailable": terminal,
            "issue": lifecycle_error(
                getattr(inspection, "code", None),
                "RUNTIME_CONTROL_FAILED",
            ),
            "members": members,
            "verified": True,
        }
    return {
        "status": status,
        "running": (
            status in ("running", "stopping")
            and inspection_running
            and bool(members)
        ),
        "controlAvailable": status == "running",
        "deleteAvailable": status == "running",
        "issue": None,
        "members": members,
        "verified": True,
    }


def migrate_config_v0_to_v1(raw):
    """旧配置没有 schemaVersion；v1 只建立显式版本基线。"""
    migrated = dict(raw)
    migrated["schemaVersion"] = 1
    return migrated


def migrate_config_v1_to_v2(raw):
    """Add command metadata without changing legacy macOS runtime state."""
    migrated = json.loads(json.dumps(raw, ensure_ascii=False))
    apps = migrated.get("apps")
    if isinstance(apps, list):
        for app in apps:
            if not isinstance(app, dict):
                continue
            command = app.get("command")
            if not isinstance(app.get("commandSpec"), dict):
                safe_command = (command if isinstance(command, str)
                                and "\x00" not in command else "")
                app["commandSpec"] = legacy_command_spec(
                    safe_command)
                if safe_command != command:
                    app["importStatus"] = "blocked"
            app["runtimeIdentity"] = None
            app.setdefault("importStatus", "needs_review")
    migrated["schemaVersion"] = 2
    return migrated


def migrate_config_v2_to_v3(raw):
    """Add explicit external-resource identity without changing managed apps."""
    migrated = json.loads(json.dumps(raw, ensure_ascii=False))
    apps = migrated.get("apps")
    if isinstance(apps, list):
        for app in apps:
            if isinstance(app, dict):
                app.setdefault("dockerResource", None)
    migrated["schemaVersion"] = 3
    return migrated


def migrate_config_v3_to_v4(raw):
    """Add explicit per-app elevation intent; existing apps remain standard."""
    migrated = json.loads(json.dumps(raw, ensure_ascii=False))
    apps = migrated.get("apps")
    if isinstance(apps, list):
        for app in apps:
            if isinstance(app, dict):
                app.setdefault("elevated", False)
    migrated["schemaVersion"] = 4
    return migrated


def migrate_config_v4_to_v5(raw):
    """Add disabled per-app keep-alive intent without starting anything."""
    migrated = json.loads(json.dumps(raw, ensure_ascii=False))
    apps = migrated.get("apps")
    if isinstance(apps, list):
        for app in apps:
            if isinstance(app, dict):
                app.setdefault("keepAlive", False)
                app.setdefault("desiredRunning", False)
                app.setdefault("keepAliveGrant", None)
    migrated["schemaVersion"] = 5
    return migrated


CONFIG_MIGRATIONS = {
    0: migrate_config_v0_to_v1,
    1: migrate_config_v1_to_v2,
    2: migrate_config_v2_to_v3,
    3: migrate_config_v3_to_v4,
    4: migrate_config_v4_to_v5,
}


def migrate_config(raw):
    """将任意已支持的旧 schema 逐版幂等迁移到当前版本。"""
    if not isinstance(raw, dict):
        raise ConfigSchemaError("配置根节点必须是 JSON 对象")
    version = raw.get("schemaVersion", 0)
    if type(version) is not int or version < 0:
        raise ConfigSchemaError("schemaVersion 必须是非负整数")
    if version > CURRENT_SCHEMA_VERSION:
        raise FutureConfigSchemaError(
            "配置 schemaVersion=%d 新于当前程序支持的 %d" %
            (version, CURRENT_SCHEMA_VERSION))
    source_version = version
    migrated = json.loads(json.dumps(raw, ensure_ascii=False))
    while version < CURRENT_SCHEMA_VERSION:
        migration = CONFIG_MIGRATIONS.get(version)
        if migration is None:
            raise ConfigSchemaError("缺少 schemaVersion=%d 的迁移器" % version)
        migrated = migration(migrated)
        next_version = migrated.get("schemaVersion")
        if next_version != version + 1:
            raise ConfigSchemaError("配置迁移器未正确递增 schemaVersion")
        version = next_version
    return migrated, source_version


class Config:
    """配置读写：显式 schema 迁移 + 原子写 + 上一份良好备份。"""

    DEFAULT = {"schemaVersion": CURRENT_SCHEMA_VERSION,
               "apps": [], "hidden": [], "pinned": [], "promoted": [],
               "watchedKeywords": [], "uiTheme": DEFAULT_UI_THEME}
    APP_DEFAULT = {"id": None, "name": "", "command": "", "cwd": None,
                   "commandSpec": None, "runtimeIdentity": None,
                   "importStatus": "needs_review",
                   "scheduledTaskPath": None,
                   "dockerResource": None,
                   "elevated": False,
                   "port": None, "emoji": None, "glyph": None, "icon": None,
                   "favicon": None, "kind": "service", "lastPid": None,
                   "lastPgid": None, "runToken": None,
                   "attached": False, "lastExit": None,
                   "keepAlive": False, "desiredRunning": False,
                   "keepAliveGrant": None,
                   "createdAt": 0}

    def __init__(self, path, force_read_only_reason=None):
        self._lock = threading.RLock()
        self._path = path
        self._writable = not bool(force_read_only_reason)
        self._recovered_from_backup = False
        self._migration_from = None
        self._health_issues = (
            [str(force_read_only_reason)] if force_read_only_reason else []
        )
        self._data = self._load()

    @staticmethod
    def _payload(data):
        return json.dumps(data, ensure_ascii=False, indent=2) + "\n"

    @classmethod
    def _normalize(cls, raw, *, strict_runtime=False):
        data = {"schemaVersion": CURRENT_SCHEMA_VERSION}
        for key, default in cls.DEFAULT.items():
            if key == "schemaVersion":
                continue
            value = raw.get(key)
            if isinstance(value, type(default)):
                data[key] = (json.loads(json.dumps(value, ensure_ascii=False))
                             if isinstance(value, (list, dict)) else value)
            else:
                data[key] = list(default) if isinstance(default, list) else default
        apps = []
        for item in data["apps"]:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            app = dict(cls.APP_DEFAULT)
            for key in app:
                if key in item:
                    app[key] = item[key]
            invalid_external_resource = False
            try:
                app["runtimeIdentity"] = normalize_runtime_identity(
                    app.get("runtimeIdentity"),
                    app["id"],
                    current_owner=(
                        SELF_PRINCIPAL.identifier
                        if PLATFORM.name == "windows" else None
                    ),
                )
            except ConfigSchemaError:
                if strict_runtime:
                    raise
                # Explicit imports normalize first and clear legacy identity
                # later; an untrusted PID-only source must never survive that
                # pipeline or become a Windows ownership claim.
                app["runtimeIdentity"] = None
            try:
                resource = app.get("dockerResource")
                app["dockerResource"] = (
                    normalize_docker_resource(resource)
                    if resource is not None else None
                )
            except ValueError as exc:
                if strict_runtime:
                    raise ConfigSchemaError(
                        "dockerResource 无效: %s" % exc
                    ) from exc
                app["dockerResource"] = None
                app["importStatus"] = "blocked"
                invalid_external_resource = True
            app["elevated"] = app.get("elevated") is True
            app["keepAlive"] = app.get("keepAlive") is True
            app["desiredRunning"] = (
                app["keepAlive"] and app.get("desiredRunning") is True
            )
            grant = app.get("keepAliveGrant")
            if (PLATFORM.name != "windows" or not isinstance(grant, dict)
                    or set(grant) != {
                    "version", "grantId", "kind", "bindingDigest",
                    "configDigest",
                } or grant.get("version") != 1
                    or not isinstance(grant.get("grantId"), str)
                    or not 16 <= len(grant["grantId"]) <= 128
                    or grant.get("kind") not in {
                        "elevatedProgram", "scheduledService"
                    } or not isinstance(grant.get("bindingDigest"), str)
                    or not re.fullmatch(
                        r"sha256:[0-9a-f]{64}", grant["bindingDigest"]
                    ) or not isinstance(grant.get("configDigest"), str)
                    or not re.fullmatch(
                        r"sha256:[0-9a-f]{64}", grant["configDigest"]
                    )):
                app["keepAliveGrant"] = None
            invalid_command_spec = False
            try:
                command_spec = app.get("commandSpec")
                if command_spec is None:
                    command = app.get("command")
                    safe_command = (command if isinstance(command, str)
                                    and "\x00" not in command else "")
                    command_spec = legacy_command_spec(
                        safe_command)
                    if safe_command != command:
                        app["importStatus"] = "blocked"
                        invalid_command_spec = True
                app["commandSpec"] = normalize_command_spec(command_spec)
            except CommandSpecError:
                command = app.get("command")
                safe_command = (command if isinstance(command, str)
                                and "\x00" not in command else "")
                app["commandSpec"] = legacy_command_spec(
                    safe_command)
                app["importStatus"] = "blocked"
                invalid_command_spec = True
            if not invalid_command_spec and not invalid_external_resource:
                app["importStatus"] = command_import_status(
                    app["commandSpec"], app.get("cwd"))
            apps.append(app)
        data["apps"] = apps
        return data

    def _load(self):
        paths = (self._path, self._path + ".bak")
        found_candidate = False
        for index, path in enumerate(paths):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                migrated, source_version = migrate_config(raw)
                data = self._normalize(migrated, strict_runtime=True)
                if index:
                    self._recovered_from_backup = True
                    LOG.warning("主配置不可读，已从备份恢复: %s", path)
                if source_version < CURRENT_SCHEMA_VERSION:
                    self._migration_from = source_version
                if self._writable:
                    self._persist_loaded_state(
                        data, raw, source_index=index,
                        source_version=source_version)
                return data
            except FileNotFoundError:
                continue
            except FutureConfigSchemaError as e:
                # 回退到旧程序时绝不用旧 .bak 覆盖更新 schema 的主文件。
                found_candidate = True
                self._health_issues.append(str(e))
                LOG.error("拒绝降级读取配置: %s", path)
                break
            except (OSError, UnicodeError, json.JSONDecodeError,
                    ConfigSchemaError, TypeError, ValueError):
                found_candidate = True
                LOG.exception("读取配置失败: %s", path)
        data = self._normalize(self.DEFAULT)
        if found_candidate:
            # 配置和备份都不可用时，展示空状态但禁止写入，
            # 避免一次 UI 操作就把尚可人工恢复的文件覆盖。
            self._writable = False
            self._health_issues.append(
                "主配置与备份均不可读，已进入只读保护状态")
            return data
        if not self._writable:
            return data
        try:
            self._write_atomic(self._path, self._payload(data))
        except OSError as e:
            self._writable = False
            self._health_issues.append("无法创建配置文件: %s" % e)
        return data

    def _persist_loaded_state(self, data, raw, source_index, source_version):
        """将已恢复/迁移的配置落回主文件，不破坏良好备份。"""
        needs_migration = source_version < CURRENT_SCHEMA_VERSION
        if not source_index and not needs_migration:
            return
        try:
            if not source_index and needs_migration:
                # 迁移前的配置是上一份良好版本。
                if not self._write_atomic(
                        self._path + ".bak", self._payload(raw)):
                    raise OSError("配置备份权限验证失败")
            # 从 .bak 恢复时只修复主文件，保留已验证的备份。
            self._write_atomic(self._path, self._payload(data))
        except OSError as e:
            self._writable = False
            self._health_issues.append("配置恢复/迁移落盘失败: %s" % e)
            LOG.exception("配置恢复/迁移落盘失败")

    def snapshot(self):
        """返回配置的深拷贝（数据均为 JSON 可序列化）。"""
        with self._lock:
            return json.loads(json.dumps(self._data, ensure_ascii=False))

    def health_info(self):
        with self._lock:
            return {
                "writable": self._writable,
                "recoveredFromBackup": self._recovered_from_backup,
                "migratedFromSchema": self._migration_from,
                "issues": list(self._health_issues),
            }

    def update(self, fn):
        """在锁内执行 fn(self._data) 修改配置，随后原子落盘，返回 fn 的返回值。"""
        with self._lock:
            if not self._writable:
                raise OSError("配置处于只读保护状态，请先恢复配置或权限")
            previous = json.loads(json.dumps(self._data, ensure_ascii=False))
            try:
                result = fn(self._data)
                payload = self._payload(self._data)
                previous_payload = self._payload(previous)
                # 先保存上一份良好内容，再替换主文件。
                if not self._write_atomic(
                        self._path + ".bak", previous_payload):
                    raise OSError("配置备份权限验证失败")
                self._write_atomic(self._path, payload)
                invalidate_state_cache()
                return result
            except Exception:
                self._data = previous
                raise

    def mutate_app_if_generation(self, app_id, expected_generation, fn):
        """Apply one app mutation only when its runtime generation still matches.

        A mismatch performs no file write, backup rotation, or cache invalidation.
        Returns ``(status, result, actual_generation)`` where status is one of
        ``applied``, ``not_found``, or ``mismatch``.
        """
        with self._lock:
            if not self._writable:
                raise OSError("配置处于只读保护状态，请先恢复配置或权限")
            target = find_app(self._data, app_id)
            if target is None:
                return "not_found", None, None
            actual_generation = runtime_generation(target)
            if actual_generation != expected_generation:
                return "mismatch", None, actual_generation
            previous = json.loads(json.dumps(self._data, ensure_ascii=False))
            try:
                result = fn(self._data, target)
                payload = self._payload(self._data)
                previous_payload = self._payload(previous)
                if not self._write_atomic(
                        self._path + ".bak", previous_payload):
                    raise OSError("配置备份权限验证失败")
                self._write_atomic(self._path, payload)
                invalidate_state_cache()
                return "applied", result, runtime_generation(target)
            except Exception:
                self._data = previous
                raise

    def replace_if_hash(self, expected_hash, replacement):
        """Atomically replace the full config only if its normalized hash matches."""
        return self._replace_if_hash(
            expected_hash, replacement, normalize_replacement=True
        )

    def replace_normalized_if_hash(self, expected_hash, replacement):
        """Commit an already-normalized import payload without re-running probes."""
        return self._replace_if_hash(
            expected_hash, replacement, normalize_replacement=False
        )

    def _replace_if_hash(
            self, expected_hash, replacement, *, normalize_replacement):
        with self._lock:
            if not self._writable:
                raise OSError("配置处于只读保护状态，请先恢复配置或权限")
            if config_hash(self._data) != expected_hash:
                return False
            if normalize_replacement:
                normalized = self._normalize(
                    replacement, strict_runtime=True
                )
            else:
                if (not isinstance(replacement, dict)
                        or replacement.get("schemaVersion")
                        != CURRENT_SCHEMA_VERSION
                        or not isinstance(replacement.get("apps"), list)):
                    raise ValueError(
                        "导入配置不是已规范化的当前 schema"
                    )
                normalized = json.loads(json.dumps(
                    replacement, ensure_ascii=False
                ))
            previous = json.loads(json.dumps(self._data, ensure_ascii=False))
            try:
                if not self._write_atomic(
                        self._path + ".bak", self._payload(previous)):
                    raise OSError("配置备份权限验证失败")
                self._write_atomic(self._path, self._payload(normalized))
                self._data = normalized
                invalidate_state_cache()
                return True
            except Exception:
                self._data = previous
                raise

    def _write_atomic(self, path, payload):
        _ensure_private_dir(os.path.dirname(path) or ".")
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            PLATFORM.ensure_private_file(tmp)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = -1
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        os.replace(tmp, path)
        try:
            PLATFORM.ensure_private_file(path)
        except OSError:
            # os.replace above is the commit point. The new bytes are already
            # authoritative, so callers must keep memory aligned with disk.
            # Fail closed for later writes instead of reporting a false
            # rollback that would strand an import without its receipt.
            self._writable = False
            issue = "配置文件提交后权限验证失败，已进入只读保护"
            if issue not in self._health_issues:
                self._health_issues.append(issue)
            LOG.exception("配置文件提交后权限验证失败: %s", path)
            return False
        return True


def normalize_import_config(raw):
    """Migrate and normalize import data through the existing config contract."""
    migrated, _source_version = migrate_config(raw)
    return Config._normalize(migrated)


def acquire_instance_lock(path=INSTANCE_LOCK_PATH):
    """Acquire the native per-data-directory single-instance lock."""
    return PLATFORM.acquire_instance_lock(path)


def release_instance_lock(lock_file):
    if lock_file is None:
        return
    lock_file.release()


# ---------------------------------------------------------------- 子进程与解析

def run_cmd(args, timeout=SUBPROCESS_TIMEOUT):
    """Legacy test helper; production platform scans do not use it."""
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return r.stdout or ""
    except Exception:
        LOG.exception("命令执行失败: %r", args)
        return ""


def parse_etime(s):
    """ps 的 etime：[[dd-]hh:]mm:ss → 秒。异常返回 0。"""
    try:
        s = s.strip()
        days = 0
        if "-" in s:
            d, s = s.split("-", 1)
            days = int(d)
        parts = [int(p) for p in s.split(":")]
        if len(parts) == 2:
            hours, minutes, secs = 0, parts[0], parts[1]
        elif len(parts) == 3:
            hours, minutes, secs = parts
        else:
            return 0
        return days * 86400 + hours * 3600 + minutes * 60 + secs
    except Exception:
        return 0


def _to_float(tok, default=0.0):
    try:
        return float(tok)
    except (TypeError, ValueError):
        return default


def scan_listeners():
    """Return native listener data while preserving scan failures."""
    snapshot = PLATFORM.scan_listeners()
    _record_platform_issues(snapshot.status, snapshot.issues)
    return snapshot.listeners


def listener_open_host(listeners, port, pids=None):
    """返回浏览器访问监听端口时应使用的本地主机名。

    macOS 上有些开发服务器只绑定 IPv6 回环 ``::1``；这时
    ``127.0.0.1`` 会直接拒绝连接，而 ``localhost`` 能正确解析到它。
    对旧测试/旧调用传入的 set 快照则保持原来的 IPv4 默认值。
    """
    if not isinstance(listeners, dict):
        return "127.0.0.1"
    allowed_pids = set(pids) if pids is not None else None
    hosts = set()
    for (pid, listening_port), values in listeners.items():
        if listening_port != port or (
                allowed_pids is not None and pid not in allowed_pids):
            continue
        if isinstance(values, str):
            hosts.add(values)
        elif isinstance(values, (set, list, tuple)):
            hosts.update(value for value in values if isinstance(value, str))
    normalized = {host.strip("[]").casefold() for host in hosts if host}
    ipv4_capable = any(
        host in ("*", "0.0.0.0") or host.startswith("127.")
        for host in normalized)
    ipv6_loopback_only = bool(normalized) and not ipv4_capable and all(
        host in ("::", "::1", "localhost") for host in normalized)
    return "localhost" if ipv6_loopback_only else "127.0.0.1"


def ps_snapshot(pids=None, with_uid=True):
    snapshot = PLATFORM.process_snapshot(
        None if pids is None else set(pids), with_owner=with_uid,
    )
    _record_platform_issues(snapshot.status, snapshot.issues)
    return snapshot.processes


def lsof_cwds(pids):
    snapshot = PLATFORM.process_cwds(set(pids))
    _record_platform_issues(snapshot.status, snapshot.issues)
    return snapshot.cwds


def pid_alive(pid):
    return PLATFORM.pid_alive(int(pid))


# ---------------------------------------------------------------- 状态构建

SYSTEM_PATH_PREFIXES = ("/usr/libexec/", "/usr/sbin/", "/sbin/", "/System/", "/usr/lib/")

# 开发服务关键词：命中 name/args 时优先归为 "mine"（覆盖 .app 规则，
# 例如 ollama 守护进程在 Ollama.app 内、Docker 在 Docker.app 内）
DEV_KEYWORDS = (
    "python", "node", "ruby", "php", "nginx", "caddy", "postgres",
    "mysql", "redis", "mongo", "ollama", "docker", "deno", "bun",
    "uvicorn", "gunicorn", "hugo", "vite", "streamlit", "jupyter",
    "ngrok", "frp", "code-server", "java",
)


def classify_group(key, name, comm, args, cwd, promoted):
    if key in promoted:
        return "mine"
    text = name.lower()
    if any(k in text for k in DEV_KEYWORDS):
        return "mine"
    if ".app/Contents/" in comm or ".app/Contents/" in args:
        return "background"
    if comm.startswith(SYSTEM_PATH_PREFIXES):
        return "background"
    if "/Library/Containers/" in comm or "/Library/Containers/" in (cwd or ""):
        return "background"
    return "mine"


HOME_DIR = os.path.expanduser("~")


def project_name(cwd):
    """从工作目录推断项目名（最后一段目录名），无有效 cwd 时返回 None。"""
    if not cwd:
        return None
    cwd = cwd.rstrip("/")
    if not cwd or cwd == "/" or cwd == HOME_DIR:
        return None
    return os.path.basename(cwd) or None


# ---------------------------------------------------------------- 进程溯源
# 沿 PPID 链向上识别「是谁启动了这个服务」：AI 编程助手、编辑器、终端、
# 总控台自身或 launchd。结果只是展示用的尽力判断，不影响任何启停逻辑。

# 向上爬时要跳过的包装层（按 argv[0] 基名匹配）：壳、包管理器与任务执行器
_ORIGIN_SKIP_NAMES = {
    "zsh", "bash", "sh", "dash", "fish", "login", "su", "sudo", "env",
    "command", "xargs", "nohup", "setsid", "script", "expect", "caffeinate",
    "launchd",
    "npm", "npx", "pnpm", "yarn", "corepack", "make", "just",
    "node", "tsx", "nodemon", "deno", "bun", "bunx",
    "python", "python3", "uv", "poetry", "pip", "pipx",
    "ruby", "php", "java", "dotnet", "go", "cargo",
}

# 已知 AI 编程助手签名（在祖先 args 中做词边界匹配，按顺序取先命中者）
_ORIGIN_AGENT_PATTERNS = (
    (re.compile(r"\bcodex\b", re.I), "Codex"),
    (re.compile(r"claude-code|\bclaude\b", re.I), "Claude Code"),
    (re.compile(r"\bkimi\b", re.I), "Kimi"),
    (re.compile(r"\bgemini\b", re.I), "Gemini"),
    (re.compile(r"\baider\b", re.I), "Aider"),
    (re.compile(r"\bopencode\b", re.I), "OpenCode"),
    (re.compile(r"\bgoose\b", re.I), "Goose"),
    (re.compile(r"\bcursor-agent\b", re.I), "Cursor"),
    (re.compile(r"\bcopilot\b", re.I), "Copilot"),
    (re.compile(r"\bqwen\b", re.I), "Qwen"),
    (re.compile(r"\bqoder\b", re.I), "Qoder"),
    (re.compile(r"\bamp\b", re.I), "Amp"),
    (re.compile(r"\bcodebuddy\b", re.I), "CodeBuddy"),
)

# .app 包名 → (展示名, 图标)。未列出的包按原名 + package 图标展示
_ORIGIN_APP_ALIASES = {
    "visual studio code": ("VS Code", "code"),
    "visual studio code - insiders": ("VS Code", "code"),
    "cursor": ("Cursor", "code"),
    "trae": ("Trae", "code"),
    "windsurf": ("Windsurf", "code"),
    "zed": ("Zed", "code"),
    "sublime text": ("Sublime", "code"),
    "webstorm": ("WebStorm", "code"),
    "intellij idea": ("IDEA", "code"),
    "goland": ("GoLand", "code"),
    "pycharm": ("PyCharm", "code"),
    "nova": ("Nova", "code"),
    "xcode": ("Xcode", "code"),
    "iterm2": ("iTerm", "terminal"),
    "iterm": ("iTerm", "terminal"),
    "terminal": ("终端", "terminal"),
    "warp": ("Warp", "terminal"),
    "kitty": ("kitty", "terminal"),
    "alacritty": ("Alacritty", "terminal"),
    "wezterm": ("WezTerm", "terminal"),
    "docker": ("Docker", "package"),
    "ollama": ("Ollama", "package"),
    "obsidian": ("Obsidian", "package"),
}
_ORIGIN_BUNDLE_RE = re.compile(r"/([^/]+)\.app/Contents/MacOS/", re.I)

# 终端复用器（直接以 comm 命名，不进跳过表）
_ORIGIN_MULTIPLEXERS = {"tmux": "tmux", "screen": "screen"}


def origin_snapshot(pids=None):
    """Return {pid: (ppid, args)} for origin attribution."""
    snapshot = PLATFORM.process_parents(None if pids is None else set(pids))
    _record_platform_issues(snapshot.status, snapshot.issues)
    return {
        pid: (int(info.get("ppid", 0)), str(info.get("args") or ""))
        for pid, info in snapshot.processes.items()
    }


def attribute_origin(pid, table):
    """沿 PPID 链识别来源应用，返回 {"label", "icon"} 或 None。

    祖先 args 中带有总控台 run-token 前缀（console-run:）即判定为
    「总控台启动」——本机任一总控台实例的受管进程组都持有该标记。
    未识别的中间层先记为候选并继续上爬；AI 助手 / 编辑器 / 终端 /
    总控台 / launchd 是更优答案，都没有时才以最近的未识别进程命名。
    最多上爬 12 层，遇到环或缺失即终止。
    """
    cur, seen, candidate = pid, set(), None
    for _ in range(12):
        entry = table.get(cur)
        if not entry:
            break
        ppid, _ = entry
        if ppid in seen:
            break
        seen.add(ppid)
        parent_args = (table.get(ppid) or (0, ""))[1] or ""
        if ppid <= 1:
            return candidate or {"label": "系统", "icon": "server"}
        if RUN_TOKEN_ARG_PREFIX in parent_args:
            return {"label": "总控台", "icon": "rocket"}
        hay = parent_args.casefold()
        for pattern, label in _ORIGIN_AGENT_PATTERNS:
            if pattern.search(hay):
                return {"label": label, "icon": "bot"}
        bundle = _ORIGIN_BUNDLE_RE.search(parent_args)
        if bundle:
            app_name = bundle.group(1)
            label, icon = _ORIGIN_APP_ALIASES.get(
                app_name.casefold(), (app_name, "package"))
            return {"label": label, "icon": icon}
        base = os.path.basename(
            parent_args.split()[0]).lstrip("-") if parent_args.split() else ""
        if base in _ORIGIN_MULTIPLEXERS:
            return {"label": _ORIGIN_MULTIPLEXERS[base], "icon": "terminal"}
        if base and base not in _ORIGIN_SKIP_NAMES and candidate is None:
            candidate = {"label": base, "icon": "package"}
        cur = ppid
    return candidate


def build_services(cfg, groups=None):
    """返回 (services, listeners)。只含当前用户进程，排除控制台自身。"""
    listeners = scan_listeners()
    snap = ps_snapshot({pid for pid, _ in listeners}, with_uid=True)
    mine_pids = [pid for pid, _ in listeners
                 if pid != SELF_PID and pid in snap
                 and process_owned_by_current(snap[pid])]
    cwds = lsof_cwds(mine_pids)
    origin_table = origin_snapshot(mine_pids) if mine_pids else {}

    hidden = set(cfg.get("hidden") or [])
    pinned = set(cfg.get("pinned") or [])
    promoted = set(cfg.get("promoted") or [])
    # “配置了相同端口”不代表“拥有当前监听进程”。只有 run token / 进程组
    # 校验通过（或严格命中旧版身份）的进程才关联启动台卡片。
    app_by_pid = listener_app_owners(
        cfg.get("apps") or [], listeners, snap, cwds, groups)

    services = []
    for pid, port in sorted(listeners, key=lambda x: (x[1], x[0])):
        if pid == SELF_PID:
            continue
        info = snap.get(pid)
        if not process_owned_by_current(info):
            continue
        comm = info.get("comm") or ""
        args = info.get("args") or comm
        name = os.path.basename(comm) if comm else "?"
        key = "%s:%d" % (name, port)
        cwd = cwds.get(pid)
        app = app_by_pid.get(pid)
        services.append({
            "key": key,
            # key 保持 name:port 以兼容既有隐藏/置顶配置；instanceKey 用于
            # 区分同名同端口在不同时间出现的新进程，以及极少数共享监听。
            "instanceKey": "%d:%d" % (pid, port),
            "pid": pid, "name": name, "port": port,
            "openHost": listener_open_host(listeners, port, {pid}),
            "cwd": cwd, "project": project_name(cwd), "cmd": args,
            "cpu": info["cpu"], "mem": info["mem"], "uptimeSec": info["etime"],
            "group": classify_group(key, name, comm, args, cwd, promoted),
            "pinned": key in pinned, "hidden": key in hidden,
            "promoted": key in promoted,
            "appId": app["id"] if app else None,
            "appName": app["name"] if app else None,
            # 来源溯源（尽力判断）：哪个应用/AI 助手启动了这个进程
            "origin": attribute_origin(pid, origin_table),
        })
    return services, listeners


def build_watched(keywords):
    """关注进程：每个 PID 只返回一次，并合并它命中的全部关键字。"""
    normalized = []
    seen_keywords = set()
    for keyword in (keywords or []):
        if not isinstance(keyword, str) or not keyword.strip():
            continue
        keyword = keyword.strip()
        lowered = keyword.casefold()
        if lowered in seen_keywords:
            continue
        seen_keywords.add(lowered)
        normalized.append((keyword, lowered))
    if not normalized:
        return []
    snapshot = PLATFORM.processes_matching_keywords(
        [keyword for keyword, _ in normalized]
    )
    _record_platform_issues(snapshot.status, snapshot.issues)
    snap = snapshot.processes
    result = []
    for pid, info in sorted(snap.items()):
        if pid == SELF_PID or not process_owned_by_current(info):
            continue
        name = os.path.basename(info.get("comm") or "") or "?"
        if name in ("ps", "lsof"):
            continue
        args = info.get("args") or ""
        args_lower = args.casefold()
        matched = [keyword for keyword, lowered in normalized
                   if lowered in args_lower]
        if not matched:
            continue
        result.append({"pid": pid, "name": name, "cmd": args,
                       "cpu": info["cpu"], "mem": info["mem"],
                       "uptimeSec": info["etime"],
                       # keyword 保留给旧前端，keywords 提供无损结构化数据。
                       "keyword": "、".join(matched), "keywords": matched})
    return result


def pgid_members_map():
    """Return {group_id: [pid, ...]} from the native adapter."""
    snapshot = PLATFORM.process_groups()
    _record_platform_issues(snapshot.status, snapshot.issues)
    result = {}
    for group_id, info in snapshot.processes.items():
        members = info.get("members")
        if isinstance(members, list):
            result[group_id] = [int(pid) for pid in members]
    return result


def _managed_candidates(app, groups):
    token = app.get("runToken")
    pgid = app.get("lastPgid") or app.get("lastPid")
    if not isinstance(token, str) or not token or not isinstance(pgid, int) or pgid <= 0:
        return set()
    return set(groups.get(pgid, []))


def managed_process_index(apps, groups=None):
    """批量校验应用的受控进程，返回 (appId -> [pid], ps, groups)。

    必须同时满足：属于记录的进程组、属于当前用户、argv 中带本次启动的
    随机 token。即使 PID/PGID 被系统复用，也不会把无关进程当成应用或停止它。
    """
    if groups is None:
        needs_groups = any(
            app.get("runToken")
            and isinstance(app.get("lastPgid") or app.get("lastPid"), int)
            for app in apps)
        groups = pgid_members_map() if needs_groups else {}
    candidates = {}
    all_pids = set()
    for app in apps:
        pids = _managed_candidates(app, groups)
        candidates[app.get("id")] = pids
        all_pids.update(pids)
    snap = ps_snapshot(all_pids, with_uid=True) if all_pids else {}
    result = {}
    for app in apps:
        token = app.get("runToken")
        marker = RUN_TOKEN_ARG_PREFIX + token if token else None
        current_user = sorted(
            pid for pid in candidates.get(app.get("id"), set())
            if process_owned_by_current(snap.get(pid)))
        controller_found = bool(marker and any(
            marker in snap.get(pid, {}).get("args", "") for pid in current_user))
        # 随机标记在进程组的常驻外层 shell 上；校验后整组均为受控后代。
        result[app.get("id")] = current_user if controller_found else []
    return result, snap, groups


def managed_pids(app, groups=None):
    index, _, _ = managed_process_index([app], groups)
    return index.get(app.get("id"), [])


def legacy_managed_pid(app, listeners=None, snap=None, cwds=None):
    """识别升级前身份或用户明确认领的外部监听进程。

    普通旧数据仍只接受原 lastPid。明确 ``attached`` 的卡片允许监听子进程
    换 PID，但仍必须在配置端口上按当前 UID + 真实 cwd 唯一命中；因此
    Next/Vite 等重建子进程后不会丢失关联，也不会只凭端口误认其他项目。
    """
    if app.get("runToken"):
        return None
    recorded_pid = app.get("lastPid")
    port = app.get("port")
    expected_cwd = app.get("cwd")
    if (not isinstance(port, int) or port <= 0
            or not isinstance(expected_cwd, str) or not expected_cwd):
        return None
    if listeners is None:
        listeners = scan_listeners()
    port_pids = {pid for pid, listening_port in listeners
                 if listening_port == port}
    if not app.get("attached"):
        if not isinstance(recorded_pid, int) or recorded_pid <= 0:
            return None
        port_pids.intersection_update({recorded_pid})
    if not port_pids:
        return None
    if snap is None:
        snap = ps_snapshot(port_pids, with_uid=True)
    if cwds is None:
        cwds = lsof_cwds(port_pids)
    matches = []
    for pid in sorted(port_pids):
        if not process_owned_by_current(snap.get(pid)):
            continue
        actual_cwd = cwds.get(pid)
        if not actual_cwd:
            continue
        try:
            same_cwd = (
                os.path.realpath(actual_cwd) == os.path.realpath(expected_cwd))
        except OSError:
            same_cwd = False
        if same_cwd:
            matches.append(pid)
    if recorded_pid in matches:
        return recorded_pid
    return matches[0] if app.get("attached") and len(matches) == 1 else None


def listener_app_owners(
        apps, listeners, snap, cwds, groups=None, managed_override=None):
    """返回真实受管监听进程的 ``pid -> app`` 映射。

    端口只是配置与网络资源，不能作为进程所有权证明。映射沿用应用状态的
    run token / PGID / UID 校验，并为升级前的进程保留严格 legacy 识别。
    如果异常配置让同一 PID 同时命中多张卡片，则不做关联，避免误导 UI。
    """
    managed = managed_override
    if managed is None:
        managed, _, _ = managed_process_index(apps, groups)
    candidates = {}
    for app in apps:
        live = managed.get(app.get("id"), [])
        if not live and managed_override is None:
            legacy_pid = legacy_managed_pid(app, listeners, snap, cwds)
            live = [legacy_pid] if legacy_pid else []
        for pid in live:
            candidates.setdefault(pid, []).append(app)
    return {
        pid: owners[0]
        for pid, owners in candidates.items()
        if len(owners) == 1
    }


def scheduled_task_path(app):
    value = app.get("scheduledTaskPath") if isinstance(app, dict) else None
    return value if isinstance(value, str) and value else None


def elevated_favorite(app):
    return bool(
        isinstance(app, dict)
        and app.get("elevated") is True
        and (app.get("kind") or "service") == "program"
    )


def elevated_task(app):
    return bool(
        isinstance(app, dict)
        and app.get("elevated") is True
        and (app.get("kind") or "service") == "task"
    )


def keep_alive_supported(app):
    """保活只适用于长期运行的服务与程序；一次性任务不得循环执行。"""
    if not isinstance(app, dict):
        return False
    kind = app.get("kind") or "service"
    if kind not in ("service", "program"):
        return False
    if scheduled_task_path(app) and kind != "service":
        return False
    return True


def keep_alive_requires_elevation(app):
    return bool(
        PLATFORM.name == "windows"
        and (
            scheduled_task_path(app)
            or docker_resource(app)
            or elevated_favorite(app)
            or app.get("attached") is True
        )
    )


def keep_alive_grant_required(app):
    return bool(
        PLATFORM.name == "windows"
        and (scheduled_task_path(app) or elevated_favorite(app))
    )


def keep_alive_grant_request(app):
    if elevated_favorite(app):
        spec = normalize_command_spec(app.get("commandSpec"))
        return {
            "appId": app["id"],
            "kind": "elevatedProgram",
            "request": {
                "executable": spec.get("executable"),
                "args": list(spec.get("args") or []),
                "cwd": app.get("cwd") or ntpath.dirname(
                    str(spec.get("executable") or "")
                ),
            },
        }
    path = scheduled_task_path(app)
    if path:
        return {
            "appId": app["id"],
            "kind": "scheduledService",
            "path": path,
        }
    return None


def keep_alive_config_digest(app):
    request = keep_alive_grant_request(app)
    if request is None:
        return None
    payload = json.dumps(
        request, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def keep_alive_grant_matches_app(app):
    grant = app.get("keepAliveGrant")
    expected_kind = (
        "elevatedProgram" if elevated_favorite(app)
        else "scheduledService" if scheduled_task_path(app) else None
    )
    return bool(
        isinstance(grant, dict)
        and grant.get("kind") == expected_kind
        and grant.get("configDigest") == keep_alive_config_digest(app)
    )


def keep_alive_persistent_authorized(app):
    if app.get("keepAlive") is not True:
        return False
    if keep_alive_grant_required(app):
        return keep_alive_grant_matches_app(app)
    return keep_alive_requires_elevation(app)


def keep_alive_row_fields(app):
    requires_elevation = keep_alive_requires_elevation(app)
    enabled = app.get("keepAlive") is True
    persistent_authorization = keep_alive_persistent_authorized(app)
    return {
        "keepAlive": enabled,
        "desiredRunning": enabled and app.get("desiredRunning") is True,
        "keepAliveAvailable": keep_alive_supported(app),
        "keepAliveRequiresElevation": requires_elevation,
        "keepAlivePersistentAuthorization": persistent_authorization,
        # Sensitive rows are projected per authenticated browser session later.
        "keepAliveAuthorized": not requires_elevation,
    }


def keep_alive_resource_key(app):
    task_path = scheduled_task_path(app)
    if task_path:
        return ("scheduled", task_path.casefold())
    resource = docker_resource(app)
    if resource:
        return ("docker", json.dumps(
            resource, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ))
    if elevated_favorite(app):
        try:
            spec = normalize_command_spec(app.get("commandSpec"))
        except CommandSpecError:
            spec = app.get("commandSpec")
        return (
            "elevated",
            json.dumps(spec, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            ntpath.normcase(ntpath.normpath(app.get("cwd") or "")),
        )
    if app.get("attached") is True:
        try:
            cwd = os.path.normcase(os.path.realpath(app.get("cwd") or ""))
        except OSError:
            cwd = str(app.get("cwd") or "")
        return ("attached", app.get("port"), cwd)
    return ("app", app.get("id"))


def set_keep_alive_desired(cfg, app_id, desired, expected_generation=None):
    """Persist user run intent before lifecycle control crosses the OS boundary."""
    current = find_app(cfg.snapshot(), app_id)
    if current is None or current.get("keepAlive") is not True:
        return "applied", False

    def op(_data, target):
        target["desiredRunning"] = bool(desired)
        return True

    if PLATFORM.name == "windows":
        status, changed, _ = cfg.mutate_app_if_generation(
            app_id, expected_generation, op
        )
        if status == "applied" and changed and not desired:
            # Rotate the already-paused main config into .bak as well; a later
            # recovery must not resurrect an armed desired state.
            cfg.update(lambda _data: False)
        return status, bool(changed)
    changed = cfg.update(lambda data: op(data, find_app(data, app_id)))
    if changed and not desired:
        cfg.update(lambda _data: False)
    return "applied", bool(changed)


def _program_args_match(expected_args, command_line):
    args = expected_args if isinstance(expected_args, list) else []
    if not args:
        return True
    if not isinstance(command_line, str) or not command_line.strip():
        return False
    expected_tail = subprocess.list2cmdline(args).casefold()
    actual = command_line.strip().casefold()
    return actual.endswith(" " + expected_tail)


def _program_executable_matches(
        configured, candidate, expected_args=None, command_line=None):
    if not isinstance(configured, str) or not isinstance(candidate, str):
        return False
    configured = ntpath.normcase(ntpath.normpath(configured))
    candidate = ntpath.normcase(ntpath.normpath(candidate))
    if not ntpath.isabs(configured) or not ntpath.isabs(candidate):
        return False
    if ntpath.basename(candidate) != ntpath.basename(configured):
        return False
    parent = ntpath.dirname(configured).rstrip("\\")
    if candidate != configured and not candidate.startswith(parent + "\\"):
        return False
    return _program_args_match(expected_args, command_line)


def _restricted_program_process_matches(executable, expected_args, info):
    if info.get("restricted") is not True or not isinstance(
            info.get("comm"), str):
        return False
    candidate = info["comm"]
    if ntpath.isabs(candidate):
        return _program_executable_matches(
            executable, candidate, expected_args, info.get("args")
        )
    return bool(
        ntpath.basename(candidate).casefold()
        == ntpath.basename(executable).casefold()
        and _program_args_match(expected_args, info.get("args"))
    )


def build_program_process_snapshot(cfg, broker_status=None):
    executables = []
    for app in cfg.get("apps") or []:
        if not elevated_favorite(app):
            continue
        try:
            spec = normalize_command_spec(app.get("commandSpec"))
        except CommandSpecError:
            continue
        executable = spec.get("executable")
        if (spec.get("mode") == "direct" and isinstance(executable, str)
                and ntpath.isabs(executable)
                and executable.casefold().endswith(".exe")):
            executables.append(ntpath.basename(executable))
    names = sorted(set(executables), key=str.casefold)
    if PLATFORM.name != "windows" or not names:
        return {}
    snapshot = PLATFORM.processes_matching_keywords(names)
    _record_platform_issues(snapshot.status, snapshot.issues)
    processes = dict(snapshot.processes)
    if (bool(getattr(broker_status, "unlocked", False))
            and bool(getattr(broker_status, "stop_supported", False))):
        for app in cfg.get("apps") or []:
            if not elevated_favorite(app):
                continue
            try:
                spec = normalize_command_spec(app.get("commandSpec"))
            except CommandSpecError:
                continue
            observed = PLATFORM.observe_elevated(spec, app.get("cwd"))
            _record_platform_issues(observed.status, observed.issues)
            if observed.status is not ScanStatus.FAILED:
                processes.update(observed.processes)
    return processes


def build_scheduled_task_index(cfg):
    paths = {
        value for value in (
            scheduled_task_path(app) for app in (cfg.get("apps") or [])
        ) if value
    }
    if not paths:
        return {}
    snapshot = PLATFORM.scheduled_tasks(paths)
    _record_platform_issues(snapshot.status, snapshot.issues)
    return snapshot.tasks


def scheduled_task_health(task):
    if not isinstance(task, dict) or task.get("state") == "missing":
        return {
            "status": "error",
            "blocking": True,
            "issues": [{
                "kind": "scheduled-task-missing",
                "title": "Windows 计划任务不存在",
                "detail": "请重新选择一个已注册的 Windows 计划任务。",
                "action": "select-scheduled-task",
            }],
        }
    if task.get("state") == "unknown":
        return {
            "status": "unknown",
            "blocking": True,
            "issues": [{
                "kind": "scheduled-task-unavailable",
                "title": "Windows 计划任务暂不可读取",
                "detail": "当前权限无法确认该任务的状态，其他计划任务仍可正常显示。",
            }],
        }
    if not task.get("enabled") or task.get("state") == "disabled":
        return {
            "status": "error",
            "blocking": True,
            "issues": [{
                "kind": "scheduled-task-disabled",
                "title": "Windows 计划任务已禁用",
                "detail": "请先在任务计划程序中启用该任务。",
                "action": "select-scheduled-task",
            }],
        }
    return {"status": "ok", "blocking": False, "issues": []}


def scheduled_task_last_exit(app, task):
    if ((app.get("kind") or "service") != "task"
            or not isinstance(task, dict)
            or task.get("state") in ("running", "queued", "missing")):
        return public_last_exit(app)
    result = task.get("lastResult")
    ended_at = task.get("lastRunAt")
    if not isinstance(result, int) or not isinstance(ended_at, int):
        return public_last_exit(app)
    return {
        "code": result,
        "at": ended_at,
        "status": "succeeded" if result == 0 else "failed",
    }


def scheduled_task_app_row(app, task):
    task = task if isinstance(task, dict) else {
        "path": scheduled_task_path(app),
        "name": scheduled_task_path(app),
        "state": "missing",
        "enabled": False,
        "enginePids": [],
    }
    state = task.get("state") or "unknown"
    running = state == "running"
    lifecycle_status = (
        "running" if running else "starting" if state == "queued"
        else "unknown" if state in ("missing", "unknown") else "stopped"
    )
    engine_pids = [
        int(pid) for pid in (task.get("enginePids") or [])
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
    ]
    started_at = task.get("lastRunAt")
    uptime = (
        max(0, int(time.time()) - started_at)
        if running and isinstance(started_at, int) else None
    )
    health = scheduled_task_health(task)
    can_run = (
        state == "ready" and bool(task.get("enabled"))
        and bool(getattr(PLATFORM.capabilities, "run_scheduled_tasks", False))
    )
    can_stop = (
        state == "running"
        and bool(getattr(PLATFORM.capabilities, "stop_scheduled_tasks", False))
    )
    issue = None
    if health["blocking"]:
        first = health["issues"][0]
        issue = {"code": first["kind"], "message": first["detail"]}
    command_spec = app.get("commandSpec")
    if command_spec is None:
        command_spec = legacy_command_spec(app.get("command") or "")
    return {
        **keep_alive_row_fields(app),
        "id": app["id"],
        "name": app["name"],
        "command": app["command"],
        "commandSpec": command_spec,
        "runtimeIdentity": None,
        "runtimeSource": "windowsTaskScheduler",
        "scheduledTask": task,
        "scheduledTaskPath": scheduled_task_path(app),
        "scheduledTaskControlAvailable": (
            state not in ("missing", "unknown")
            and bool(getattr(
                PLATFORM.capabilities, "toggle_scheduled_tasks", False
            ))
        ),
        "dockerResource": None,
        "docker": None,
        "lifecycleStatus": lifecycle_status,
        "controlAvailable": can_run or can_stop,
        "deleteAvailable": True,
        "runtimeIssue": issue,
        "importStatus": "ready",
        "platformCompatibility": {"status": "ready", "reasons": []},
        "cwd": None,
        "port": None,
        "emoji": app.get("emoji"),
        "glyph": app.get("glyph"),
        "icon": app.get("icon"),
        "favicon": app.get("favicon"),
        "running": running,
        "pid": engine_pids[0] if engine_pids else None,
        "uptimeSec": uptime,
        "kind": app.get("kind") or "service",
        "attached": False,
        "lastExit": scheduled_task_last_exit(app, task),
        "health": health,
        "ports": [],
        "openHosts": {},
        "listening": False,
        "portOccupied": False,
        "portOccupiedPid": None,
        "portOwner": None,
        "portConflict": False,
        "portConflictApps": [],
        "legacyManaged": False,
    }


def elevation_broker_public(status):
    if status is None:
        return {
            "installed": False, "verified": False,
            "running": False, "unlocked": False, "stopSupported": False,
            "scheduledTaskSupported": False,
            "issue": None,
        }
    issue = getattr(status, "issue", None)
    return {
        "installed": bool(getattr(status, "installed", False)),
        "verified": bool(getattr(status, "verified", False)),
        "running": bool(getattr(status, "running", False)),
        "unlocked": bool(getattr(status, "unlocked", False)),
        "stopSupported": bool(getattr(status, "stop_supported", False)),
        "scheduledTaskSupported": bool(
            getattr(status, "scheduled_supported", False)
        ),
        "issue": ({
            "code": issue.code, "message": issue.message,
        } if issue is not None else None),
    }


def elevated_task_last_exit(app, result):
    if (not isinstance(result, ElevatedTaskResult) or not result.ok
            or not result.found or result.running
            or result.completed_at is None):
        return app.get("lastExit")
    started_at = result.started_at
    duration = (
        round(max(0.0, (result.completed_at - started_at) / 1000.0), 3)
        if isinstance(started_at, int) else None
    )
    manually_stopped = result.manually_stopped
    code = None if manually_stopped else result.exit_code
    return {
        "status": "stopped" if manually_stopped else classify_task_exit(code),
        "code": code,
        "at": int(result.completed_at / 1000),
        "startedAt": started_at,
        "durationSec": duration,
    }


def elevated_task_app_row(app, broker_status, result=None):
    broker = elevation_broker_public(broker_status)
    query_ok = isinstance(result, ElevatedTaskResult) and result.ok
    running = bool(query_ok and result.found and result.running)
    unlocked = bool(
        broker["installed"] and broker["verified"] and broker["unlocked"]
    )
    query_failed = bool(result is not None and not query_ok)
    if query_failed:
        detail = result.error or "管理员批处理状态查询失败。"
        issue_code = result.code or "BROKER_ELEVATED_TASK_QUERY_FAILED"
    elif not broker["installed"]:
        detail = "管理员启动代理尚未安装。"
        issue_code = "BROKER_NOT_INSTALLED"
    elif not broker["verified"]:
        detail = "管理员启动代理定义无法验证，需要重新安装。"
        issue_code = "BROKER_TASK_MISMATCH"
    else:
        detail = "本次 Local Ops 会话尚未输入解锁密码。"
        issue_code = "BROKER_SESSION_LOCKED"
    blocking = query_failed or (not running and not unlocked)
    issues = [] if not blocking else [{
        "kind": "elevation-broker-locked",
        "severity": "error",
        "title": "管理员批处理不可用",
        "detail": detail,
        "fix": "请完成代理安装或输入本次会话的解锁密码。",
        "action": (
            "install-elevation-broker"
            if not broker["installed"] or not broker["verified"]
            else "unlock-elevation-broker"
        ),
    }]
    uptime = None
    if running and isinstance(result.started_at, int):
        uptime = max(0, int(time.time() - result.started_at / 1000.0))
    return {
        **keep_alive_row_fields(app),
        "id": app["id"], "name": app["name"], "command": app["command"],
        "commandSpec": app.get("commandSpec"),
        "runtimeIdentity": None,
        "runtimeSource": "windowsElevationBrokerTask",
        "scheduledTask": None,
        "scheduledTaskPath": None,
        "scheduledTaskControlAvailable": False,
        "dockerResource": None,
        "docker": None,
        "elevated": True,
        "elevationBroker": broker,
        "lifecycleStatus": (
            "unknown" if query_failed else "running" if running else "stopped"
        ),
        "controlAvailable": bool(unlocked and not query_failed),
        "deleteAvailable": not query_failed,
        "runtimeIssue": (
            {"code": issue_code, "message": detail} if blocking else None
        ),
        "importStatus": "ready",
        "platformCompatibility": {"status": "ready", "reasons": []},
        "cwd": app.get("cwd"), "port": None,
        "emoji": app.get("emoji"), "glyph": app.get("glyph"),
        "icon": app.get("icon"), "favicon": app.get("favicon"),
        "running": running,
        "pid": result.process_id if running else None,
        "uptimeSec": uptime,
        "kind": "task", "attached": False,
        "lastExit": elevated_task_last_exit(app, result),
        "health": {
            "status": "error" if blocking else "ok",
            "blocking": blocking,
            "issues": issues,
        },
        "ports": [], "openHosts": {}, "listening": False,
        "portOccupied": False, "portOccupiedPid": None, "portOwner": None,
        "portConflict": False, "portConflictApps": [], "legacyManaged": False,
    }


def elevated_program_app_row(app, broker_status, program_processes=None):
    broker = elevation_broker_public(broker_status)
    executable = None
    try:
        command_spec = normalize_command_spec(app.get("commandSpec"))
        executable = command_spec.get("executable")
        spec_valid = (
            command_spec.get("mode") == "direct"
            and isinstance(executable, str)
            and ntpath.isabs(executable)
            and executable.casefold().endswith(".exe")
        )
    except CommandSpecError:
        spec_valid = False
    observed = []
    restricted = []
    if spec_valid:
        for pid, info in (program_processes or {}).items():
            if (process_owned_by_current(info)
                    and _program_executable_matches(
                        executable, info.get("comm"), command_spec.get("args"),
                        info.get("args"),
                    )):
                observed.append((int(pid), info))
            elif _restricted_program_process_matches(
                    executable, command_spec.get("args"), info):
                restricted.append((int(pid), info))
    if not observed and len(restricted) == 1:
        observed = restricted
    observed.sort(key=lambda item: item[0])
    representative = max(
        observed,
        key=lambda item: (int(item[1].get("etime") or 0), -item[0]),
        default=None,
    )
    running = bool(observed)
    observed_processes = [
        {"pid": pid, "createTime": float(info["createTime"])}
        for pid, info in observed
        if (info.get("restricted") is not True
            and process_owned_by_current(info)
            and isinstance(info.get("createTime"), (int, float))
            and not isinstance(info.get("createTime"), bool)
            and float(info["createTime"]) > 0)
    ]
    program_identity_verified = (
        running and len(observed_processes) == len(observed)
    )
    program_stop_available = (
        program_identity_verified and broker["stopSupported"]
    )
    unlocked = (
        spec_valid and broker["installed"]
        and broker["verified"] and broker["unlocked"]
    )
    if not spec_valid:
        detail = "收藏的程序不是有效的 absolute EXE。"
        action = "edit-command"
    elif not broker["installed"]:
        detail = "管理员启动代理尚未安装。"
        action = "install-elevation-broker"
    elif not broker["verified"]:
        detail = "管理员启动代理定义无法验证，需要重新安装。"
        action = "install-elevation-broker"
    else:
        detail = "本次 Local Ops 会话尚未输入解锁密码。"
        action = "unlock-elevation-broker"
    issues = [] if unlocked else [{
        "kind": "elevation-broker-locked",
        "severity": "error",
        "title": "管理员启动未解锁",
        "detail": detail,
        "fix": "请完成代理安装或输入本次会话的解锁密码。",
        "action": action,
    }]
    return {
        **keep_alive_row_fields(app),
        "id": app["id"], "name": app["name"], "command": app["command"],
        "commandSpec": app.get("commandSpec"),
        "runtimeIdentity": None,
        "runtimeSource": "windowsElevationBroker",
        "scheduledTask": None,
        "scheduledTaskPath": None,
        "scheduledTaskControlAvailable": False,
        "dockerResource": None, "docker": None,
        "elevated": True,
        "elevationBroker": broker,
        "lifecycleStatus": "running" if running else "stopped",
        "controlAvailable": bool(
            program_stop_available if running else
            unlocked and getattr(PLATFORM.capabilities, "launch_elevated", False)
        ),
        "deleteAvailable": True,
        "runtimeIssue": (
            None if program_stop_available or (not running and unlocked)
            else {
                "code": "PROGRAM_STOP_UNVERIFIED",
                "message": "程序正在运行，但进程身份受保护，无法安全停止。",
            } if running else {
                "code": "ELEVATION_BROKER_LOCKED", "message": detail,
            }
        ),
        "importStatus": "ready",
        "platformCompatibility": {"status": "ready", "reasons": []},
        "cwd": app.get("cwd"), "port": None,
        "emoji": app.get("emoji"), "glyph": app.get("glyph"),
        "icon": app.get("icon"), "favicon": app.get("favicon"),
        "running": running,
        "pid": representative[0] if representative else None,
        "uptimeSec": (
            int(representative[1]["etime"])
            if representative and isinstance(
                representative[1].get("etime"), (int, float)
            ) else None
        ),
        "observedPids": [pid for pid, _ in observed],
        "observedProcesses": observed_processes,
        "observedOnly": bool(running and not program_stop_available),
        "programIdentityVerified": program_identity_verified,
        "programStopAvailable": program_stop_available,
        "observedRestricted": any(
            info.get("restricted") is True for _, info in observed
        ),
        "kind": "program", "attached": False,
        "lastExit": app.get("lastExit"),
        "health": {
            "status": "ok" if unlocked else "error",
            "blocking": not unlocked, "issues": issues,
        },
        "ports": [], "openHosts": {}, "listening": False,
        "portOccupied": False, "portOccupiedPid": None, "portOwner": None,
        "portConflict": False, "portConflictApps": [], "legacyManaged": False,
    }


def normalize_expected_processes(value):
    if not isinstance(value, list) or not value:
        return None
    normalized = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"pid", "createTime"}:
            return None
        pid = item.get("pid")
        created = item.get("createTime")
        if (not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0
                or not isinstance(created, (int, float))
                or isinstance(created, bool) or float(created) <= 0):
            return None
        normalized.append({"pid": pid, "createTime": float(created)})
    normalized.sort(key=lambda item: item["pid"])
    return normalized


def stop_elevated_program_app(platform, app, expected_processes, *, force=False):
    if force:
        return {
            "ok": False,
            "error": "管理员程序停止不支持强制模式",
            "code": "PROGRAM_FORCE_UNSUPPORTED",
        }
    broker_status = platform.elevation_broker_status()
    process_snapshot = build_program_process_snapshot(
        {"apps": [app]}, broker_status
    )
    current = elevated_program_app_row(
        app,
        None,
        process_snapshot,
    )
    observed = current.get("observedProcesses") or []
    if observed != expected_processes:
        return {
            "ok": False,
            "error": "程序进程已变化，请刷新状态后重试",
            "code": "PROGRAM_OBSERVATION_MISMATCH",
        }
    if not current.get("programIdentityVerified"):
        return {
            "ok": False,
            "error": "程序进程身份无法验证，不能安全停止",
            "code": "PROGRAM_STOP_UNVERIFIED",
        }
    try:
        executable = normalize_command_spec(app.get("commandSpec"))["executable"]
    except (CommandSpecError, KeyError, TypeError):
        return {
            "ok": False,
            "error": "收藏的程序不是有效的 absolute EXE",
            "code": "PROGRAM_STOP_UNVERIFIED",
        }
    identities = []
    for process in observed:
        actual_executable = (process_snapshot.get(process["pid"]) or {}).get(
            "comm"
        )
        identities.append({
            "pid": process["pid"],
            "createTime": process["createTime"],
            "executable": actual_executable or executable,
        })
    result = platform.stop_elevated(executable, identities)
    if not result.ok:
        payload = {
            "ok": False,
            "error": result.error or "程序停止失败",
            "code": result.code or "BROKER_STOP_FAILED",
        }
        record_app_action(app, "管理员程序停止", payload)
        return payload
    payload = {"ok": True, "status": "stopped"}
    record_app_action(
        app, "管理员程序强制停止" if force else "管理员程序停止", payload
    )
    return payload


def docker_resource(app):
    value = app.get("dockerResource") if isinstance(app, dict) else None
    return value if isinstance(value, dict) else None


def build_docker_snapshot(cfg):
    if not any(docker_resource(app) for app in (cfg.get("apps") or [])):
        return None
    return DOCKER.discover()


def docker_app_row(app, snapshot):
    resource = docker_resource(app)
    containers = {
        row.get("id"): row for row in (snapshot.containers if snapshot else ())
        if isinstance(row, dict) and row.get("id")
    }
    projects = {
        row.get("projectName"): row for row in (snapshot.projects if snapshot else ())
        if isinstance(row, dict) and row.get("projectName")
    }
    kind = resource.get("kind") if resource else None
    observed = (
        containers.get(resource.get("containerId"))
        if kind == "container" else projects.get(resource.get("projectName"))
    ) if resource else None
    snapshot_ok = snapshot is not None and snapshot.status is not ScanStatus.FAILED
    issues = []
    if not snapshot_ok:
        detail = (
            snapshot.issues[0].message
            if snapshot is not None and snapshot.issues else "Docker 状态不可用"
        )
        issues.append({
            "kind": "docker-unavailable", "severity": "error",
            "title": "Docker 不可用", "detail": detail,
            "fix": "请启动 Docker Desktop 并确认 docker CLI 可以连接本机 daemon。",
            "action": None,
        })
    elif kind == "container" and observed is None:
        issues.append({
            "kind": "docker-container-missing", "severity": "error",
            "title": "容器不存在", "detail": "收藏的 exact container ID 已不存在。",
            "fix": "请删除该收藏并重新选择当前容器。", "action": None,
        })
    elif kind == "compose":
        missing = [
            path for path in (resource.get("configFiles") or [])
            if not os.path.isfile(path)
        ]
        if not os.path.isdir(resource.get("workingDir") or "") or missing:
            issues.append({
                "kind": "docker-compose-config-missing", "severity": "error",
                "title": "Compose 配置不存在",
                "detail": "工作目录或 Compose 配置文件已移动。",
                "fix": "请重新收藏当前 Compose 项目。", "action": None,
            })
    running = bool(observed and observed.get("running"))
    blocking = bool(issues)
    control = (
        not blocking
        and bool(getattr(PLATFORM.capabilities, "control_docker", False))
    )
    runtime_source = (
        "dockerContainer" if kind == "container" else "dockerCompose"
    )
    issue = None
    if issues:
        issue = {"code": issues[0]["kind"], "message": issues[0]["detail"]}
    return {
        **keep_alive_row_fields(app),
        "id": app["id"], "name": app["name"], "command": app["command"],
        "commandSpec": app.get("commandSpec"),
        "runtimeIdentity": None,
        "runtimeSource": runtime_source,
        "scheduledTask": None,
        "scheduledTaskPath": None,
        "scheduledTaskControlAvailable": False,
        "dockerResource": resource,
        "docker": observed,
        "lifecycleStatus": "unknown" if not snapshot_ok else (
            "running" if running else "stopped"
        ),
        "controlAvailable": control,
        "deleteAvailable": True,
        "runtimeIssue": issue,
        "importStatus": "ready",
        "platformCompatibility": {"status": "ready", "reasons": []},
        "cwd": resource.get("workingDir") if kind == "compose" else None,
        "port": None,
        "emoji": app.get("emoji"), "glyph": app.get("glyph"),
        "icon": app.get("icon"), "favicon": app.get("favicon"),
        "running": running, "pid": None, "uptimeSec": None,
        "kind": "service", "attached": False,
        "lastExit": app.get("lastExit"),
        "health": {
            "status": "error" if blocking else "ok",
            "blocking": blocking, "issues": issues,
        },
        "ports": [], "openHosts": {}, "listening": False,
        "portOccupied": False, "portOccupiedPid": None, "portOwner": None,
        "portConflict": False, "portConflictApps": [], "legacyManaged": False,
    }


def build_apps(
        cfg, listeners, groups=None, scheduled_tasks=None, docker_snapshot=None,
        broker_status=None, program_processes=None,
        elevated_task_statuses=None):
    """token 校验通过或严格命中旧版身份的进程才算 running。

    多张卡片可共享配置端口；只有当前真实监听者不属于本卡片时才返回
    “端口被其他进程占用”，不再把任意监听者误当成应用本身。
    """
    port_map = {}
    for pid, port in listeners:
        port_map.setdefault(port, []).append(pid)
    apps_cfg = cfg.get("apps") or []
    scheduled_tasks = scheduled_tasks or {}
    elevated_task_statuses = elevated_task_statuses or {}
    runtime_states = (
        {app["id"]: inspect_windows_runtime(app) for app in apps_cfg
         if not scheduled_task_path(app)
         and not docker_resource(app)
         and not elevated_favorite(app)
         and not elevated_task(app)}
        if PLATFORM.name == "windows" else {}
    )
    if PLATFORM.name == "windows":
        managed = {
            app_id: list(state["members"])
            for app_id, state in runtime_states.items()
            if state["verified"] and state["status"] in ("running", "stopping")
        }
        snap = {}
    else:
        managed, snap, _ = managed_process_index(apps_cfg, groups)
    listen_by_pid = {}
    for pid, port in listeners:
        listen_by_pid.setdefault(pid, []).append(port)
    configured_ports = {
        app["port"] for app in apps_cfg if app.get("port")}

    # 端口诊断需要展示占用者的真实身份，一次批量取详情，避免逐卡 ps。
    configured_listener_pids = {
        pid for port in configured_ports for pid in port_map.get(port, [])}
    listener_snap = (ps_snapshot(configured_listener_pids, with_uid=True)
                     if configured_listener_pids else {})
    listener_cwds = lsof_cwds(configured_listener_pids)
    verified_owner = listener_app_owners(
        apps_cfg,
        listeners,
        listener_snap,
        listener_cwds,
        managed_override=managed if PLATFORM.name == "windows" else None,
    )

    apps = []
    for app in apps_cfg:
        if elevated_favorite(app):
            apps.append(elevated_program_app_row(
                app, broker_status, program_processes
            ))
            continue
        if elevated_task(app):
            apps.append(elevated_task_app_row(
                app, broker_status, elevated_task_statuses.get(app["id"])
            ))
            continue
        if docker_resource(app):
            apps.append(docker_app_row(app, docker_snapshot))
            continue
        task_path = scheduled_task_path(app)
        if task_path:
            apps.append(scheduled_task_app_row(
                app, scheduled_tasks.get(task_path.casefold())
            ))
            continue
        runtime_state = runtime_states.get(app["id"])
        managed_live = managed.get(app["id"], [])
        legacy_pid = (
            None
            if PLATFORM.name == "windows" or managed_live
            else legacy_managed_pid(app, listeners, listener_snap, listener_cwds)
        )
        if (legacy_pid and
                (verified_owner.get(legacy_pid) or {}).get("id") != app.get("id")):
            legacy_pid = None
        live = managed_live or ([legacy_pid] if legacy_pid else [])
        lp = (
            (app.get("runtimeIdentity") or {}).get("rootPid")
            if PLATFORM.name == "windows" else app.get("lastPid")
        )
        pid = lp if lp in live else (live[0] if live else None)
        port = app.get("port")
        configured_listeners = port_map.get(port, []) if port else []
        listening = bool(port and any(p in live for p in configured_listeners))
        occupied = bool(port and configured_listeners and not listening)
        owner_pid = configured_listeners[0] if occupied else None
        owner_info = listener_snap.get(owner_pid, {}) if owner_pid else {}
        owner_app = verified_owner.get(owner_pid)
        owner_cwd = listener_cwds.get(owner_pid) if owner_pid else None
        port_owner = None
        if owner_pid:
            comm = owner_info.get("comm") or ""
            port_owner = {
                "pid": owner_pid,
                "openHost": listener_open_host(
                    listeners, port, {owner_pid}),
                "name": os.path.basename(comm) or "?",
                "cmd": owner_info.get("args") or comm,
                "cwd": owner_cwd,
                "project": project_name(owner_cwd),
                "uid": owner_info.get("uid"),
                "currentUser": process_owned_by_current(owner_info),
                "uptimeSec": owner_info.get("etime"),
                "appId": owner_app.get("id") if owner_app else None,
                "appName": owner_app.get("name") if owner_app else None,
            }
        actual_ports = sorted({p for member in live
                               for p in listen_by_pid.get(member, [])})
        open_hosts = {
            str(actual_port): listener_open_host(
                listeners, actual_port, set(live))
            for actual_port in actual_ports
        }
        try:
            health = inspect_app_health(app)
        except Exception as exc:
            LOG.warning("检查应用配置失败（%s）：%s", app.get("id"), exc)
            health = {"status": "unknown", "blocking": False, "issues": []}
        command_spec = app.get("commandSpec")
        if command_spec is None:
            command_spec = legacy_command_spec(app.get("command") or "")
        try:
            command_spec = normalize_command_spec(command_spec)
            compatibility = platform_compatibility(
                command_spec, app.get("cwd"), PLATFORM.name)
            if (app.get("importStatus") == "blocked"
                    and compatibility.get("status") != "blocked"):
                compatibility = {
                    "status": "blocked",
                    "reasons": [{
                        "code": "COMMAND_SPEC_INVALID",
                        "message": "The stored command requires correction.",
                    }],
                }
        except CommandSpecError as exc:
            command_spec = legacy_command_spec(app.get("command") or "")
            compatibility = {
                "status": "blocked",
                "reasons": [{
                    "code": "COMMAND_SPEC_INVALID",
                    "message": str(exc),
                }],
            }
        apps.append({
            **keep_alive_row_fields(app),
            "id": app["id"], "name": app["name"], "command": app["command"],
            "commandSpec": command_spec,
            "runtimeIdentity": app.get("runtimeIdentity"),
            "runtimeSource": "managed",
            "scheduledTask": None,
            "scheduledTaskPath": None,
            "scheduledTaskControlAvailable": False,
            "dockerResource": None,
            "docker": None,
            "lifecycleStatus": (
                runtime_state["status"]
                if runtime_state is not None
                else ("running" if live else "stopped")
            ),
            "controlAvailable": (
                runtime_state["controlAvailable"]
                if runtime_state is not None else True
            ),
            "deleteAvailable": (
                runtime_state["deleteAvailable"]
                if runtime_state is not None else True
            ),
            "runtimeIssue": (
                runtime_state["issue"] if runtime_state is not None else None
            ),
            "importStatus": compatibility.get("status", "blocked"),
            "platformCompatibility": compatibility,
            "cwd": app.get("cwd"), "port": port,
            "emoji": app.get("emoji"), "glyph": app.get("glyph"), "icon": app.get("icon"),
            "favicon": app.get("favicon"),
            "running": (
                runtime_state["running"]
                if runtime_state is not None else bool(live)
            ), "pid": pid,
            "uptimeSec": ((snap.get(pid) or listener_snap.get(pid) or {}).get("etime")
                          if pid else None),
            "kind": app.get("kind") or "service",
            "attached": bool(app.get("attached")),
            "lastExit": public_last_exit(app),
            "health": health,
            "ports": actual_ports,
            "openHosts": open_hosts,
            "listening": listening,
            "portOccupied": occupied,
            "portOccupiedPid": configured_listeners[0] if occupied else None,
            "portOwner": port_owner,
            # 多张停止卡片可以共享常见开发端口；只有真正启动时的监听占用
            # 才是冲突。字段保留给旧前端兼容，但不再表示配置重复。
            "portConflict": False,
            "portConflictApps": [],
            "legacyManaged": bool(legacy_pid),
        })
    return apps


def build_state(cfg, console_port, config_health=None):
    _begin_platform_scan_cycle()
    degraded_reasons = []
    visibility_notices = []
    # 一次 pgid 快照供 build_services / build_apps 共享，避免每轮两次全量 ps。
    needs_groups = any(
        app.get("runToken")
        and isinstance(app.get("lastPgid") or app.get("lastPid"), int)
        for app in cfg.get("apps") or [])
    try:
        groups = pgid_members_map() if needs_groups else None
    except Exception:
        LOG.exception("构建受控进程组状态失败")
        groups = {}
        degraded_reasons.append({"component": "process_groups"})
    try:
        services, listeners = build_services(cfg, groups)
    except Exception:
        LOG.exception("构建服务监控状态失败")
        services, listeners = [], set()
        degraded_reasons.append({"component": "services"})
    try:
        watched = build_watched(cfg.get("watchedKeywords"))
    except Exception:
        LOG.exception("构建关注进程状态失败")
        watched = []
        degraded_reasons.append({"component": "watched"})
    try:
        scheduled_tasks = build_scheduled_task_index(cfg)
    except Exception:
        LOG.exception("构建 Windows 计划任务状态失败")
        scheduled_tasks = {}
        if any(scheduled_task_path(app) for app in (cfg.get("apps") or [])):
            degraded_reasons.append({"component": "scheduled_tasks"})
    try:
        docker_snapshot = build_docker_snapshot(cfg)
        if (docker_snapshot is not None
                and docker_snapshot.status is ScanStatus.FAILED):
            degraded_reasons.append({
                "component": "docker",
                "error": (
                    docker_snapshot.issues[0].message
                    if docker_snapshot.issues else "Docker 状态不可用"
                ),
            })
    except Exception as exc:
        LOG.exception("构建 Docker 状态失败")
        docker_snapshot = DockerSnapshot(ScanStatus.FAILED)
        if any(docker_resource(app) for app in (cfg.get("apps") or [])):
            degraded_reasons.append({"component": "docker", "error": str(exc)})
    try:
        broker_status = (
            PLATFORM.elevation_broker_status()
            if getattr(PLATFORM.capabilities, "manage_elevation_broker", False)
            else None
        )
    except Exception as exc:
        LOG.exception("构建管理员启动代理状态失败")
        broker_status = None
        if any(
                elevated_favorite(app) or elevated_task(app)
                for app in (cfg.get("apps") or [])):
            degraded_reasons.append({
                "component": "elevation_broker", "error": str(exc),
            })
    elevated_task_statuses = {}
    if broker_status is not None and getattr(broker_status, "running", False):
        for app in cfg.get("apps") or []:
            if not elevated_task(app):
                continue
            try:
                result = PLATFORM.query_elevated_task(app["id"])
            except Exception as exc:
                result = ElevatedTaskResult(
                    False, error=str(exc),
                    code="BROKER_ELEVATED_TASK_QUERY_FAILED",
                )
            elevated_task_statuses[app["id"]] = result
            if not result.ok:
                degraded_reasons.append({
                    "component": "elevated_tasks",
                    "error": result.error or result.code,
                })
    try:
        program_processes = build_program_process_snapshot(cfg, broker_status)
    except Exception as exc:
        LOG.exception("构建程序运行观察状态失败")
        program_processes = {}
        if any(elevated_favorite(app) for app in (cfg.get("apps") or [])):
            degraded_reasons.append({
                "component": "program_processes", "error": str(exc),
            })
    try:
        apps = build_apps(
            cfg, listeners, groups, scheduled_tasks, docker_snapshot,
            broker_status, program_processes, elevated_task_statuses,
        )
    except Exception:
        LOG.exception("构建启动台状态失败")
        apps = []
        degraded_reasons.append({"component": "apps"})
    if VERSION_LOAD_ERROR:
        degraded_reasons.append(
            {"component": "version", "error": VERSION_LOAD_ERROR})
    for issue in (config_health or {}).get("issues", []):
        degraded_reasons.append({"component": "config", "error": issue})
    for issue in _consume_platform_scan_issues():
        if getattr(issue, "degrades", True):
            reason = {
                "component": issue.component,
                "code": issue.code,
                "error": issue.message,
            }
            if reason not in degraded_reasons:
                degraded_reasons.append(reason)
        else:
            notice = {
                "component": issue.component,
                "code": issue.code,
                "message": issue.message,
            }
            if notice not in visibility_notices:
                visibility_notices.append(notice)
    platform_metadata = PLATFORM.platform_metadata()
    platform_name = platform_metadata.get("platform", PLATFORM.name)
    controller_elevated = bool(platform_metadata.get("controllerElevated", False))
    if controller_elevated:
        degraded_reasons.append({
            "component": "security",
            "code": "CONTROLLER_ELEVATED_UNSAFE",
            "error": "Local Ops controller is running with administrator elevation",
        })
    if platform_name == "windows":
        launch_instruction = "运行 python server.py 启动总控台。"
        lifecycle_notice = (
            "仅可控制由 Local Ops 创建且身份验证完整的 Windows Job；"
            "当前项目不可控时请查看诊断。"
        )
        shortcut_modifier = "Ctrl"
    else:
        launch_instruction = "运行 start.command 或打开总控台应用。"
        lifecycle_notice = "仅对总控台验证启动的进程提供生命周期控制。"
        shortcut_modifier = "⌘"
    return {
        "services": services,
        "watched": watched,
        "apps": apps,
        "watchedKeywords": cfg.get("watchedKeywords") or [],
        "consolePort": console_port,
        "consolePid": SELF_PID,
        "consoleCwd": BASE_DIR,
        "logicalCpuCount": max(1, os.cpu_count() or 1),
        "version": APP_VERSION,
        "schemaVersion": cfg.get("schemaVersion", CURRENT_SCHEMA_VERSION),
        "platform": platform_name,
        "capabilities": dict(platform_metadata.get("capabilities") or {}),
        "elevationBroker": elevation_broker_public(broker_status),
        "platformInfo": {
            "shortcutModifier": shortcut_modifier,
            "dataDir": DATA_DIR,
            "logsDir": LOGS_DIR,
            "consoleLogPath": os.path.join(LOGS_DIR, "console.log"),
            "launchInstruction": launch_instruction,
            "lifecycleNotice": lifecycle_notice,
            "controllerElevated": controller_elevated,
        },
        "degraded": bool(degraded_reasons),
        "degradedReasons": degraded_reasons,
        "visibilityNotices": visibility_notices,
        "configHealth": dict(config_health or {}),
        "uiTheme": cfg.get("uiTheme") or DEFAULT_UI_THEME,
        "themes": list_themes(),
    }


# ---------------------------------------------------------------- 状态快照缓存
# 每次快照要跑约十余个 ps/lsof 子进程。TTL 略大于前端 2s 轮询周期：
# 单标签页约每 2-3 轮重建一次，多标签页请求通过独立 build lock 合并。
# cache lock 只保护元数据；配置/进程变更时 invalidate 立即失效。
STATE_CACHE_TTL = 2.2  # 秒
_state_cache_lock = threading.Lock()
_state_build_lock = threading.Lock()
_state_cache = {"mono": 0.0, "state": None, "epoch": 0}


def invalidate_state_cache():
    with _state_cache_lock:
        _state_cache["state"] = None
        _state_cache["epoch"] = int(_state_cache.get("epoch", 0)) + 1


def get_state_snapshot(cfg, console_port):
    now = time.monotonic()
    with _state_cache_lock:
        cached = _state_cache["state"]
        if cached is not None and now - _state_cache["mono"] < STATE_CACHE_TTL:
            return cached
    with _state_build_lock:
        now = time.monotonic()
        with _state_cache_lock:
            cached = _state_cache["state"]
            if cached is not None and now - _state_cache["mono"] < STATE_CACHE_TTL:
                return cached

        while True:
            with _state_cache_lock:
                epoch = int(_state_cache.get("epoch", 0))
            config_snapshot = cfg.snapshot()
            config_health = cfg.health_info()
            state = build_state(config_snapshot, console_port, config_health)
            with _state_cache_lock:
                if epoch != int(_state_cache.get("epoch", 0)):
                    continue
                _state_cache["mono"] = time.monotonic()
                _state_cache["state"] = state
                return state


def build_health(cfg):
    """不执行 ps/lsof 的轻量健康检查。"""
    health = cfg.health_info()
    issues = list(health.get("issues") or [])
    if VERSION_LOAD_ERROR:
        issues.append("VERSION 读取失败: %s" % VERSION_LOAD_ERROR)
    for label, path in (("data", DATA_DIR), ("icons", ICONS_DIR),
                        ("logs", LOGS_DIR)):
        if not os.path.isdir(path):
            issues.append("%s 目录不存在" % label)
        elif not os.access(path, os.R_OK | os.W_OK | os.X_OK):
            issues.append("%s 目录不可读写" % label)
        elif PLATFORM.name == "windows":
            try:
                PLATFORM.verify_private_directory(path)
            except (OSError, PermissionError) as e:
                issues.append("%s 目录 ACL 不符合私有权限要求: %s" % (label, e))
        else:
            try:
                mode = os.lstat(path).st_mode
                if stat.S_ISLNK(mode) or mode & 0o077:
                    issues.append("%s 目录权限不是 0700" % label)
            except OSError as e:
                issues.append("无法检查 %s 目录: %s" % (label, e))
    for label, path in (("config", CONFIG_PATH),
                        ("configBackup", CONFIG_PATH + ".bak")):
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            if label == "config":
                issues.append("主配置文件不存在")
            continue
        except OSError as e:
            issues.append("无法检查 %s: %s" % (label, e))
            continue
        if PLATFORM.name == "windows":
            try:
                PLATFORM.verify_private_file(path)
            except (OSError, PermissionError) as e:
                issues.append("%s 文件 ACL 不符合私有权限要求: %s" % (label, e))
        elif not stat.S_ISREG(mode) or mode & 0o077:
            issues.append("%s 文件权限不是 0600" % label)
    degraded = bool(issues)
    snapshot = cfg.snapshot()
    return {
        "ok": not degraded,
        "status": "degraded" if degraded else "ok",
        "version": APP_VERSION,
        "schemaVersion": snapshot.get(
            "schemaVersion", CURRENT_SCHEMA_VERSION),
        "degraded": degraded,
        "issues": issues,
        "config": health,
    }


def list_themes():
    """扫描 static/themes/*.json 主题清单（css 文件必须存在），供注册切换。
    默认主题固定排在首位，其余按文件名排序。"""
    themes = []
    try:
        names = sorted(os.listdir(THEMES_DIR))
    except OSError:
        return themes
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(THEMES_DIR, name), "r", encoding="utf-8") as f:
                meta = json.load(f)
            theme_id = str(meta.get("id") or os.path.splitext(name)[0])
            if not theme_id or not os.path.isfile(
                    os.path.join(THEMES_DIR, theme_id + ".css")):
                continue
            themes.append({
                "id": theme_id,
                "name": str(meta.get("name") or theme_id),
                "author": str(meta.get("author") or ""),
                "desc": str(meta.get("desc") or ""),
                "colors": [str(c) for c in (meta.get("colors") or [])][:6],
            })
        except Exception:
            LOG.exception("读取主题清单失败: %s", name)
    themes.sort(key=lambda t: t["id"] != DEFAULT_UI_THEME)
    return themes


# ---------------------------------------------------------------- 进程/应用操作

def process_uid(pid):
    """Return the native owner id for one process, or None."""
    try:
        snapshot = PLATFORM.process_snapshot({int(pid)}, with_owner=True)
        _record_platform_issues(snapshot.status, snapshot.issues)
    except PlatformScanError:
        return None
    return process_owner_value(snapshot.processes.get(int(pid)))


def kill_process(pid, force):
    """End one external current-user process through the platform boundary."""
    result = PLATFORM.stop_external_process(int(pid), bool(force))
    return result.ok, result.error


def stop_pid_tree(pid, sig=signal.SIGTERM):
    """向受控进程组发信号；返回 (ok, error)。

    ProcessLookupError means the target completed between validation and the
    signal and is therefore an idempotent success. Permission and other OS
    failures must never be swallowed: callers use them to retain management
    identity instead of creating an orphan process.
    """
    identity = RuntimeIdentity(
        PLATFORM.name,
        "group",
        int(pid),
        SELF_PRINCIPAL.identifier,
    )
    result = PLATFORM.stop_managed(
        identity, force=sig == getattr(signal, "SIGKILL", None)
    )
    return result.ok, result.error


def app_running(app, listeners=None):
    return bool(managed_pids(app) or legacy_managed_pid(app, listeners))


def app_alive_sign(app, listeners=None):
    """start/stop 的存活判断：新版 token 或严格校验通过的旧版身份。"""
    return app_running(app, listeners)


def build_launch_env(token, environ=None):
    """Compatibility wrapper for the native launch environment."""
    builder = getattr(PLATFORM, "launch_environment", None)
    if builder is None:
        raise RuntimeError("当前平台尚未实现启动环境")
    return builder(token, environ)


def start_app(app):
    """返回 (ok, error, proc|None, pgid|None, token|None)。"""
    _ensure_private_dir(LOGS_DIR)
    log_path = os.path.join(LOGS_DIR, "%s.log" % app["id"])
    rotate_log_file(log_path)
    cwd = app.get("cwd") or os.path.expanduser("~")
    result = PLATFORM.launch(LaunchRequest(
        app_id=app["id"],
        command=app["command"],
        cwd=cwd,
        log_path=log_path,
    ))
    return (result.ok, result.error, result.process, result.group_id,
            result.token)


def _windows_lifecycle_result(ok, *, code=None, pid=None,
                              generation_id=None, status=None):
    result = {"ok": bool(ok)}
    if code:
        error = lifecycle_error(code)
        result.update({"code": error["code"], "error": error["message"]})
    if pid is not None:
        result["pid"] = pid
    if generation_id is not None:
        result["generationId"] = generation_id
    if status is not None:
        result["lifecycleStatus"] = status
    return result


def _windows_inspection_matches(identity, inspection):
    """Accept inspection evidence only when it is bound to the exact identity."""
    if not bool(getattr(inspection, "verified", False)):
        return False
    observed = getattr(inspection, "identity", None)
    if observed is None:
        return False
    try:
        return public_runtime_identity(observed, identity.app_id) == (
            public_runtime_identity(identity, identity.app_id)
        )
    except (ConfigSchemaError, TypeError, ValueError):
        return False


def _windows_terminal_last_exit(app, inspection, *, manually_stopped=False):
    """Map authenticated terminal receipt metadata to bounded product state."""
    if manually_stopped:
        if (app.get("kind") or "service") != "task":
            return None
        return {"status": "stopped", "code": None, "at": int(time.time())}
    if not hasattr(inspection, "exit_code"):
        return None
    exit_code = getattr(inspection, "exit_code", None)
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        exit_code = None
    updated_at = getattr(inspection, "updated_at", None)
    if isinstance(updated_at, bool) or not isinstance(updated_at, (int, float)):
        ended_at = int(time.time())
    else:
        ended_at = int(updated_at / 1000 if updated_at > 10_000_000_000
                       else updated_at)
    value = {"code": exit_code, "at": ended_at}
    if (app.get("kind") or "service") == "task":
        value["status"] = (
            classify_task_exit(exit_code)
            if exit_code is not None else "failed"
        )
    return value


def _defer_windows_release(identity):
    release_key = (str(identity.app_id), str(identity.generation_id))
    with _WINDOWS_RELEASE_LOCK:
        previous = _WINDOWS_PENDING_RELEASES.get(release_key) or {"attempts": 0}
        attempts = int(previous["attempts"]) + 1
        _WINDOWS_PENDING_RELEASES[release_key] = {
            "attempts": attempts,
            "nextAttempt": time.monotonic() + min(60.0, 2.0 ** min(attempts, 6)),
            "identity": identity,
        }


def _release_windows_runtime_records(identity):
    release_key = (str(identity.app_id), str(identity.generation_id))
    with _WINDOWS_RELEASE_LOCK:
        try:
            release_managed = getattr(PLATFORM, "release_managed", None)
            released = (
                release_managed(identity) if release_managed is not None else None
            )
        except Exception:
            LOG.exception(
                "Windows runtime record cleanup failed: %s generation %s",
                release_key[0], release_key[1],
            )
            released = None
        if released is not None and bool(getattr(released, "ok", False)):
            _WINDOWS_PENDING_RELEASES.pop(release_key, None)
            return True
        _defer_windows_release(identity)
        LOG.warning(
            "Windows runtime record cleanup deferred for app %s generation %s",
            release_key[0], release_key[1],
        )
        return False


def _abort_unpersisted_windows_runtime(identity):
    """Abort and release only a generation proven absent from config."""
    try:
        aborted = PLATFORM.abort_managed(identity)
    except Exception:
        LOG.exception("Windows prepared Job abort failed: %s", identity.app_id)
        _defer_windows_release(identity)
        return False
    if not bool(getattr(aborted, "ok", False)):
        _defer_windows_release(identity)
        return False
    return _release_windows_runtime_records(identity)


def _persist_windows_cleanup_identity(cfg, app_id, identity):
    """Retain an ambiguous generation so restart reconciliation can finish it."""
    try:
        public = public_runtime_identity(identity, app_id)
    except (ConfigSchemaError, TypeError, ValueError):
        return False

    def persist(_data, target):
        target["runtimeIdentity"] = public
        target["lastPid"] = None
        target["lastPgid"] = None
        target["runToken"] = None
        target["attached"] = False
        return True

    try:
        status, saved, _ = cfg.mutate_app_if_generation(
            app_id, None, persist
        )
    except OSError:
        return False
    return status == "applied" and bool(saved)


def _abort_or_retain_windows_runtime(cfg, app_id, identity):
    """Clean an unpublished generation or durably retain its exact identity."""
    with _WINDOWS_RELEASE_LOCK:
        if _abort_unpersisted_windows_runtime(identity):
            return True
        return _persist_windows_cleanup_identity(cfg, app_id, identity)


def _clear_windows_generation(cfg, app, inspection, *, manually_stopped=False):
    generation_id = runtime_generation(app)
    try:
        identity = native_runtime_identity(app)
    except (ConfigSchemaError, TypeError, ValueError):
        return False, "invalid"
    if identity is None:
        return False, "invalid"
    release_key = (str(identity.app_id), str(identity.generation_id))
    with _WINDOWS_RELEASE_LOCK:
        pending = _WINDOWS_PENDING_RELEASES.get(release_key)
        if pending is not None and time.monotonic() < pending["nextAttempt"]:
            return False, "cleanup_pending"
        last_exit = _windows_terminal_last_exit(
            app, inspection, manually_stopped=manually_stopped
        )

        def op(_data, target):
            target["runtimeIdentity"] = None
            target["lastPid"] = None
            target["lastPgid"] = None
            target["runToken"] = None
            target["attached"] = False
            if last_exit is not None:
                target["lastExit"] = last_exit
            return True

        try:
            status, cleared, _ = cfg.mutate_app_if_generation(
                app["id"], generation_id, op
            )
        except OSError:
            return False, "failed"
        if status != "applied" or not cleared:
            return False, status

        if _release_windows_runtime_records(identity):
            return True, status

        # Keep the terminal identity when possible so a later state reconciliation
        # can authenticate the same receipt and retry exact-generation cleanup.
        public = public_runtime_identity(identity, app["id"])

        def restore(_data, target):
            target["runtimeIdentity"] = public
            return True

        try:
            restore_status, restored, _ = cfg.mutate_app_if_generation(
                app["id"], None, restore
            )
        except OSError:
            restore_status, restored = "failed", False
        return False, (
            "cleanup_pending"
            if restore_status == "applied" and restored else "cleanup_failed"
        )


def _retry_windows_pending_releases(cfg):
    """Retry exact terminal cleanup, including records recovered after restart."""
    if PLATFORM.name != "windows":
        return
    with _WINDOWS_RELEASE_LOCK:
        persisted = {
            (str(app.get("id")), str(runtime_generation(app)))
            for app in cfg.snapshot().get("apps", [])
            if runtime_generation(app) is not None
        }
        try:
            recover = getattr(PLATFORM, "recover_managed_cleanups", None)
            recovered = recover() if recover is not None else ()
        except Exception:
            LOG.exception("Windows terminal cleanup recovery failed")
            recovered = ()
        for identity in recovered:
            key = (str(identity.app_id), str(identity.generation_id))
            if key in persisted:
                continue
            _WINDOWS_PENDING_RELEASES.setdefault(key, {
                "attempts": 0,
                "nextAttempt": 0.0,
                "identity": identity,
            })
        now = time.monotonic()
        due = [
            (key, value["identity"])
            for key, value in _WINDOWS_PENDING_RELEASES.items()
            if key not in persisted and now >= value["nextAttempt"]
        ]
        for key, identity in due:
            current = _WINDOWS_PENDING_RELEASES.get(key)
            if current is None:
                continue
            current_app = find_app(cfg.snapshot(), key[0])
            if current_app is not None and runtime_generation(current_app) == key[1]:
                # The identity was restored after an earlier release failure.
                # Its authenticated terminal reconciliation owns the next CAS.
                continue
            _release_windows_runtime_records(identity)


def _inspect_windows_terminal(identity):
    """Return a verified terminal inspection, or None without guessing."""
    try:
        inspection = PLATFORM.inspect_managed(identity)
    except Exception:
        LOG.exception("Windows runtime reconciliation failed: %s", identity.app_id)
        return None
    if not _windows_inspection_matches(identity, inspection):
        return None
    members = tuple(getattr(inspection, "members", ()) or ())
    status = getattr(inspection, "status", None)
    if (not bool(getattr(inspection, "running", False))
            and not members and status in ("exited", "failed")):
        return inspection
    return None


def start_windows_app(cfg, app):
    """Prepare, persist, activate, and verify one new Windows Job generation."""
    def launch_result(ok, **values):
        payload = _windows_lifecycle_result(ok, **values)
        record_app_action(app, "Windows 受管应用启动", payload)
        return payload

    if not bool(cfg.health_info().get("writable")):
        return launch_result(False, code="LAUNCH_COMMIT_FAILED")
    generation_id = str(uuid.uuid4())
    _ensure_private_dir(LOGS_DIR)
    log_path = os.path.join(LOGS_DIR, "%s.log" % app["id"])
    rotate_log_file(log_path)
    cwd = app.get("cwd") or os.path.expanduser("~")
    try:
        command_spec = normalize_command_spec(app.get("commandSpec"))
        # Revalidate the native boundary before the runner creates any process.
        prepared_invocation(command_spec)
        prepared = PLATFORM.launch(LaunchRequest(
            app_id=app["id"],
            command=app["command"],
            cwd=cwd,
            log_path=log_path,
            command_spec=command_spec,
            generation_id=generation_id,
        ))
    except Exception:
        LOG.exception("Windows managed launch preparation failed: %s", app["id"])
        return launch_result(
            False, code="LAUNCH_PREPARE_FAILED"
        )
    identity = getattr(prepared, "runtime_identity", None)
    if not getattr(prepared, "ok", False) or identity is None:
        if identity is not None:
            _abort_or_retain_windows_runtime(cfg, app["id"], identity)
        return launch_result(False, code=(
            prepared.code
            if getattr(prepared, "code", None) in _LIFECYCLE_ERROR_MESSAGES
            else "LAUNCH_PREPARE_FAILED"
        ))
    try:
        public = public_runtime_identity(identity, app["id"])
        if (public["generationId"] != generation_id
                or getattr(prepared, "status", None) != "prepared"):
            raise ConfigSchemaError("runner did not prepare the requested generation")
    except (ConfigSchemaError, TypeError, ValueError):
        _abort_or_retain_windows_runtime(cfg, app["id"], identity)
        return launch_result(False, code="LAUNCH_PREPARE_FAILED")

    def persist(_data, target):
        target["runtimeIdentity"] = public
        target["lastPid"] = None
        target["lastPgid"] = None
        target["runToken"] = None
        target["attached"] = False
        if (target.get("kind") or "service") != "task":
            target["lastExit"] = None
        return True

    try:
        commit_status, saved, _ = cfg.mutate_app_if_generation(
            app["id"], None, persist
        )
    except Exception:
        commit_status, saved = "failed", False
    config_writable = bool(cfg.health_info().get("writable"))
    if commit_status != "applied" or not saved or not config_writable:
        current = find_app(cfg.snapshot(), app["id"])
        identity_was_persisted = (
            current is not None
            and runtime_generation(current) == generation_id
        )
        if identity_was_persisted:
            try:
                PLATFORM.abort_managed(identity)
            except Exception:
                LOG.exception("Windows launch rollback failed: %s", app["id"])
        else:
            _abort_or_retain_windows_runtime(cfg, app["id"], identity)
        return launch_result(False, code="LAUNCH_COMMIT_FAILED")

    try:
        activation = PLATFORM.activate_managed(identity)
    except Exception:
        LOG.exception("Windows managed activation response failed: %s", app["id"])
        activation = None
    try:
        inspection = PLATFORM.inspect_managed(identity)
    except Exception:
        inspection = None
    if inspection is not None and _windows_inspection_matches(identity, inspection):
        members = tuple(getattr(inspection, "members", ()) or ())
        inspection_status = getattr(inspection, "status", None)
        if (bool(getattr(inspection, "running", False))
                and members and inspection_status == "running"):
            return launch_result(
                True,
                pid=(getattr(activation, "process_id", None)
                     or identity.root_pid),
                generation_id=generation_id,
                status="running",
            )
        if (not bool(getattr(inspection, "running", False))
                and not members and inspection_status in ("exited", "failed")):
            current = find_app(cfg.snapshot(), app["id"])
            cleared = False
            clear_status = "not_found"
            if current is not None:
                cleared, clear_status = _clear_windows_generation(
                    cfg, current, inspection
                )
            if ((app.get("kind") or "service") == "task"
                    and inspection_status == "exited" and cleared):
                return launch_result(
                    True,
                    pid=identity.root_pid,
                    generation_id=generation_id,
                    status="stopped",
                )
            if clear_status == "mismatch":
                return launch_result(
                    False, code="GENERATION_MISMATCH"
                )
    # Resume may have reached the runner even when its response was lost. Keep
    # the persisted identity so a later authenticated inspect can reconcile it.
    return launch_result(False, code="LAUNCH_ACTIVATE_FAILED")


def start_scheduled_task_app(platform, app):
    path = scheduled_task_path(app)
    if not path:
        return {
            "ok": False,
            "error": "应用没有关联 Windows 计划任务",
            "code": "SCHEDULED_TASK_NOT_CONFIGURED",
        }
    result = platform.run_scheduled_task(path)
    payload = {
        "ok": bool(getattr(result, "ok", False)),
        "taskPath": getattr(result, "task_path", path) or path,
        "runtimeSource": "windowsTaskScheduler",
    }
    if not payload["ok"]:
        payload["error"] = (
            getattr(result, "error", None) or "Windows 计划任务启动失败"
        )
        payload["code"] = (
            getattr(result, "code", None) or "SCHEDULED_TASK_RUN_FAILED"
        )
    record_app_action(app, "Windows 计划任务启动", payload)
    return payload


def stop_scheduled_task_app(platform, app):
    path = scheduled_task_path(app)
    if not path:
        return {
            "ok": False,
            "error": "应用没有关联 Windows 计划任务",
            "code": "SCHEDULED_TASK_NOT_CONFIGURED",
        }
    result = platform.stop_scheduled_task(path)
    payload = {
        "ok": bool(getattr(result, "ok", False)),
        "taskPath": getattr(result, "task_path", path) or path,
        "runtimeSource": "windowsTaskScheduler",
    }
    if not payload["ok"]:
        payload["error"] = (
            getattr(result, "error", None) or "Windows 计划任务停止失败"
        )
        payload["code"] = (
            getattr(result, "code", None) or "SCHEDULED_TASK_STOP_FAILED"
        )
    record_app_action(app, "Windows 计划任务停止", payload)
    return payload


def set_scheduled_task_enabled_app(platform, app, enabled):
    path = scheduled_task_path(app)
    if not path:
        return {
            "ok": False,
            "error": "应用没有关联 Windows 计划任务",
            "code": "SCHEDULED_TASK_NOT_CONFIGURED",
        }
    result = platform.set_scheduled_task_enabled(path, enabled)
    payload = {
        "ok": bool(getattr(result, "ok", False)),
        "taskPath": getattr(result, "task_path", path) or path,
        "enabled": enabled,
        "runtimeSource": "windowsTaskScheduler",
    }
    if not payload["ok"]:
        payload["error"] = (
            getattr(result, "error", None) or "Windows 计划任务状态修改失败"
        )
        payload["code"] = (
            getattr(result, "code", None) or "SCHEDULED_TASK_TOGGLE_FAILED"
        )
    record_app_action(
        app, "Windows 计划任务%s" % ("启用" if enabled else "禁用"), payload
    )
    return payload


def set_scheduled_task_history_app(platform, app, enabled):
    result = platform.set_scheduled_task_history_enabled(enabled)
    payload = {
        "ok": bool(getattr(result, "ok", False)),
        "enabled": bool(getattr(result, "enabled", False)),
        "runtimeSource": "windowsTaskScheduler",
    }
    if not payload["ok"]:
        payload["error"] = (
            getattr(result, "error", None) or "计划任务历史记录修改失败"
        )
        payload["code"] = (
            getattr(result, "code", None)
            or "SCHEDULED_TASK_HISTORY_UPDATE_FAILED"
        )
    record_app_action(
        app, "计划任务历史记录%s" % ("启用" if enabled else "禁用"), payload
    )
    return payload


def control_docker_app(controller, app, start):
    resource = docker_resource(app)
    if not resource:
        return {
            "ok": False, "error": "应用没有关联 Docker 资源",
            "code": "DOCKER_RESOURCE_NOT_CONFIGURED",
        }
    result = controller.start(resource) if start else controller.stop(resource)
    payload = {
        "ok": bool(getattr(result, "ok", False)),
        "runtimeSource": (
            "dockerContainer" if resource.get("kind") == "container"
            else "dockerCompose"
        ),
    }
    if not payload["ok"]:
        payload["error"] = getattr(result, "error", None) or "Docker 操作失败"
        payload["code"] = getattr(result, "code", None) or "DOCKER_CONTROL_FAILED"
    record_app_action(app, "Docker %s" % ("启动" if start else "停止"), payload)
    return payload


def launch_elevated_program_app(platform, app):
    result = platform.launch_elevated(
        app.get("commandSpec"), app.get("cwd")
    )
    payload = {
        "ok": bool(getattr(result, "ok", False)),
        "pid": getattr(result, "process_id", None),
        "runtimeSource": "windowsElevationBroker",
    }
    if not payload["ok"]:
        payload["error"] = getattr(result, "error", None) or "管理员程序启动失败"
        payload["code"] = getattr(result, "code", None) or "ELEVATED_LAUNCH_FAILED"
    record_app_action(app, "管理员程序启动", payload)
    return payload


def launch_elevated_task_app(platform, app):
    result = platform.launch_elevated_task(
        app["id"], app.get("commandSpec"), app.get("cwd") or HOME_DIR
    )
    payload = {
        "ok": bool(getattr(result, "ok", False)),
        "pid": getattr(result, "process_id", None),
        "runtimeSource": "windowsElevationBrokerTask",
    }
    if not payload["ok"]:
        payload["error"] = (
            getattr(result, "error", None) or "管理员批处理启动失败"
        )
        payload["code"] = (
            getattr(result, "code", None)
            or "BROKER_ELEVATED_TASK_LAUNCH_FAILED"
        )
    record_app_action(app, "管理员批处理启动", payload)
    return payload


def stop_elevated_task_app(platform, app):
    result = platform.stop_elevated_task(app["id"])
    payload = {
        "ok": bool(getattr(result, "ok", False)),
        "runtimeSource": "windowsElevationBrokerTask",
    }
    if not payload["ok"]:
        payload["error"] = (
            getattr(result, "error", None) or "管理员批处理中止失败"
        )
        payload["code"] = (
            getattr(result, "code", None)
            or "BROKER_ELEVATED_TASK_STOP_FAILED"
        )
    record_app_action(app, "管理员批处理中止", payload)
    return payload


def stop_windows_app(
        cfg, app, *, force=False, timeout=APP_STOP_TIMEOUT_SEC,
        initial_inspection=None):
    """Stop only the authenticated Job and clear only the same generation."""
    try:
        identity = native_runtime_identity(app)
    except (ConfigSchemaError, TypeError, ValueError):
        return _windows_lifecycle_result(False, code="RUNTIME_IDENTITY_INVALID")
    if identity is None:
        return _windows_lifecycle_result(False, code="GENERATION_MISMATCH")
    before = initial_inspection
    if before is None:
        try:
            before = PLATFORM.inspect_managed(identity)
        except Exception:
            before = None
    if before is not None and _windows_inspection_matches(identity, before):
        before_members = tuple(getattr(before, "members", ()) or ())
        before_status = getattr(before, "status", None)
        if (not bool(getattr(before, "running", False))
                and not before_members and before_status in ("exited", "failed")):
            cleared, cas_status = _clear_windows_generation(
                cfg, app, before, manually_stopped=True
            )
            if cleared:
                return _windows_lifecycle_result(
                    True,
                    generation_id=identity.generation_id,
                    status="stopped",
                )
            return _windows_lifecycle_result(
                False,
                code=("GENERATION_MISMATCH" if cas_status == "mismatch"
                      else "RUNTIME_CONTROL_FAILED"),
            )
        controllable_statuses = (
            ("running", "stopping") if force else ("running",)
        )
        if not (bool(getattr(before, "running", False))
                and before_members and before_status in controllable_statuses):
            return _windows_lifecycle_result(
                False, code="RUNTIME_IDENTITY_UNVERIFIED"
            )
    else:
        return _windows_lifecycle_result(
            False, code="RUNTIME_IDENTITY_UNVERIFIED"
        )
    try:
        result = PLATFORM.stop_managed(
            identity, force=bool(force), timeout=float(timeout)
        )
    except Exception:
        LOG.exception("Windows managed stop failed: %s", app["id"])
        result = None
    terminal = _inspect_windows_terminal(identity)
    if terminal is not None:
        cleared, cas_status = _clear_windows_generation(
            cfg, app, terminal, manually_stopped=True
        )
        if cleared:
            return _windows_lifecycle_result(
                True,
                generation_id=identity.generation_id,
                status="stopped",
            )
        return _windows_lifecycle_result(
            False,
            code=("GENERATION_MISMATCH" if cas_status == "mismatch"
                  else "RUNTIME_CONTROL_FAILED"),
        )
    code = getattr(result, "code", None)
    if (code == "STOP_TIMEOUT"
            or bool(getattr(result, "still_running", False))
            or getattr(result, "status", None) in ("running", "stopping")):
        return _windows_lifecycle_result(False, code="STOP_TIMEOUT")
    if code in _LIFECYCLE_ERROR_MESSAGES:
        return _windows_lifecycle_result(False, code=code)
    return _windows_lifecycle_result(False, code="RUNTIME_CONTROL_FAILED")


def reconcile_windows_terminal_runtimes(cfg):
    """Clear only authenticated terminal receipts for the exact persisted generation."""
    if PLATFORM.name != "windows":
        return
    _retry_windows_pending_releases(cfg)
    for app in cfg.snapshot().get("apps", []):
        if app.get("runtimeIdentity") is None:
            continue
        try:
            identity = native_runtime_identity(app)
        except (ConfigSchemaError, TypeError, ValueError):
            continue
        terminal = _inspect_windows_terminal(identity)
        if terminal is not None:
            _clear_windows_generation(cfg, app, terminal)


def start_windows_runtime_reconciler(cfg, interval=30.0):
    """Run authenticated terminal cleanup without delaying HTTP state reads."""
    stop = threading.Event()
    if PLATFORM.name != "windows":
        return stop

    def _reconcile_loop():
        while not stop.is_set():
            try:
                reconcile_windows_terminal_runtimes(cfg)
            except Exception:
                LOG.exception("Windows runtime background reconciliation failed")
            stop.wait(max(1.0, float(interval)))

    threading.Thread(
        target=_reconcile_loop,
        name="windows-runtime-reconciler",
        daemon=True,
    ).start()
    return stop


def reconcile_elevated_task_results(cfg):
    if PLATFORM.name != "windows":
        return
    for app in cfg.snapshot().get("apps", []):
        if not elevated_task(app):
            continue
        result = PLATFORM.query_elevated_task(app["id"])
        last_exit = elevated_task_last_exit(app, result)
        if (not isinstance(last_exit, dict)
                or last_exit == app.get("lastExit")):
            continue

        def op(data, app_id=app["id"], expected=last_exit):
            target = find_app(data, app_id)
            if target is None or not elevated_task(target):
                return False
            target["lastExit"] = expected
            return True

        if cfg.update(op):
            record_app_action(app, "管理员批处理完成", {
                "ok": last_exit.get("status") == "succeeded",
                "status": last_exit.get("status"),
                "code": last_exit.get("code"),
                "durationSec": last_exit.get("durationSec"),
            })
            invalidate_state_cache()


def start_elevated_task_reconciler(cfg, interval=2.0):
    stop = threading.Event()
    if PLATFORM.name != "windows":
        return stop

    def _reconcile_loop():
        while not stop.is_set():
            try:
                reconcile_elevated_task_results(cfg)
            except Exception:
                LOG.exception("Elevated task background reconciliation failed")
            stop.wait(max(1.0, float(interval)))

    threading.Thread(
        target=_reconcile_loop,
        name="elevated-task-reconciler",
        daemon=True,
    ).start()
    return stop


def startup_failure_message(app_id, code):
    """从日志末尾提取一行可直接显示给用户的启动错误。"""
    text = read_log_tail(app_id, 30)
    for line in reversed(text.splitlines()):
        line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line).strip()
        if line and not line.startswith("====="):
            if len(line) > 180:
                line = line[:179] + "…"
            return "启动命令立即退出（exit %s）：%s" % (code, line)
    return "启动命令立即退出（exit %s），请查看日志" % code


def watch_app_exit(cfg, app_id, proc, token, started_at=None):
    """后台线程等子进程退出：若期间未被手动 stop/重启（lastPid 仍指向它），
    记录 lastExit（退出码、结束时间和运行耗时）。保留 lastPid 作为进程组锚点——
    脚本可能把服务放后台后退出，后续的运行判定/停止都靠 pgid 找到存活成员。"""
    started_at = time.time() if started_at is None else started_at

    def _wait():
        code = proc.wait()
        ended_at = time.time()
        duration = round(max(0.0, ended_at - started_at), 3)

        with MANUAL_STOP_LOCK:
            manually_stopped = (app_id, token) in MANUAL_STOP_TOKENS

        def op(c):
            target = find_app(c, app_id)
            if (not manually_stopped and target
                    and target.get("lastPid") == proc.pid
                    and target.get("runToken") == token):
                last_exit = {
                    "code": code,
                    "at": int(ended_at),
                    "startedAt": int(started_at * 1000),
                    "durationSec": duration,
                }
                if (target.get("kind") or "service") == "task":
                    last_exit["status"] = classify_task_exit(code)
                target["lastExit"] = last_exit
        cfg.update(op)
        rotate_log_file(os.path.join(LOGS_DIR, "%s.log" % app_id))
    thread = threading.Thread(target=_wait, daemon=True)
    thread.start()
    return thread


def persist_started_app(cfg, app_id, proc, pgid, token):
    """保存新的受控身份并启动退出监视线程。"""
    started_at = time.time()

    def op(c):
        target = find_app(c, app_id)
        if target:
            target["lastPid"] = proc.pid
            target["lastPgid"] = pgid
            target["runToken"] = token
            target["attached"] = False
            # 批处理任务运行时先保留上一次结果；自然退出或手动停止后再原子覆盖。
            if (target.get("kind") or "service") != "task":
                target["lastExit"] = None
            return True
        return False
    saved = cfg.update(op)
    if saved:
        watch_app_exit(cfg, app_id, proc, token, started_at)
    return saved


def clear_app_runtime(cfg, app_id, expected_token=None, last_exit=None):
    """清除受控身份；可用 token 防竞态，并可原子写入本次退出结果。"""
    def op(c):
        target = find_app(c, app_id)
        if not target:
            return False
        if expected_token is not None and target.get("runToken") != expected_token:
            return False
        target["lastPid"] = None
        target["lastPgid"] = None
        target["runToken"] = None
        target["attached"] = False
        if last_exit is not None:
            target["lastExit"] = last_exit
        return True
    return cfg.update(op)


class KeepAliveSupervisor:
    """Single low-overhead desired-state loop for explicitly armed cards."""

    BACKOFF_SECONDS = (0.5, 1.0, 2.0, 4.0, 8.0, 15.0, 30.0, 60.0)
    STABLE_SECONDS = 30.0

    def __init__(self, console, *, clock=time.monotonic, jitter=None):
        self.console = console
        self.clock = clock
        self.jitter = jitter or (lambda delay: random.uniform(0.0, delay * 0.1))
        self._guard = threading.RLock()
        self._entries = {}
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None

    def status(self, app_id):
        with self._guard:
            return dict(self._entries.get(app_id) or {
                "state": "disabled", "attempts": 0,
                "nextRetryAt": None, "nextObserveAt": None, "error": None,
            })

    def wake(self):
        self._wake.set()

    def stop(self):
        self._stop.set()
        self._wake.set()

    def join(self, timeout=None):
        if self._thread is not None:
            self._thread.join(timeout)

    def is_alive(self):
        return bool(self._thread is not None and self._thread.is_alive())

    def start(self):
        if self._thread is not None:
            return self
        self._thread = threading.Thread(
            target=self._run, name="keep-alive-supervisor", daemon=True,
        )
        self._thread.start()
        return self

    def _run(self):
        while not self._stop.is_set():
            active = self.run_once()
            timeout = 0.5 if active else 30.0
            self._wake.wait(timeout)
            self._wake.clear()

    def _set_status(self, app_id, **values):
        with self._guard:
            current = dict(self._entries.get(app_id) or {})
            current.update(values)
            current.setdefault("attempts", 0)
            current.setdefault("nextRetryAt", None)
            current.setdefault("nextObserveAt", None)
            current.setdefault("error", None)
            self._entries[app_id] = current
            return current

    def _observe(self, app):
        grant = app.get("keepAliveGrant")
        if keep_alive_grant_required(app) and not keep_alive_grant_matches_app(app):
            return "unknown", "特权保活尚未取得持久精确授权"
        if elevated_favorite(app):
            response = PLATFORM.keep_alive_grant_use(
                grant["grantId"], app["id"], grant["bindingDigest"],
                "observe"
            )
            if not response.get("ok"):
                return "unknown", response.get("error") or response.get("code")
            self._set_status(app["id"], leaseId=response.get("leaseId"))
            if response.get("processes"):
                return "running", None
            if isinstance(response.get("leaseId"), str):
                return "stopped", None
            return "unknown", "管理员程序零实例观察未签发启动租约"
        if docker_resource(app):
            inspect_resource = getattr(DOCKER, "inspect", None)
            snapshot = (
                inspect_resource(docker_resource(app))
                if inspect_resource is not None else DOCKER.discover()
            )
            row = docker_app_row(app, snapshot)
            status = row.get("lifecycleStatus")
            if status == "running":
                return "running", None
            if status == "stopped" and not row.get("health", {}).get("blocking"):
                return "stopped", None
            issue = row.get("runtimeIssue") or {}
            return "unknown", issue.get("message") or "无法确认 Docker 资源状态"
        task_path = scheduled_task_path(app)
        if task_path:
            response = PLATFORM.keep_alive_grant_use(
                grant["grantId"], app["id"], grant["bindingDigest"],
                "query"
            )
            if not response.get("ok"):
                return "unknown", response.get("error") or response.get("code")
            task = (response.get("tasks") or {}).get(task_path.casefold())
            if not isinstance(task, dict):
                return "unknown", "无法确认计划任务状态"
            state = task.get("state") or "unknown"
            if state in ("running", "queued"):
                return "running", None
            if (state == "ready" and task.get("enabled") is True
                    and isinstance(response.get("leaseId"), str)):
                self._set_status(app["id"], leaseId=response.get("leaseId"))
                return "stopped", None
            return "unknown", "计划任务未处于可安全运行状态"
        if app.get("attached") is True:
            listeners = scan_listeners()
            pid = legacy_managed_pid(app, listeners=listeners)
            if pid:
                self._set_status(app["id"], attachedMisses=0)
                return "running", None
            port = app.get("port")
            if port and any(item_port == port for _, item_port in listeners):
                self._set_status(app["id"], attachedMisses=0)
                return "unknown", "端口由无法匹配当前卡片身份的进程占用"
            entry = self.status(app["id"])
            misses = int(entry.get("attachedMisses") or 0) + 1
            self._set_status(app["id"], attachedMisses=misses)
            if misses < 2:
                return "unknown", "正在复验外部认领服务是否已经退出"
            return "stopped", None
        if PLATFORM.name == "windows":
            if app.get("runtimeIdentity") is not None:
                try:
                    identity = native_runtime_identity(app)
                except (ConfigSchemaError, TypeError, ValueError) as exc:
                    return "unknown", str(exc)
                terminal = _inspect_windows_terminal(identity)
                if terminal is not None:
                    cleared, clear_status = _clear_windows_generation(
                        self.console.cfg, app, terminal
                    )
                    if cleared:
                        return "stopped", None
                    return "unknown", (
                        "Windows 运行终态清理尚未完成: %s" % clear_status
                    )
                state = inspect_windows_runtime(app)
                if state.get("running"):
                    return "running", None
                return "unknown", state.get("issue")
            return "stopped", None
        if managed_pids(app):
            return "running", None
        return "stopped", None

    def _start_managed(self, app):
        health = inspect_app_health(app)
        if health.get("blocking"):
            issue = (health.get("issues") or [{}])[0]
            return {"ok": False, "error": (
                issue.get("detail") or issue.get("title") or "配置不可用"
            )}
        port = app.get("port")
        occupied = [
            (pid, observed_port)
            for pid, observed_port in scan_listeners()
            if observed_port == port
        ] if port else []
        if occupied:
            return {
                "ok": False,
                "error": "端口 %d 已被 PID %d 占用" % (port, occupied[0][0]),
            }
        if PLATFORM.name == "windows":
            return start_windows_app(self.console.cfg, app)
        ok, error, proc, pgid, token = start_app(app)
        if not ok:
            return {"ok": False, "error": error or "启动失败"}
        if not persist_started_app(
                self.console.cfg, app["id"], proc, pgid, token):
            stop_pid_tree(pgid)
            return {"ok": False, "error": "应用已被删除，已取消保活启动"}
        return {"ok": True, "pid": proc.pid}

    def _start_app(self, app):
        if elevated_favorite(app):
            grant = app.get("keepAliveGrant") or {}
            return PLATFORM.keep_alive_grant_use(
                grant.get("grantId"), app["id"], grant.get("bindingDigest"),
                "launch",
                self.status(app["id"]).get("leaseId"),
            )
        if docker_resource(app):
            return control_docker_app(DOCKER, app, True)
        if scheduled_task_path(app):
            grant = app.get("keepAliveGrant") or {}
            return PLATFORM.keep_alive_grant_use(
                grant.get("grantId"), app["id"], grant.get("bindingDigest"),
                "run",
                self.status(app["id"]).get("leaseId"),
            )
        return self._start_managed(app)

    def _record_failure(self, app_id, entry, error, now):
        attempts = int(entry.get("attempts") or 0) + 1
        base = self.BACKOFF_SECONDS[min(
            attempts - 1, len(self.BACKOFF_SECONDS) - 1
        )]
        delay = base + max(0.0, float(self.jitter(base)))
        self._set_status(
            app_id,
            state="backoff",
            attempts=attempts,
            nextRetryAt=now + delay,
            nextObserveAt=now + delay,
            runningSince=None,
            launchPending=False,
            error=str(error or "启动失败"),
        )

    @staticmethod
    def _observe_interval(app):
        if docker_resource(app):
            return 5.0
        if scheduled_task_path(app) or elevated_favorite(app):
            return 2.0
        return 1.0

    def run_once(self):
        now = self.clock()
        snapshot = self.console.cfg.snapshot()
        config_writable = bool(
            self.console.cfg.health_info().get("writable")
        )
        active = [
            app for app in snapshot.get("apps") or []
            if app.get("keepAlive") is True
            and app.get("desiredRunning") is True
            and keep_alive_supported(app)
        ]
        active_ids = {app["id"] for app in active}
        resource_owners = {}
        for app in active:
            resource_owners.setdefault(keep_alive_resource_key(app), []).append(
                app["id"]
            )
        conflicts = {
            app_id
            for owners in resource_owners.values() if len(owners) > 1
            for app_id in owners
        }
        with self._guard:
            for app_id in list(self._entries):
                if app_id not in active_ids:
                    self._entries.pop(app_id, None)
        for app in active:
            if self._stop.is_set():
                break
            app_id = app["id"]
            if not config_writable:
                self._set_status(
                    app_id, state="blocked", nextRetryAt=None,
                    error="配置处于只读保护，保活已暂停",
                )
                continue
            if app_id in conflicts:
                self._set_status(
                    app_id,
                    state="conflict",
                    nextRetryAt=None,
                    error="另一张保活卡片使用了相同的精确资源身份",
                )
                continue
            entry = self.status(app_id)
            next_retry = entry.get("nextRetryAt")
            if isinstance(next_retry, (int, float)) and now < next_retry:
                continue
            next_observe = entry.get("nextObserveAt")
            if (next_retry is None and isinstance(next_observe, (int, float))
                    and now < next_observe):
                continue
            operation_lock = self.console.try_app_operation(app_id)
            if operation_lock is None:
                self._set_status(app_id, state="waiting", error=None)
                continue
            try:
                current = find_app(self.console.cfg.snapshot(), app_id)
                if (current is None or current.get("keepAlive") is not True
                        or current.get("desiredRunning") is not True
                        or not keep_alive_supported(current)):
                    continue
                observed, issue = self._observe(current)
                next_observe = now + self._observe_interval(current)
                if observed == "running":
                    running_since = entry.get("runningSince")
                    if not isinstance(running_since, (int, float)):
                        running_since = now
                    attempts = int(entry.get("attempts") or 0)
                    launch_pending = entry.get("launchPending") is True
                    if now - running_since >= self.STABLE_SECONDS:
                        attempts = 0
                        launch_pending = False
                    self._set_status(
                        app_id, state="watching", attempts=attempts,
                        nextRetryAt=None, nextObserveAt=next_observe,
                        runningSince=running_since,
                        launchPending=launch_pending, error=None,
                    )
                    continue
                if observed != "stopped":
                    self._set_status(
                        app_id, state="blocked", nextRetryAt=None,
                        nextObserveAt=next_observe,
                        error=str(issue or "运行状态无法确认"),
                    )
                    continue
                running_since = entry.get("runningSince")
                if (entry.get("launchPending") is True
                        and isinstance(running_since, (int, float))
                        and now - running_since < self.STABLE_SECONDS):
                    self._record_failure(
                        app_id, entry,
                        "保活启动后在稳定窗口内退出", now,
                    )
                    continue
                current = find_app(self.console.cfg.snapshot(), app_id)
                if (current is None or current.get("keepAlive") is not True
                        or current.get("desiredRunning") is not True):
                    continue
                result = self._start_app(current)
                if result.get("ok"):
                    self._set_status(
                        app_id, state="starting", nextRetryAt=None,
                        nextObserveAt=next_observe,
                        runningSince=now, launchPending=True, error=None,
                    )
                else:
                    self._record_failure(
                        app_id, entry, result.get("error"), now
                    )
            except Exception as exc:
                LOG.exception("保活检查失败: %s", app_id)
                self._record_failure(app_id, entry, exc, now)
            finally:
                operation_lock.release()
        return bool(active)


def start_keep_alive_supervisor(console):
    return KeepAliveSupervisor(console).start()


def stop_app_for_update(cfg, app, timeout=5.0):
    """为修改运行参数安全停止应用；返回 (ok, error, stopped)。"""
    if not app_alive_sign(app):
        return True, None, False
    ok, error = stop_app_and_clear(cfg, app, timeout)
    return ok, error, bool(ok)


def pick_path(what):
    """Open the native file/folder picker."""
    return PLATFORM.pick_path(what)


def command_import_status(command_spec, cwd):
    """Return the persisted Phase 3 status from the platform contract."""
    status = platform_compatibility(command_spec, cwd, PLATFORM.name).get(
        "status")
    return status if status in ("ready", "needs_review", "blocked") else "blocked"


def picker_payload(path, what):
    """Return native path components so the browser never parses separators."""
    normalized = os.path.abspath(os.path.expanduser(str(path)))
    parent = os.path.dirname(normalized)
    stem = os.path.splitext(os.path.basename(normalized))[0]
    payload = {
        "ok": True,
        "canceled": False,
        "path": normalized,
        "dir": parent,
        "stem": stem,
    }
    if what in ("script", "exe"):
        python_executable = (
            select_python_executable(
                PLATFORM.name,
                current_executable=sys.executable,
                current_version=sys.version_info[:2],
                frozen=bool(getattr(sys, "frozen", False)),
            ) if PLATFORM.name == "windows" else None)
        spec = (
            command_spec_for_executable(
                normalized, platform_name=PLATFORM.name, cwd=parent
            )
            if what == "exe" else
            command_spec_for_script(
                normalized, PLATFORM.name, python_executable)
        )
        payload["command"] = (display_command(spec)
                              if PLATFORM.name == "windows"
                              else command_for_script(normalized))
        payload["commandSpec"] = spec
        payload["platformCompatibility"] = platform_compatibility(
            spec, parent, PLATFORM.name)
    return payload


def command_for_script(path):
    """按脚本类型生成可直接保存的 shell 命令，并安全引用任意文件名。"""
    normalized = os.path.abspath(os.path.expanduser(str(path)))
    quoted = shlex.quote(normalized)
    suffix = os.path.splitext(normalized)[1].lower()
    if suffix == ".py":
        return "python3 -- %s" % quoted
    if suffix == ".zsh":
        return "/bin/zsh -- %s" % quoted
    if suffix in (".sh", ".bash"):
        return "/bin/bash -- %s" % quoted
    if os.access(normalized, os.X_OK):
        return quoted
    # .command 常见于 Finder 双击脚本；没有执行位时仍可明确交给 bash。
    return "/bin/bash -- %s" % quoted


SCRIPT_SUFFIXES = {".py", ".sh", ".bash", ".zsh", ".command"}
SHELL_BUILTINS = {
    ".", ":", "[", "alias", "break", "cd", "command", "continue", "echo",
    "eval", "exec", "exit", "export", "false", "printf", "pwd", "read",
    "return", "set", "shift", "source", "test", "true", "type", "ulimit",
    "umask", "unalias", "unset", "wait",
}


def _simple_command_tokens(command):
    """解析无管道/重定向/展开的简单命令；不确定时返回 None。"""
    if not isinstance(command, str) or not command.strip():
        return []
    try:
        lexer = shlex.shlex(
            command, posix=True, punctuation_chars="|&;<>()")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return None
    if not tokens:
        return []
    if any(token and all(char in "|&;<>()" for char in token)
           for token in tokens):
        return None
    # 健康检查绝不展开变量、通配符或命令替换；这类命令照常允许运行。
    if any(any(char in token for char in ("$", "*", "?", "[", "]", "`"))
           for token in tokens):
        return None
    return tokens


def _resolve_command_path(value, cwd):
    value = os.path.expanduser(value)
    if os.path.isabs(value):
        return os.path.normpath(value)
    return os.path.normpath(os.path.join(cwd, value))


def _script_target(tokens, cwd):
    """提取 (路径, 是否直接执行, 原路径是否相对)，否则返回空。"""
    if not tokens:
        return None, False, False
    index = 0
    while index < len(tokens) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    if index >= len(tokens):
        return None, False, False
    executable = tokens[index]
    base = os.path.basename(executable)
    args = tokens[index + 1:]

    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", base):
        if "-m" in args or "-c" in args:
            return None, False, False
        if args and args[0] == "--":
            args = args[1:]
        candidate = next((arg for arg in args if not arg.startswith("-")), None)
        if candidate and (os.path.splitext(candidate)[1].lower() in SCRIPT_SUFFIXES
                          or "/" in candidate):
            return (_resolve_command_path(candidate, cwd), False,
                    not os.path.isabs(os.path.expanduser(candidate)))
        return None, False, False

    if base in {"bash", "sh", "zsh"}:
        if any(arg == "--command"
               or (arg.startswith("-") and "c" in arg[1:])
               for arg in args):
            return None, False, False
        if args and args[0] == "--":
            args = args[1:]
        candidate = next((arg for arg in args if not arg.startswith("-")), None)
        if candidate and (os.path.splitext(candidate)[1].lower() in SCRIPT_SUFFIXES
                          or "/" in candidate):
            return (_resolve_command_path(candidate, cwd), False,
                    not os.path.isabs(os.path.expanduser(candidate)))
        return None, False, False

    suffix = os.path.splitext(executable)[1].lower()
    if suffix in SCRIPT_SUFFIXES or "/" in executable:
        return (_resolve_command_path(executable, cwd), True,
                not os.path.isabs(os.path.expanduser(executable)))
    return None, False, False


def inspect_app_health(app):
    """静态检查配置是否可运行；只读文件系统，绝不执行或展开用户命令。"""
    if PLATFORM.name == "windows":
        spec = app.get("commandSpec") or legacy_command_spec(
            app.get("command") or "")
        return static_preflight(spec, app.get("cwd"), "windows")
    issues = []

    def add(kind, title, detail, fix, action):
        issues.append({
            "kind": kind,
            "severity": "error",
            "title": title,
            "detail": detail,
            "fix": fix,
            "action": action,
        })

    configured_cwd = app.get("cwd")
    cwd = configured_cwd or os.path.expanduser("~")
    cwd_ok = os.path.isdir(cwd)
    if configured_cwd and not cwd_ok:
        add(
            "cwd-missing", "工作目录不可用",
            "找不到配置的工作目录：%s" % configured_cwd,
            "编辑这个项目，重新选择工作区文件夹。",
            "pick-cwd",
        )

    tokens = _simple_command_tokens(app.get("command") or "")
    if tokens is None:
        return {
            "status": "error" if issues else "unknown",
            "blocking": bool(issues),
            "issues": issues,
        }

    script_path, direct, script_was_relative = _script_target(tokens, cwd)
    if script_path and (cwd_ok or not script_was_relative):
        if not os.path.isfile(script_path):
            add(
                "script-missing", "脚本不可用",
                "找不到脚本：%s" % script_path,
                "编辑这个任务，重新选择脚本或修改执行命令。",
                "pick-script",
            )
        elif not os.access(script_path, os.R_OK):
            add(
                "path-unreadable", "脚本不可读取",
                "当前用户没有读取权限：%s" % script_path,
                "检查脚本权限，或重新选择一个可读取的脚本。",
                "pick-script",
            )
        elif direct and not os.access(script_path, os.X_OK):
            add(
                "script-not-executable", "脚本不可执行",
                "直接运行的脚本没有执行权限：%s" % script_path,
                "给脚本执行权限，或改为使用 bash / python3 执行。",
                "edit-command",
            )

    # 直接脚本已由上面的文件检查覆盖；其他简单命令检查首个运行时。
    index = 0
    while tokens and index < len(tokens) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    executable = tokens[index] if tokens and index < len(tokens) else ""
    executable_base = os.path.basename(executable)
    if executable and not direct and executable_base not in SHELL_BUILTINS:
        if "/" in executable:
            runtime = _resolve_command_path(executable, cwd)
            runtime_ok = os.path.isfile(runtime) and os.access(runtime, os.X_OK)
        else:
            runtime = executable
            runtime_ok = bool(shutil.which(
                executable, path=build_launch_env("health-check").get("PATH")))
        if not runtime_ok:
            add(
                "runtime-missing", "找不到 %s" % executable_base,
                "总控台的运行环境里找不到命令：%s" % executable,
                "安装对应运行时，或在编辑中修改执行命令。",
                "edit-command",
            )

    return {
        "status": "error" if issues else "ok",
        "blocking": bool(issues),
        "issues": issues,
    }


# ---------------------------------------------------------------- 项目启动识别

def _read_project_text(root, name):
    """只读取项目根目录下的小型文本配置；不存在、过大或不可读均返回 None。"""
    path = os.path.join(root, name)
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > MAX_DETECT_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(MAX_DETECT_FILE_BYTES + 1)
    except OSError:
        return None


def _port_from_command(command):
    """从常见 CLI 参数和环境变量中提取显式端口。"""
    patterns = (
        r"(?:^|\s)--port(?:=|\s+)(\d{1,5})(?=\s|$)",
        r"(?:^|\s)-p\s+(\d{1,5})(?=\s|$)",
        r"(?:^|\s)PORT\s*=\s*(\d{1,5})(?=\s|$)",
        r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0):(\d{1,5})",
        r"\bhttp\.server\s+(\d{1,5})(?=\s|$)",
    )
    for pattern in patterns:
        match = re.search(pattern, command, re.IGNORECASE)
        if match:
            port = int(match.group(1))
            if 1 <= port <= 65535:
                return port
    return None


def _package_default_port(script_name, command, dependencies):
    """根据直接依赖和脚本内容给出开发服务器的惯用端口。"""
    haystack = " ".join((script_name, command, " ".join(dependencies))).lower()
    defaults = (
        (("hexo",), 4000),
        (("gatsby",), 8000),
        (("@docusaurus/", "docusaurus"), 3000),
        (("vuepress",), 8080),
        (("docsify",), 3000),
        (("eleventy", "@11ty/eleventy"), 8080),
        (("astro",), 4321),
        (("next", "nextjs"), 3000),
        (("nuxt",), 3000),
        (("react-scripts",), 3000),
        (("vue-cli-service", "@vue/cli-service"), 8080),
        (("vite",), 4173 if script_name == "preview" else 5173),
    )
    for needles, port in defaults:
        if any(needle in haystack for needle in needles):
            return port
    return None


def detect_project(root):
    """只读分析项目根目录，返回可由启动台直接使用的启动候选。"""
    if not isinstance(root, str) or not root.strip():
        return None, "请选择项目文件夹"
    raw_root = root.strip()
    if PLATFORM.name == "windows" and not is_local_windows_path(raw_root):
        return None, "项目文件夹不存在或不可访问"
    root = os.path.abspath(os.path.expanduser(raw_root))
    if not os.path.isdir(root):
        return None, "项目文件夹不存在或不可访问"

    candidates = []
    detected_files = []

    def note_file(name, text=None):
        path = os.path.join(root, name)
        exists = text is not None or os.path.isfile(path)
        if exists and name not in detected_files:
            detected_files.append(name)
        return exists

    def add(command, label, source, port=None, priority=50, detail=None,
            kind="service", command_spec=None):
        if not command or any(item["command"] == command for item in candidates):
            return
        if port is not None and not (isinstance(port, int) and 1 <= port <= 65535):
            port = None
        if command_spec is None:
            command_spec = legacy_command_spec(command)
        command_spec = normalize_command_spec(command_spec)
        if PLATFORM.name == "windows":
            command = display_command(command_spec)
        candidates.append({
            "command": command,
            "commandSpec": command_spec,
            "platformCompatibility": platform_compatibility(
                command_spec, root, PLATFORM.name),
            "label": label,
            "source": source,
            "port": port,
            "kind": "task" if kind == "task" else "service",
            "detail": detail,
            "_priority": priority,
        })

    def native_spec(executable, args=()):
        if PLATFORM.name == "windows":
            return command_spec_for_executable(
                executable, args, platform_name="windows", cwd=root)
        return direct_command_spec(executable, args)

    # Node / 前端 / 博客项目：优先读取 package.json 的 scripts。
    package = {}
    scripts = {}
    deps = set()
    hexo_config = os.path.isfile(os.path.join(root, "_config.yml"))
    is_hexo = hexo_config and (
        os.path.isdir(os.path.join(root, "source")) or
        os.path.isdir(os.path.join(root, "scaffolds")) or
        os.path.isdir(os.path.join(root, "themes")))
    package_text = _read_project_text(root, "package.json")
    if package_text is not None:
        note_file("package.json", package_text)
        try:
            package = json.loads(package_text)
        except (TypeError, ValueError):
            package = {}
        scripts = package.get("scripts") if isinstance(package, dict) else {}
        if not isinstance(scripts, dict):
            scripts = {}
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            values = package.get(key) if isinstance(package, dict) else None
            if isinstance(values, dict):
                deps.update(str(name).lower() for name in values)
        is_hexo = (is_hexo or "hexo" in deps or
                   (isinstance(package, dict) and isinstance(package.get("hexo"), dict)))

        if os.path.isfile(os.path.join(root, "pnpm-lock.yaml")):
            runner = "pnpm run"
            note_file("pnpm-lock.yaml")
        elif (os.path.isfile(os.path.join(root, "bun.lock")) or
              os.path.isfile(os.path.join(root, "bun.lockb"))):
            runner = "bun run"
            note_file("bun.lock" if os.path.isfile(os.path.join(root, "bun.lock")) else "bun.lockb")
        elif os.path.isfile(os.path.join(root, "yarn.lock")):
            runner = "yarn"
            note_file("yarn.lock")
        else:
            runner = "npm run"

        labels = {
            "dev": "开发服务器", "develop": "开发服务器",
            "start": "正式启动", "serve": "本地服务", "server": "本地服务",
            "preview": "本地预览", "docs": "文档站",
            "storybook": "组件预览",
        }
        preferred = ("dev", "develop", "start", "serve", "server", "preview", "docs", "storybook")
        ordered = [name for name in preferred if name in scripts]
        service_name = re.compile(r"(?:^|[:_-])(dev|develop|start|serve|server|preview|watch|docs|storybook|web|blog)(?:$|[:_-])", re.I)
        ordered.extend(name for name in scripts if name not in ordered and service_name.search(str(name)))
        for index, name in enumerate(ordered[:8]):
            script = scripts.get(name)
            if not isinstance(script, str):
                continue
            if is_hexo and str(name).lower() == "server" and re.search(
                    r"\bhexo\s+(?:s|server)\b", script, re.I):
                continue  # 下方提供更短、更通用的 hexo s，不重复同一操作
            command = "%s %s" % (runner, shlex.quote(str(name)))
            port = _port_from_command(script)
            if port is None:
                port = _package_default_port(str(name).lower(), script, deps)
            spec = native_spec(runner.split()[0], [
                *runner.split()[1:], str(name)])
            add(command, labels.get(str(name).lower(), "项目脚本：%s" % name),
                "package.json · scripts.%s" % name, port,
                10 + index, "由项目自己的脚本定义", command_spec=spec)

    # Hexo 即使没有 scripts 也有稳定 CLI：服务与清缓存分别作为服务/任务。
    if is_hexo:
        if hexo_config:
            note_file("_config.yml")
        add("hexo s", "Hexo 本地服务", "Hexo 项目结构", 4000, 8,
            "等同于 hexo server", command_spec=native_spec("hexo", ["s"]))
        add("hexo cl", "Hexo 清除缓存", "Hexo 项目结构", None, 9,
            "清除缓存和已生成文件，不启动服务", kind="task",
            command_spec=native_spec("hexo", ["cl"]))

    # 常见博客与静态站点生成器。
    hugo_config = next((name for name in ("hugo.toml", "hugo.yaml", "hugo.yml")
                        if os.path.isfile(os.path.join(root, name))), None)
    if hugo_config or (os.path.isdir(os.path.join(root, "content")) and
                       os.path.isdir(os.path.join(root, "layouts")) and
                       os.path.isfile(os.path.join(root, "config.toml"))):
        source = hugo_config or "config.toml"
        note_file(source)
        add("hugo server -D", "Hugo 本地预览", source, 1313, 18,
            "包含草稿内容",
            command_spec=native_spec("hugo", ["server", "-D"]))

    gemfile = _read_project_text(root, "Gemfile")
    if gemfile is not None:
        note_file("Gemfile", gemfile)
        if "jekyll" in gemfile.lower():
            add("bundle exec jekyll serve", "Jekyll 本地预览", "Gemfile", 4000, 19,
                command_spec=native_spec("bundle", ["exec", "jekyll", "serve"]))

    # Python Web 项目。
    pyproject = _read_project_text(root, "pyproject.toml")
    requirements = _read_project_text(root, "requirements.txt")
    if pyproject is not None:
        note_file("pyproject.toml", pyproject)
    if requirements is not None:
        note_file("requirements.txt", requirements)
    py_deps = "\n".join(text for text in (pyproject, requirements) if text).lower()
    python_runner = "uv run" if os.path.isfile(os.path.join(root, "uv.lock")) else "python3 -m"
    if os.path.isfile(os.path.join(root, "uv.lock")):
        note_file("uv.lock")
    if os.path.isfile(os.path.join(root, "manage.py")):
        note_file("manage.py")
        prefix = "uv run python" if python_runner == "uv run" else "python3"
        django_spec = (native_spec("uv", ["run", "python", "manage.py", "runserver"])
                       if python_runner == "uv run" else
                       python_command_spec(
                           ["manage.py", "runserver"],
                           platform_name=PLATFORM.name,
                           current_executable=sys.executable,
                           current_version=sys.version_info[:2],
                           frozen=bool(getattr(sys, "frozen", False))))
        add(prefix + " manage.py runserver", "Django 开发服务器", "manage.py", 8000, 20,
            command_spec=django_spec)
    else:
        for module_file in ("app.py", "main.py", "server.py"):
            module_text = _read_project_text(root, module_file)
            if module_text is None:
                continue
            module = os.path.splitext(module_file)[0]
            imports_streamlit = re.search(
                r"(?m)^\s*(?:import\s+streamlit\b|from\s+streamlit\b)", module_text)
            imports_fastapi = re.search(
                r"(?m)^\s*(?:import\s+fastapi\b|from\s+fastapi\b)", module_text)
            imports_flask = re.search(
                r"(?m)^\s*(?:import\s+flask\b|from\s+flask\b)", module_text)
            if "streamlit" in py_deps or imports_streamlit:
                note_file(module_file, module_text)
                prefix = "uv run" if python_runner == "uv run" else "python3 -m"
                streamlit_spec = (native_spec("uv", ["run", "streamlit", "run", module_file])
                                  if python_runner == "uv run" else
                                  python_command_spec(
                                      ["-m", "streamlit", "run", module_file],
                                      platform_name=PLATFORM.name,
                                      current_executable=sys.executable,
                                      current_version=sys.version_info[:2],
                                      frozen=bool(getattr(sys, "frozen", False))))
                add(prefix + " streamlit run " + module_file,
                    "Streamlit 应用", module_file, 8501, 22,
                    command_spec=streamlit_spec)
                break
            if "fastapi" in py_deps or imports_fastapi:
                note_file(module_file, module_text)
                prefix = "uv run" if python_runner == "uv run" else "python3 -m"
                uvicorn_args = ["uvicorn", "%s:app" % module, "--reload"]
                fastapi_spec = (native_spec("uv", ["run", *uvicorn_args])
                                if python_runner == "uv run" else
                                python_command_spec(
                                    ["-m", *uvicorn_args],
                                    platform_name=PLATFORM.name,
                                    current_executable=sys.executable,
                                    current_version=sys.version_info[:2],
                                    frozen=bool(getattr(sys, "frozen", False))))
                add(prefix + " uvicorn %s:app --reload" % module,
                    "FastAPI 开发服务器", module_file, 8000, 23,
                    command_spec=fastapi_spec)
                break
            if "flask" in py_deps or imports_flask:
                note_file(module_file, module_text)
                prefix = "uv run" if python_runner == "uv run" else "python3 -m"
                flask_args = ["flask", "--app", module, "run", "--debug"]
                flask_spec = (native_spec("uv", ["run", *flask_args])
                              if python_runner == "uv run" else
                              python_command_spec(
                                  ["-m", *flask_args],
                                  platform_name=PLATFORM.name,
                                  current_executable=sys.executable,
                                  current_version=sys.version_info[:2],
                                  frozen=bool(getattr(sys, "frozen", False))))
                add(prefix + " flask --app %s run --debug" % module,
                    "Flask 开发服务器", module_file, 5000, 24,
                    command_spec=flask_spec)
                break

    # Docker Compose、Go、Rust 和已有的常用启动脚本。
    compose_name = next((name for name in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
                         if os.path.isfile(os.path.join(root, name))), None)
    if compose_name:
        compose_text = _read_project_text(root, compose_name)
        note_file(compose_name, compose_text)
        port = None
        if compose_text:
            match = re.search(r"[\"']?(\d{2,5})\s*:\s*\d{2,5}[\"']?", compose_text)
            if match and 1 <= int(match.group(1)) <= 65535:
                port = int(match.group(1))
        add("docker compose up", "Docker Compose", compose_name, port, 55,
            "以前台方式运行，停止按钮可正常关闭",
            command_spec=native_spec("docker", ["compose", "up"]))
    if os.path.isfile(os.path.join(root, "go.mod")):
        note_file("go.mod")
        add("go run .", "Go 项目", "go.mod", None, 60,
            command_spec=native_spec("go", ["run", "."]))
    if os.path.isfile(os.path.join(root, "Cargo.toml")):
        note_file("Cargo.toml")
        add("cargo run", "Rust 项目", "Cargo.toml", None, 61,
            command_spec=native_spec("cargo", ["run"]))

    script_names = (
        ("start.cmd", "dev.cmd", "run.cmd",
         "start.bat", "dev.bat", "run.bat",
         "start.ps1", "dev.ps1", "run.ps1",
         "start.command", "dev.command", "run.command",
         "start.sh", "dev.sh", "run.sh")
        if PLATFORM.name == "windows" else
        ("start.command", "dev.command", "run.command",
         "start.sh", "dev.sh", "run.sh")
    )
    for script_name in script_names:
        if os.path.isfile(os.path.join(root, script_name)):
            note_file(script_name)
            script_spec = command_spec_for_script(
                os.path.join(root, script_name), PLATFORM.name)
            command = (display_command(script_spec)
                       if PLATFORM.name == "windows"
                       else "bash %s" % shlex.quote("./" + script_name))
            add(command,
                "现有启动脚本", script_name, None, 70,
                "也可以继续使用“选择脚本”手动指定",
                command_spec=script_spec)
            if PLATFORM.name != "windows":
                break

    # 纯静态站点最后兜底，避免把 Vite/Next 等项目误当成普通文件目录。
    if not candidates and os.path.isfile(os.path.join(root, "index.html")):
        note_file("index.html")
        add("python3 -m http.server 8000", "静态网站预览", "index.html", 8000, 90,
            command_spec=python_command_spec(
                ["-m", "http.server", "8000"],
                platform_name=PLATFORM.name,
                current_executable=sys.executable,
                current_version=sys.version_info[:2],
                frozen=bool(getattr(sys, "frozen", False))))

    candidates.sort(key=lambda item: item.pop("_priority"))
    return {
        "ok": True,
        "cwd": root,
        "name": os.path.basename(root) or root,
        "files": detected_files,
        "candidates": candidates[:8],
    }, None


def _current_user_group_members(pgid):
    """Return live current-user members of a previously verified group.

    Once SIGTERM is sent the token-bearing controller may exit before a child
    that ignores SIGTERM.  Requiring the marker again would incorrectly report
    success, so the wait phase follows the already-verified PGID until empty.
    """
    members = pgid_members_map().get(pgid, [])
    if not members:
        return []
    snap = ps_snapshot(members, with_uid=True)
    return sorted(pid for pid in members
                  if process_owned_by_current(snap.get(pid)))


def resolve_app_stop_target(app, listeners=None):
    """Resolve and validate a stop target before any signal is sent."""
    current = managed_pids(app)
    if current:
        pgid = app.get("lastPgid") or app.get("lastPid")
        if isinstance(pgid, int) and pgid > 0:
            return {"kind": "group", "id": pgid, "members": list(current)}, None
        return None, "受控进程组信息无效"
    legacy_pid = legacy_managed_pid(app, listeners)
    if legacy_pid:
        if app.get("attached"):
            pgid = PLATFORM.process_group_id(legacy_pid)
            own_group = PLATFORM.current_process_group_id()
            if isinstance(pgid, int) and pgid > 0 and pgid != own_group:
                members = _current_user_group_members(pgid)
                member_cwds = lsof_cwds(members)
                expected_cwd = app.get("cwd")
                try:
                    safe_group = bool(members and expected_cwd) and all(
                        member_cwds.get(pid)
                        and os.path.realpath(member_cwds[pid])
                        == os.path.realpath(expected_cwd)
                        for pid in members
                    )
                except OSError:
                    safe_group = False
                if safe_group:
                    return {
                        "kind": "group",
                        "id": pgid,
                        "members": list(members),
                    }, None
        return {"kind": "pid", "id": legacy_pid, "members": [legacy_pid]}, None
    return None, "无法确认受控进程，未执行停止"


def signal_app_stop(target, sig=signal.SIGTERM):
    """Signal a target returned by resolve_app_stop_target."""
    identity = RuntimeIdentity(
        PLATFORM.name,
        target["kind"],
        target["id"],
        SELF_PRINCIPAL.identifier,
        tuple(target.get("members") or ()),
    )
    result = PLATFORM.stop_managed(
        identity, force=sig == getattr(signal, "SIGKILL", None)
    )
    return result.ok, result.error


def stop_target_alive(target, expected_uid=None):
    if target["kind"] == "group":
        return bool(_current_user_group_members(target["id"]))
    if not PLATFORM.pid_alive(target["id"]):
        return False
    if expected_uid is None:
        expected_uid = process_uid(target["id"])
    return expected_uid in (SELF_UID, SELF_PRINCIPAL.identifier)


def stop_app_and_wait(app, timeout=APP_STOP_TIMEOUT_SEC, listeners=None):
    """Signal a verified app and wait until the exact target is gone.

    Returns (ok, error).  A timeout is deliberately not escalated to SIGKILL;
    the caller keeps the runtime token so the user can retry or choose a force
    action without losing control of a still-live process.
    """
    target, error = resolve_app_stop_target(app, listeners)
    if target is None:
        return False, error
    ok, error = signal_app_stop(target)
    if not ok:
        return False, error
    deadline = time.monotonic() + max(0.0, timeout)
    # uid 只查一次：信号已在循环外发出，循环仅做存活探测，
    # 避免 50ms 一次的 ps 子进程（PID 复用时最坏多等一个超时周期，无副作用）。
    expected_uid = (process_uid(target["id"]) if target["kind"] == "pid"
                    else None)
    while stop_target_alive(target, expected_uid):
        if time.monotonic() >= deadline:
            remaining = (target["members"] if target["kind"] == "pid"
                         else _current_user_group_members(target["id"]))
            suffix = "（PID %s）" % "、".join(str(p) for p in remaining) if remaining else ""
            return False, "应用未在 %.1f 秒内退出%s，仍保留管理状态" % (timeout, suffix)
        time.sleep(0.05)
    return True, None


def stop_app_and_clear(cfg, app, timeout=APP_STOP_TIMEOUT_SEC, listeners=None):
    """Manual stop transaction: wait first, clear persisted identity last."""
    marker = (app.get("id"), app.get("runToken"))
    with MANUAL_STOP_LOCK:
        MANUAL_STOP_TOKENS.add(marker)
    try:
        ok, error = stop_app_and_wait(app, timeout, listeners)
        if not ok:
            return False, error
        last_exit = None
        if (app.get("kind") or "service") == "task":
            # 覆盖可能保留的旧成功记录，避免“刚刚手动停止”仍显示上次成功。
            last_exit = {
                "status": "stopped",
                "code": None,
                "at": int(time.time()),
            }
        if not clear_app_runtime(
                cfg, app["id"], app.get("runToken"), last_exit=last_exit):
            return False, "进程已停止，但应用状态已变化，请刷新后重试"
        return True, None
    finally:
        with MANUAL_STOP_LOCK:
            MANUAL_STOP_TOKENS.discard(marker)


def inspect_attach_process(cfg, app, pid):
    """只读校验待认领进程，返回其可信工作目录。

    创建卡片时先调用本函数，再把卡片与运行身份一次写入配置，避免前端
    “先创建、再认领”只完成一半。已有卡片的手动认领也复用同一套校验。"""
    if (app.get("kind") or "service") != "service":
        return False, "批处理任务没有端口，无法认领进程", {"status": 422}
    port = app.get("port")
    if not isinstance(port, int) or port <= 0:
        return False, "卡片未配置端口，无法认领进程", {"status": 422}
    if app_alive_sign(app):
        return False, "应用已在运行", {"status": 409}
    if pid == os.getpid():
        return False, "不能认领总控台自身", {"status": 409}
    listeners = scan_listeners()
    if (pid, port) not in listeners:
        return False, "PID %d 并未监听端口 %d，进程可能已退出" % (pid, port), {"status": 409}
    snap = ps_snapshot({pid}, with_uid=True)
    if not process_owned_by_current(snap.get(pid)):
        return False, "该进程不属于当前用户，不能认领", {"status": 403}
    cfg_now = cfg.snapshot()
    owners = listener_app_owners(cfg_now.get("apps") or [], listeners, snap, None)
    if pid in owners:
        return False, "该进程已由卡片「%s」管理" % owners[pid].get("name", ""), {"status": 409}
    actual_cwd = lsof_cwds({pid}).get(pid)
    if not actual_cwd:
        return False, "无法读取进程工作目录，已取消认领", {"status": 409}
    return True, None, {"status": 200, "cwd": actual_cwd}


def attach_app_process(cfg, app_id, app, pid):
    """把已在监听配置端口的当前用户进程认领为本卡片受管进程。

    认领走旧版身份通道（lastPid + 监听端口 + 当前 UID + 真实 cwd 四重校验），
    与卡片 cwd 不一致时原子同步卡片 cwd。认领后卡片显示运行中，可正常
    停止/重启（重启后转为 token 受管）。返回 (ok, error, info)。"""
    ok, error, identity = inspect_attach_process(cfg, app, pid)
    if not ok:
        return False, error, identity
    actual_cwd = identity["cwd"]
    cwd_updated = False
    pid_conflict = False

    def op(c):
        nonlocal cwd_updated, pid_conflict
        target = find_app(c, app_id)
        if not target:
            return False
        # 认领检查与写入必须同锁：inspect 用的是旧快照，并发请求可能同时
        # 通过校验。在写锁内重验 pid 是否已被其他卡片认领。
        if any(other.get("lastPid") == pid
               for other in c.get("apps") or [] if other.get("id") != app_id):
            pid_conflict = True
            return False
        target["lastPid"] = pid
        target["lastPgid"] = None
        target["runToken"] = None
        target["attached"] = True
        target["lastExit"] = None
        try:
            same = (isinstance(target.get("cwd"), str) and target["cwd"]
                    and os.path.realpath(target["cwd"]) == os.path.realpath(actual_cwd))
        except OSError:
            same = False
        if not same:
            target["cwd"] = actual_cwd
            cwd_updated = True
        return True

    if not cfg.update(op):
        if pid_conflict:
            return False, "该进程已由其他卡片管理", {"status": 409}
        return False, "应用已被删除", {"status": 404}
    info = {}
    if cwd_updated:
        info["cwdUpdated"] = True
        info["cwd"] = actual_cwd
    return True, None, info


# ---------------------------------------------------------------- 日志

def append_app_log(app_id, message):
    """Append one UTF-8 controller event to an ACL-protected app log."""
    if not isinstance(app_id, str) or not re.fullmatch(r"[0-9a-fA-F]{8}", app_id):
        return False
    _ensure_private_dir(LOGS_DIR)
    path = os.path.join(LOGS_DIR, "%s.log" % app_id)
    rotate_log_file(path)
    text = str(message).replace("\r", " ").replace("\n", " ").strip()
    line = ("[%s] [Local Ops] %s\n" %
            (time.strftime("%Y-%m-%d %H:%M:%S"), text[:2000])).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    with LOG_LOCK:
        if os.path.lexists(path) and (
                os.path.islink(path) or not os.path.isfile(path)):
            raise OSError("应用日志路径不是普通文件")
        fd = os.open(path, flags, 0o600)
        try:
            PLATFORM.ensure_private_file(path)
            os.write(fd, line)
        finally:
            os.close(fd)
        PLATFORM.ensure_private_file(path)
    return True


def record_app_action(app, action, result):
    """Persist the observable outcome of an external controller operation."""
    ok = bool(result.get("ok"))
    message = "%s%s" % (action, "成功" if ok else "失败")
    code = result.get("code")
    error = result.get("error")
    if code:
        message += " [%s]" % code
    if error:
        message += "：%s" % error
    try:
        append_app_log(app.get("id"), message)
    except OSError:
        LOG.exception("写入应用控制日志失败: %s", app.get("id"))

def rotate_log_file(path, max_bytes=MAX_LOG_BYTES, backups=LOG_BACKUPS):
    """超限后 copy-truncate，保持子进程已打开的文件描述符继续可写。"""
    with LOG_LOCK:
        try:
            if os.path.getsize(path) <= max_bytes:
                return False
        except OSError:
            return False
        try:
            for index in range(backups, 1, -1):
                older = "%s.%d" % (path, index - 1)
                newer = "%s.%d" % (path, index)
                if os.path.exists(older):
                    os.replace(older, newer)
            shutil.copyfile(path, path + ".1")
            os.chmod(path + ".1", 0o600)
            with open(path, "r+b") as f:
                f.truncate(0)
            os.chmod(path, 0o600)
            return True
        except OSError:
            LOG.exception("轮转日志失败: %s", path)
            return False


def _decode_log_bytes(data):
    """Decode UTF logs first, then legacy Simplified-Chinese Windows output."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    decoded = []
    for line in data.splitlines():
        try:
            decoded.append(line.decode("utf-8-sig"))
        except UnicodeDecodeError:
            try:
                decoded.append(line.decode("gb18030"))
            except UnicodeDecodeError:
                decoded.append(line.decode("utf-8", errors="replace"))
    return "\n".join(decoded)


def _tail_file_lines(path, count, block_size=65536):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            chunks = []
            newlines = 0
            while pos > 0 and newlines <= count:
                size = min(block_size, pos)
                pos -= size
                f.seek(pos)
                chunk = f.read(size)
                if not chunk.strip(b"\x00"):
                    break  # 空洞/被外部截断后残留的 NUL 段：之前没有内容，停止回扫
                chunks.append(chunk)
                newlines += chunk.count(b"\n")
        data = b"".join(reversed(chunks))
        return _decode_log_bytes(data).splitlines()[-count:]
    except OSError:
        return []


def read_log_tail(app_id, count):
    """从当前日志和轮转备份中高效读取最后 count 行。"""
    path = os.path.join(LOGS_DIR, "%s.log" % app_id)
    rotate_log_file(path)
    collected = []
    with LOG_LOCK:
        for candidate in [path] + ["%s.%d" % (path, i)
                                   for i in range(1, LOG_BACKUPS + 1)]:
            remaining = count - len(collected)
            if remaining <= 0:
                break
            lines = _tail_file_lines(candidate, remaining)
            collected = lines + collected
    return "\n".join(collected[-count:])


SCHEDULED_TASK_EVENT_LABELS = {
    100: "任务已启动",
    101: "任务启动失败",
    102: "任务已完成",
    107: "触发器已触发",
    108: "事件触发器已触发",
    110: "用户请求运行",
    111: "任务已终止",
    118: "系统启动触发器已触发",
    119: "登录触发器已触发",
    129: "已创建任务进程",
    140: "任务定义已更新",
    141: "任务已删除",
    142: "任务已禁用",
    200: "操作已启动",
    201: "操作已完成",
    202: "操作失败",
    203: "操作启动失败",
    204: "操作完成失败",
}


def _scheduled_task_event_line(event):
    event_id = int(event.get("eventId") or 0)
    label = SCHEDULED_TASK_EVENT_LABELS.get(event_id, "计划任务事件")
    timestamp = event.get("timestamp")
    when = (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        if isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool)
        else "时间未知"
    )
    details = []
    action = event.get("actionName")
    if action:
        details.append("操作 %s" % action)
    process_id = event.get("processId")
    if isinstance(process_id, int) and not isinstance(process_id, bool):
        details.append("PID %d" % process_id)
    result = event.get("resultCode")
    if isinstance(result, int) and not isinstance(result, bool):
        unsigned = result & 0xFFFFFFFF
        details.append(
            "结果 0x%08X（%s）" % (
                unsigned, "成功" if unsigned == 0 else "失败",
            )
        )
    suffix = " · " + " · ".join(details) if details else ""
    return "[%s] %s (Event %d)%s" % (when, label, event_id, suffix)


def scheduled_task_log_data(app, count):
    path = scheduled_task_path(app)
    if not path:
        return [], {"applicable": False}
    try:
        snapshot = PLATFORM.scheduled_tasks({path})
        task = snapshot.tasks.get(path.casefold())
    except Exception as exc:
        task = None
        state_error = "[Local Ops] Windows 计划任务状态读取失败：%s" % exc
    else:
        state_error = None

    try:
        event_snapshot = PLATFORM.scheduled_task_events(path, count)
    except Exception as exc:
        event_snapshot = None
        event_error = {
            "code": "query_failed", "message": str(exc),
        }
    else:
        event_error = None

    events = list(getattr(event_snapshot, "events", ()) or ())
    events.sort(key=lambda event: (
        int(event.get("timestamp") or 0), int(event.get("recordId") or 0)
    ))
    event_issues = [
        {"code": issue.code, "message": issue.message}
        for issue in (getattr(event_snapshot, "issues", ()) or ())
    ]
    if event_error:
        event_issues.append(event_error)
    history_enabled = getattr(event_snapshot, "history_enabled", None)
    history_status = getattr(event_snapshot, "status", ScanStatus.FAILED)
    meta = {
        "applicable": True,
        "enabled": history_enabled,
        "available": history_status is not ScanStatus.FAILED,
        "partial": history_status is ScanStatus.PARTIAL,
        "eventCount": len(events),
        "issues": event_issues,
    }
    lines = ["=== Windows 计划任务运行时间线 ==="]
    if history_enabled is False:
        lines.append(
            "[Local Ops] Windows 计划任务历史记录未启用；"
            "启用后会记录后续每次触发、启动、操作和完成事件。"
        )
    if events:
        lines.extend(_scheduled_task_event_line(event) for event in events)
    elif event_error or history_status is ScanStatus.FAILED:
        detail = event_issues[0]["message"] if event_issues else "事件查询失败"
        lines.append("[Local Ops] 计划任务事件读取失败：%s" % detail)
    else:
        lines.append("[Local Ops] 尚无该计划任务的历史事件。")

    lines.append("=== Windows 计划任务当前状态 ===")
    if state_error:
        lines.append(state_error)
        return lines, meta
    if not isinstance(task, dict) or task.get("state") == "missing":
        lines.append("[Local Ops] Windows 计划任务不存在：%s" % path)
        return lines, meta
    meta["state"] = str(task.get("state") or "unknown")
    state_label = {
        "ready": "就绪", "running": "运行中", "queued": "排队中",
        "disabled": "已禁用", "missing": "不存在", "unknown": "未知",
    }.get(str(task.get("state") or "unknown"), "未知")
    lines.extend([
        "Windows 计划任务：%s" % path,
        "状态：%s" % state_label,
    ])
    last_run = task.get("lastRunAt")
    if isinstance(last_run, (int, float)) and not isinstance(last_run, bool):
        meta["lastRunAt"] = last_run
        lines.append("上次运行：%s" % time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(last_run)
        ))
    result = task.get("lastResult")
    if isinstance(result, int) and not isinstance(result, bool):
        unsigned = result & 0xFFFFFFFF
        meta["lastResult"] = unsigned
        if unsigned == 0:
            result_label = "成功"
        elif unsigned == 0x00041301:
            result_label = "运行中"
        else:
            result_label = "失败"
        lines.append("最近结果：%s (0x%08X)" % (result_label, unsigned))
    return lines, meta


def scheduled_task_log_lines(app, count=300):
    return scheduled_task_log_data(app, count)[0]


def read_app_log_payload(app, count):
    """Combine controller events with logs owned by an external runtime."""
    controller_lines = read_log_tail(app.get("id"), count).splitlines()
    lines = []
    if controller_lines:
        lines.append("=== Local Ops 控制记录 ===")
        lines.extend(controller_lines)
    task_history = {"applicable": False}
    resource = docker_resource(app)
    if resource:
        result = DOCKER.logs(resource, count)
        if getattr(result, "ok", False):
            lines.extend(str(getattr(result, "text", "") or "").splitlines())
        else:
            code = getattr(result, "code", None) or "DOCKER_LOG_FAILED"
            error = getattr(result, "error", None) or "Docker 日志读取失败"
            lines.append("[Local Ops] Docker 日志读取失败 [%s]：%s" % (code, error))
    elif scheduled_task_path(app):
        scheduled_lines, task_history = scheduled_task_log_data(app, count)
        lines.extend(scheduled_lines)
    return {
        "text": "\n".join(lines[-count:]),
        "taskHistory": task_history,
    }


def read_app_log(app, count):
    return read_app_log_payload(app, count)["text"]


def start_log_maintenance():
    def _maintain():
        while True:
            try:
                for name in os.listdir(LOGS_DIR):
                    if name.endswith(".log"):
                        rotate_log_file(os.path.join(LOGS_DIR, name))
            except OSError:
                LOG.exception("日志维护失败")
            time.sleep(LOG_MAINTENANCE_SEC)
    threading.Thread(target=_maintain, daemon=True).start()


def sniff_image(data):
    """magic bytes 校验 → "png" / "jpg" / "webp" / None。"""
    if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def extract_program_icon(app_id, app):
    if (app.get("kind") != "program" or app.get("glyph") or app.get("icon")):
        return None
    command_spec = app.get("commandSpec")
    if not isinstance(command_spec, dict) or command_spec.get("mode") != "direct":
        return None
    executable = command_spec.get("executable")
    if not isinstance(executable, str) or not executable.casefold().endswith(".exe"):
        return None
    try:
        payload = PLATFORM.extract_executable_icon(executable)
    except (OSError, TypeError, ValueError):
        LOG.exception("program icon extraction failed for app %s", app_id)
        return None
    if not payload or sniff_image(payload) != "png" or len(payload) > MAX_ICON_BYTES:
        return None
    _ensure_private_dir(ICONS_DIR)
    path = os.path.join(ICONS_DIR, app_id + ".png")
    try:
        write_private_bytes(path, payload)
    except OSError:
        LOG.exception("program icon storage failed for app %s", app_id)
        return None
    app["icon"] = "/icons/" + app_id + ".png"
    return path


# ---------------------------------------------------------------- 站点图标抓取

ICON_LINK_RE = re.compile(
    r"<link[^>]+rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*>", re.I)
HREF_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)


def is_loopback_service_url(url, port):
    """仅允许抓取指定端口的明文 loopback URL，避免 favicon SSRF。"""
    try:
        parsed = urllib.parse.urlsplit(url)
        return (parsed.scheme == "http"
                and (parsed.hostname or "").lower() in (
                    "127.0.0.1", "localhost", "::1")
                and parsed.port == port
                and not parsed.username and not parsed.password)
    except (TypeError, ValueError, UnicodeError):
        return False


class LoopbackRedirectHandler(urllib.request.HTTPRedirectHandler):
    """只跟随仍停留在同一 loopback 端口的重定向。"""

    def __init__(self, port):
        super().__init__()
        self.port = port

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_loopback_service_url(newurl, self.port):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get(url, port, timeout=3, limit=262144):
    """GET → (bytes, content-type) | (None, None)。仅抓同一 loopback 端口。"""
    if not is_loopback_service_url(url, port):
        return None, None
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Console/1.0", "Accept": "*/*"})
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), LoopbackRedirectHandler(port))
        with opener.open(req, timeout=timeout) as r:
            return r.read(limit), (r.headers.get("Content-Type") or "")
    except Exception:
        return None, None


def sniff_icon_bytes(data, ctype=""):
    """→ "png" / "jpg" / "webp" / "ico" / None。拒绝主动 SVG 内容。"""
    if len(data) >= 4 and data[:4] == b"\x00\x00\x01\x00":
        return "ico"
    ext = sniff_image(data)
    if ext:
        return ext
    return None


def fetch_favicon(port, host="127.0.0.1"):
    """抓本地站点图标 → (bytes, ext) | (None, None)。
    先解析首页 <link rel=...icon...>（含 apple-touch-icon），兜底 /favicon.ico。"""
    if host not in ("127.0.0.1", "localhost"):
        host = "127.0.0.1"
    base = "http://%s:%d" % (host, port)
    candidates = []
    html, _ = http_get(base + "/", port)
    if html:
        text = html.decode("utf-8", errors="replace")
        for m in ICON_LINK_RE.finditer(text):
            hm = HREF_RE.search(m.group(0))
            if hm:
                url = urllib.parse.urljoin(base + "/", hm.group(1))
                if is_loopback_service_url(url, port):
                    candidates.append(url)
    candidates.append(base + "/favicon.ico")
    for url in candidates[:4]:
        data, ctype = http_get(url, port, limit=1024 * 1024)
        if data:
            ext = sniff_icon_bytes(data, ctype)
            if ext:
                return data, ext
    return None, None


def find_app(cfg, app_id):
    for app in cfg.get("apps") or []:
        if app.get("id") == app_id:
            return app
    return None


def diagnose_app(cfg, app):
    """规则诊断：退出码 + 日志模式 + 文件系统检查 → 可执行的修复建议列表。

    覆盖常见失败：依赖未装、命令/脚本不存在、运行时缺失、npm 脚本名错误、
    端口占用、权限不足、Python 包缺失。
    """
    issues = []

    def add(kind, title, detail, fix, action=None):
        if not any(i["kind"] == kind for i in issues):
            issue = {"kind": kind, "title": title,
                     "detail": detail, "fix": fix}
            if action:
                issue["action"] = action
            issues.append(issue)

    app_id = app.get("id") or ""
    cwd = app.get("cwd") or ""
    last_exit = app.get("lastExit") or {}
    code = last_exit.get("code")
    port = app.get("port")
    log_payload = read_app_log_payload(app, 150) if app_id else {
        "text": "", "taskHistory": {"applicable": False},
    }
    log_tail = log_payload["text"]
    task_history = log_payload.get("taskHistory") or {}
    log_lower = log_tail.lower()

    # ---- 配置层检查（不依赖日志） ----
    for health_issue in inspect_app_health(app).get("issues", []):
        add(
            health_issue["kind"],
            health_issue["title"],
            health_issue["detail"],
            health_issue["fix"],
            health_issue.get("action"),
        )

    pkg_json = os.path.join(cwd, "package.json") if cwd else ""
    has_pkg = bool(cwd) and os.path.isfile(pkg_json)
    has_node_modules = bool(cwd) and os.path.isdir(os.path.join(cwd, "node_modules"))
    if has_pkg and not has_node_modules:
        mgr = ("yarn" if os.path.isfile(os.path.join(cwd, "yarn.lock"))
               else "pnpm" if os.path.isfile(os.path.join(cwd, "pnpm-lock.yaml"))
               else "npm")
        add("deps-missing", "依赖未安装（node_modules 缺失）",
            "目录里有 package.json，但没有 node_modules。",
            "终端执行：cd \"%s\" && %s install，装完再启动。" % (cwd, mgr))

    # ---- 日志模式匹配 ----
    m = re.search(r"cannot find module '([^']+)'", log_lower)
    if m:
        add("deps-missing", "找不到模块 %s" % m.group(1),
            "日志报 Cannot find module '%s'，通常是依赖没装或装坏了。" % m.group(1),
            "终端执行：cd \"%s\" && npm install（仍报错再 rm -rf node_modules 后重装）。" % (cwd or "<项目目录>"))

    m = re.search(r"(?:env: )?(\S+): (?:no such file or directory|command not found)", log_lower)
    if m and "cannot find module" not in log_lower:
        add("runtime-missing", "找不到运行时：%s" % m.group(1),
            "系统里找不到 %s 这个命令。" % m.group(1),
            "确认该运行时已安装（如 node / python3 / pnpm）；总控台启动时会补常见 PATH，但程序本身需要存在。")

    if "missing script" in log_lower and has_pkg:
        script_names = []
        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                script_names = list((json.load(f).get("scripts") or {}).keys())
        except Exception:
            pass
        hint = ("package.json 里可用的脚本：%s。" % "、".join(script_names)
                if script_names else "package.json 里没有 scripts。")
        add("npm-script", "npm 脚本名写错了",
            "日志报 missing script。%s" % hint,
            "把启动命令改成上面列出的脚本名，例如 npm run %s。" % (script_names[0] if script_names else "dev"))

    if "eaddrinuse" in log_lower or "address already in use" in log_lower:
        add("port-busy", "端口被占用",
            "日志报地址已占用%s。" % ("（:%s）" % port if port else ""),
            "点卡片上的端口数字看是谁占用的，停掉它或给本应用换个端口。")

    if "eacces" in log_lower or "permission denied" in log_lower:
        add("perm", "权限不足",
            "日志报权限不足（EACCES / permission denied）。",
            "检查文件/目录权限；脚本需要可执行权限：chmod +x <脚本>。不要简单用 sudo 运行。")

    m = re.search(r"modulenotfounderror: no module named '([^']+)'", log_lower)
    if m:
        add("pip-missing", "缺少 Python 包：%s" % m.group(1),
            "日志报 ModuleNotFoundError: No module named '%s'。" % m.group(1),
            "建议在项目目录建虚拟环境再装：python3 -m venv .venv && .venv/bin/pip install %s" % m.group(1))

    task_result = task_history.get("lastResult")
    if (task_history.get("applicable") and isinstance(task_result, int)
            and not isinstance(task_result, bool)
            and task_result not in (0, 0x00041301)):
        add(
            "scheduled-task-failed",
            "Windows 计划任务最近一次运行失败",
            "Task Scheduler 最近结果为 0x%08X。" % task_result,
            "打开完整日志查看运行时间线，并检查任务动作、账户权限与脚本退出码。",
        )

    if re.search(r"no such file or directory", log_lower) and not issues:
        add("file-missing", "命令里的文件/脚本不存在",
            "日志报 No such file or directory，命令里引用的路径可能写错了。",
            "检查启动命令和工作目录里的相对路径是否正确。")

    # ---- 退出码兜底 ----
    if not issues:
        if code == 126:
            add("not-exec", "命令没有执行权限（exit 126）",
                "退出码 126 表示文件不可执行。",
                "给脚本加执行权限：chmod +x <脚本>，或用 bash <脚本> 启动。")
        elif code == 127:
            add("not-found", "命令不存在（exit 127）",
                "退出码 127 表示 shell 找不到这个命令。",
                "确认命令已安装且在 PATH 里；总控台会补常见路径，但程序本身要存在。")
        elif (isinstance(code, int) and code == 0
              and (app.get("kind") or "service") != "task"):
            add("quick-exit", "命令立即正常退出（exit 0）",
                "进程启动后马上正常结束——长期服务命令不应立刻退出。",
                "确认写的是常驻命令（如 hexo s / npm run dev），而不是一次就完成的命令。")
        elif isinstance(code, int) and code < 0:
            add("signaled", "进程被信号终止（signal %d）" % -code,
                "进程不是自然退出，是被系统信号杀掉的。",
                "常见于内存不足被系统回收或外部 kill；查看系统日志确认原因。")

    # ---- 汇总 ----
    if issues:
        summary = "发现 %d 个可能原因，按「修复建议」处理后再启动。" % len(issues)
    elif not log_tail.strip():
        summary = "暂无日志可供诊断；先启动一次让日志产生，再看完整日志定位。"
    elif code is None:
        summary = "该应用还没有退出记录；当前日志未见明显异常。"
    else:
        summary = "日志里没有命中常见错误模式，建议打开完整日志人工排查。"
    return {"ok": True, "issues": issues, "summary": summary}


def validate_port(value):
    """→ (port|None, error|None)。接受 null / 整数 / 数字字符串，范围 1-65535。"""
    if value is None or value == "":
        return None, None
    if isinstance(value, bool):
        return None, "port 必须是 1-65535 的整数"
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.strip().isdigit():
        port = int(value.strip())
    else:
        return None, "port 必须是 1-65535 的整数"
    if not (1 <= port <= 65535):
        return None, "port 必须在 1-65535 之间"
    return port, None


def normalize_scheduled_task_path(value):
    if value is None or value == "":
        return None, None
    if not isinstance(value, str):
        return None, "scheduledTaskPath 必须是字符串或 null"
    if any(ord(char) < 32 for char in value) or '"' in value:
        return None, "scheduledTaskPath 包含非法字符"
    normalized = "\\" + value.strip().replace("/", "\\").lstrip("\\")
    parts = normalized.split("\\")[1:]
    if (len(normalized) > 512 or not parts or any(
            not part or part in (".", "..") for part in parts)):
        return None, "scheduledTaskPath 不是有效的 Windows 计划任务路径"
    return normalized, None


def scheduled_task_command(path):
    return 'schtasks.exe /Run /TN "%s"' % path


def scheduled_task_command_spec(path):
    executable = os.path.join(
        os.environ.get("SystemRoot") or r"C:\Windows", "System32", "schtasks.exe"
    )
    return direct_command_spec(executable, ["/Run", "/TN", path])


def docker_resource_command_spec(resource):
    if resource["kind"] == "container":
        args = ["container", "start", resource["containerId"]]
    else:
        args = [
            "compose", "--project-name", resource["projectName"],
            "--project-directory", resource["workingDir"],
        ]
        for path in resource["configFiles"]:
            args.extend(["--file", path])
        args.extend(["up", "--detach"])
    return direct_command_spec("docker", args)


def docker_resource_command(resource):
    return display_command(docker_resource_command_spec(resource))


def validate_app_fields(data, partial):
    """校验/规范化应用字段。partial=True 时仅校验出现的字段。
    返回 (fields, error)：fields 为规范化后的字段子集。"""
    fields = {}
    if "dockerResource" in data:
        value = data["dockerResource"]
        if value is None:
            fields["dockerResource"] = None
        else:
            try:
                fields["dockerResource"] = normalize_docker_resource(value)
            except ValueError as exc:
                return None, "dockerResource 无效: %s" % exc
    elif not partial:
        fields["dockerResource"] = None
    if "scheduledTaskPath" in data:
        task_path, err = normalize_scheduled_task_path(data["scheduledTaskPath"])
        if err:
            return None, err
        fields["scheduledTaskPath"] = task_path
    elif not partial:
        fields["scheduledTaskPath"] = None
    for key in ("name", "command"):
        if key in data:
            v = data[key]
            if not isinstance(v, str) or not v.strip():
                return None, "字段 %s 必须是非空字符串" % key
            fields[key] = v.strip()
        elif not partial and not (
                key == "command" and fields.get("dockerResource")):
            return None, "缺少字段 %s" % key
    if "commandSpec" in data:
        try:
            fields["commandSpec"] = normalize_command_spec(
                data["commandSpec"])
        except CommandSpecError as exc:
            return None, "commandSpec 无效: %s" % exc
    elif "command" in fields:
        # Legacy clients remain valid, but a changed display command must not
        # leave an older structured command attached to the app.
        fields["commandSpec"] = legacy_command_spec(fields["command"])
    if "cwd" in data:
        v = data["cwd"]
        if v is not None and not isinstance(v, str):
            return None, "cwd 必须是字符串或 null"
        fields["cwd"] = (v or "").strip() or None if isinstance(v, str) else None
    elif not partial:
        fields["cwd"] = None
    if "port" in data:
        port, err = validate_port(data["port"])
        if err:
            return None, err
        fields["port"] = port
    elif not partial:
        fields["port"] = None
    if "emoji" in data:
        v = data["emoji"]
        if v is not None and not isinstance(v, str):
            return None, "emoji 必须是字符串或 null"
        fields["emoji"] = (v or None)
    elif not partial:
        fields["emoji"] = None
    if "glyph" in data:
        v = data["glyph"]
        if v is not None and (not isinstance(v, str) or len(v) > 40):
            return None, "glyph 必须是字符串或 null"
        fields["glyph"] = (v or None)
    elif not partial:
        fields["glyph"] = None
    if "elevated" in data:
        if not isinstance(data["elevated"], bool):
            return None, "elevated 必须是布尔值"
        fields["elevated"] = data["elevated"]
    elif not partial:
        fields["elevated"] = False
    if "kind" in data:
        if data["kind"] not in ("service", "task", "program"):
            return None, "kind 必须是 service/task/program"
        fields["kind"] = data["kind"]
    elif not partial:
        fields["kind"] = "service"
    if fields.get("kind") in ("task", "program"):
        fields["port"] = None  # Tasks and launch-only programs have no port.
    task_path = fields.get("scheduledTaskPath")
    resource = fields.get("dockerResource")
    if task_path and resource:
        return None, "scheduledTaskPath 与 dockerResource 不能同时设置"
    if fields.get("elevated") and (task_path or resource):
        return None, "管理员程序不能同时关联计划任务或 Docker 资源"
    if task_path:
        fields["command"] = scheduled_task_command(task_path)
        fields["commandSpec"] = scheduled_task_command_spec(task_path)
        fields["cwd"] = None
        fields["port"] = None
    elif resource:
        fields["commandSpec"] = docker_resource_command_spec(resource)
        fields["command"] = docker_resource_command(resource)
        fields["cwd"] = (
            resource["workingDir"] if resource["kind"] == "compose" else None
        )
        fields["port"] = None
        fields["kind"] = "service"
    elif fields.get("elevated") and fields.get("kind") == "task":
        if PLATFORM.name != "windows":
            return None, "管理员批处理仅支持 Windows"
        try:
            fields["commandSpec"] = normalize_elevated_task_command_spec(
                fields.get("commandSpec")
            )
        except CommandSpecError as exc:
            if ("interpreter" in str(exc)
                    or "direct mode requires" in str(exc)):
                return None, (
                    "管理员批处理的 direct 程序必须是无参数的绝对本机 "
                    "EXE/COM，带参数命令请使用结构化脚本"
                )
            return None, "管理员批处理必须选择经过复核的结构化脚本或程序"
        fields["port"] = None
    elif fields.get("elevated"):
        if fields.get("kind") != "program":
            return None, "管理员启动仅适用于批处理任务或程序"
        spec = fields.get("commandSpec")
        executable = spec.get("executable") if isinstance(spec, dict) else None
        if (not isinstance(spec, dict) or spec.get("mode") != "direct"
                or not isinstance(executable, str)
                or not is_local_windows_path(executable)
                or not ntpath.isabs(executable)
                or not executable.casefold().endswith(".exe")):
            return None, "管理员程序必须使用绝对路径的 direct EXE"
        fields["kind"] = "program"
        fields["port"] = None
    return fields, None


# ---------------------------------------------------------------- HTTP 处理

def serialized_app_operation(fn):
    """Reject overlapping mutations for one app instead of racing/queueing."""
    @functools.wraps(fn)
    def wrapped(self, app_id, *args, **kwargs):
        lock = self.server.try_app_operation(app_id)
        if lock is None:
            self.discard_body()
            self.send_err(
                409,
                "该应用正在执行其他操作，请稍后重试",
                "APP_OPERATION_IN_PROGRESS",
            )
            return None
        try:
            return fn(self, app_id, *args, **kwargs)
        finally:
            lock.release()
    return wrapped


class ConsoleServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def server_bind(self):
        PLATFORM.configure_server_socket(self.socket)
        super().server_bind()

    def __init__(
            self, addr, handler_cls, cfg, port,
            tailscale_proxy_token=None):
        super().__init__(addr, handler_cls)
        self.cfg = cfg
        self.console_port = self.server_address[1]
        self.cli_token = secrets.token_urlsafe(32)
        self.tailscale_proxy_token = tailscale_proxy_token
        self._control_sessions = {}
        self._browser_bootstraps = {}
        self._control_sessions_guard = threading.Lock()
        self._app_locks = {}
        self._app_locks_guard = threading.Lock()
        self._console_action_guard = threading.Lock()
        self._console_action = None
        self._console_helper_pid = None
        self.keep_alive_supervisor = None

    def _prune_control_sessions(self, now):
        self._browser_bootstraps = {
            token: expires for token, expires in self._browser_bootstraps.items()
            if expires > now
        }
        self._control_sessions = {
            token: session for token, session in self._control_sessions.items()
            if now - float(session.get("lastSeen") or 0) <= CONTROL_SESSION_IDLE_SEC
        }

    def issue_browser_bootstrap(self):
        now = time.monotonic()
        with self._control_sessions_guard:
            self._prune_control_sessions(now)
            while len(self._browser_bootstraps) >= 8:
                oldest = min(
                    self._browser_bootstraps,
                    key=self._browser_bootstraps.__getitem__,
                )
                self._browser_bootstraps.pop(oldest, None)
            token = secrets.token_urlsafe(32)
            self._browser_bootstraps[token] = now + BROWSER_BOOTSTRAP_TTL_SEC
            return token

    def consume_browser_bootstrap(self, token):
        if not isinstance(token, str):
            return None
        now = time.monotonic()
        with self._control_sessions_guard:
            self._prune_control_sessions(now)
            expires = self._browser_bootstraps.pop(token, None)
            if expires is None or expires <= now:
                return None
            session_id = secrets.token_urlsafe(32)
            self._control_sessions[session_id] = {
                "lastSeen": now,
                "elevated": False,
            }
            return session_id

    def authenticate_browser_session(self, session_id):
        if not isinstance(session_id, str):
            return None
        now = time.monotonic()
        with self._control_sessions_guard:
            self._prune_control_sessions(now)
            session = self._control_sessions.get(session_id)
            if session is None:
                return None
            session["lastSeen"] = now
            return session_id

    def issue_tailscale_browser_session(self, login):
        if (not isinstance(login, str) or len(login) > 320
                or not TAILSCALE_LOGIN_RE.fullmatch(login)):
            return None
        now = time.monotonic()
        with self._control_sessions_guard:
            self._prune_control_sessions(now)
            session_id = secrets.token_urlsafe(32)
            self._control_sessions[session_id] = {
                "lastSeen": now,
                "elevated": False,
                "source": "tailscale-serve",
                "login": login,
            }
            return session_id

    def browser_session_elevated(self, session_id):
        with self._control_sessions_guard:
            session = self._control_sessions.get(session_id)
            return bool(session and session.get("elevated"))

    def set_browser_session_elevated(self, session_id, value):
        with self._control_sessions_guard:
            session = self._control_sessions.get(session_id)
            if session is None:
                return False
            session["elevated"] = bool(value)
            session["lastSeen"] = time.monotonic()
            return True

    def clear_elevated_browser_sessions(self):
        with self._control_sessions_guard:
            for session in self._control_sessions.values():
                session["elevated"] = False

    def wake_keep_alive(self):
        if self.keep_alive_supervisor is not None:
            self.keep_alive_supervisor.wake()

    def keep_alive_status(self, app_id):
        if self.keep_alive_supervisor is not None:
            return self.keep_alive_supervisor.status(app_id)
        return {
            "state": "disabled", "attempts": 0,
            "nextRetryAt": None, "error": None,
        }

    def handle_error(self, request, client_address):
        """空闲连接超时 / 客户端中途断开属正常现象，不刷 traceback。"""
        exc_type, exc, _ = sys.exc_info()
        if exc_type and isinstance(exc, (TimeoutError, BrokenPipeError,
                                         ConnectionResetError,
                                         ConnectionAbortedError)):
            return
        super().handle_error(request, client_address)

    def try_app_operation(self, app_id):
        with self._app_locks_guard:
            lock = self._app_locks.setdefault(app_id, threading.Lock())
        return lock if lock.acquire(blocking=False) else None

    def forget_app_lock(self, app_id):
        """应用删除后回收其操作锁（调用方应已持有该锁）。"""
        with self._app_locks_guard:
            self._app_locks.pop(app_id, None)

    def reserve_console_action(self, action):
        with self._console_action_guard:
            if self._console_action is not None:
                return False, self._console_action, self._console_helper_pid
            self._console_action = action
            return True, action, None

    def set_console_helper_pid(self, pid):
        with self._console_action_guard:
            self._console_helper_pid = pid

    def release_console_action(self, action):
        with self._console_action_guard:
            if self._console_action == action:
                self._console_action = None
                self._console_helper_pid = None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Console/%s" % APP_VERSION
    # 每连接 socket 超时：慢速/谎报 Content-Length 的客户端无法无限占住
    # 线程（默认 None 会永久阻塞 rfile.read）；空闲 keep-alive 连接也会回收。
    SOCKET_TIMEOUT_SEC = 30.0

    def setup(self):
        super().setup()
        try:
            self.connection.settimeout(self.SOCKET_TIMEOUT_SEC)
        except OSError:
            pass

    # ---------- 基础工具 ----------

    def log_message(self, fmt, *args):
        try:
            if self.path.startswith("/api/state"):
                return  # 2s 轮询不刷日志
        except Exception:
            pass
        sys.stderr.write("%s - %s\n" % (self.client_address[0], fmt % args))

    def _require_capability(self, name, message):
        if getattr(PLATFORM.capabilities, name, False):
            return True
        self.send_err(409, message, "CAPABILITY_DISABLED")
        return False

    def _require_browser_session(self, elevated=False):
        if self.control_auth_kind != "browser" or not self.control_session_id:
            self.send_err(
                403, "此操作必须从已验证的总控台页面执行",
                "BROWSER_SESSION_REQUIRED",
            )
            return False
        if (elevated and not self.server.browser_session_elevated(
                self.control_session_id)):
            self.send_err(
                403, "当前页面尚未解锁管理员程序控制",
                "ELEVATION_SESSION_REQUIRED",
            )
            return False
        return True

    def _project_state_authorization(self, state):
        browser_authorized = bool(
            self.control_auth_kind == "browser"
            and self.control_session_id
            and self.server.browser_session_elevated(self.control_session_id)
        )
        projected = dict(state)
        broker = dict(projected.get("elevationBroker") or {})
        session_authorized = bool(
            browser_authorized and broker.get("unlocked")
        )
        broker["sessionAuthorized"] = session_authorized
        projected["elevationBroker"] = broker
        apps = []
        for app in projected.get("apps") or []:
            row = dict(app)
            row["keepAliveAuthorized"] = bool(
                not row.get("keepAliveRequiresElevation")
                or row.get("keepAlivePersistentAuthorization")
                or session_authorized
            )
            row["keepAliveStatus"] = self.server.keep_alive_status(
                row.get("id")
            )
            if not row.get("elevated"):
                apps.append(row)
                continue
            row_broker = dict(row.get("elevationBroker") or {})
            row_broker["sessionAuthorized"] = session_authorized
            row["elevationBroker"] = row_broker
            row["controlAvailable"] = bool(
                row.get("controlAvailable") and session_authorized
            )
            apps.append(row)
        projected["apps"] = apps
        return projected

    def _parsed_request_host(self):
        """Return (hostname, port) only for the exact local console origin."""
        raw = (self.headers.get("Host") or "").strip()
        if not raw or any(ch in raw for ch in "\r\n,@/"):
            return None
        try:
            parsed = urllib.parse.urlsplit("http://" + raw)
            hostname = (parsed.hostname or "").lower()
            port = parsed.port
        except (ValueError, UnicodeError):
            return None
        if hostname in ("127.0.0.1", "localhost", "::1"):
            if port != self.server.console_port:
                return None
            return hostname, port, "http", "loopback"
        if (hostname.endswith(".ts.net") and port in (None, 443)
                and self._tailscale_proxy_identity() is not None):
            return hostname, 443, "https", "tailscale"
        return None

    def _tailscale_proxy_identity(self):
        try:
            authorizations = self.headers.get_all(
                TAILSCALE_PROXY_AUTH_HEADER
            ) or []
            logins = self.headers.get_all(TAILSCALE_USER_LOGIN_HEADER) or []
            expected = self.server.tailscale_proxy_token
            if (len(authorizations) != 1 or len(logins) != 1
                    or not isinstance(expected, str)):
                return None
            value = authorizations[0].strip()
            prefix = "Bearer "
            if (not value.startswith(prefix) or not secrets.compare_digest(
                    value[len(prefix):], expected)):
                return None
            login = logins[0].strip()
            if len(login) > 320 or not TAILSCALE_LOGIN_RE.fullmatch(login):
                return None
            return login
        except (AttributeError, TypeError, ValueError):
            return None

    def _request_host_allowed(self):
        if self._parsed_request_host() is None:
            return False
        try:
            return self.client_address[0] in ("127.0.0.1", "::1")
        except (AttributeError, IndexError):
            return False

    def _same_origin(self, origin, host):
        try:
            parsed = urllib.parse.urlsplit(origin)
            port = parsed.port or (80 if parsed.scheme == "http" else 443)
            return (parsed.scheme == host[2]
                    and (parsed.hostname or "").lower() == host[0]
                    and port == host[1]
                    and not parsed.username and not parsed.password
                    and not parsed.path and not parsed.query and not parsed.fragment)
        except (ValueError, UnicodeError):
            return False

    def _has_control_cookie(self):
        try:
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie") or "")
            morsel = cookie.get("console_session")
            return self.server.authenticate_browser_session(
                morsel.value if morsel else None)
        except (KeyError, TypeError, ValueError):
            return None

    def _has_cli_bearer(self):
        value = (self.headers.get("Authorization") or "").strip()
        prefix = "Bearer "
        return bool(
            value.startswith(prefix)
            and secrets.compare_digest(value[len(prefix):], self.server.cli_token)
        )

    def _deny_request(self, status, message):
        # Do not consume attacker-controlled bodies. Closing after the bounded
        # JSON error prevents keep-alive request smuggling via leftover bytes.
        self.close_connection = True
        self.send_err(status, message)
        return False

    def _handle_request_error(self, method, exc):
        """请求处理异常统一入口：细节只进日志，响应不回内部信息。"""
        LOG.exception("%s %s 处理失败", method, self.path)
        try:
            self.send_err(500, "服务器错误")
        except Exception:
            pass

    def authorize_request(self, mutating=False, content_kind=None,
                          require_auth=False, allow_unauthenticated=False):
        """Enforce the loopback browser trust boundary.

        Browser writes require exact same-origin metadata plus the HttpOnly
        session cookie issued by this process. Local CLI control requires the
        private per-process bearer credential; loopback location and JSON/image
        Content-Type alone never authorize a control request.
        """
        host = self._parsed_request_host()
        if host is None or not self._request_host_allowed():
            return self._deny_request(421, "请求 Host 不是当前本地控制台")
        if not mutating and not require_auth:
            return True

        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        origin = (self.headers.get("Origin") or "").strip()
        if site and site not in ("same-origin", "none"):
            return self._deny_request(403, "拒绝跨站控制请求")
        if origin and not self._same_origin(origin, host):
            return self._deny_request(403, "请求 Origin 不是当前控制台")
        self.control_session_id = self._has_control_cookie()
        self.control_auth_kind = (
            "browser" if self.control_session_id else
            "cli" if self._has_cli_bearer() else None
        )
        if (self.control_auth_kind is None and not mutating
                and urllib.parse.urlparse(self.path).path == "/api/state"
                and host[3] == "tailscale"):
            self.control_session_id = self.server.issue_tailscale_browser_session(
                self._tailscale_proxy_identity()
            )
            if self.control_session_id:
                self.control_auth_kind = "browser"
                self._pending_session_cookie = self.control_session_id
        if not allow_unauthenticated and self.control_auth_kind is None:
            return self._deny_request(403, "控制会话已失效，请重新打开总控台")

        if self.headers.get("Transfer-Encoding"):
            return self._deny_request(400, "不支持 Transfer-Encoding 请求体")

        media_type = (self.headers.get("Content-Type") or "").split(";", 1)[0]
        media_type = media_type.strip().lower()
        if content_kind == "json" and media_type != "application/json":
            return self._deny_request(415, "接口仅接受 application/json")
        if content_kind == "image" and media_type not in (
                "image/png", "image/jpeg", "image/webp",
                "application/octet-stream"):
            return self._deny_request(415, "图标接口仅接受 PNG/JPEG/WebP 原始数据")
        if content_kind:
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1:
                return self._deny_request(400, "请求必须包含唯一的 Content-Length")
            try:
                length = int(lengths[0])
            except ValueError:
                return self._deny_request(400, "非法的 Content-Length")
            limit = MAX_ICON_BYTES if content_kind == "image" else MAX_JSON_BYTES
            if length < 0 or length > limit:
                return self._deny_request(413, "请求体过大")
        return True

    def _send(self, body, status=200, ctype="text/plain; charset=utf-8",
              set_cookie=False, session_cookie=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'; connect-src 'self'; img-src 'self' data: blob:; "
            "font-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'")
        session_cookie = session_cookie or getattr(
            self, "_pending_session_cookie", None
        )
        if session_cookie and self._request_host_allowed():
            parsed_host = self._parsed_request_host()
            secure = "; Secure" if parsed_host and parsed_host[2] == "https" else ""
            self.send_header(
                "Set-Cookie",
                "console_session=%s; Path=/; HttpOnly; SameSite=Strict%s" %
                (session_cookie, secure))
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def send_json(self, obj, status=200, session_cookie=None):
        self._send(json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   status, "application/json; charset=utf-8",
                   session_cookie=session_cookie)

    def send_err(self, status, msg, code=None):
        payload = {"ok": False, "error": msg}
        if code:
            payload["code"] = code
        self.send_json(payload, status)

    def discard_body(self):
        """读掉并丢弃请求体。keep-alive 连接复用前必须清空，
        否则残留字节会污染同一连接上的下一个请求（method 解析错乱 → 501）。"""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 0:
            try:
                self.rfile.read(length)
            except OSError:
                pass

    def read_json_body(self):
        """→ (data|None, error|None)。非法 JSON / 非对象 / 超限都返回 error。"""
        media_type = (self.headers.get("Content-Type") or "").split(";", 1)[0]
        if media_type.strip().lower() != "application/json":
            return None, "Content-Type 必须是 application/json"
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None, "非法的 Content-Length"
        if length < 0 or length > MAX_JSON_BYTES:
            return None, "请求体过大"
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return None, "请求体不是合法 JSON"
        if not isinstance(data, dict):
            return None, "请求体必须是 JSON 对象"
        return data, None

    def _get_app_or_404(self, app_id):
        cfg = self.server.cfg.snapshot()
        app = find_app(cfg, app_id)
        if app is None:
            self.send_err(404, "应用不存在")
            return None, None
        return cfg, app

    def _read_json_request(self):
        data, error = self.read_json_body()
        if error:
            self.send_err(400, error, "INVALID_REQUEST")
            return None
        return data

    def _expected_generation(self, data):
        expected, error = normalize_expected_generation(
            data, required=PLATFORM.name == "windows")
        if error:
            self.send_err(400, error, "GENERATION_REQUIRED")
            return False, None
        return True, expected

    def _generation_matches(self, app, expected_generation):
        if PLATFORM.name != "windows":
            return True
        if runtime_generation(app) == expected_generation:
            return True
        self.send_err(
            409,
            "应用运行代次已变化，请刷新状态后重试",
            "GENERATION_MISMATCH",
        )
        return False

    def _send_app_cas_failure(self, status):
        if status == "not_found":
            self.send_err(404, "应用不存在")
        else:
            self.send_err(
                409,
                "应用运行代次已变化，请刷新状态后重试",
                "GENERATION_MISMATCH",
            )

    def _send_windows_lifecycle_result(self, result):
        if result.get("ok"):
            self.send_json(result)
            return
        code = result.get("code") or "RUNTIME_CONTROL_FAILED"
        status = {
            "GENERATION_REQUIRED": 400,
            "GENERATION_MISMATCH": 409,
            "RUNTIME_IDENTITY_INVALID": 409,
            "RUNTIME_IDENTITY_UNVERIFIED": 409,
            "RUNTIME_RECORD_INSECURE": 409,
            "LAUNCH_PREPARE_FAILED": 500,
            "LAUNCH_COMMIT_FAILED": 409,
            "LAUNCH_ACTIVATE_FAILED": 500,
            "STOP_TIMEOUT": 409,
            "RUNTIME_CONTROL_FAILED": 500,
        }.get(code, 500)
        self.send_json(result, status)

    # ---------- GET ----------

    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            if not self.authorize_request(
                    require_auth=path.startswith("/api/")
                    and path != "/api/health"):
                return
            if path == "/favicon.ico":
                self.serve_static("/assets/favicon.ico")
                return
            if path == "/api/health":
                self.send_json(build_health(self.server.cfg))
                return
            if path == "/api/state":
                state = get_state_snapshot(
                    self.server.cfg, self.server.console_port
                )
                self.send_json(self._project_state_authorization(state))
                return
            if path == "/api/windows/scheduled-tasks":
                self.handle_scheduled_tasks_list(parsed.query)
                return
            if path == "/api/docker/resources":
                self.handle_docker_resources_list()
                return
            if path == "/api/console/log":
                self.handle_console_log(parsed.query)
                return
            m = APP_ROUTE_RE.match(path)
            if m and m.group(2) == "logs":
                self.handle_logs(m.group(1), parsed.query)
                return
            if path.startswith("/api/"):
                self.send_err(404, "接口不存在")
                return
            if path.startswith("/icons/"):
                self.serve_icon(path)
                return
            self.serve_static(path)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._handle_request_error("GET", e)

    def serve_static(self, path):
        rel = urllib.parse.unquote(path).lstrip("/") or "index.html"
        full = os.path.normpath(os.path.join(STATIC_DIR, rel))
        # realpath 解析后必须仍在 STATIC_DIR 内，防路径穿越与符号链接逃逸。
        try:
            inside = os.path.commonpath(
                [os.path.realpath(STATIC_DIR), os.path.realpath(full)]
            ) == os.path.realpath(STATIC_DIR)
        except (ValueError, OSError):
            inside = False
        if not inside or not os.path.isfile(full):
            if rel == "index.html":
                self._send(PLACEHOLDER_HTML.encode("utf-8"), 200,
                           "text/html; charset=utf-8")
            else:
                self._send(b"404 Not Found", 404, set_cookie=False)
            return
        ctype = STATIC_TYPES.get(os.path.splitext(full)[1].lower(),
                                 "application/octet-stream")
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            self._send(b"404 Not Found", 404, set_cookie=False)
            return
        self._send(data, 200, ctype, set_cookie=False)

    def handle_scheduled_tasks_list(self, query):
        if not self._require_capability(
                "monitor_scheduled_tasks",
                "当前平台未启用 Windows 计划任务监控"):
            return
        snapshot = PLATFORM.scheduled_tasks(None)
        if snapshot.status is ScanStatus.FAILED:
            message = (
                snapshot.issues[0].message if snapshot.issues
                else "Windows 计划任务读取失败"
            )
            self.send_err(503, message, "SCHEDULED_TASK_QUERY_FAILED")
            return
        params = urllib.parse.parse_qs(query or "", keep_blank_values=True)
        include_system = (params.get("includeSystem") or [""])[0] == "1"
        tasks = [
            dict(task) for task in snapshot.tasks.values()
            if include_system or not str(task.get("path") or "").casefold().startswith(
                "\\microsoft\\"
            )
        ]
        tasks.sort(key=lambda item: str(item.get("path") or "").casefold())
        self.send_json({
            "ok": True,
            "tasks": tasks,
            "partial": snapshot.status is ScanStatus.PARTIAL,
            "issues": [issue.message for issue in snapshot.issues],
        })

    def handle_docker_resources_list(self):
        if not self._require_capability(
                "monitor_docker", "当前平台未启用 Docker 资源监控"):
            return
        snapshot = DOCKER.discover()
        if snapshot.status is ScanStatus.FAILED:
            message = (
                snapshot.issues[0].message if snapshot.issues
                else "Docker 资源读取失败"
            )
            self.send_err(503, message, "DOCKER_QUERY_FAILED")
            return
        self.send_json({
            "ok": True,
            "containers": list(snapshot.containers),
            "projects": list(snapshot.projects),
            "partial": snapshot.status is ScanStatus.PARTIAL,
            "issues": [issue.message for issue in snapshot.issues],
        })

    def serve_icon(self, path):
        name = os.path.basename(urllib.parse.unquote(path[len("/icons/"):]))
        ext = os.path.splitext(name)[1].lower()
        if ext not in ICON_EXTS:
            self._send(b"404 Not Found", 404)
            return
        full = os.path.join(ICONS_DIR, name)
        if not os.path.isfile(full):
            self._send(b"404 Not Found", 404, set_cookie=False)
            return
        ctype = STATIC_TYPES.get(ext, "application/octet-stream")
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            self._send(b"404 Not Found", 404, set_cookie=False)
            return
        self._send(data, 200, ctype, set_cookie=False)

    def handle_logs(self, app_id, query):
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        tail = self._parse_log_tail(query)
        self.send_json(read_app_log_payload(app, tail))

    def handle_console_log(self, query):
        """总控台自身日志（data/logs/console.log），与维护线程共用轮转。"""
        tail = self._parse_log_tail(query)
        self.send_json({"text": read_log_tail("console", tail)})

    @staticmethod
    def _parse_log_tail(query, default=300):
        try:
            tail = int(urllib.parse.parse_qs(query).get("tail", [default])[0])
        except (ValueError, IndexError):
            tail = default
        return max(1, min(tail, 5000))

    # ---------- POST ----------

    def do_POST(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            route_match = APP_ROUTE_RE.match(path)
            content_kind = ("image" if route_match and
                            route_match.group(2) == "icon" else "json")
            if path == "/api/session/bootstrap":
                if not self.authorize_request(
                        mutating=True, content_kind="json",
                        allow_unauthenticated=True):
                    return
                self.handle_session_bootstrap()
                return
            if not self.authorize_request(mutating=True,
                                          content_kind=content_kind):
                return
            if path == "/api/kill":
                self.handle_kill()
                return
            if path == "/api/services/flag":
                self.handle_flag()
                return
            if path == "/api/watch":
                self.handle_watch()
                return
            if path == "/api/ui/theme":
                self.handle_ui_theme()
                return
            if path == "/api/pick":
                self.handle_pick()
                return
            if path == "/api/project/detect":
                self.handle_project_detect()
                return
            if path == "/api/config/import/preview":
                self.handle_config_import_preview()
                return
            if path == "/api/config/import/commit":
                self.handle_config_import_commit()
                return
            if path == "/api/config/import/rollback":
                self.handle_config_import_rollback()
                return
            if path == "/api/windows/elevation-broker/install":
                self.handle_elevation_broker_install()
                return
            if path == "/api/windows/elevation-broker/unlock":
                self.handle_elevation_broker_unlock()
                return
            if path == "/api/windows/elevation-broker/lock":
                self.handle_elevation_broker_lock()
                return
            if path == "/api/console/open":
                self.handle_console_open()
                return
            if path == "/api/console/restart":
                self.discard_body()
                self.handle_console_restart()
                return
            if path == "/api/console/stop":
                self.discard_body()
                self.handle_console_stop()
                return
            if path == "/api/apps":
                self.handle_app_create()
                return
            if path == "/api/apps/reorder":
                self.handle_apps_reorder()
                return
            m = APP_ROUTE_RE.match(path)
            if m:
                app_id, action = m.group(1), m.group(2)
                if action == "start":
                    self.handle_app_start(app_id)
                    return
                if action == "stop":
                    self.handle_app_stop(app_id)
                    return
                if action == "restart":
                    self.handle_app_restart(app_id)
                    return
                if action == "diagnose":
                    self.discard_body()
                    self.handle_app_diagnose(app_id)
                    return
                if action == "attach":
                    self.handle_app_attach(app_id)
                    return
                if action == "keep-alive":
                    self.handle_app_keep_alive(app_id)
                    return
                if action == "scheduled-enabled":
                    self.handle_scheduled_task_enabled(app_id)
                    return
                if action == "scheduled-history":
                    self.handle_scheduled_task_history(app_id)
                    return
                if action == "icon":
                    self.handle_icon_upload(app_id)
                    return
                if action == "favicon":
                    self.discard_body()
                    self.handle_fetch_favicon(app_id)
                    return
            self.send_err(404, "接口不存在")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._handle_request_error("POST", e)

    def handle_session_bootstrap(self):
        data = self._read_json_request()
        if data is None:
            return
        if set(data) != {"token"} or not isinstance(data.get("token"), str):
            self.send_err(400, "会话引导请求无效", "SESSION_BOOTSTRAP_INVALID")
            return
        session_id = self.server.consume_browser_bootstrap(data["token"])
        if session_id is None:
            self.send_err(403, "会话引导已失效，请重新打开总控台",
                          "SESSION_BOOTSTRAP_INVALID")
            return
        self.control_session_id = session_id
        self.control_auth_kind = "browser"
        self.send_json({"ok": True}, session_cookie=session_id)

    def handle_console_open(self):
        data = self._read_json_request()
        if data is None:
            return
        if data:
            self.send_err(400, "打开控制台请求不接受额外字段",
                          "INVALID_REQUEST")
            return
        if self.control_auth_kind != "cli":
            self.send_err(403, "只有当前用户的本地启动器可以打开新控制页面",
                          "CLI_AUTH_REQUIRED")
            return
        open_browser_later(self.server, delay=0)
        self.send_json({"ok": True})

    def handle_pick(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err, "INVALID_REQUEST")
            return
        if not self._require_capability(
                "pick_path", "当前平台未启用系统路径选择器"):
            return
        what = data.get("what")
        if what not in ("dir", "script", "exe"):
            self.send_err(400, "what 必须是 dir/script/exe", "INVALID_REQUEST")
            return
        result = pick_path(what)
        if result.issue:
            LOG.warning("系统选择框失败（%s）", result.issue.code)
            self.send_err(500, "无法打开系统选择框", "PICKER_UNAVAILABLE")
        elif result.canceled:  # 用户取消不是错误，前端静默
            self.send_json({"ok": True, "canceled": True})
        elif not result.path:
            self.send_err(500, "无法打开系统选择框", "PICKER_UNAVAILABLE")
        else:
            self.send_json(picker_payload(result.path, what))

    def handle_project_detect(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err, "INVALID_REQUEST")
            return
        result, err = detect_project(data.get("cwd"))
        if err:
            self.send_err(400, err, "INVALID_PATH")
            return
        self.send_json(result)

    def _import_available(self):
        if PLATFORM.name == "windows":
            return True
        self.send_err(
            409,
            "当前平台不提供 macOS 到 Windows 的配置导入",
            "CAPABILITY_DISABLED",
        )
        return False

    def _read_import_request(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err, "INVALID_REQUEST")
            return None
        return data

    def _send_import_error(self, exc):
        self.send_err(exc.http_status, exc.message, exc.code)

    def handle_config_import_preview(self):
        data = self._read_import_request()
        if data is None or not self._import_available():
            return
        try:
            result = preview_import(
                data.get("sourcePath"),
                data.get("pathMappings", []),
                self.server.cfg.snapshot(),
                normalize_config=normalize_import_config,
            )
        except ConfigImportError as exc:
            self._send_import_error(exc)
            return
        self.send_json(result)

    def handle_config_import_commit(self):
        data = self._read_import_request()
        if data is None or not self._import_available():
            return
        if not self.server.cfg.health_info().get("writable"):
            self.send_err(
                409,
                "配置处于只读保护状态，请先恢复配置或权限",
                "CONFIG_READ_ONLY",
            )
            return
        if any(
                isinstance(app.get("keepAliveGrant"), dict)
                for app in self.server.cfg.snapshot().get("apps") or []):
            self.send_err(
                409,
                "导入前请先逐卡关闭并撤销特权保活",
                "KEEP_ALIVE_GRANT_REVOKE_REQUIRED",
            )
            return
        try:
            _ensure_private_dir(IMPORT_RECORDS_DIR)
            result = commit_import(
                data.get("sourcePath"),
                data.get("pathMappings", []),
                data.get("previewId"),
                data.get("selectedAppIds"),
                records_dir=IMPORT_RECORDS_DIR,
                get_target=self.server.cfg.snapshot,
                replace_target=self.server.cfg.replace_normalized_if_hash,
                normalize_config=normalize_import_config,
                ensure_private_file=PLATFORM.ensure_private_file,
            )
        except ConfigImportError as exc:
            self._send_import_error(exc)
            return
        except OSError:
            self.send_err(500, "无法写入私有导入记录", "IMPORT_COMMIT_FAILED")
            return
        self.send_json(result)

    def handle_config_import_rollback(self):
        data = self._read_import_request()
        if data is None or not self._import_available():
            return
        if not self.server.cfg.health_info().get("writable"):
            self.send_err(
                409,
                "配置处于只读保护状态，请先恢复配置或权限",
                "CONFIG_READ_ONLY",
            )
            return
        try:
            result = rollback_import(
                data.get("importId"),
                records_dir=IMPORT_RECORDS_DIR,
                get_target=self.server.cfg.snapshot,
                replace_target=self.server.cfg.replace_normalized_if_hash,
                normalize_config=normalize_import_config,
                ensure_private_file=PLATFORM.ensure_private_file,
            )
        except ConfigImportError as exc:
            self._send_import_error(exc)
            return
        self.send_json(result)

    def handle_app_diagnose(self, app_id):
        cfg = self.server.cfg.snapshot()
        app = find_app(cfg, app_id)
        if not app:
            self.send_err(404, "应用不存在")
            return
        self.send_json(diagnose_app(cfg, app))

    def handle_ui_theme(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        theme_id = str(data.get("theme") or "")
        known = {t["id"] for t in list_themes()}
        if theme_id not in known:
            self.send_err(400, "未知主题: %s" % theme_id)
            return
        self.server.cfg.update(lambda d: d.__setitem__("uiTheme", theme_id))
        self.send_json({"ok": True, "theme": theme_id})

    def handle_console_restart(self):
        if not self._require_capability(
                "restart_console", "当前平台或阶段未启用总控台重启"):
            return
        reserved, current, helper_pid = self.server.reserve_console_action("restart")
        if not reserved:
            if current == "restart":
                self.send_json({"ok": True, "pid": SELF_PID,
                                "helperPid": helper_pid,
                                "port": self.server.console_port,
                                "alreadyScheduled": True})
            else:
                self.send_err(409, "总控台正在停止，无法重复重启")
            return
        try:
            helper_pid = schedule_console_restart(
                self.server, self.server.console_port)
        except OSError as e:
            self.server.release_console_action("restart")
            self.send_err(500, "无法启动重启程序: %s" % e)
            return
        self.server.set_console_helper_pid(helper_pid)
        invalidate_state_cache()
        self.send_json({"ok": True, "pid": SELF_PID,
                        "helperPid": helper_pid,
                        "port": self.server.console_port})

    def handle_console_stop(self):
        if not self._require_capability(
                "restart_console", "当前平台或阶段未启用总控台停止"):
            return
        reserved, current, _ = self.server.reserve_console_action("stop")
        if not reserved:
            if current == "stop":
                self.send_json({"ok": True, "pid": SELF_PID,
                                "port": self.server.console_port,
                                "alreadyScheduled": True})
            else:
                self.send_err(409, "总控台正在重启，无法同时停止")
            return
        schedule_console_stop(self.server)
        invalidate_state_cache()
        self.send_json({"ok": True, "pid": SELF_PID,
                        "port": self.server.console_port})

    def handle_kill(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        if not self._require_capability(
                "kill_external", "当前平台或阶段禁止结束外部进程"):
            return
        pid = data.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            self.send_err(400, "缺少字段 pid（正整数）")
            return
        ok, err = kill_process(pid, bool(data.get("force")))
        if ok:
            invalidate_state_cache()
        self.send_json({"ok": True} if ok else {"ok": False, "error": err})

    def handle_flag(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        key, flag, value = data.get("key"), data.get("flag"), data.get("value")
        if not isinstance(key, str) or not key:
            self.send_err(400, "缺少字段 key")
            return
        if flag not in ("hidden", "pinned", "promoted"):
            self.send_err(400, "flag 必须是 hidden/pinned/promoted")
            return
        if not isinstance(value, bool):
            self.send_err(400, "value 必须是布尔值")
            return

        def op(c):
            lst = c.setdefault(flag, [])
            if value and key not in lst:
                lst.append(key)
            elif not value and key in lst:
                lst.remove(key)

        self.server.cfg.update(op)
        self.send_json({"ok": True})

    def handle_watch(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        keyword, action = data.get("keyword"), data.get("action")
        if not isinstance(keyword, str) or not keyword.strip():
            self.send_err(400, "缺少字段 keyword")
            return
        if action not in ("add", "remove"):
            self.send_err(400, "action 必须是 add/remove")
            return
        keyword = keyword.strip()

        def op(c):
            kws = c.setdefault("watchedKeywords", [])
            if action == "add" and keyword not in kws:
                kws.append(keyword)
            elif action == "remove":
                c["watchedKeywords"] = [k for k in kws if k != keyword]
            return list(c["watchedKeywords"])

        keywords = self.server.cfg.update(op)
        self.send_json({"ok": True, "keywords": keywords})

    def handle_app_create(self):
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        attach_pid = data.get("attachPid")
        if attach_pid is not None and (
                not isinstance(attach_pid, int)
                or isinstance(attach_pid, bool)
                or attach_pid <= 0):
            self.send_err(400, "attachPid 必须是正整数")
            return
        if attach_pid is not None and not self._require_capability(
                "attach_external", "当前平台或阶段禁止认领外部进程"):
            return
        fields, err = validate_app_fields(data, partial=False)
        if err:
            self.send_err(
                400, err,
                "COMMAND_SPEC_INVALID"
                if err.startswith("commandSpec 无效:") else None)
            return

        snapshot = self.server.cfg.snapshot()
        new_id = secrets.token_hex(4)
        while find_app(snapshot, new_id):
            new_id = secrets.token_hex(4)
        app = {"id": new_id, "name": fields["name"],
               "command": fields["command"], "cwd": fields["cwd"],
               "commandSpec": fields["commandSpec"],
               "runtimeIdentity": None,
               "scheduledTaskPath": fields["scheduledTaskPath"],
               "dockerResource": fields["dockerResource"],
               "elevated": fields["elevated"],
               "importStatus": (
                   "ready" if (
                       fields["scheduledTaskPath"] or fields["dockerResource"]
                   ) else "needs_review" if fields["elevated"] else
                   command_import_status(fields["commandSpec"], fields["cwd"])
               ),
               "port": fields["port"], "emoji": fields["emoji"],
               "glyph": fields["glyph"], "kind": fields["kind"],
               "icon": None, "favicon": None, "lastPid": None,
               "lastPgid": None, "runToken": None,
               "attached": False, "lastExit": None,
               "keepAlive": False, "desiredRunning": False,
               "keepAliveGrant": None,
               "createdAt": int(time.time())}
        automatic_icon = extract_program_icon(new_id, app)
        cwd_updated = False
        if attach_pid is not None:
            ok, error, identity = inspect_attach_process(
                self.server.cfg, app, attach_pid)
            if not ok:
                self.send_json(
                    {"ok": False, "error": error},
                    identity.get("status", 409),
                )
                return
            actual_cwd = identity["cwd"]
            try:
                cwd_updated = (
                    not app.get("cwd")
                    or os.path.realpath(app["cwd"]) != os.path.realpath(actual_cwd)
                )
            except OSError:
                cwd_updated = True
            app["cwd"] = actual_cwd
            app["lastPid"] = attach_pid
            app["attached"] = True

        attach_conflict = [False]

        def op(c):
            if find_app(c, new_id):
                return None
            # 与 attach_app_process 同规则：写锁内重验 pid 未被其他卡片认领。
            if attach_pid is not None and any(
                    other.get("lastPid") == attach_pid
                    for other in c.get("apps") or []):
                attach_conflict[0] = True
                return None
            c["apps"].append(app)
            return dict(app)

        created = self.server.cfg.update(op)
        if created is None:
            if automatic_icon:
                try:
                    os.remove(automatic_icon)
                except OSError:
                    pass
            if attach_conflict[0]:
                self.send_json(
                    {"ok": False, "error": "该进程已由其他卡片管理"}, 409)
            else:
                self.send_err(409, "应用标识发生冲突，请重试")
            return
        if attach_pid is not None:
            created.update({
                "attached": True,
                "running": True,
                "pid": attach_pid,
                "cwdUpdated": cwd_updated,
            })
        self.send_json(created)

    @serialized_app_operation
    def handle_fetch_favicon(self, app_id):
        """抓取应用有效端口对应站点的 favicon，存为 data/icons/fav-{id}.{ext}。
        优先级低于用户自定义 icon/glyph，仅作兜底。"""
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        live = set(managed_pids(app))
        port = None
        listeners = scan_listeners()
        configured_port = app.get("port")
        if configured_port and any(pid in live and p == configured_port
                                   for pid, p in listeners):
            port = configured_port
        if not port:
            owned_ports = sorted({p for pid, p in listeners if pid in live})
            port = owned_ports[0] if owned_ports else None
        if not port:
            self.send_json({"ok": False, "error": "应用未运行或无可用端口"})
            return
        host = listener_open_host(listeners, port, live)
        data, ext = fetch_favicon(port, host)
        if not data:
            self.send_json({"ok": False, "error": "未找到站点图标"})
            return
        fname = "fav-%s.%s" % (app_id, ext)
        try:
            _ensure_private_dir(ICONS_DIR)
            write_private_bytes(os.path.join(ICONS_DIR, fname), data)
        except OSError as e:
            self.send_json({"ok": False, "error": "图标保存失败: %s" % e})
            return
        url = "/icons/" + fname

        def op(c):
            target = find_app(c, app_id)
            if target:
                target["favicon"] = url

        self.server.cfg.update(op)
        self.send_json({"ok": True, "favicon": url})

    def handle_apps_reorder(self):
        """按收到的 id 顺序重排 apps（Python sort 稳定：未涉及的 id 相对顺序不变，
        服务/任务两区可独立排序互不干扰）。"""
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        ids = data.get("ids")
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            self.send_err(400, "ids 必须是字符串数组")
            return
        order = {i: n for n, i in enumerate(ids)}

        class InvalidAppOrder(ValueError):
            pass

        def op(c):
            app_ids = {
                app.get("id") for app in c["apps"] if isinstance(app, dict)
            }
            if len(order) != len(ids) or any(i not in app_ids for i in ids):
                raise InvalidAppOrder
            c["apps"].sort(key=lambda a: order.get(a.get("id"), len(order)))

        try:
            self.server.cfg.update(op)
        except InvalidAppOrder:
            self.send_err(400, "ids 必须是当前应用的唯一 ID")
            return
        self.send_json({"ok": True})

    @serialized_app_operation
    def handle_app_start(self, app_id):
        if (PLATFORM.name != "windows"
                and int(self.headers.get("Content-Length") or 0) == 0):
            data = {}
        else:
            data = self._read_json_request()
            if data is None:
                return
        valid, expected_generation = self._expected_generation(data)
        if not valid:
            return
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        if not self._generation_matches(app, expected_generation):
            return
        if app.get("keepAlive") is True:
            persistent_authorized = keep_alive_persistent_authorized(app)
            if (keep_alive_requires_elevation(app) and not persistent_authorized
                    and not self._require_browser_session(elevated=True)):
                return
            desired_status, _ = set_keep_alive_desired(
                self.server.cfg, app_id, True, expected_generation
            )
            if desired_status != "applied":
                self._send_app_cas_failure(desired_status)
                return
            self.server.wake_keep_alive()
            app = find_app(self.server.cfg.snapshot(), app_id)
            if keep_alive_requires_elevation(app) and persistent_authorized:
                self.send_json({
                    "ok": True,
                    "keepAliveResumed": True,
                    "lifecycleStatus": "starting",
                })
                return
        if elevated_task(app):
            if not self._require_browser_session(elevated=True):
                return
            if not self._require_capability(
                    "launch_elevated", "当前平台未启用管理员批处理启动"):
                return
            if expected_generation is not None:
                self.send_err(
                    409, "管理员批处理没有受管 generation",
                    "GENERATION_MISMATCH",
                )
                return
            current = PLATFORM.query_elevated_task(app_id)
            if current.ok and current.found and current.running:
                self.send_err(
                    409, "管理员批处理正在运行",
                    "BROKER_ELEVATED_TASK_ALREADY_RUNNING",
                )
                return
            health = inspect_app_health(app)
            if health["blocking"]:
                issue = health["issues"][0]
                self.send_json({
                    "ok": False,
                    "error": "%s：%s" % (issue["title"], issue["detail"]),
                    "health": health,
                }, 422)
                return
            result = launch_elevated_task_app(PLATFORM, app)
            if result.get("ok"):
                invalidate_state_cache()
            self.send_json(result, 200 if result.get("ok") else 409)
            return
        if elevated_favorite(app):
            if not self._require_browser_session(elevated=True):
                return
            if not self._require_capability(
                    "launch_elevated", "当前平台未启用管理员程序启动"):
                return
            result = launch_elevated_program_app(PLATFORM, app)
            if result.get("ok"):
                invalidate_state_cache()
            self.send_json(result, 200 if result.get("ok") else 409)
            return
        if docker_resource(app):
            if not self._require_capability(
                    "control_docker", "当前平台未启用 Docker 资源控制"):
                return
            result = control_docker_app(DOCKER, app, True)
            if result.get("ok"):
                invalidate_state_cache()
            self.send_json(result, 200 if result.get("ok") else 409)
            return
        if scheduled_task_path(app):
            if (PLATFORM.name == "windows"
                    and not self._require_browser_session(elevated=True)):
                return
            if not self._require_capability(
                    "run_scheduled_tasks", "当前平台未启用 Windows 计划任务运行"):
                return
            if expected_generation is not None:
                self.send_err(
                    409, "计划任务监控不使用受管运行代次",
                    "GENERATION_MISMATCH",
                )
                return
            result = start_scheduled_task_app(PLATFORM, app)
            if result.get("ok"):
                invalidate_state_cache()
            self.send_json(result, 200 if result.get("ok") else 409)
            return
        if not self._require_capability(
                "launch_managed", "当前平台或阶段未启用应用启动"):
            return
        if PLATFORM.name == "windows" and expected_generation is not None:
            self.send_err(
                409,
                "应用已有受管运行代次，请刷新状态后重试",
                "GENERATION_MISMATCH",
            )
            return
        if (PLATFORM.name == "windows"
                and app.get("runtimeIdentity") is not None):
            self.send_err(
                409,
                "应用已有受管运行代次，请刷新状态后重试",
                "GENERATION_MISMATCH",
            )
            return
        if PLATFORM.name != "windows" and app_alive_sign(app):
            self.send_json({"ok": False, "error": "应用已在运行"})
            return
        health = inspect_app_health(app)
        if health["blocking"]:
            issue = health["issues"][0]
            self.send_json({
                "ok": False,
                "error": "%s：%s" % (issue["title"], issue["detail"]),
                "health": health,
            }, 422)
            return
        port = app.get("port")
        occupied = [(pid, p) for pid, p in scan_listeners() if p == port] if port else []
        if occupied:
            self.send_json({"ok": False, "error": "端口 %d 已被 PID %d 占用" %
                            (port, occupied[0][0])}, 409)
            return
        if PLATFORM.name == "windows":
            self._send_windows_lifecycle_result(
                start_windows_app(self.server.cfg, app)
            )
            return
        ok, err, proc, pgid, token = start_app(app)
        if not ok:
            self.send_json({"ok": False, "error": err})
            return
        if not persist_started_app(self.server.cfg, app_id, proc, pgid, token):
            stop_pid_tree(pgid)
            self.send_json({"ok": False, "error": "应用已被删除，已取消启动"}, 409)
            return
        # 一次性任务的正常形态就是快速退出，不能沿用服务的启动探测逻辑把
        # `echo`、清缓存等成功任务误判成“启动失败”。退出线程会独立记录结果。
        if (app.get("kind") or "service") == "task":
            self.send_json({"ok": True, "pid": proc.pid})
            return
        deadline = time.monotonic() + STARTUP_PROBE_SEC
        code = proc.poll()
        while code is None and time.monotonic() < deadline:
            time.sleep(0.025)
            code = proc.poll()
        if code is not None:
            self.send_json({"ok": False,
                            "error": startup_failure_message(app_id, code)}, 422)
            return
        self.send_json({"ok": True, "pid": proc.pid})

    @serialized_app_operation
    def handle_app_stop(self, app_id):
        if (PLATFORM.name != "windows"
                and int(self.headers.get("Content-Length") or 0) == 0):
            data = {}
        else:
            data = self._read_json_request()
            if data is None:
                return
        force = data.get("force", False)
        if not isinstance(force, bool):
            self.send_err(400, "force 必须是布尔值", "INVALID_REQUEST")
            return
        valid, expected_generation = self._expected_generation(data)
        if not valid:
            return
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        desired_status, _ = set_keep_alive_desired(
            self.server.cfg, app_id, False, expected_generation
        )
        if desired_status != "applied":
            self._send_app_cas_failure(desired_status)
            return
        self.server.wake_keep_alive()
        app = find_app(self.server.cfg.snapshot(), app_id)
        if elevated_task(app):
            if not self._require_browser_session(elevated=True):
                return
            if expected_generation is not None:
                self.send_err(
                    409, "管理员批处理不使用受管运行代次",
                    "GENERATION_MISMATCH",
                )
                return
            if force:
                self.send_err(
                    409, "管理员批处理中止不支持强制模式",
                    "ELEVATED_TASK_FORCE_UNSUPPORTED",
                )
                return
            result = stop_elevated_task_app(PLATFORM, app)
            if result.get("ok"):
                task_state = PLATFORM.query_elevated_task(app_id)
                last_exit = elevated_task_last_exit(app, task_state)

                def op(config):
                    target = find_app(config, app_id)
                    if (target is not None and elevated_task(target)
                            and isinstance(last_exit, dict)):
                        target["lastExit"] = last_exit

                self.server.cfg.update(op)
                invalidate_state_cache()
            self.send_json(result, 200 if result.get("ok") else 409)
            return
        if elevated_favorite(app):
            if not self._require_browser_session(elevated=True):
                return
            if expected_generation is not None:
                self.send_err(
                    409, "管理员程序不使用受管运行代次",
                    "GENERATION_MISMATCH",
                )
                return
            expected_processes = normalize_expected_processes(
                data.get("expectedProcesses")
            )
            if expected_processes is None:
                self.send_err(
                    400, "expectedProcesses 必须包含程序 PID 与创建时间",
                    "PROGRAM_OBSERVATION_REQUIRED",
                )
                return
            result = stop_elevated_program_app(
                PLATFORM, app, expected_processes, force=force
            )
            if result.get("ok"):
                invalidate_state_cache()
            self.send_json(result, 200 if result.get("ok") else 409)
            return
        if docker_resource(app):
            if expected_generation is not None:
                self.send_err(
                    409, "Docker 资源不使用受管运行代次", "GENERATION_MISMATCH"
                )
                return
            if force:
                self.send_err(
                    409, "Docker 资源停止不支持强制模式",
                    "DOCKER_FORCE_UNSUPPORTED",
                )
                return
            if not self._require_capability(
                    "control_docker", "当前平台未启用 Docker 资源控制"):
                return
            result = control_docker_app(DOCKER, app, False)
            if result.get("ok"):
                invalidate_state_cache()
            self.send_json(result, 200 if result.get("ok") else 409)
            return
        if scheduled_task_path(app):
            if (PLATFORM.name == "windows"
                    and not self._require_browser_session(elevated=True)):
                return
            if not self._require_capability(
                    "stop_scheduled_tasks", "当前平台未启用 Windows 计划任务停止"):
                return
            if expected_generation is not None:
                self.send_err(
                    409, "计划任务监控不使用受管运行代次",
                    "GENERATION_MISMATCH",
                )
                return
            if force:
                self.send_err(
                    409, "Windows 计划任务停止不支持强制模式",
                    "SCHEDULED_TASK_FORCE_UNSUPPORTED",
                )
                return
            result = stop_scheduled_task_app(PLATFORM, app)
            if result.get("ok"):
                invalidate_state_cache()
            self.send_json(result, 200 if result.get("ok") else 409)
            return
        if not self._require_capability(
                "stop_managed", "当前平台或阶段未启用应用停止"):
            return
        if force and not self._require_capability(
                "force_stop_managed", "当前平台或阶段未启用强制停止"):
            return
        if not self._generation_matches(app, expected_generation):
            return
        if PLATFORM.name == "windows":
            if app.get("runtimeIdentity") is None:
                self.send_err(409, "应用未在运行")
                return
            self._send_windows_lifecycle_result(
                stop_windows_app(
                    self.server.cfg,
                    app,
                    force=force,
                    timeout=APP_STOP_TIMEOUT_SEC,
                )
            )
            return
        if not app_alive_sign(app):
            self.send_json({"ok": False, "error": "应用未在运行"})
            return
        ok, error = stop_app_and_clear(self.server.cfg, app)
        if not ok:
            self.send_json({"ok": False, "error": error}, 409)
            return
        self.send_json({"ok": True})

    @serialized_app_operation
    def handle_scheduled_task_enabled(self, app_id):
        data = self._read_json_request()
        if data is None:
            return
        enabled = data.get("enabled")
        if not isinstance(enabled, bool):
            self.send_err(400, "enabled 必须是布尔值", "INVALID_REQUEST")
            return
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        if (PLATFORM.name == "windows"
                and not self._require_browser_session(elevated=True)):
            return
        if not scheduled_task_path(app):
            self.send_err(
                409, "应用没有关联 Windows 计划任务",
                "SCHEDULED_TASK_NOT_CONFIGURED",
            )
            return
        if not self._require_capability(
                "toggle_scheduled_tasks", "当前平台未启用 Windows 计划任务启禁用"):
            return
        result = set_scheduled_task_enabled_app(PLATFORM, app, enabled)
        if result.get("ok"):
            invalidate_state_cache()
        self.send_json(result, 200 if result.get("ok") else 409)

    @serialized_app_operation
    def handle_app_keep_alive(self, app_id):
        data = self._read_json_request()
        if data is None:
            return
        if set(data) != {"enabled", "expectedGeneration"}:
            self.send_err(
                400,
                "保活请求只接受 enabled 与 expectedGeneration",
                "INVALID_REQUEST",
            )
            return
        enabled = data.get("enabled")
        if not isinstance(enabled, bool):
            self.send_err(400, "enabled 必须是布尔值", "INVALID_REQUEST")
            return
        valid, expected_generation = self._expected_generation(data)
        if not valid:
            return
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        if not self._generation_matches(app, expected_generation):
            return
        if not keep_alive_supported(app):
            self.send_err(
                409,
                "保活只适用于长期运行的服务或程序",
                "KEEP_ALIVE_UNSUPPORTED",
            )
            return
        if (enabled and keep_alive_requires_elevation(app)
                and not self._require_browser_session(elevated=True)):
            return

        def apply_fields(fields):
            def op(_data, target):
                target.update(fields)
                return {
                    "ok": True,
                    "keepAlive": target.get("keepAlive") is True,
                    "desiredRunning": target.get("desiredRunning") is True,
                }

            if PLATFORM.name == "windows":
                status, result, _ = self.server.cfg.mutate_app_if_generation(
                    app_id, expected_generation, op
                )
                if status != "applied":
                    return status, None
                return status, result
            result = self.server.cfg.update(
                lambda current: op(current, find_app(current, app_id))
            )
            return "applied", result

        def rotate_safe_backup():
            # Config.update stores the pre-write state in .bak. Once a stop or
            # revoke path has made the current state safe, rotate that same
            # state into .bak so recovery cannot resurrect an armed intent.
            self.server.cfg.update(lambda _data: False)

        current_grant = app.get("keepAliveGrant")
        if not enabled and isinstance(current_grant, dict):
            pause_status, _ = apply_fields({"desiredRunning": False})
            if pause_status != "applied":
                self._send_app_cas_failure(pause_status)
                return
            rotate_safe_backup()
            revoke = PLATFORM.keep_alive_grant_revoke(
                current_grant["grantId"], app_id,
                current_grant["bindingDigest"],
            )
            if not revoke.get("ok"):
                self.server.wake_keep_alive()
                self.send_json({
                    "ok": False,
                    "error": revoke.get("error") or "保活授权撤销失败，已暂停重试",
                    "code": revoke.get("code") or "KEEP_ALIVE_REVOKE_FAILED",
                }, 409)
                return
            status, result = apply_fields({
                "keepAlive": False,
                "desiredRunning": False,
                "keepAliveGrant": None,
            })
            if status != "applied":
                self._send_app_cas_failure(status)
                return
            rotate_safe_backup()
        elif enabled and keep_alive_grant_required(app):
            if isinstance(current_grant, dict):
                stale_revoke = PLATFORM.keep_alive_grant_revoke(
                    current_grant["grantId"], app_id,
                    current_grant["bindingDigest"],
                )
                if not stale_revoke.get("ok"):
                    self.send_json({
                        "ok": False,
                        "error": stale_revoke.get("error")
                                 or "旧保活授权仍待撤销",
                        "code": stale_revoke.get("code")
                                or "KEEP_ALIVE_REVOKE_FAILED",
                    }, 409)
                    return
            request = keep_alive_grant_request(app)
            issued = PLATFORM.keep_alive_grant_issue(request)
            if not issued.get("ok"):
                self.send_json({
                    "ok": False,
                    "error": issued.get("error") or "无法签发精确保活授权",
                    "code": issued.get("code") or "KEEP_ALIVE_GRANT_FAILED",
                }, 409)
                return
            grant_id = issued.get("grantId")
            digest = issued.get("resourceDigest")
            grant_kind = request.get("kind") if isinstance(request, dict) else None
            if (not isinstance(grant_id, str) or not 16 <= len(grant_id) <= 128
                    or not isinstance(digest, str)
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                    or grant_kind not in {"elevatedProgram", "scheduledService"}):
                self.send_err(500, "Broker 返回了无效的保活授权")
                return
            metadata = {
                "version": 1,
                "grantId": grant_id,
                "kind": grant_kind,
                "bindingDigest": digest,
                "configDigest": keep_alive_config_digest(app),
            }
            try:
                status, result = apply_fields({
                    "keepAlive": True,
                    "desiredRunning": True,
                    "keepAliveGrant": metadata,
                })
            except Exception:
                PLATFORM.keep_alive_grant_revoke(
                    grant_id, app_id, digest
                )
                raise
            if status != "applied":
                PLATFORM.keep_alive_grant_revoke(
                    grant_id, app_id, digest
                )
                self._send_app_cas_failure(status)
                return
            # Persist the grant handle in both main and backup before the
            # Broker can activate it; recovery must retain a revoke handle.
            rotate_safe_backup()
            activated = PLATFORM.keep_alive_grant_activate(
                grant_id, app_id, digest
            )
            if not activated.get("ok"):
                apply_fields({
                    "keepAlive": False,
                    "desiredRunning": False,
                    "keepAliveGrant": metadata,
                })
                # Ensure .bak is paused too before a possibly ambiguous revoke.
                self.server.cfg.update(lambda _data: False)
                revoke_after_failure = PLATFORM.keep_alive_grant_revoke(
                    grant_id, app_id, digest
                )
                if revoke_after_failure.get("ok"):
                    cleared_status, _ = apply_fields({"keepAliveGrant": None})
                    if cleared_status == "applied":
                        rotate_safe_backup()
                self.send_json({
                    "ok": False,
                    "error": activated.get("error") or "保活授权激活失败",
                    "code": activated.get("code") or "KEEP_ALIVE_ACTIVATE_FAILED",
                }, 409)
                return
        else:
            status, result = apply_fields({
                "keepAlive": enabled,
                "desiredRunning": enabled,
                "keepAliveGrant": None if not enabled else app.get("keepAliveGrant"),
            })
            if status != "applied":
                self._send_app_cas_failure(status)
                return
            if not enabled:
                rotate_safe_backup()
        self.server.wake_keep_alive()
        self.send_json(result)

    @serialized_app_operation
    def handle_scheduled_task_history(self, app_id):
        data = self._read_json_request()
        if data is None:
            return
        enabled = data.get("enabled")
        if not isinstance(enabled, bool):
            self.send_err(400, "enabled 必须是布尔值", "INVALID_REQUEST")
            return
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        if (PLATFORM.name == "windows"
                and not self._require_browser_session(elevated=True)):
            return
        if not scheduled_task_path(app):
            self.send_err(
                409, "应用没有关联 Windows 计划任务",
                "SCHEDULED_TASK_NOT_CONFIGURED",
            )
            return
        if not self._require_capability(
                "manage_scheduled_task_history",
                "当前平台未启用 Windows 计划任务历史记录管理"):
            return
        result = set_scheduled_task_history_app(PLATFORM, app, enabled)
        self.send_json(result, 200 if result.get("ok") else 409)

    def handle_elevation_broker_install(self):
        data = self._read_json_request()
        if data is None:
            return
        if not self._require_browser_session():
            return
        if set(data) != {"password"}:
            self.send_err(
                400, "安装请求只接受 password", "INVALID_REQUEST"
            )
            return
        password = data.get("password")
        if not isinstance(password, str):
            self.send_err(400, "password 必须是字符串", "INVALID_REQUEST")
            return
        if not self._require_capability(
                "manage_elevation_broker", "当前平台未启用管理员启动代理"):
            return
        try:
            password_record = new_password_record(password)
        except ValueError as exc:
            self.send_err(400, str(exc), "BROKER_PASSWORD_INVALID")
            return
        result = PLATFORM.install_elevation_broker(password_record)
        payload = {
            "ok": bool(getattr(result, "ok", False)),
            "code": getattr(result, "code", None),
        }
        if not payload["ok"]:
            payload["error"] = getattr(result, "error", None) or "管理员启动代理安装失败"
        else:
            invalidate_state_cache()
        self.send_json(payload, 200 if payload["ok"] else 409)

    def handle_elevation_broker_unlock(self):
        data = self._read_json_request()
        if data is None:
            return
        if not self._require_browser_session():
            return
        password = data.get("password")
        if not isinstance(password, str):
            self.send_err(400, "password 必须是字符串", "INVALID_REQUEST")
            return
        if not self._require_capability(
                "manage_elevation_broker", "当前平台未启用管理员启动代理"):
            return
        result = PLATFORM.unlock_elevation_broker(password)
        payload = {
            "ok": bool(getattr(result, "ok", False)),
            "code": getattr(result, "code", None),
        }
        if not payload["ok"]:
            payload["error"] = getattr(result, "error", None) or "管理员启动解锁失败"
        else:
            self.server.set_browser_session_elevated(
                self.control_session_id, True)
            invalidate_state_cache()
        self.send_json(payload, 200 if payload["ok"] else 409)

    def handle_elevation_broker_lock(self):
        data = self._read_json_request()
        if data is None:
            return
        if not self._require_browser_session():
            return
        if data:
            self.send_err(400, "锁定请求不接受额外字段", "INVALID_REQUEST")
            return
        if not self._require_capability(
                "manage_elevation_broker", "当前平台未启用管理员启动代理"):
            return
        result = PLATFORM.lock_elevation_broker()
        payload = {
            "ok": bool(getattr(result, "ok", False)),
            "code": getattr(result, "code", None),
        }
        if not payload["ok"]:
            payload["error"] = getattr(result, "error", None) or "管理员启动锁定失败"
        else:
            self.server.clear_elevated_browser_sessions()
            invalidate_state_cache()
        self.send_json(payload, 200 if payload["ok"] else 409)

    @serialized_app_operation
    def handle_app_attach(self, app_id):
        if not getattr(PLATFORM.capabilities, "attach_external", False):
            self.discard_body()
            self._require_capability(
                "attach_external", "当前平台或阶段禁止认领外部进程"
            )
            return
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        data, err = self.read_json_body()
        if err:
            self.send_err(400, err)
            return
        pid = data.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            self.send_err(400, "pid 必须是正整数")
            return
        ok, error, info = attach_app_process(self.server.cfg, app_id, app, pid)
        if not ok:
            self.send_json({"ok": False, "error": error}, info.get("status", 409))
            return
        resp = {"ok": True, "pid": pid}
        resp.update(info)
        self.send_json(resp)

    @serialized_app_operation
    def handle_app_restart(self, app_id):
        if (PLATFORM.name != "windows"
                and int(self.headers.get("Content-Length") or 0) == 0):
            data = {}
        else:
            data = self._read_json_request()
            if data is None:
                return
        if not (self._require_capability(
                "stop_managed", "当前平台或阶段未启用应用重启")
                and self._require_capability(
                    "launch_managed", "当前平台或阶段未启用应用重启")):
            return
        valid, expected_generation = self._expected_generation(data)
        if not valid:
            return
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        if elevated_favorite(app):
            self.send_err(
                409,
                "管理员程序不提供重启；请分别执行停止和启动",
                "ELEVATED_RESTART_UNSUPPORTED",
            )
            return
        if docker_resource(app):
            self.send_err(
                409,
                "Docker 资源不提供重启；请分别执行停止和启动",
                "DOCKER_RESTART_UNSUPPORTED",
            )
            return
        if scheduled_task_path(app):
            self.send_err(
                409,
                "Windows 计划任务监控不提供重启；请等待任务结束后重新运行",
                "SCHEDULED_TASK_MONITOR_ONLY",
            )
            return
        if not self._generation_matches(app, expected_generation):
            return
        if (PLATFORM.name == "windows"
                and app.get("runtimeIdentity") is None):
            self.send_err(409, "应用未在运行")
            return
        if PLATFORM.name != "windows" and not app_alive_sign(app):
            self.send_err(409, "应用未在运行")
            return
        # 必须在停止旧服务前预检；配置已失效时保留仍在工作的旧进程。
        health = inspect_app_health(app)
        if health["blocking"]:
            issue = health["issues"][0]
            self.send_json({
                "ok": False,
                "error": "%s：%s。旧服务仍在运行" %
                         (issue["title"], issue["detail"]),
                "health": health,
            }, 422)
            return

        if app.get("keepAlive") is True:
            desired_status, _ = set_keep_alive_desired(
                self.server.cfg, app_id, True, expected_generation
            )
            if desired_status != "applied":
                self._send_app_cas_failure(desired_status)
                return
            self.server.wake_keep_alive()
            app = find_app(self.server.cfg.snapshot(), app_id)

        if PLATFORM.name == "windows":
            stopped = stop_windows_app(
                self.server.cfg,
                app,
                force=False,
                timeout=APP_STOP_TIMEOUT_SEC,
            )
            if not stopped.get("ok"):
                self._send_windows_lifecycle_result(stopped)
                return
            port = app.get("port")
            occupied = [
                (pid, item_port)
                for pid, item_port in scan_listeners()
                if item_port == port
            ] if port else []
            if occupied:
                self.send_err(
                    409,
                    "端口 %d 已被 PID %d 占用，旧应用已停止" %
                    (port, occupied[0][0]),
                )
                return
            current = find_app(self.server.cfg.snapshot(), app_id)
            if current is None:
                self.send_err(404, "应用已被删除")
                return
            self._send_windows_lifecycle_result(
                start_windows_app(self.server.cfg, current)
            )
            return

        stopped, error = stop_app_and_clear(self.server.cfg, app)
        if not stopped:
            self.send_err(409, error or "旧进程停止失败，已取消重启")
            return

        port = app.get("port")
        occupied = [(pid, p) for pid, p in scan_listeners() if p == port] if port else []
        if occupied:
            self.send_err(409, "端口 %d 已被 PID %d 占用，旧应用已停止" %
                          (port, occupied[0][0]))
            return

        latest = self.server.cfg.snapshot()
        current = find_app(latest, app_id)
        if not current:
            self.send_err(404, "应用已被删除")
            return
        ok, err, proc, pgid, new_token = start_app(current)
        if not ok:
            self.send_err(500, err)
            return
        if not persist_started_app(
                self.server.cfg, app_id, proc, pgid, new_token):
            stop_pid_tree(pgid)
            self.send_err(409, "应用已被删除，已取消重启")
            return
        self.send_json({"ok": True, "pid": proc.pid})

    @serialized_app_operation
    def handle_icon_upload(self, app_id):
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        try:
            length = int(self.headers.get("Content-Length") or -1)
        except ValueError:
            length = -1
        if length < 0:
            self.send_err(400, "缺少 Content-Length")
            return
        if length > MAX_ICON_BYTES:
            self.send_err(400, "图标大小不能超过 5MB")
            return
        raw = self.rfile.read(length)
        kind = sniff_image(raw)
        if kind is None:
            self.send_err(400, "仅支持 PNG / JPEG / WebP 图片")
            return
        _ensure_private_dir(ICONS_DIR)
        for ext in ICON_EXTS:
            old = os.path.join(ICONS_DIR, app_id + ext)
            if ext != "." + kind and os.path.isfile(old):
                try:
                    os.remove(old)
                except OSError:
                    pass
        fname = "%s.%s" % (app_id, kind)
        try:
            write_private_bytes(os.path.join(ICONS_DIR, fname), raw)
        except OSError as e:
            self.send_err(500, "图标保存失败: %s" % e)
            return
        icon_url = "/icons/" + fname

        def op(c):
            target = find_app(c, app_id)
            if target:
                target["icon"] = icon_url

        self.server.cfg.update(op)
        self.send_json({"ok": True, "icon": icon_url})

    # ---------- PUT ----------

    def do_PUT(self):
        operation_lock = None
        try:
            if not self.authorize_request(mutating=True,
                                          content_kind="json"):
                return
            path = urllib.parse.urlparse(self.path).path
            m = APP_ROUTE_RE.match(path)
            if not (m and m.group(2) is None):
                self.send_err(404, "接口不存在")
                return
            operation_lock = self.server.try_app_operation(m.group(1))
            if operation_lock is None:
                self.discard_body()
                self.send_err(
                    409,
                    "该应用正在执行其他操作，请稍后重试",
                    "APP_OPERATION_IN_PROGRESS",
                )
                return
            data = self._read_json_request()
            if data is None:
                return
            valid, expected_generation = self._expected_generation(data)
            if not valid:
                return
            stop_before_update = data.get("stopBeforeUpdate", False)
            if not isinstance(stop_before_update, bool):
                self.send_err(400, "stopBeforeUpdate 必须是布尔值")
                return
            _, app = self._get_app_or_404(m.group(1))
            if app is None:
                return
            if not self._generation_matches(app, expected_generation):
                return
            fields, err = validate_app_fields(data, partial=True)
            if err:
                self.send_err(
                    400, err,
                    "COMMAND_SPEC_INVALID"
                    if err.startswith("commandSpec 无效:") else None)
                return
            if not fields:
                self.send_err(400, "没有可更新的字段")
                return
            lifecycle_fields = {
                "command", "commandSpec", "cwd", "port", "kind",
                "scheduledTaskPath", "dockerResource", "elevated",
            }
            lifecycle_changed = any(
                key in fields and fields[key] != app.get(key)
                for key in lifecycle_fields)
            grant = app.get("keepAliveGrant")
            if lifecycle_changed and isinstance(grant, dict):
                desired_status, _ = set_keep_alive_desired(
                    self.server.cfg, m.group(1), False, expected_generation
                )
                if desired_status != "applied":
                    self._send_app_cas_failure(desired_status)
                    return
                revoked = PLATFORM.keep_alive_grant_revoke(
                    grant["grantId"], app["id"], grant["bindingDigest"]
                )
                if not revoked.get("ok"):
                    self.send_json({
                        "ok": False,
                        "error": revoked.get("error") or "旧保活授权撤销失败",
                        "code": revoked.get("code") or "KEEP_ALIVE_REVOKE_FAILED",
                    }, 409)
                    return

                def clear_grant(_data, target):
                    target["keepAlive"] = False
                    target["desiredRunning"] = False
                    target["keepAliveGrant"] = None
                    return True

                if PLATFORM.name == "windows":
                    clear_status, _, _ = self.server.cfg.mutate_app_if_generation(
                        m.group(1), expected_generation, clear_grant
                    )
                    if clear_status != "applied":
                        self._send_app_cas_failure(clear_status)
                        return
                else:
                    self.server.cfg.update(lambda current: clear_grant(
                        current, find_app(current, m.group(1))
                    ))
                app = find_app(self.server.cfg.snapshot(), m.group(1))
            stopped_for_update = False
            if (PLATFORM.name == "windows" and lifecycle_changed
                    and elevated_task(app)):
                task_state = PLATFORM.query_elevated_task(app["id"])
                if not task_state.ok:
                    self.send_err(
                        409,
                        task_state.error or "管理员批处理状态无法确认",
                        task_state.code or "BROKER_ELEVATED_TASK_QUERY_FAILED",
                    )
                    return
                if task_state.found and task_state.running:
                    if not stop_before_update:
                        self.send_json({
                            "ok": False,
                            "error": "管理员批处理正在运行，请先中止；填写内容会保留",
                            "requiresStop": True,
                        }, 409)
                        return
                    if not self._require_browser_session(elevated=True):
                        return
                    stopped = stop_elevated_task_app(PLATFORM, app)
                    if not stopped.get("ok"):
                        self.send_json(stopped, 409)
                        return
                    stopped_for_update = True
            elif (PLATFORM.name == "windows" and lifecycle_changed
                    and app.get("runtimeIdentity") is not None):
                if not self._require_capability(
                        "stop_managed",
                        "当前平台或阶段禁止修改运行中应用的生命周期配置"):
                    return
                if not stop_before_update:
                    stop_label = ("中止任务"
                                  if (app.get("kind") or "service") == "task"
                                  else "停止服务")
                    self.send_json({
                        "ok": False,
                        "error": "应用正在运行，请先在当前编辑面板%s；填写内容会保留" %
                                 stop_label,
                        "requiresStop": True,
                    }, 409)
                    return
                desired_status, _ = set_keep_alive_desired(
                    self.server.cfg, m.group(1), False, expected_generation
                )
                if desired_status != "applied":
                    self._send_app_cas_failure(desired_status)
                    return
                self.server.wake_keep_alive()
                app = find_app(self.server.cfg.snapshot(), m.group(1))
                stopped = stop_windows_app(
                    self.server.cfg,
                    app,
                    force=False,
                    timeout=APP_STOP_TIMEOUT_SEC,
                )
                if not stopped.get("ok"):
                    self._send_windows_lifecycle_result(stopped)
                    return
                stopped_for_update = True
            elif (PLATFORM.name != "windows" and lifecycle_changed
                  and app_alive_sign(app)):
                if not self._require_capability(
                        "stop_managed",
                        "当前平台或阶段禁止修改运行中应用的生命周期配置"):
                    return
                if not stop_before_update:
                    stop_label = ("中止任务"
                                  if (app.get("kind") or "service") == "task"
                                  else "停止服务")
                    self.send_json({
                        "ok": False,
                        "error": "应用正在运行，请先在当前编辑面板%s；填写内容会保留" %
                                 stop_label,
                        "requiresStop": True,
                    }, 409)
                    return
                desired_status, _ = set_keep_alive_desired(
                    self.server.cfg, m.group(1), False, expected_generation
                )
                if desired_status != "applied":
                    self._send_app_cas_failure(desired_status)
                    return
                self.server.wake_keep_alive()
                app = find_app(self.server.cfg.snapshot(), m.group(1))
                ok, stop_error, stopped_for_update = stop_app_for_update(
                    self.server.cfg, app)
                if not ok:
                    self.send_err(409, stop_error)
                    return

            def op(c, target):
                target.update(fields)
                if not keep_alive_supported(target):
                    target["keepAlive"] = False
                    target["desiredRunning"] = False
                if ("commandSpec" in fields or "cwd" in fields
                        or "scheduledTaskPath" in fields
                        or "dockerResource" in fields
                        or "elevated" in fields):
                    target["importStatus"] = (
                        "ready" if (
                            target.get("scheduledTaskPath")
                            or target.get("dockerResource")
                        ) else "needs_review" if target.get("elevated") else
                        command_import_status(
                            target["commandSpec"], target.get("cwd")
                        )
                    )
                return dict(target)

            mutation_generation = (
                None
                if PLATFORM.name == "windows" and stopped_for_update
                else expected_generation
            )
            if PLATFORM.name == "windows":
                cas_status, updated, _ = (
                    self.server.cfg.mutate_app_if_generation(
                        m.group(1), mutation_generation, op
                    )
                )
                if cas_status != "applied":
                    self._send_app_cas_failure(cas_status)
                    return
            else:
                updated = self.server.cfg.update(
                    lambda c: op(c, find_app(c, m.group(1)))
                )
            if stopped_for_update:
                updated = dict(updated)
                updated["stoppedForUpdate"] = True
            self.send_json(updated)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._handle_request_error("PUT", e)
        finally:
            if operation_lock is not None:
                operation_lock.release()

    # ---------- DELETE ----------

    def do_DELETE(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            m = APP_ROUTE_RE.match(path)
            if not m:
                if not self.authorize_request(mutating=True):
                    return
                self.send_err(404, "接口不存在")
                return
            app_id, action = m.group(1), m.group(2)
            content_kind = (
                "json"
                if action is None and PLATFORM.name == "windows" else None
            )
            if not self.authorize_request(
                    mutating=True, content_kind=content_kind):
                return
            if action is None:
                self.handle_app_delete(app_id)
                return
            if action == "icon":
                self.handle_icon_delete(app_id)
                return
            self.send_err(404, "接口不存在")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._handle_request_error("DELETE", e)

    def do_OPTIONS(self):
        # No CORS endpoint exists. An explicit denial is clearer than the
        # BaseHTTPRequestHandler HTML 501 response and never grants ACAO.
        self._deny_request(403, "控制台不接受跨域预检请求")

    @serialized_app_operation
    def handle_app_delete(self, app_id):
        if (PLATFORM.name != "windows"
                and int(self.headers.get("Content-Length") or 0) == 0):
            data = {}
        else:
            data = self._read_json_request()
            if data is None:
                return
        valid, expected_generation = self._expected_generation(data)
        if not valid:
            return
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        if not self._generation_matches(app, expected_generation):
            return
        desired_status, _ = set_keep_alive_desired(
            self.server.cfg, app_id, False, expected_generation
        )
        if desired_status != "applied":
            self._send_app_cas_failure(desired_status)
            return
        app = find_app(self.server.cfg.snapshot(), app_id)
        stopped_for_delete = False
        terminal_identity = None
        if PLATFORM.name == "windows" and elevated_task(app):
            task_state = PLATFORM.query_elevated_task(app_id)
            if not task_state.ok:
                self.send_err(
                    409,
                    task_state.error or "管理员批处理状态无法确认，删除已取消",
                    task_state.code or "BROKER_ELEVATED_TASK_QUERY_FAILED",
                )
                return
            if task_state.found and task_state.running:
                if not self._require_browser_session(elevated=True):
                    return
                stopped = stop_elevated_task_app(PLATFORM, app)
                if not stopped.get("ok"):
                    self.send_json(stopped, 409)
                    return
                stopped_for_delete = True
        elif (PLATFORM.name == "windows"
                and app.get("runtimeIdentity") is not None):
            try:
                identity = native_runtime_identity(app)
            except (ConfigSchemaError, TypeError, ValueError):
                identity = None
            inspection = None
            if identity is not None:
                try:
                    inspection = PLATFORM.inspect_managed(identity)
                except Exception:
                    inspection = None
            terminal = None
            if (inspection is not None
                    and _windows_inspection_matches(identity, inspection)
                    and not bool(getattr(inspection, "running", False))
                    and not tuple(getattr(inspection, "members", ()) or ())
                    and getattr(inspection, "status", None) in ("exited", "failed")):
                terminal = inspection
            if terminal is not None:
                # The signed receipt proves that no workload remains. Card
                # deletion does not wait for or terminate a stale runner; the
                # background exact-generation release owns record cleanup.
                terminal_identity = identity
            else:
                if not self._require_capability(
                        "stop_managed", "当前平台或阶段禁止删除运行中的应用"):
                    return
                stopped = stop_windows_app(
                    self.server.cfg,
                    app,
                    force=False,
                    timeout=APP_STOP_TIMEOUT_SEC,
                    initial_inspection=inspection,
                )
                if not stopped.get("ok"):
                    self._send_windows_lifecycle_result(stopped)
                    return
                stopped_for_delete = True
        elif PLATFORM.name != "windows" and app_running(app):
            if not self._require_capability(
                    "stop_managed", "当前平台或阶段禁止删除运行中的应用"):
                return
            stopped, error = stop_app_and_clear(self.server.cfg, app)
            if not stopped:
                self.send_err(409, "删除已取消：%s" %
                              (error or "应用未能正常退出"))
                return
            stopped_for_delete = True

        grant = app.get("keepAliveGrant")
        if isinstance(grant, dict):
            revoked = PLATFORM.keep_alive_grant_revoke(
                grant["grantId"], app_id, grant["bindingDigest"]
            )
            if not revoked.get("ok"):
                self.send_json({
                    "ok": False,
                    "error": revoked.get("error") or "保活授权撤销失败，删除已取消",
                    "code": revoked.get("code") or "KEEP_ALIVE_REVOKE_FAILED",
                }, 409)
                return

        def op(c, target):
            before = len(c["apps"])
            c["apps"] = [a for a in c["apps"] if a.get("id") != app_id]
            return len(c["apps"]) != before

        if PLATFORM.name == "windows":
            cas_status, deleted, _ = self.server.cfg.mutate_app_if_generation(
                app_id,
                None if stopped_for_delete else expected_generation,
                op,
            )
            if cas_status != "applied":
                self._send_app_cas_failure(cas_status)
                return
        else:
            deleted = self.server.cfg.update(
                lambda c: op(c, find_app(c, app_id))
            )
            if not deleted:
                self.send_err(404, "应用不存在")
                return
        self.server.forget_app_lock(app_id)
        if terminal_identity is not None:
            _defer_windows_release(terminal_identity)

        for ext in ICON_EXTS:
            for fname in (app_id + ext, "fav-" + app_id + ext):
                try:
                    os.remove(os.path.join(ICONS_DIR, fname))
                except OSError:
                    pass
        log_path = os.path.join(LOGS_DIR, "%s.log" % app_id)
        for candidate in [log_path] + ["%s.%d" % (log_path, i)
                                       for i in range(1, LOG_BACKUPS + 1)]:
            try:
                os.remove(candidate)
            except OSError:
                pass

        self.send_json({
            "ok": True,
            "cleanupPending": terminal_identity is not None,
        })

    @serialized_app_operation
    def handle_icon_delete(self, app_id):
        _, app = self._get_app_or_404(app_id)
        if app is None:
            return
        for ext in ICON_EXTS:
            try:
                os.remove(os.path.join(ICONS_DIR, app_id + ext))
            except OSError:
                pass

        def op(c):
            target = find_app(c, app_id)
            if target:
                target["icon"] = None

        self.server.cfg.update(op)
        self.send_json({"ok": True})


# ---------------------------------------------------------------- 启动

def browser_control_url(server):
    fragment = urllib.parse.urlencode({
        "control": server.issue_browser_bootstrap(),
    })
    return "http://%s:%d/#%s" % (HOST, server.console_port, fragment)


def request_console_browser_open(port, credential_path=CONTROL_CREDENTIAL_PATH):
    credential = read_control_credential(credential_path, port)
    if credential is None:
        return False
    request = urllib.request.Request(
        "http://%s:%d/api/console/open" % (HOST, port),
        data=b"{}",
        headers={
            "Authorization": "Bearer " + credential["token"],
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=3) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def open_browser_later(server, delay=0.8):
    def _open():
        try:
            time.sleep(delay)
            PLATFORM.open_browser(browser_control_url(server))
        except Exception:
            pass
    threading.Thread(target=_open, daemon=True).start()


def find_console_instances():
    """查找从同一项目目录启动的总控台，用于双击启动器去重。"""
    snap = ps_snapshot(None, with_uid=True)
    candidates = []
    for pid, info in snap.items():
        args = info.get("args") or ""
        if (pid == SELF_PID or not process_owned_by_current(info)
                or "server.py" not in args
                or "--restart-helper" in args):
            continue
        candidates.append(pid)
    cwds = lsof_cwds(candidates)
    listener_map = {}
    for pid, port in scan_listeners():
        listener_map.setdefault(pid, []).append(port)
    result = []
    for pid in candidates:
        cwd = cwds.get(pid)
        try:
            same_dir = cwd and os.path.realpath(cwd) == os.path.realpath(BASE_DIR)
        except OSError:
            same_dir = False
        if not same_dir:
            continue
        info = snap.get(pid, {})
        result.append({
            "pid": pid,
            "ports": sorted(listener_map.get(pid, [])),
            "cmd": info.get("args") or "",
            "cwd": cwd,
            "uptimeSec": info.get("etime"),
        })
    return sorted(result, key=lambda item: (item["ports"] or [65536], item["pid"]))


def _launcher_dialog(message):
    return PLATFORM.launcher_dialog(message)


def _launcher_alert(message):
    PLATFORM.launcher_alert(message)


def launcher_main():
    """start.command 的无命令启动入口。"""
    instances = find_console_instances()
    if not instances:
        try:
            main(log_to_file=True)
        except Exception:
            _launcher_alert("总控台启动失败。请检查数据目录权限和 console.log。")
            raise
        return
    labels = []
    for item in instances:
        ports = " / ".join(":%d" % p for p in item["ports"]) or "未监听"
        labels.append("%s  ·  PID %d" % (ports, item["pid"]))
    extra = ("\n\n检测到 %d 个同项目实例，重启时会合并为一个。" % len(instances)
             if len(instances) > 1 else "")
    choice = _launcher_dialog(
        "总控台已在运行：\n" + "\n".join(labels) + extra)
    if choice == "打开控制台":
        ports = [p for item in instances for p in item["ports"]]
        port = min(ports) if ports else PORT_START
        if not request_console_browser_open(port):
            _launcher_alert("无法验证现有总控台会话，请从任务管理器确认实例状态。")
        return
    if choice != "重新启动":
        return

    preferred_ports = [p for item in instances for p in item["ports"]]
    preferred = min(preferred_ports) if preferred_ports else PORT_START
    targets = [item["pid"] for item in instances]
    for pid in targets:
        if process_uid(pid) in (SELF_UID, SELF_PRINCIPAL.identifier):
            PLATFORM.stop_external_process(pid, force=False)
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline and any(pid_alive(pid) for pid in targets):
        time.sleep(0.1)
    survivors = [pid for pid in targets if pid_alive(pid)]
    if survivors:
        _launcher_alert("旧总控台未能正常退出（PID %s），未强制结束。" %
                        "、".join(str(pid) for pid in survivors))
        return
    try:
        main(preferred_port=preferred, log_to_file=True)
    except Exception:
        _launcher_alert("总控台重启失败。请检查数据目录权限和 console.log。")
        raise


def schedule_console_restart(server, preferred_port):
    """启动独立 helper，响应发出后关闭当前 HTTP 服务。"""
    result = PLATFORM.restart_console(preferred_port)
    if not result.ok:
        raise OSError(result.error or "无法启动重启程序")

    def _shutdown():
        time.sleep(0.25)
        server.shutdown()
    threading.Thread(target=_shutdown, daemon=True).start()
    return result.helper_pid


def schedule_console_stop(server):
    """响应发送完成后关闭 HTTP 服务，不结束启动台里的独立进程组。"""
    def _shutdown():
        time.sleep(0.25)
        server.shutdown()
    threading.Thread(target=_shutdown, daemon=True).start()


def restart_helper(old_pid, preferred_port):
    """Complete a native console restart from the detached helper."""
    return PLATFORM.complete_console_restart(old_pid, preferred_port)


def _run_console(preferred_port=None, open_browser=True, storage_issues=None):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    storage_issues = list(storage_issues or [])
    if not storage_issues:
        start_log_maintenance()
    cfg = Config(
        CONFIG_PATH,
        force_read_only_reason=(
            "Windows 存储安全验证失败，已进入只读保护: "
            + "; ".join(storage_issues)
            if storage_issues else None
        ),
    )

    try:
        tailscale_proxy_token = ensure_tailscale_proxy_credential(
            TAILSCALE_PROXY_CREDENTIAL_PATH
        )
    except OSError as exc:
        tailscale_proxy_token = None
        LOG.warning("Tailscale 代理会话已禁用: %s", exc)

    server, port = None, None
    candidates = list(range(PORT_START, PORT_START + PORT_TRIES))
    if isinstance(preferred_port, int) and preferred_port in candidates:
        candidates.remove(preferred_port)
        candidates.insert(0, preferred_port)
    for p in candidates:
        try:
            server = ConsoleServer(
                (HOST, p), Handler, cfg, p,
                tailscale_proxy_token=tailscale_proxy_token,
            )
            port = p
            break
        except OSError:
            continue
    if server is None:
        print("错误：端口 %d-%d 均被占用，无法启动。" %
              (PORT_START, PORT_START + PORT_TRIES - 1))
        sys.exit(1)

    write_control_credential(CONTROL_CREDENTIAL_PATH, server)
    print("总控台已启动: http://%s:%d/  (Ctrl+C 停止)" % (HOST, port), flush=True)
    reconcile_stop = start_windows_runtime_reconciler(cfg)
    elevated_task_reconcile_stop = start_elevated_task_reconciler(cfg)
    keep_alive_supervisor = start_keep_alive_supervisor(server)
    server.keep_alive_supervisor = keep_alive_supervisor
    if open_browser:
        open_browser_later(server)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        reconcile_stop.set()
        elevated_task_reconcile_stop.set()
        keep_alive_supervisor.stop()
        keep_alive_supervisor.join(2.0)
        if getattr(PLATFORM.capabilities, "manage_elevation_broker", False):
            try:
                PLATFORM.lock_elevation_broker()
            except Exception:
                LOG.exception("锁定管理员启动代理失败")
        server.server_close()
        remove_control_credential(CONTROL_CREDENTIAL_PATH, server)
        print("已停止", flush=True)


def redirect_console_output():
    """在运行目录迁移完成后，将 .app 输出安全追加到 Library Logs。"""
    path = os.path.join(LOGS_DIR, "console.log")
    flags = (os.O_WRONLY | os.O_CREAT | os.O_APPEND
             | getattr(os, "O_BINARY", 0))
    fd = os.open(path, flags, 0o600)
    try:
        PLATFORM.ensure_private_file(path)
        if os.name == "nt":
            stream = os.fdopen(
                fd, "a", encoding="utf-8", errors="backslashreplace",
                buffering=1,
            )
            fd = -1
            sys.stdout = stream
            sys.stderr = stream
            return
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:
            os.chmod(path, 0o600)
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except (AttributeError, OSError):
                pass
        os.dup2(fd, 1)
        os.dup2(fd, 2)
    finally:
        if fd >= 0:
            os.close(fd)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, OSError):
            pass


def parse_source_console_options(argv, platform_name=None):
    preferred = None
    if "--preferred-port" in argv:
        index = argv.index("--preferred-port")
        preferred = int(argv[index + 1])
    no_browser = "--no-browser" in argv
    return (
        preferred,
        not no_browser,
        ("--log-to-file" in argv
         or ((platform_name or PLATFORM.name) == "windows" and no_browser)),
    )


def configure_console_output():
    """Keep localized CLI output safe when Windows redirects legacy stdio."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(
                encoding="utf-8", errors="backslashreplace", line_buffering=True)
        except (AttributeError, OSError, ValueError):
            pass


def main(preferred_port=None, open_browser=True, log_to_file=False):
    """Run exactly one console for this project/data directory."""
    migration = prepare_runtime_storage()
    if log_to_file and not migration.get("securityIssues"):
        redirect_console_output()
    if migration["dataMigrated"]:
        print("已将项目内旧配置和图标复制到: %s" % DATA_DIR,
              flush=True)
    if migration["logsMigrated"]:
        print("已将项目内旧日志复制到: %s" % LOGS_DIR,
              flush=True)
    instance_lock = acquire_instance_lock()
    if instance_lock is None:
        print("总控台已在运行（同一数据目录只允许一个实例）。", flush=True)
        if open_browser:
            instances = find_console_instances()
            ports = [port for item in instances for port in item.get("ports", [])]
            if ports:
                request_console_browser_open(min(ports))
        return False
    try:
        _run_console(preferred_port, open_browser, migration.get("securityIssues"))
        return True
    finally:
        release_instance_lock(instance_lock)


if __name__ == "__main__":
    configure_console_output()
    if "--prepare-storage" in sys.argv:
        # 供安装/诊断流程预先验证迁移和目录权限，不启动 HTTP。
        storage = prepare_runtime_storage()
        if storage.get("securityIssues"):
            for issue in storage["securityIssues"]:
                print(issue, file=sys.stderr)
            sys.exit(1)
    elif "--launcher" in sys.argv:
        launcher_main()
    elif "--restart-helper" in sys.argv:
        index = sys.argv.index("--restart-helper")
        try:
            old = int(sys.argv[index + 1])
            preferred = int(sys.argv[index + 2])
        except (ValueError, IndexError):
            sys.exit(2)
        sys.exit(restart_helper(old, preferred))
    else:
        try:
            preferred, open_browser, log_to_file = parse_source_console_options(
                sys.argv
            )
        except (ValueError, IndexError):
            sys.exit(2)
        main(
            preferred_port=preferred,
            open_browser=open_browser,
            log_to_file=log_to_file,
        )

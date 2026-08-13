"""Pure CommandSpec validation, construction, and static Windows preflight.

This module deliberately prepares data only. Process creation belongs to the
Phase 4 runner and must not be added here.
"""

from __future__ import annotations

import json
import ntpath
import os
import re
import shutil
from collections.abc import Mapping, Sequence


COMMAND_SPEC_VERSION = 1
COMMAND_SPEC_KEYS = (
    "version",
    "mode",
    "executable",
    "args",
    "shell",
    "text",
    "needsReview",
)
COMMAND_MODES = frozenset(("direct", "cmd", "powershell", "legacy-posix"))
WINDOWS_PATHEXT_DEFAULT = (".COM", ".EXE", ".BAT", ".CMD")


class CommandSpecError(ValueError):
    """Raised when a CommandSpec cannot satisfy the tagged-union contract."""

    code = "COMMAND_SPEC_INVALID"


def _nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CommandSpecError(f"{field} must be a non-empty string")
    if "\x00" in value:
        raise CommandSpecError(f"{field} must not contain NUL")
    return value


def _string_args(value: object) -> list[str]:
    if not isinstance(value, list):
        raise CommandSpecError("args must be an array of strings")
    args = []
    for item in value:
        if not isinstance(item, str):
            raise CommandSpecError("args must be an array of strings")
        if "\x00" in item:
            raise CommandSpecError("args must not contain NUL")
        args.append(item)
    return args


def normalize_command_spec(value: object) -> dict[str, object]:
    """Validate and return the fixed-key canonical CommandSpec v1 shape."""
    if not isinstance(value, Mapping):
        raise CommandSpecError("commandSpec must be an object")
    missing = [key for key in COMMAND_SPEC_KEYS if key not in value]
    if missing:
        raise CommandSpecError("commandSpec is missing: " + ", ".join(missing))

    version = value["version"]
    if type(version) is not int or version != COMMAND_SPEC_VERSION:
        raise CommandSpecError("version must be 1")
    mode = value["mode"]
    if not isinstance(mode, str) or mode not in COMMAND_MODES:
        raise CommandSpecError("mode is not supported")
    needs_review = value["needsReview"]
    if type(needs_review) is not bool:
        raise CommandSpecError("needsReview must be a boolean")

    executable = value["executable"]
    shell = value["shell"]
    text = value["text"]
    args = _string_args(value["args"])

    if mode == "direct":
        executable = _nonempty_string(executable, "executable")
        if shell is not None or text is not None:
            raise CommandSpecError("direct forbids shell and text")
    elif mode in ("cmd", "powershell"):
        expected_shell = "cmd.exe" if mode == "cmd" else "powershell.exe"
        if not isinstance(shell, str) or shell.lower() != expected_shell:
            raise CommandSpecError(f"{mode} requires shell={expected_shell}")
        shell = expected_shell
        structured = executable is not None
        raw = text is not None
        if structured == raw:
            raise CommandSpecError(
                f"{mode} requires exactly one of executable or text"
            )
        if structured:
            executable = _nonempty_string(executable, "executable")
            suffix = ntpath.splitext(executable)[1].lower()
            allowed = (".bat", ".cmd") if mode == "cmd" else (".ps1",)
            if suffix not in allowed:
                raise CommandSpecError(
                    f"structured {mode} executable must end with "
                    + " or ".join(allowed)
                )
            if text is not None:
                raise CommandSpecError(f"structured {mode} forbids text")
        else:
            text = _nonempty_string(text, "text")
            if executable is not None or args:
                raise CommandSpecError(f"raw {mode} forbids executable and args")
    else:
        if not isinstance(text, str):
            raise CommandSpecError("legacy-posix text must be a string")
        if "\x00" in text:
            raise CommandSpecError("legacy-posix text must not contain NUL")
        if executable is not None or shell is not None or args:
            raise CommandSpecError(
                "legacy-posix forbids executable, shell, and args"
            )
        if not needs_review:
            raise CommandSpecError("legacy-posix requires needsReview=true")

    return {
        "version": COMMAND_SPEC_VERSION,
        "mode": mode,
        "executable": executable,
        "args": args,
        "shell": shell,
        "text": text,
        "needsReview": needs_review,
    }


def legacy_command_spec(command: str) -> dict[str, object]:
    """Preserve legacy POSIX text without attempting cross-platform rewriting."""
    return normalize_command_spec({
        "version": COMMAND_SPEC_VERSION,
        "mode": "legacy-posix",
        "executable": None,
        "args": [],
        "shell": None,
        "text": command,
        "needsReview": True,
    })


def direct_command_spec(
    executable: str,
    args: Sequence[str] = (),
    *,
    needs_review: bool = False,
) -> dict[str, object]:
    """Build a direct spec while preserving every argument as a separate value."""
    return normalize_command_spec({
        "version": COMMAND_SPEC_VERSION,
        "mode": "direct",
        "executable": executable,
        "args": list(args),
        "shell": None,
        "text": None,
        "needsReview": needs_review,
    })


def shell_command_spec(
    mode: str,
    text: str,
    *,
    needs_review: bool = True,
) -> dict[str, object]:
    """Build an explicit raw cmd or PowerShell program."""
    shell = "cmd.exe" if mode == "cmd" else "powershell.exe"
    return normalize_command_spec({
        "version": COMMAND_SPEC_VERSION,
        "mode": mode,
        "executable": None,
        "args": [],
        "shell": shell,
        "text": text,
        "needsReview": needs_review,
    })


def _structured_shell_spec(
    mode: str,
    executable: str,
    args: Sequence[str] = (),
) -> dict[str, object]:
    shell = "cmd.exe" if mode == "cmd" else "powershell.exe"
    return normalize_command_spec({
        "version": COMMAND_SPEC_VERSION,
        "mode": mode,
        "executable": executable,
        "args": list(args),
        "shell": shell,
        "text": None,
        "needsReview": False,
    })


def _environment(env: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if env is None else env


def is_local_windows_path(path: object) -> bool:
    """Reject UNC and device namespaces before any filesystem probe."""
    if not isinstance(path, str) or not path or "\x00" in path:
        return False
    normalized = path.replace("/", "\\")
    return not normalized.startswith(("\\\\", "\\??\\"))


def _windows_pathext(env: Mapping[str, str]) -> tuple[str, ...]:
    raw = env.get("PATHEXT") or ";".join(WINDOWS_PATHEXT_DEFAULT)
    result = []
    for item in raw.split(";"):
        suffix = item.strip()
        if not suffix:
            continue
        if not suffix.startswith("."):
            suffix = "." + suffix
        suffix = suffix.upper()
        if suffix not in result:
            result.append(suffix)
    return tuple(result or WINDOWS_PATHEXT_DEFAULT)


def resolve_windows_executable(
    executable: str,
    *,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
) -> str | None:
    """Resolve a Windows executable from explicit PATH/PATHEXT without running it."""
    if (not isinstance(executable, str) or not executable.strip()
            or not is_local_windows_path(executable)
            or (cwd is not None and not is_local_windows_path(cwd))):
        return None
    environment = _environment(env)
    suffix = ntpath.splitext(executable)[1]
    names = [executable]
    if not suffix:
        names = [executable + ext for ext in _windows_pathext(environment)]
        names.append(executable)

    has_directory = bool(
        ntpath.dirname(executable)
        or ntpath.splitdrive(executable)[0]
        or "/" in executable
        or "\\" in executable
    )
    if has_directory:
        base = executable if ntpath.isabs(executable) else os.path.join(cwd or os.getcwd(), executable)
        base_names = [base]
        if not suffix:
            base_names = [base + ext for ext in _windows_pathext(environment)] + [base]
        for candidate in base_names:
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
        return None

    directories = (environment.get("PATH") or "").split(os.pathsep)
    for directory in directories:
        if not directory or not is_local_windows_path(directory):
            continue
        for name in names:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
    return None


def command_spec_for_executable(
    executable: str,
    args: Sequence[str] = (),
    *,
    platform_name: str = "windows",
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
) -> dict[str, object]:
    """Classify an executable or Windows shim after static PATH resolution."""
    target = executable
    if platform_name == "windows":
        target = resolve_windows_executable(executable, env=env, cwd=cwd) or executable
    suffix = ntpath.splitext(target)[1].lower()
    if platform_name == "windows" and suffix in (".bat", ".cmd"):
        return _structured_shell_spec("cmd", target, args)
    if platform_name == "windows" and suffix == ".ps1":
        return _structured_shell_spec("powershell", target, args)
    return direct_command_spec(target, args)


def command_spec_for_script(
    path: str | os.PathLike[str],
    platform_name: str,
    python_executable: str | None = None,
) -> dict[str, object]:
    """Build a candidate spec for a selected script without inspecting its contents."""
    raw_path = os.fspath(path)
    normalized_path = os.path.abspath(os.path.expanduser(
        _nonempty_string(raw_path, "path")
    ))
    suffix = ntpath.splitext(normalized_path)[1].lower()

    if platform_name == "windows":
        if suffix == ".py":
            launcher = python_executable or "py.exe"
            launcher_args = ["-3.12"] if ntpath.basename(launcher).lower() in (
                "py", "py.exe"
            ) else []
            return direct_command_spec(launcher, [*launcher_args, normalized_path])
        if suffix in (".bat", ".cmd"):
            return _structured_shell_spec("cmd", normalized_path)
        if suffix == ".ps1":
            return _structured_shell_spec("powershell", normalized_path)
        if suffix in (".com", ".exe"):
            return direct_command_spec(normalized_path)
        return legacy_command_spec(normalized_path)

    if suffix == ".py":
        return direct_command_spec(python_executable or "python3", ["--", normalized_path])
    if suffix == ".zsh":
        return direct_command_spec("/bin/zsh", ["--", normalized_path])
    if suffix in (".bash", ".command", ".sh"):
        return direct_command_spec("/bin/bash", ["--", normalized_path])
    return direct_command_spec(normalized_path)


def select_python_executable(
    platform_name: str,
    *,
    current_executable: str | None = None,
    current_version: tuple[int, int] | None = None,
    frozen: bool = False,
    env: Mapping[str, str] | None = None,
) -> str:
    """Select an explicit interpreter path without running a discovery command."""
    current = current_executable or ""
    base = ntpath.basename(current).lower()
    if (not frozen and current and is_local_windows_path(current)
            and os.path.isfile(current)
            and (platform_name != "windows" or current_version == (3, 12))
            and re.fullmatch(r"python(?:\d+(?:\.\d+)*)?\.exe", base)):
        return os.path.abspath(current)
    if platform_name == "windows":
        return (resolve_windows_executable("py.exe", env=env)
                or "py.exe")
    return current if current and os.path.isfile(current) else "python3"


def python_command_spec(
    args: Sequence[str],
    *,
    platform_name: str,
    current_executable: str | None = None,
    current_version: tuple[int, int] | None = None,
    frozen: bool = False,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Build a direct Python command with an explicit Windows launcher choice."""
    executable = select_python_executable(
        platform_name,
        current_executable=current_executable,
        current_version=current_version,
        frozen=frozen,
        env=env,
    )
    prefix = (["-3.12"] if platform_name == "windows"
              and ntpath.basename(executable).lower() in ("py", "py.exe")
              else [])
    return direct_command_spec(executable, [*prefix, *args])


def _display_arg(value: str) -> str:
    if value and not any(
        char.isspace() or char in "&|<>^()%!'\"`$;" for char in value
    ):
        return value
    return json.dumps(value, ensure_ascii=False)


def display_command(spec: object) -> str:
    """Return a presentation string that must never be parsed for execution."""
    normalized = normalize_command_spec(spec)
    if normalized["text"] is not None:
        return str(normalized["text"])
    values = [str(normalized["executable"]), *normalized["args"]]
    return " ".join(_display_arg(value) for value in values)


def _validate_structured_cmd_values(executable: str, args: Sequence[str]) -> None:
    values = [executable, *args]
    for value in values:
        if any(char in value for char in ("\x00", "\r", "\n", "%", "!", '"')):
            raise CommandSpecError(
                "structured cmd values containing %, !, quotes, or newlines "
                "require review"
            )


def prepared_invocation(
    spec: object,
    env: Mapping[str, str] | None = None,
) -> list[str] | dict[str, object]:
    """Return future-runner argv data without starting or probing a process."""
    normalized = normalize_command_spec(spec)
    if normalized["needsReview"]:
        raise CommandSpecError("command requires review before invocation")
    mode = normalized["mode"]
    executable = normalized["executable"]
    args = normalized["args"]
    text = normalized["text"]

    if mode == "direct":
        return [str(executable), *args]
    if mode == "legacy-posix":
        raise CommandSpecError("legacy-posix is not a Windows invocation")
    if mode == "cmd":
        environment = _environment(env)
        comspec = environment.get("COMSPEC") or "cmd.exe"
        if text is not None:
            return [comspec, "/d", "/s", "/c", str(text)]
        _validate_structured_cmd_values(str(executable), args)
        return {
            "mode": "cmd",
            "executable": comspec,
            "prefixArgs": ["/d", "/s", "/c"],
            "script": str(executable),
            "args": list(args),
        }

    prefix = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
    ]
    if text is not None:
        return [*prefix, "-Command", str(text)]
    return {
        "mode": "powershell",
        "executable": prefix[0],
        "prefixArgs": [*prefix[1:], "-File"],
        "script": str(executable),
        "args": list(args),
    }


def _issue(
    kind: str,
    title: str,
    detail: str,
    fix: str,
    action: str,
    *,
    severity: str = "error",
) -> dict[str, str]:
    return {
        "kind": kind,
        "severity": severity,
        "title": title,
        "detail": detail,
        "fix": fix,
        "action": action,
    }


def _shell_path(
    mode: str,
    environment: Mapping[str, str],
    cwd: str | None,
) -> str | None:
    if mode == "cmd":
        comspec = environment.get("COMSPEC")
        if (comspec and is_local_windows_path(comspec)
                and os.path.isfile(comspec)):
            return os.path.abspath(comspec)
        return resolve_windows_executable("cmd.exe", env=environment, cwd=cwd)
    found = resolve_windows_executable("powershell.exe", env=environment, cwd=cwd)
    if found:
        return found
    system_root = environment.get("SystemRoot") or environment.get("SYSTEMROOT")
    if system_root and is_local_windows_path(system_root):
        fallback = os.path.join(
            system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
        )
        if os.path.isfile(fallback):
            return os.path.abspath(fallback)
    return None


def _resolve_non_windows_executable(
    executable: str,
    environment: Mapping[str, str],
    cwd: str | None,
) -> str | None:
    if os.path.dirname(executable):
        path = executable if os.path.isabs(executable) else os.path.join(
            cwd or os.getcwd(), executable
        )
        return os.path.abspath(path) if os.path.isfile(path) else None
    return shutil.which(executable, path=environment.get("PATH"))


def static_preflight(
    spec: object,
    cwd: str | None = None,
    platform_name: str = "windows",
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Perform stat/PATH checks only; never parse shell text or execute code."""
    try:
        normalized = normalize_command_spec(spec)
    except CommandSpecError as exc:
        return {
            "status": "error",
            "blocking": True,
            "issues": [_issue(
                "command-spec-invalid",
                "命令配置无效",
                str(exc),
                "重新选择脚本或修正命令配置。",
                "edit-command",
            )],
        }

    issues = []
    cwd_ok = cwd is None or (
        isinstance(cwd, str)
        and (platform_name != "windows" or is_local_windows_path(cwd))
        and os.path.isdir(cwd)
    )
    if not cwd_ok:
        issues.append(_issue(
            "cwd-missing",
            "工作目录不可用",
            f"找不到配置的工作目录：{cwd}",
            "重新选择工作区文件夹。",
            "pick-cwd",
        ))

    mode = str(normalized["mode"])
    if mode == "legacy-posix" and platform_name == "windows":
        return {
            "status": "error" if issues else "unknown",
            "blocking": bool(issues),
            "issues": issues,
        }

    environment = _environment(env)
    executable = normalized["executable"]
    if platform_name == "windows" and mode in ("cmd", "powershell"):
        if not _shell_path(mode, environment, cwd):
            issues.append(_issue(
                "runtime-missing",
                "找不到命令运行时",
                f"PATH 中找不到 {normalized['shell']}。",
                "安装对应运行时，或修改命令配置。",
                "edit-command",
            ))

    if executable is not None and cwd_ok:
        if platform_name == "windows":
            resolved = None
            if cwd and not ntpath.dirname(str(executable)):
                local = os.path.join(cwd, str(executable))
                if os.path.isfile(local):
                    resolved = os.path.abspath(local)
            resolved = resolved or resolve_windows_executable(
                str(executable), env=environment, cwd=cwd
            )
        else:
            resolved = _resolve_non_windows_executable(
                str(executable), environment, cwd
            )
        if not resolved:
            issues.append(_issue(
                "runtime-missing" if mode == "direct" else "script-missing",
                "找不到命令或脚本",
                f"静态检查找不到：{executable}",
                "安装运行时，或重新选择脚本。",
                "edit-command" if mode == "direct" else "pick-script",
            ))

    if platform_name == "windows" and mode == "cmd" and executable is not None:
        try:
            _validate_structured_cmd_values(str(executable), normalized["args"])
        except CommandSpecError as exc:
            issues.append(_issue(
                "cmd-argument-needs-review",
                "cmd 参数需要复核",
                str(exc),
                "改用 direct/PowerShell，或人工确认 cmd 参数编码。",
                "edit-command",
                severity="warning",
            ))

    blocking = any(issue["severity"] == "error" for issue in issues)
    review = any(issue["severity"] == "warning" for issue in issues)
    return {
        "status": "error" if blocking else ("unknown" if review else "ok"),
        "blocking": blocking,
        "issues": issues,
    }


def platform_compatibility(
    spec: object,
    cwd: str | None = None,
    platform_name: str = "windows",
) -> dict[str, object]:
    """Classify a spec using the stable compatibility response shape."""
    try:
        normalized = normalize_command_spec(spec)
    except CommandSpecError as exc:
        return {
            "status": "blocked",
            "reasons": [{
                "code": "COMMAND_SPEC_INVALID",
                "message": str(exc),
            }],
        }

    mode = normalized["mode"]
    if mode == "legacy-posix" and not str(normalized["text"]).strip():
        return {
            "status": "blocked",
            "reasons": [{
                "code": "COMMAND_SPEC_INVALID",
                "message": "The legacy command is empty.",
            }],
        }
    if platform_name == "windows" and mode == "legacy-posix":
        return {
            "status": "needs_review",
            "reasons": [{
                "code": "LEGACY_POSIX_COMMAND",
                "message": "Review this command for Windows.",
            }],
        }
    if platform_name != "windows" and mode == "legacy-posix":
        return {"status": "ready", "reasons": []}
    if normalized["needsReview"]:
        return {
            "status": "needs_review",
            "reasons": [{
                "code": "COMMAND_SPEC_INVALID",
                "message": "The command requires review before execution.",
            }],
        }
    if platform_name != "windows" and mode in ("cmd", "powershell"):
        return {
            "status": "needs_review",
            "reasons": [{
                "code": "UNSUPPORTED_SCRIPT_TYPE",
                "message": "Review this Windows-specific command for the target platform.",
            }],
        }
    health = static_preflight(normalized, cwd, platform_name)
    if health["status"] == "ok":
        return {"status": "ready", "reasons": []}
    if health["status"] == "unknown":
        return {
            "status": "needs_review",
            "reasons": [{
                "code": "COMMAND_SPEC_INVALID",
                "message": "The command needs review before Windows execution.",
            }],
        }
    reason_code = (
        "COMMAND_SPEC_INVALID"
        if any(issue["kind"] == "command-spec-invalid" for issue in health["issues"])
        else "PATH_NOT_FOUND"
    )
    return {
        "status": "blocked",
        "reasons": [{
            "code": reason_code,
            "message": "A required command or path was not found.",
        }],
    }

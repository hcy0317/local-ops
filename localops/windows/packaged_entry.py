"""PyInstaller windowed entry point for the Windows package."""

from __future__ import annotations

import os
from pathlib import Path
import sys
from types import ModuleType
from typing import Callable, Sequence, TextIO


RUNNER_MODULE = "localops.windows.runner"


def _bind_private_console_log(server: ModuleType) -> TextIO:
    """Replace absent windowed stdio with the ACL-protected console log."""
    path = Path(server.LOGS_DIR) / "console.log"
    log_existed = os.path.lexists(path)
    if os.path.lexists(server.LOGS_DIR):
        server.PLATFORM.verify_private_directory(server.LOGS_DIR)
    if log_existed:
        server.PLATFORM.verify_private_file(str(path))
    storage = server.prepare_runtime_storage()
    issues = storage.get("securityIssues") or []
    if issues:
        raise PermissionError("; ".join(str(issue) for issue in issues))
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    if log_existed:
        fd = os.open(path, flags)
    else:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if log_existed:
            server.PLATFORM.verify_private_file(str(path))
        else:
            server.PLATFORM.ensure_private_file(str(path))
        stream = os.fdopen(
            fd,
            "a",
            encoding="utf-8",
            errors="backslashreplace",
            buffering=1,
        )
        fd = -1
    finally:
        if fd >= 0:
            os.close(fd)
    sys.stdout = stream
    sys.stderr = stream
    return stream


def _console_options(argv: Sequence[str]) -> tuple[int | None, bool]:
    preferred = None
    if "--preferred-port" in argv:
        index = argv.index("--preferred-port")
        try:
            preferred = int(argv[index + 1])
        except (IndexError, ValueError) as exc:
            raise ValueError("--preferred-port requires an integer") from exc
    return preferred, "--no-browser" not in argv


def _run_console(argv: Sequence[str]) -> int:
    import server

    stream = _bind_private_console_log(server)
    try:
        server.configure_console_output()
        if "--prepare-storage" in argv:
            return 0
        preferred, open_browser = _console_options(argv)
        server.main(
            preferred_port=preferred,
            open_browser=open_browser,
            log_to_file=False,
        )
        return 0
    except Exception:
        server.LOG.exception("packaged console failed")
        return 1
    finally:
        stream.flush()


def main(
    argv: Sequence[str] | None = None,
    *,
    runner_main: Callable[[list[str]], int] | None = None,
) -> int:
    """Dispatch the frozen runner CLI or start the windowed console."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:2] == ["-m", RUNNER_MODULE]:
        if runner_main is None:
            from localops.windows.runner import main as runner_main
        return runner_main(args[2:])
    if args[:1] == ["-m"]:
        return 2
    return _run_console(args)


if __name__ == "__main__":
    raise SystemExit(main())

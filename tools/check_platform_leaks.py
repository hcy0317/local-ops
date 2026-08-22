#!/usr/bin/env python3
"""Fail when shared core calls a native platform API directly."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BANNED_IMPORTS = {"fcntl", "psutil", "win32api", "win32con", "win32event", "win32job"}
BANNED_OS_CALLS = {"execv", "getuid", "getpgid", "getpgrp", "kill", "killpg"}
BANNED_COMMANDS = {"lsof", "ps", "osascript"}


def platform_leaks(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    leaks: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", 1)[0] in BANNED_IMPORTS:
                    leaks.append(f"{path.name}:{node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".", 1)[0] in BANNED_IMPORTS:
                leaks.append(f"{path.name}:{node.lineno}: from {node.module}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and node.func.attr in BANNED_OS_CALLS):
                leaks.append(f"{path.name}:{node.lineno}: os.{node.func.attr}")
            if (isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "webbrowser"
                    and node.func.attr == "open"):
                leaks.append(f"{path.name}:{node.lineno}: webbrowser.open")
            if (isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                    and node.func.attr in {"run", "Popen"}
                    and node.args
                    and isinstance(node.args[0], (ast.List, ast.Tuple))
                    and node.args[0].elts
                    and isinstance(node.args[0].elts[0], ast.Constant)
                    and node.args[0].elts[0].value in BANNED_COMMANDS):
                command = node.args[0].elts[0].value
                leaks.append(f"{path.name}:{node.lineno}: subprocess {command}")
    return leaks


def main() -> int:
    leaks = platform_leaks(ROOT / "server.py")
    if leaks:
        print("Shared-core platform leaks:")
        for leak in leaks:
            print(f"- {leak}")
        return 1
    print("Shared-core platform boundary: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

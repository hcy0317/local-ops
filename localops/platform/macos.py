"""macOS adapter preserving the original POSIX process semantics."""

from __future__ import annotations

import errno
import glob
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
import webbrowser
from dataclasses import asdict
from typing import Literal, Mapping, Sequence

from .contracts import (
    CwdSnapshot,
    ElevationBrokerResult,
    ElevationBrokerStatus,
    InstanceLock,
    LaunchRequest,
    ListenerSnapshot,
    ManagedInspection,
    ManagedRuntime,
    PickResult,
    PlatformCapabilities,
    PlatformIssue,
    Principal,
    ProcessSnapshot,
    RestartResult,
    RuntimeIdentity,
    RuntimePaths,
    ScanStatus,
    ScheduledTaskRunResult,
    ScheduledTaskSnapshot,
    StopResult,
)


SUBPROCESS_TIMEOUT = 5
RUN_TOKEN_ENV = "CONSOLE_RUN_TOKEN"
RUN_TOKEN_ARG_PREFIX = "console-run:"


class MacOSInstanceLock:
    def __init__(self, file_object: object):
        self._file = file_object

    def release(self) -> None:
        if self._file is None:
            return
        import fcntl

        file_object, self._file = self._file, None
        try:
            fcntl.flock(file_object.fileno(), fcntl.LOCK_UN)
        finally:
            file_object.close()


def _issue(component: str, code: str, message: str) -> PlatformIssue:
    return PlatformIssue(component, code, message)


def _to_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_etime(value: str) -> int:
    try:
        value = value.strip()
        days = 0
        if "-" in value:
            day_text, value = value.split("-", 1)
            days = int(day_text)
        parts = [int(part) for part in value.split(":")]
        if len(parts) == 2:
            hours, minutes, seconds = 0, parts[0], parts[1]
        elif len(parts) == 3:
            hours, minutes, seconds = parts
        else:
            return 0
        return days * 86400 + hours * 3600 + minutes * 60 + seconds
    except (TypeError, ValueError):
        return 0


class MacOSPlatform:
    name = "macos"
    requires_verified_permissions = False
    capabilities = PlatformCapabilities(
        monitor_processes=True,
        launch_managed=True,
        stop_managed=True,
        force_stop_managed=True,
        kill_external=True,
        attach_external=True,
        pick_path=True,
        restart_console=True,
        monitor_docker=True,
        control_docker=True,
    )

    def __init__(self, base_dir: str, entrypoint: str):
        self.base_dir = os.path.abspath(base_dir)
        self.entrypoint = os.path.abspath(entrypoint)
        self.self_pid = os.getpid()
        self._principal = Principal(str(os.getuid()), os.getuid())

    def runtime_paths(self) -> RuntimePaths:
        data = os.path.expanduser("~/Library/Application Support/总控台")
        logs = os.path.expanduser("~/Library/Logs/总控台")
        return RuntimePaths(data, logs, os.path.join(data, "runtime"))

    def current_principal(self) -> Principal:
        return self._principal

    def validate_runtime_path(self, path: str, forbidden: set[str]) -> str:
        normalized = os.path.abspath(path)
        if normalized in forbidden:
            raise ValueError("runtime path must be a dedicated subdirectory")
        return normalized

    @staticmethod
    def ensure_private_directory(path: str) -> None:
        os.chmod(path, 0o700)

    @staticmethod
    def ensure_private_file(path: str) -> None:
        os.chmod(path, 0o600)

    @staticmethod
    def should_migrate_legacy_data() -> bool:
        return True

    def acquire_instance_lock(self, identity: str) -> InstanceLock | None:
        import fcntl

        path = os.path.abspath(identity)
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        lock_file = os.fdopen(fd, "r+", encoding="ascii")
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            lock_file.close()
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return None
            raise
        try:
            os.fchmod(lock_file.fileno(), 0o600)
            lock_file.seek(0)
            lock_file.truncate()
            lock_file.write(f"{self.self_pid}\n")
            lock_file.flush()
            os.fsync(lock_file.fileno())
        except OSError:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()
            raise
        return MacOSInstanceLock(lock_file)

    @staticmethod
    def _run(
        args: Sequence[str], *, timeout: float = SUBPROCESS_TIMEOUT,
        empty_returncodes: tuple[int, ...] = (), component: str,
    ) -> tuple[str, PlatformIssue | None]:
        try:
            result = subprocess.run(
                list(args), capture_output=True, text=True, errors="replace",
                timeout=timeout,
            )
        except FileNotFoundError:
            return "", _issue(component, "tool_missing", f"command not found: {args[0]}")
        except subprocess.TimeoutExpired:
            return "", _issue(component, "timeout", f"command timed out: {args[0]}")
        except OSError as exc:
            return "", _issue(component, "os_error", f"command failed: {exc}")
        if result.returncode and result.returncode not in empty_returncodes:
            detail = (result.stderr or "").strip()
            message = f"{args[0]} exited with {result.returncode}"
            if detail:
                message += f": {detail[:240]}"
            return result.stdout or "", _issue(component, "command_failed", message)
        return result.stdout or "", None

    def scan_listeners(self) -> ListenerSnapshot:
        output, problem = self._run(
            ["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"],
            empty_returncodes=(1,), component="listeners",
        )
        if problem:
            return ListenerSnapshot(ScanStatus.FAILED, issues=(problem,))
        found: dict[tuple[int, int], set[str]] = {}
        for line in output.splitlines():
            if not line or line.startswith("COMMAND"):
                continue
            parts = line.split()
            if len(parts) < 9:
                continue
            try:
                pid = int(parts[1])
            except ValueError:
                continue
            port = None
            bind_host = None
            for token in reversed(parts):
                match = re.search(r":(\d+)$", token)
                if match:
                    port = int(match.group(1))
                    bind_host = token[:match.start()].strip("[]")
                    break
            if port is not None:
                found.setdefault((pid, port), set()).add(bind_host or "")
        return ListenerSnapshot(ScanStatus.OK, found)

    def process_snapshot(
        self, pids: set[int] | None = None, *, with_owner: bool = True,
    ) -> ProcessSnapshot:
        base = ["ps"]
        if pids is None:
            base.append("-ax")
        else:
            normalized = sorted(int(pid) for pid in pids)
            if not normalized:
                return ProcessSnapshot(ScanStatus.OK)
            base += ["-p", ",".join(str(pid) for pid in normalized)]
        fields = ["pid"] + (["uid"] if with_owner else []) + [
            "etime", "%cpu", "%mem", "comm",
        ]
        details, detail_issue = self._run(
            base + ["-o", ",".join(fields)], component="processes"
        )
        if pids is not None and detail_issue:
            message = detail_issue.message.lower()
            if (message == "ps exited with 1"
                    or "process id too large" in message):
                return ProcessSnapshot(ScanStatus.OK)
        args_output, args_issue = self._run(
            base + ["-o", "pid,args"], component="process_args"
        )
        issues = tuple(issue for issue in (detail_issue, args_issue) if issue)
        if detail_issue:
            return ProcessSnapshot(ScanStatus.FAILED, issues=issues)
        processes: dict[int, dict[str, object]] = {}
        fixed = 5 if with_owner else 4
        for line in details.splitlines():
            tokens = line.split()
            if len(tokens) < fixed + 1:
                continue
            try:
                pid = int(tokens[0])
            except ValueError:
                continue
            index = 1
            entry: dict[str, object] = {"args": ""}
            if with_owner:
                try:
                    entry["uid"] = int(tokens[1])
                except ValueError:
                    entry["uid"] = -1
                index = 2
            entry["etime"] = _parse_etime(tokens[index])
            entry["cpu"] = _to_float(tokens[index + 1])
            entry["mem"] = _to_float(tokens[index + 2])
            entry["comm"] = " ".join(tokens[index + 3:])
            processes[pid] = entry
        if not args_issue:
            for line in args_output.splitlines():
                tokens = line.split(None, 1)
                if not tokens:
                    continue
                try:
                    pid = int(tokens[0])
                except ValueError:
                    continue
                if pid in processes:
                    processes[pid]["args"] = tokens[1] if len(tokens) > 1 else ""
        status = ScanStatus.PARTIAL if issues else ScanStatus.OK
        return ProcessSnapshot(status, processes, issues)

    def processes_matching_keywords(self, keywords: Sequence[str]) -> ProcessSnapshot:
        return self.process_snapshot(None, with_owner=True)

    def process_cwds(self, pids: set[int]) -> CwdSnapshot:
        normalized = sorted(int(pid) for pid in pids)
        if not normalized:
            return CwdSnapshot(ScanStatus.OK)
        output, problem = self._run(
            ["lsof", "-a", "-p", ",".join(str(pid) for pid in normalized),
             "-d", "cwd", "-Fn"],
            empty_returncodes=(1,), component="process_cwds",
        )
        if problem:
            return CwdSnapshot(ScanStatus.FAILED, issues=(problem,))
        result: dict[int, str | None] = {}
        current = None
        for line in output.splitlines():
            if line.startswith("p"):
                try:
                    current = int(line[1:])
                except ValueError:
                    current = None
            elif line.startswith("n") and current is not None:
                result[current] = line[1:]
        return CwdSnapshot(ScanStatus.OK, result)

    def process_parents(self, pids: set[int] | None = None) -> ProcessSnapshot:
        output, problem = self._run(
            ["ps", "-axo", "pid=,ppid=,args"], component="process_parents"
        )
        if problem:
            return ProcessSnapshot(ScanStatus.FAILED, issues=(problem,))
        table: dict[int, dict[str, object]] = {}
        for line in output.splitlines():
            tokens = line.split(None, 2)
            if len(tokens) < 2:
                continue
            try:
                pid, ppid = int(tokens[0]), int(tokens[1])
            except ValueError:
                continue
            table[pid] = {"ppid": ppid, "args": tokens[2] if len(tokens) > 2 else ""}
        return ProcessSnapshot(ScanStatus.OK, table)

    def process_groups(self) -> ProcessSnapshot:
        output, problem = self._run(
            ["ps", "-axo", "pid=,pgid="], component="process_groups"
        )
        if problem:
            return ProcessSnapshot(ScanStatus.FAILED, issues=(problem,))
        groups: dict[int, dict[str, object]] = {}
        for line in output.splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            try:
                pid, pgid = int(parts[0]), int(parts[1])
            except ValueError:
                continue
            group = groups.setdefault(pgid, {"members": []})
            members = group["members"]
            if isinstance(members, list):
                members.append(pid)
        return ProcessSnapshot(ScanStatus.OK, groups)

    @staticmethod
    def launch_environment(
        token: str, environ: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        env = dict(os.environ if environ is None else environ)
        home = os.path.expanduser("~")
        preferred = [
            os.path.join(home, ".local", "bin"),
            os.path.join(home, ".volta", "bin"),
            os.path.join(home, ".bun", "bin"),
            os.path.join(home, "Library", "pnpm"),
            os.path.join(home, ".asdf", "shims"),
            "/opt/homebrew/bin", "/opt/homebrew/sbin",
            "/usr/local/bin", "/usr/local/sbin",
        ]
        preferred.extend(sorted(
            glob.glob(os.path.join(home, ".nvm", "versions", "node", "*", "bin")),
            reverse=True,
        ))
        preferred.extend(sorted(
            glob.glob(os.path.join(home, ".fnm", "node-versions", "*", "installation", "bin")),
            reverse=True,
        ))
        preferred.extend((env.get("PATH") or "").split(os.pathsep))
        preferred.extend(("/usr/bin", "/bin", "/usr/sbin", "/sbin"))
        seen: set[str] = set()
        env["PATH"] = os.pathsep.join(
            path for path in preferred if path and not (path in seen or seen.add(path))
        )
        env.setdefault("PNPM_HOME", os.path.join(home, "Library", "pnpm"))
        env[RUN_TOKEN_ENV] = token
        return env

    def launch(self, app: LaunchRequest) -> ManagedRuntime:
        try:
            log_fd = os.open(app.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.fchmod(log_fd, 0o600)
            log_file = os.fdopen(log_fd, "ab", buffering=0)
        except OSError as exc:
            return ManagedRuntime(False, f"无法打开日志文件: {exc}")
        token = secrets.token_urlsafe(24)
        marker = RUN_TOKEN_ARG_PREFIX + token
        outer_script = '/bin/bash -c "$1"\nconsole_status=$?\nexit "$console_status"'
        inner_script = app.command + '\nconsole_status=$?\nwait\nexit "$console_status"'
        try:
            header = f"\n===== 启动于 {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n"
            log_file.write(header.encode("utf-8"))
            process = subprocess.Popen(
                ["/bin/bash", "-c", outer_script, marker, inner_script],
                cwd=app.cwd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env=self.launch_environment(token),
            )
        except Exception as exc:
            log_file.close()
            return ManagedRuntime(False, f"启动失败: {exc}")
        log_file.close()
        return ManagedRuntime(True, process=process, process_id=process.pid,
                              group_id=process.pid, token=token)

    def inspect_managed(self, identity: RuntimeIdentity) -> ManagedInspection:
        if identity.platform != self.name:
            return ManagedInspection(False, False, issue=_issue(
                "managed", "platform_mismatch", "runtime platform does not match adapter"
            ))
        members = identity.members or ((int(identity.identifier),)
                                       if isinstance(identity.identifier, int) else ())
        processes = self.process_snapshot(set(members), with_owner=True)
        if processes.status is ScanStatus.FAILED:
            return ManagedInspection(False, False, issue=processes.issues[0])
        verified = [
            pid for pid in members
            if processes.processes.get(pid, {}).get("uid") == self._principal.numeric_id
        ]
        return ManagedInspection(bool(verified), bool(verified), tuple(verified))

    def stop_managed(self, identity: RuntimeIdentity, force: bool = False) -> StopResult:
        if identity.platform != self.name or identity.owner != self._principal.identifier:
            return StopResult(False, "受控进程身份与当前平台用户不匹配")
        signal_value = signal.SIGKILL if force else signal.SIGTERM
        try:
            if identity.kind == "group":
                os.killpg(int(identity.identifier), signal_value)
            else:
                os.kill(int(identity.identifier), signal_value)
        except ProcessLookupError:
            return StopResult(True)
        except PermissionError:
            return StopResult(False, "没有权限停止受控进程")
        except OSError as exc:
            return StopResult(False, f"停止受控进程失败: {exc}")
        return StopResult(True)

    def stop_external_process(self, pid: int, force: bool = False) -> StopResult:
        if pid == self.self_pid:
            return StopResult(False, "不能结束总控台自身进程")
        snapshot = self.process_snapshot({pid}, with_owner=True)
        if snapshot.status is ScanStatus.FAILED:
            return StopResult(False, snapshot.issues[0].message)
        process = snapshot.processes.get(pid)
        if not process:
            return StopResult(False, "进程不存在")
        if process.get("uid") != self._principal.numeric_id:
            return StopResult(False, "只能结束当前用户的进程")
        return self.stop_managed(RuntimeIdentity(
            self.name, "pid", pid, self._principal.identifier, (pid,)
        ), force)

    def process_group_id(self, pid: int) -> int | None:
        try:
            return os.getpgid(int(pid))
        except (ProcessLookupError, PermissionError, OSError, ValueError):
            return None

    @staticmethod
    def current_process_group_id() -> int | None:
        return os.getpgrp()

    @staticmethod
    def pid_alive(pid: int) -> bool:
        try:
            os.kill(int(pid), 0)
            return True
        except PermissionError:
            return True
        except (OSError, ValueError, TypeError):
            return False

    def scheduled_tasks(self, paths: set[str] | None = None) -> ScheduledTaskSnapshot:
        issue = _issue(
            "scheduled_tasks", "unsupported_platform",
            "Windows Task Scheduler is unavailable on macOS",
        )
        return ScheduledTaskSnapshot(ScanStatus.FAILED, issues=(issue,))

    def run_scheduled_task(self, path: str) -> ScheduledTaskRunResult:
        return ScheduledTaskRunResult(
            False, path, "Windows Task Scheduler is unavailable on macOS",
            "UNSUPPORTED_PLATFORM",
        )

    def stop_scheduled_task(self, path: str) -> ScheduledTaskRunResult:
        return ScheduledTaskRunResult(
            False, path, "Windows Task Scheduler is unavailable on macOS",
            "UNSUPPORTED_PLATFORM",
        )

    def set_scheduled_task_enabled(
            self, path: str, enabled: bool) -> ScheduledTaskRunResult:
        return ScheduledTaskRunResult(
            False, path, "Windows Task Scheduler is unavailable on macOS",
            "UNSUPPORTED_PLATFORM",
        )

    @staticmethod
    def elevation_broker_status() -> ElevationBrokerStatus:
        return ElevationBrokerStatus()

    @staticmethod
    def install_elevation_broker(
            password_record: Mapping[str, object],
            package_executable: str | None = None) -> ElevationBrokerResult:
        return ElevationBrokerResult(
            False, "Windows elevation broker is unavailable on macOS",
            "UNSUPPORTED_PLATFORM",
        )

    @staticmethod
    def unlock_elevation_broker(password: str) -> ElevationBrokerResult:
        return ElevationBrokerResult(
            False, "Windows elevation broker is unavailable on macOS",
            "UNSUPPORTED_PLATFORM",
        )

    @staticmethod
    def lock_elevation_broker() -> ElevationBrokerResult:
        return ElevationBrokerResult(True)

    @staticmethod
    def launch_elevated(
            command_spec: Mapping[str, object], cwd: str | None,
    ) -> ElevationBrokerResult:
        return ElevationBrokerResult(
            False, "Windows elevation broker is unavailable on macOS",
            "UNSUPPORTED_PLATFORM",
        )

    def pick_path(self, kind: Literal["dir", "script", "exe"]) -> PickResult:
        script = (
            'POSIX path of (choose folder with prompt "选择工作目录")'
            if kind == "dir"
            else 'POSIX path of (choose file with prompt "%s")' % (
                "选择 EXE 程序" if kind == "exe" else "选择批处理脚本"
            )
        )
        try:
            result = subprocess.run(
                ["osascript", "-e", script], capture_output=True,
                text=True, timeout=180,
            )
        except subprocess.TimeoutExpired:
            return PickResult(issue=_issue("picker", "timeout", "系统选择框超时"))
        except OSError as exc:
            return PickResult(issue=_issue("picker", "os_error", str(exc)))
        if result.returncode != 0:
            return PickResult(canceled=True)
        path = result.stdout.strip().rstrip("/") or None
        return PickResult(path=path)

    @staticmethod
    def open_browser(url: str) -> None:
        webbrowser.open(url)

    def restart_console(self, preferred_port: int) -> RestartResult:
        try:
            helper = subprocess.Popen(
                [sys.executable, self.entrypoint, "--restart-helper",
                 str(self.self_pid), str(int(preferred_port))],
                cwd=self.base_dir,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            return RestartResult(False, error=str(exc))
        return RestartResult(True, helper_pid=helper.pid)

    def complete_console_restart(self, old_pid: int, preferred_port: int) -> int:
        deadline = time.monotonic() + 12.0
        while time.monotonic() < deadline and self.pid_alive(old_pid):
            time.sleep(0.1)
        if self.pid_alive(old_pid):
            return 1
        args = [
            sys.executable,
            self.entrypoint,
            "--preferred-port",
            str(int(preferred_port)),
            "--no-browser",
        ]
        os.execv(sys.executable, args)
        return 0

    @staticmethod
    def launcher_dialog(message: str) -> str | None:
        script = """on run argv
set messageText to item 1 of argv
display dialog messageText with title "总控台" buttons {"取消", "重新启动", "打开控制台"} default button "打开控制台" cancel button "取消" with icon note
return button returned of result
end run"""
        try:
            result = subprocess.run(
                ["osascript", "-e", script, message], capture_output=True,
                text=True, timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return result.stdout.strip() if result.returncode == 0 else None

    @staticmethod
    def launcher_alert(message: str) -> None:
        script = """on run argv
display alert "总控台" message (item 1 of argv) as critical
end run"""
        try:
            subprocess.run(
                ["osascript", "-e", script, message], capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    def platform_metadata(self) -> Mapping[str, object]:
        return {"platform": self.name, "capabilities": asdict(self.capabilities)}

    @staticmethod
    def configure_server_socket(sock: object) -> None:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

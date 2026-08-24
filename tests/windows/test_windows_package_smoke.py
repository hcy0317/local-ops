from __future__ import annotations

import hashlib
import http.client
import json
import locale
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile

from tools import build_windows


ARCHIVE_ENV = "LOCALOPS_WINDOWS_PACKAGE_ARCHIVE"
RUN_REAL = (
    sys.platform == "win32"
    and os.environ.get("LOCALOPS_RUN_WINDOWS_PACKAGE_SMOKE") == "1"
    and bool((os.environ.get(ARCHIVE_ENV) or "").strip())
)

if sys.platform == "win32":
    import psutil
    import pywintypes
    import win32api
    import win32con
    import win32event
    import win32gui
    import win32process
    import win32security


    class _NativeProcess:
        """Minimal Popen-compatible owner for one exact fixture process handle."""

        def __init__(self, handle, pid: int):
            self._handle = handle
            self._returncode: int | None = None
            self.pid = int(pid)

        def poll(self) -> int | None:
            if self._handle is None:
                return self._returncode
            result = win32event.WaitForSingleObject(self._handle, 0)
            if result == win32event.WAIT_TIMEOUT:
                return None
            if result != win32event.WAIT_OBJECT_0:
                raise OSError("fixture process poll failed")
            code = int(win32process.GetExitCodeProcess(self._handle))
            self._returncode = code
            return code

        def wait(self, timeout: float | None = None) -> int:
            if self._returncode is not None:
                return self._returncode
            milliseconds = (
                win32event.INFINITE
                if timeout is None
                else max(0, int(float(timeout) * 1000))
            )
            result = win32event.WaitForSingleObject(self._handle, milliseconds)
            if result == win32event.WAIT_TIMEOUT:
                raise subprocess.TimeoutExpired("LocalOps.exe", timeout)
            if result != win32event.WAIT_OBJECT_0:
                raise OSError("fixture process wait failed")
            code = int(win32process.GetExitCodeProcess(self._handle))
            self._returncode = code
            return code

        def terminate(self):
            if self.poll() is None:
                win32process.TerminateProcess(self._handle, 1)

        def kill(self):
            self.terminate()

        def close(self):
            if self._handle is not None:
                self._handle.Close()
                self._handle = None


    ConsoleProcess = _NativeProcess | subprocess.Popen[bytes]


@unittest.skipUnless(
    RUN_REAL,
    "real Windows package smoke requires its explicit gate and archive path",
)
class WindowsPackageSmokeTests(unittest.TestCase):
    """Exercise only processes and storage created by this package fixture.

    The child PATH contains no Python, but the unittest harness still requires
    Python and Windows test dependencies. A PASS is not clean-VM evidence.
    """

    API_LIMIT = 128 * 1024
    CONSOLE_READY_TIMEOUT = 60.0
    STATE_TIMEOUT = 30.0
    PROCESS_EXIT_TIMEOUT = 15.0

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="LocalOps 打包冒烟 ", delete=False
        )
        self.fixture_root = Path(self.temporary.name).resolve()
        self.fixture_cleanup_safe = True
        self.fixture_acl_restored = True
        self.lifecycle_requested = False
        self.addCleanup(self._remove_fixture_tree)
        self.install_root = self.fixture_root / "安装 包"
        self.install_root.mkdir()
        self.work_dir = self.fixture_root / "项目 目录"
        self.work_dir.mkdir()
        self.temp_dir = self.fixture_root / "临时 文件"
        self.temp_dir.mkdir()
        self.data_dir = self.fixture_root / "用户 数据"
        self.log_dir = self.fixture_root / "用户 日志"
        self.archive = Path(
            os.path.abspath(os.path.expanduser(os.environ[ARCHIVE_ENV]))
        )
        self.assertTrue(self.archive.is_file(), "Windows package archive is absent")

        self.console_processes: list[tuple[ConsoleProcess, float]] = []
        self.current_console: ConsoleProcess | None = None
        self.console_port: int | None = None
        self.app_id: str | None = None
        self.runtime_identity: dict[str, object] | None = None

        self._assert_supported_host()
        self.manifest = self._audit_and_extract()
        self.executable = self.bundle / "LocalOps.exe"
        self.initial_install_hashes = self._tree_hashes(self.bundle)
        self._assert_manifest_matches_install_tree()
        self.child_environment = self._package_environment()
        self._assert_no_python_on_child_path()

        self.addCleanup(self._restore_bundle_acl)
        self._make_bundle_read_execute_only()
        self._assert_bundle_write_denied()

        # Registered after ACL restore so process cleanup runs first.
        self.addCleanup(self._cleanup_fixture_processes)

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _assert_supported_host(self):
        self.assertIn(platform.machine().casefold(), {"amd64", "x86_64"})
        # A developer-machine PASS is Windows 11 non-admin evidence only. CI is
        # separately identified as hosted Windows Server and is not relabeled.
        if not os.environ.get("CI"):
            self.assertGreaterEqual(sys.getwindowsversion().build, 22000)
            self.assertFalse(bool(__import__("ctypes").windll.shell32.IsUserAnAdmin()))

    @classmethod
    def _tree_hashes(cls, root: Path) -> dict[str, str]:
        result = {}
        for path in sorted(root.rglob("*")):
            if path.is_symlink() or (path.exists() and not path.is_file() and not path.is_dir()):
                raise AssertionError("install tree contains a non-regular entry")
            if path.is_file():
                result[path.relative_to(root).as_posix()] = cls._sha256(path)
        return result

    def _audit_and_extract(self) -> dict[str, object]:
        try:
            manifest = build_windows.audit_archive(self.archive)
        except SystemExit as exc:
            self.fail("Windows archive audit failed: %s" % self._sanitize(exc))
        expected_archive_hash = str(manifest["archive"]["sha256"])
        self.assertEqual(self._sha256(self.archive), expected_archive_hash)

        expected = {
            str(item["path"]): (str(item["sha256"]), int(item["size"]))
            for item in manifest["payload"]
        }
        with zipfile.ZipFile(self.archive) as source:
            infos = source.infolist()
            self.assertEqual([info.filename for info in infos], list(expected))
            for info in infos:
                data = source.read(info)
                digest, size = expected[info.filename]
                self.assertEqual(len(data), size)
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
                relative = PurePosixPath(info.filename)
                destination = self.install_root.joinpath(*relative.parts)
                self._assert_fixture_path(destination)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as stream:
                    stream.write(data)

        # Detect replacement during extraction as well as before it.
        self.assertEqual(self._sha256(self.archive), expected_archive_hash)
        self.bundle = self.install_root / build_windows.bundle_name(
            str(manifest["version"])
        )
        self.assertTrue(self.bundle.is_dir())
        self._assert_fixture_path(self.bundle)
        return manifest

    def _assert_manifest_matches_install_tree(self):
        prefix = self.bundle.name + "/"
        expected = {
            str(item["path"])[len(prefix):]: str(item["sha256"])
            for item in self.manifest["payload"]
            if str(item["path"]).startswith(prefix)
        }
        self.assertEqual(self.initial_install_hashes, expected)

    def _assert_fixture_path(self, path: Path):
        resolved = path.resolve(strict=False)
        self.assertEqual(
            os.path.commonpath((str(self.fixture_root), str(resolved))),
            str(self.fixture_root),
            "fixture path escaped its temporary root",
        )
        current = resolved
        while current != self.fixture_root:
            self.assertFalse(current.is_symlink(), "fixture path contains a link")
            current = current.parent

    def _package_environment(self) -> dict[str, str]:
        system_root_value = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        environment = dict(os.environ)
        python_names = {
            "VIRTUAL_ENV",
            "__PYVENV_LAUNCHER__",
            "CONDA_DEFAULT_ENV",
            "CONDA_PREFIX",
        }
        replaced_names = {
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
        }
        for name in list(environment):
            upper = name.upper()
            if (
                upper in python_names
                or upper in replaced_names
                or upper.startswith(("PYTHON", "PYENV", "PIP_", "CONDA_", "UV_"))
                or upper.startswith("LOCALOPS_")
            ):
                environment.pop(name, None)

        system_root = Path(system_root_value or "")
        self.assertTrue(system_root.is_absolute() and system_root.is_dir())
        path_entries = (
            system_root / "System32",
            system_root / "System32" / "Wbem",
            system_root / "System32" / "WindowsPowerShell" / "v1.0",
        )
        for entry in path_entries:
            self.assertTrue(entry.is_dir(), "required Windows system directory is absent")
        environment["PATH"] = os.pathsep.join(str(path) for path in path_entries)
        environment["PATHEXT"] = ".COM;.EXE;.BAT;.CMD"
        environment["SystemRoot"] = str(system_root)
        environment["WINDIR"] = str(system_root)
        environment["COMSPEC"] = str(system_root / "System32" / "cmd.exe")
        environment["CONSOLE_DATA_DIR"] = str(self.data_dir)
        environment["CONSOLE_LOG_DIR"] = str(self.log_dir)
        environment["TEMP"] = str(self.temp_dir)
        environment["TMP"] = str(self.temp_dir)
        return environment

    def _assert_no_python_on_child_path(self):
        child_path = self.child_environment["PATH"]
        for executable in ("python", "python3", "py"):
            self.assertIsNone(
                shutil.which(executable, path=child_path),
                "%s unexpectedly exists on the packaged child PATH" % executable,
            )

    @staticmethod
    def _current_user_sid() -> str:
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        try:
            sid = win32security.GetTokenInformation(
                token, win32security.TokenUser
            )[0]
            return str(win32security.ConvertSidToStringSid(sid))
        finally:
            token.Close()

    def _icacls(self, arguments: list[str], *, action: str):
        executable = Path(self.child_environment["SystemRoot"]) / "System32" / "icacls.exe"
        completed = subprocess.run(
            [str(executable), *arguments],
            cwd=self.install_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
        if completed.returncode != 0:
            output = completed.stdout.decode(
                locale.getpreferredencoding(False), errors="replace"
            )
            self.fail(
                "icacls %s failed (exit=%d, output=%r)"
                % (action, completed.returncode, self._sanitize(output))
            )

    def _make_bundle_read_execute_only(self):
        self._assert_fixture_path(self.bundle)
        sid = self._current_user_sid()
        allow_read_execute = "*%s:(OI)(CI)(RX)" % sid
        deny_write_data = "*%s:(OI)(CI)(WD,AD)" % sid
        self.fixture_acl_restored = False
        # A hosted administrator may reach the extracted tree only through its
        # Administrators ACE. The Limited smoke token intentionally disables that
        # SID, so model Program Files by granting the exact user explicit RX first.
        self._icacls(
            [
                self.bundle.name,
                "/grant",
                allow_read_execute,
                "/T",
                "/Q",
            ],
            action="grant recursive bundle read execute",
        )
        # Denying data creation/appends for the exact user overrides that write
        # path while preserving loader read/execute and ACL-recovery rights.
        self._icacls(
            [
                self.bundle.name,
                "/deny",
                deny_write_data,
                "/T",
                "/Q",
            ],
            action="deny recursive bundle data writes",
        )

    def _assert_bundle_write_denied(self):
        marker = self.bundle / build_windows.BUILD_INFO_NAME
        descriptor = None
        try:
            descriptor = os.open(marker, os.O_WRONLY | os.O_APPEND)
        except PermissionError:
            pass
        else:
            self.fail("bundle remained writable after RX-only ACL was applied")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _restore_bundle_acl(self):
        if not self.bundle.exists():
            return
        self._assert_fixture_path(self.bundle)
        deny_sid = "*%s" % self._current_user_sid()
        self._icacls(
            [self.bundle.name, "/remove:d", deny_sid, "/T", "/Q"],
            action="remove recursive bundle write deny",
        )
        marker = self.bundle / build_windows.BUILD_INFO_NAME
        descriptor = os.open(marker, os.O_WRONLY | os.O_APPEND)
        os.close(descriptor)
        self.fixture_acl_restored = True

    def _remove_fixture_tree(self):
        if not self.fixture_cleanup_safe or not self.fixture_acl_restored:
            return
        if not self.fixture_root.exists():
            return
        expected_parent = Path(tempfile.gettempdir()).resolve()
        self.assertEqual(
            os.path.normcase(str(self.fixture_root.parent)),
            os.path.normcase(str(expected_parent)),
        )
        self.assertTrue(self.fixture_root.name.startswith("LocalOps 打包冒烟 "))
        shutil.rmtree(self.fixture_root)

    @staticmethod
    def _free_port(excluded: set[int] | None = None) -> int:
        excluded = excluded or set()
        for _ in range(20):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                port = int(listener.getsockname()[1])
            if port not in excluded:
                return port
        raise AssertionError("could not reserve an isolated loopback port")

    @staticmethod
    def _free_console_port(excluded: set[int] | None = None) -> int:
        excluded = excluded or set()
        for port in reversed(range(9600, 9610)):
            if port in excluded:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                    listener.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
        raise AssertionError("no free Local Ops console port is available")

    def _authenticated_json_api(
        self,
        port: int,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
        *,
        timeout: float = 15.0,
    ) -> tuple[int, dict[str, object]]:
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        with (self.data_dir / "control-credential.json").open(
                "r", encoding="utf-8") as stream:
            credential = json.load(stream)
        if credential.get("port") != port or not isinstance(
                credential.get("token"), str):
            raise AssertionError("control credential does not match console port")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            connection.putrequest(method, path, skip_accept_encoding=True)
            connection.putheader(
                "Authorization", "Bearer " + credential["token"]
            )
            if body is not None:
                connection.putheader("Content-Type", "application/json")
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
            raw = response.read(self.API_LIMIT + 1)
            status = int(response.status)
        finally:
            connection.close()
        self.assertLessEqual(len(raw), self.API_LIMIT, "API response exceeded fixture limit")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.fail(
                "API returned non-JSON (status=%d, body=%r)"
                % (status, self._sanitize(raw.decode("utf-8", errors="replace")))
            )
        self.assertIsInstance(decoded, dict)
        return status, decoded

    def _require_api_ok(self, status: int, payload: dict[str, object], action: str):
        if status == 200 and payload.get("ok") is not False:
            return
        self.fail(
            "%s failed (status=%d, code=%r, error=%r)"
            % (
                action,
                status,
                self._sanitize(payload.get("code")),
                self._sanitize(payload.get("error")),
            )
        )

    def _console_log_tail(self) -> str:
        path = self.log_dir / "console.log"
        try:
            with path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                stream.seek(max(0, size - 4096))
                return self._sanitize(stream.read().decode("utf-8", errors="replace"))
        except OSError as exc:
            return "<unavailable:%s>" % type(exc).__name__

    def _console_process_diagnostics(self, process: ConsoleProcess) -> str:
        try:
            root = psutil.Process(process.pid)
            descendants = root.children(recursive=True)
            rows = []
            for candidate in (root, *descendants):
                try:
                    rows.append({
                        "pid": candidate.pid,
                        "name": candidate.name(),
                        "status": candidate.status(),
                        "threads": candidate.num_threads(),
                        "cmdline": candidate.cmdline(),
                    })
                except psutil.Error as exc:
                    rows.append({
                        "pid": candidate.pid,
                        "error": type(exc).__name__,
                    })
            tracked_pids = {int(row["pid"]) for row in rows}
        except psutil.Error as exc:
            return "process:%s" % type(exc).__name__

        windows = []

        def collect_window(hwnd, _context):
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if int(pid) not in tracked_pids:
                    return True
                controls = []

                def collect_control(control, _child_context):
                    try:
                        text = win32gui.GetWindowText(control)
                        if text:
                            controls.append({
                                "class": win32gui.GetClassName(control),
                                "text": text,
                            })
                    except pywintypes.error:
                        pass
                    return True

                win32gui.EnumChildWindows(hwnd, collect_control, None)
                windows.append({
                    "pid": int(pid),
                    "class": win32gui.GetClassName(hwnd),
                    "title": win32gui.GetWindowText(hwnd),
                    "visible": bool(win32gui.IsWindowVisible(hwnd)),
                    "controls": controls,
                })
            except pywintypes.error:
                pass
            return True

        win32gui.EnumWindows(collect_window, None)
        return self._sanitize({"processes": rows, "windows": windows})

    def _start_console(self, port: int) -> ConsoleProcess:
        process_token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_ALL_ACCESS
        )
        elevated = bool(win32security.GetTokenInformation(
            process_token, win32security.TokenElevation
        ))
        if not elevated:
            process_token.Close()
            process = subprocess.Popen(
                [
                    str(self.executable),
                    "--no-browser",
                    "--preferred-port",
                    str(port),
                ],
                cwd=self.work_dir,
                env=self.child_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        else:
            launch_token = None
            thread_handle = None
            try:
                try:
                    launch_token = win32security.GetTokenInformation(
                        process_token, win32security.TokenLinkedToken
                    )
                except pywintypes.error:
                    administrators = win32security.CreateWellKnownSid(
                        win32security.WinBuiltinAdministratorsSid, None
                    )
                    launch_token = win32security.CreateRestrictedToken(
                        process_token,
                        win32security.DISABLE_MAX_PRIVILEGE,
                        [(administrators, 0)],
                        [],
                        [],
                    )
                startup = win32process.STARTUPINFO()
                startup.dwFlags |= win32con.STARTF_USESHOWWINDOW
                startup.wShowWindow = win32con.SW_HIDE
                startup.lpDesktop = r"winsta0\default"
                command = subprocess.list2cmdline([
                    str(self.executable),
                    "--no-browser",
                    "--preferred-port",
                    str(port),
                ])
                process_handle, thread_handle, pid, _ = (
                    win32process.CreateProcessAsUser(
                        launch_token,
                        str(self.executable),
                        command,
                        None,
                        None,
                        False,
                        win32process.CREATE_UNICODE_ENVIRONMENT,
                        self.child_environment,
                        str(self.work_dir),
                        startup,
                    )
                )
                process = _NativeProcess(process_handle, pid)
            finally:
                if thread_handle is not None:
                    thread_handle.Close()
                if launch_token is not None:
                    launch_token.Close()
                process_token.Close()
        try:
            create_time = float(psutil.Process(process.pid).create_time())
        except psutil.Error:
            create_time = time.time()
        self.console_processes.append((process, create_time))
        self.current_console = process

        deadline = time.monotonic() + self.CONSOLE_READY_TIMEOUT
        last_error = "connection unavailable"
        while time.monotonic() < deadline:
            returncode = process.poll()
            if returncode is not None:
                self.fail(
                    "packaged console exited before readiness "
                    "(exit=%d, log=%r)" % (returncode, self._console_log_tail())
                )
            try:
                status, state = self._authenticated_json_api(
                    port, "GET", "/api/state", timeout=3.0
                )
                if (
                    status == 200
                    and state.get("consolePid") == process.pid
                    and state.get("consolePort") == port
                ):
                    return process
                last_error = "console identity did not match fixture"
            except (OSError, http.client.HTTPException, AssertionError) as exc:
                last_error = type(exc).__name__
            time.sleep(0.1)
        self.fail(
            "packaged console was not ready within %.0fs "
            "(last=%s, log=%r, diagnostics=%s)"
            % (
                self.CONSOLE_READY_TIMEOUT,
                last_error,
                self._console_log_tail(),
                self._console_process_diagnostics(process),
            )
        )

    def _terminate_console(self, process: ConsoleProcess):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=self.PROCESS_EXIT_TIMEOUT)
            except subprocess.TimeoutExpired:
                # This is the exact Popen created by this fixture.
                process.kill()
                process.wait(timeout=5.0)
        if self.current_console is process:
            self.current_console = None

    def _state_row(self, port: int) -> tuple[dict[str, object], dict[str, object] | None]:
        status, state = self._authenticated_json_api(port, "GET", "/api/state")
        self.assertEqual(status, 200)
        row = next(
            (app for app in state.get("apps", []) if app.get("id") == self.app_id),
            None,
        )
        return state, row

    def _wait(self, predicate, *, timeout: float, message: str):
        deadline = time.monotonic() + timeout
        last_error = None
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except (OSError, http.client.HTTPException, KeyError, ValueError) as exc:
                last_error = type(exc).__name__
            time.sleep(0.1)
        suffix = "" if last_error is None else " (last=%s)" % last_error
        self.fail(message + suffix)

    @staticmethod
    def _powershell_tcp_fixture(port: int) -> str:
        return "\n".join(
            (
                "$ErrorActionPreference = 'Stop'",
                "$listener = [System.Net.Sockets.TcpListener]::new("
                "[System.Net.IPAddress]::Loopback, %d)" % port,
                "$listener.Start()",
                "[Console]::Out.WriteLine('LOCALOPS_PACKAGE_SMOKE_READY')",
                "[Console]::Out.Flush()",
                "try {",
                "  while ($true) {",
                "    $client = $listener.AcceptTcpClient()",
                "    try {",
                "      $stream = $client.GetStream()",
                "      $buffer = New-Object byte[] 4096",
                "      $request = New-Object System.IO.MemoryStream",
                "      while ($request.Length -lt 8192) {",
                "        $read = $stream.Read($buffer, 0, $buffer.Length)",
                "        if ($read -le 0) { break }",
                "        $request.Write($buffer, 0, $read)",
                "        $text = [Text.Encoding]::ASCII.GetString($request.ToArray())",
                "        if ($text.Contains(\"`r`n`r`n\")) { break }",
                "      }",
                "      $body = [Text.Encoding]::UTF8.GetBytes("
                "'{\"ok\":true,\"source\":\"package-smoke\"}')",
                "      $head = [Text.Encoding]::ASCII.GetBytes("
                "\"HTTP/1.1 200 OK`r`nContent-Type: application/json`r`n\" + "
                "\"Content-Length: $($body.Length)`r`nConnection: close`r`n`r`n\")",
                "      $stream.Write($head, 0, $head.Length)",
                "      $stream.Write($body, 0, $body.Length)",
                "      $stream.Flush()",
                "    } finally {",
                "      $client.Dispose()",
                "    }",
                "  }",
                "} finally {",
                "  $listener.Stop()",
                "}",
            )
        )

    def _raw_fixture_response(self, port: int) -> dict[str, object]:
        request = (
            "GET /health HTTP/1.1\r\n"
            "Host: 127.0.0.1:%d\r\n"
            "Connection: close\r\n\r\n" % port
        ).encode("ascii")
        chunks = []
        total = 0
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as client:
            client.settimeout(2.0)
            client.sendall(request)
            while total <= self.API_LIMIT:
                chunk = client.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        self.assertLessEqual(total, self.API_LIMIT)
        head, separator, body = b"".join(chunks).partition(b"\r\n\r\n")
        self.assertEqual(separator, b"\r\n\r\n")
        self.assertTrue(head.startswith(b"HTTP/1.1 200 "))
        decoded = json.loads(body.decode("utf-8"))
        self.assertIsInstance(decoded, dict)
        return decoded

    @staticmethod
    def _exact_process_alive(pid: int, create_time: float) -> bool:
        try:
            actual = float(psutil.Process(int(pid)).create_time())
        except psutil.NoSuchProcess:
            return False
        except psutil.Error:
            return True
        return abs(actual - float(create_time)) <= 0.1

    def _assert_runtime_executables(self, identity: dict[str, object]):
        expected = {
            "runner": self.executable,
            "root": Path(self.child_environment["SystemRoot"])
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe",
        }
        for label, executable in expected.items():
            pid = int(identity[label + "Pid"])
            created = float(identity[label + "CreateTime"])
            self.assertTrue(self._exact_process_alive(pid, created))
            actual = Path(psutil.Process(pid).exe())
            self.assertEqual(
                os.path.normcase(str(actual.resolve())),
                os.path.normcase(str(executable.resolve())),
            )

    def _stop_through_api(self, port: int, generation: str):
        status, stopped = self._authenticated_json_api(
            port,
            "POST",
            "/api/apps/%s/stop" % self.app_id,
            {"expectedGeneration": generation, "force": False},
            timeout=20.0,
        )
        if status == 409 and stopped.get("code") == "STOP_TIMEOUT":
            _, fresh = self._state_row(port)
            self.assertIsNotNone(fresh)
            fresh_identity = fresh.get("runtimeIdentity") or {}
            self.assertEqual(fresh_identity.get("generationId"), generation)
            self.assertEqual(fresh.get("lifecycleStatus"), "running")
            self.assertTrue(fresh.get("controlAvailable"))
            status, stopped = self._authenticated_json_api(
                port,
                "POST",
                "/api/apps/%s/stop" % self.app_id,
                {"expectedGeneration": generation, "force": True},
                timeout=20.0,
            )
        self._require_api_ok(status, stopped, "stop packaged fixture")

    def _persisted_fixture_identity(self) -> dict[str, object] | None:
        if not self.app_id:
            return None
        path = self.data_dir / "config.json"
        if not path.is_file() or path.stat().st_size > self.API_LIMIT:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        apps = value.get("apps") if isinstance(value, dict) else None
        if not isinstance(apps, list):
            raise ValueError("fixture config apps are invalid")
        matches = [
            app for app in apps
            if isinstance(app, dict) and app.get("id") == self.app_id
        ]
        if len(matches) != 1:
            return None
        identity = matches[0].get("runtimeIdentity")
        return dict(identity) if isinstance(identity, dict) else None

    def _cleanup_fixture_processes(self):
        self.fixture_cleanup_safe = False
        problems = []
        identity_errors = []
        identity = self.runtime_identity
        if identity is None and self.current_console is not None and self.app_id:
            try:
                _, row = self._state_row(int(self.console_port))
                candidate = row.get("runtimeIdentity") if row else None
                if isinstance(candidate, dict):
                    identity = dict(candidate)
            except Exception as exc:
                identity_errors.append("state:%s" % type(exc).__name__)
        if identity is None and self.app_id:
            try:
                identity = self._persisted_fixture_identity()
            except Exception as exc:
                identity_errors.append("config:%s" % type(exc).__name__)
        if identity is not None:
            self.runtime_identity = identity

        for process, _ in reversed(self.console_processes):
            try:
                self._terminate_console(process)
            except (OSError, subprocess.SubprocessError) as exc:
                problems.append("console:%s" % type(exc).__name__)

        tracked_runtime = []
        if isinstance(identity, dict) and self.app_id:
            for label in ("root", "runner"):
                pid = identity.get(label + "Pid")
                created = identity.get(label + "CreateTime")
                if (
                    isinstance(pid, int)
                    and not isinstance(pid, bool)
                    and isinstance(created, (int, float))
                    and not isinstance(created, bool)
                ):
                    tracked_runtime.append((label, pid, float(created)))
                else:
                    problems.append("%s identity invalid" % label)

            generation = identity.get("generationId")
            runtime_records = (
                self.data_dir / "runtime" / self.app_id / str(generation)
            )
            if runtime_records.exists() or any(
                self._exact_process_alive(pid, created)
                for _, pid, created in tracked_runtime
            ):
                # Emergency cleanup is limited to the exact signed identity
                # recovered from this isolated fixture.
                try:
                    from localops.platform.windows import WindowsPlatform

                    with mock.patch.dict(
                        os.environ,
                        {
                            "CONSOLE_DATA_DIR": str(self.data_dir),
                            "CONSOLE_LOG_DIR": str(self.log_dir),
                        },
                    ):
                        platform = WindowsPlatform(
                            str(self.bundle), str(self.executable)
                        )
                        native = platform._identity_from_public(identity, self.app_id)
                        inspection = platform.inspect_managed(native)
                        if not inspection.verified:
                            raise RuntimeError("fixture identity is unverified")
                        if inspection.members:
                            stopped = platform.stop_managed(
                                native, force=True, timeout=2.0
                            )
                            if not stopped.ok:
                                raise RuntimeError("exact fixture force failed")
                        terminal = platform.inspect_managed(native)
                        if terminal.verified and not terminal.members:
                            released = platform.release_managed(native)
                            if not released.ok:
                                raise RuntimeError("fixture release failed")
                except Exception as exc:
                    problems.append("runtime:%s" % type(exc).__name__)
        elif self.lifecycle_requested:
            problems.append("runtime identity unavailable")
            problems.extend(identity_errors)

        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            console_alive = any(
                process.poll() is None for process, _ in self.console_processes
            )
            runtime_alive = any(
                self._exact_process_alive(pid, created)
                for _, pid, created in tracked_runtime
            )
            if not console_alive and not runtime_alive:
                break
            time.sleep(0.1)
        else:
            problems.append("exact fixture process remained alive")
        for process, _ in self.console_processes:
            close = getattr(process, "close", None)
            if close is not None:
                close()

        if problems:
            raise AssertionError(
                "fixture cleanup incomplete; evidence preserved at %s (%s)"
                % (self.fixture_root, ", ".join(problems))
            )
        self.fixture_cleanup_safe = True

    def _sanitize(self, value: object, limit: int = 2048) -> str:
        text = str(value).replace(str(self.fixture_root), "<fixture>")
        text = "".join(
            character
            if character in "\r\n\t" or character.isprintable()
            else "?"
            for character in text
        )
        return text[:limit]

    def test_audited_package_runs_lifecycle_from_read_only_chinese_path(self):
        service_port = self._free_port()
        self.console_port = self._free_console_port({service_port})
        first_console = self._start_console(self.console_port)

        state, _ = self._state_row(self.console_port)
        self.assertEqual(state.get("platform"), "windows")
        self.assertEqual(state.get("consolePid"), first_console.pid)
        self.assertTrue(state.get("capabilities", {}).get("launch_managed"))
        self.assertFalse(state.get("platformInfo", {}).get("controllerElevated"))
        self.assertEqual(
            os.path.normcase(
                os.path.commonpath(
                    (str(self.bundle), str(Path(state["consoleCwd"]).resolve()))
                )
            ),
            os.path.normcase(str(self.bundle)),
        )

        command_spec = {
            "version": 1,
            "mode": "powershell",
            "executable": None,
            "args": [],
            "shell": "powershell.exe",
            "text": self._powershell_tcp_fixture(service_port),
            "needsReview": False,
        }
        status, created = self._authenticated_json_api(
            self.console_port,
            "POST",
            "/api/apps",
            {
                "name": "Package TCP fixture",
                "command": "Reviewed raw PowerShell TCP fixture",
                "commandSpec": command_spec,
                "cwd": str(self.work_dir),
                "port": service_port,
                "kind": "service",
            },
        )
        self._require_api_ok(status, created, "create packaged fixture")
        self.app_id = str(created["id"])
        self.assertFalse(created["commandSpec"]["needsReview"])

        self.lifecycle_requested = True
        status, started = self._authenticated_json_api(
            self.console_port,
            "POST",
            "/api/apps/%s/start" % self.app_id,
            {"expectedGeneration": None},
            timeout=30.0,
        )
        self._require_api_ok(status, started, "start packaged fixture")
        generation = str(started["generationId"])
        _, started_row = self._state_row(self.console_port)
        self.assertIsNotNone(started_row)
        started_identity = started_row.get("runtimeIdentity")
        self.assertIsInstance(started_identity, dict)
        self.assertEqual(started_identity.get("generationId"), generation)
        self.runtime_identity = dict(started_identity)
        self._assert_runtime_executables(self.runtime_identity)

        running_row = None

        def state_is_running():
            nonlocal running_row
            _, row = self._state_row(int(self.console_port))
            if row and isinstance(row.get("runtimeIdentity"), dict):
                self.runtime_identity = dict(row["runtimeIdentity"])
            if (
                row
                and row.get("lifecycleStatus") == "running"
                and row.get("running") is True
                and row.get("listening") is True
                and service_port in row.get("ports", [])
                and (row.get("runtimeIdentity") or {}).get("generationId") == generation
            ):
                running_row = row
                return True
            return False

        self._wait(
            state_is_running,
            timeout=self.STATE_TIMEOUT,
            message="packaged fixture did not reach verified running/listening state",
        )
        self.assertIsNotNone(running_row)
        self.assertIsNotNone(self.runtime_identity)
        self.assertEqual(running_row["port"], service_port)

        def log_is_ready():
            status, log = self._authenticated_json_api(
                int(self.console_port),
                "GET",
                "/api/apps/%s/logs?tail=200" % self.app_id,
            )
            return status == 200 and "LOCALOPS_PACKAGE_SMOKE_READY" in str(log.get("text"))

        self._wait(
            log_is_ready,
            timeout=10.0,
            message="packaged fixture marker was absent from its app log",
        )
        response = None

        def fixture_responds():
            nonlocal response
            response = self._raw_fixture_response(service_port)
            return response == {"ok": True, "source": "package-smoke"}

        self._wait(
            fixture_responds,
            timeout=10.0,
            message="packaged PowerShell TCP fixture did not return JSON",
        )

        self._terminate_console(first_console)
        self.assertEqual(
            self._raw_fixture_response(service_port),
            {"ok": True, "source": "package-smoke"},
            "managed service died with its first packaged console",
        )

        second_console = self._start_console(self.console_port)
        _, reopened = self._state_row(self.console_port)
        self.assertIsNotNone(reopened)
        self.assertEqual(
            (reopened.get("runtimeIdentity") or {}).get("generationId"),
            generation,
        )
        self.assertEqual(reopened.get("lifecycleStatus"), "running")
        self.assertTrue(reopened.get("controlAvailable"))
        self.assertEqual(second_console.pid, self.current_console.pid)

        self._stop_through_api(self.console_port, generation)

        stopped_row = None

        def state_is_stopped():
            nonlocal stopped_row
            _, row = self._state_row(int(self.console_port))
            if (
                row
                and row.get("lifecycleStatus") == "stopped"
                and row.get("runtimeIdentity") is None
                and row.get("running") is False
                and row.get("listening") is False
                and row.get("ports") == []
            ):
                stopped_row = row
                return True
            return False

        self._wait(
            state_is_stopped,
            timeout=self.STATE_TIMEOUT,
            message="packaged fixture did not reach a cleared stopped state",
        )
        self.assertIsNotNone(stopped_row)

        active_records = self.data_dir / "runtime" / self.app_id / generation
        tombstone = self.data_dir / "runtime" / (".cleanup-%s-%s" % (self.app_id, generation))
        self._wait(
            lambda: not active_records.exists()
            and not tombstone.exists()
            and not active_records.parent.exists(),
            timeout=10.0,
            message="packaged runtime records were not cleaned",
        )

        status, deleted = self._authenticated_json_api(
            self.console_port,
            "DELETE",
            "/api/apps/%s" % self.app_id,
            {"expectedGeneration": None},
        )
        self._require_api_ok(status, deleted, "delete packaged fixture")
        _, deleted_row = self._state_row(self.console_port)
        self.assertIsNone(deleted_row)

        self._terminate_console(second_console)
        tracked = [
            (process.pid, create_time)
            for process, create_time in self.console_processes
        ]
        tracked.extend(
            (
                (int(self.runtime_identity["rootPid"]), float(self.runtime_identity["rootCreateTime"])),
                (int(self.runtime_identity["runnerPid"]), float(self.runtime_identity["runnerCreateTime"])),
            )
        )
        self._wait(
            lambda: all(not self._exact_process_alive(pid, created) for pid, created in tracked),
            timeout=10.0,
            message="one or more exact fixture process identities remained alive",
        )
        self.assertEqual(self._tree_hashes(self.bundle), self.initial_install_hashes)


if __name__ == "__main__":
    unittest.main()

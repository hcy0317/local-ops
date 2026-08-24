import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from localops.command_spec import shell_command_spec
from localops.elevation_broker import broker_task_sddl
from localops.platform.contracts import (
    LaunchRequest,
    ScanStatus,
    ScheduledTaskRunResult,
    ScheduledTaskSnapshot,
    StopResult,
)

if sys.platform == "win32":
    import psutil
    import win32api
    import win32con
    import win32gui
    import win32process
    import win32security
    import win32ui

    from localops.platform import windows as windows_adapter
    from localops.platform.windows import WindowsPlatform
    from localops.windows.runner_protocol import (
        PROTOCOL_VERSION,
        job_name,
        sign_record,
        token_digest,
        write_json_atomic,
    )


@unittest.skipUnless(sys.platform == "win32", "Windows-only adapter tests")
class WindowsPlatformTests(unittest.TestCase):
    def setUp(self):
        self.platform = WindowsPlatform(os.getcwd(), "server.py")
        # Adapter unit tests model the production Limited controller even when
        # the hosted runner itself has an administrator token. The explicit
        # elevated-controller test below opts back into True.
        self.platform.controller_elevated = False

    def test_broker_exchange_waits_for_new_task_pipe_to_appear(self):
        missing = windows_adapter.pywintypes.error(
            windows_adapter.winerror.ERROR_FILE_NOT_FOUND,
            "WaitNamedPipe", "pipe is not ready",
        )
        with mock.patch.object(
                windows_adapter.win32pipe, "WaitNamedPipe",
                side_effect=[missing, None]) as wait_pipe, \
                mock.patch.object(
                    windows_adapter.win32file, "CreateFile",
                    return_value="pipe"), \
                mock.patch.object(
                    windows_adapter.win32pipe, "SetNamedPipeHandleState"), \
                mock.patch.object(windows_adapter.win32file, "WriteFile"), \
                mock.patch.object(
                    windows_adapter.win32file, "ReadFile",
                    return_value=(0, windows_adapter.encode_message({
                        "ok": True,
                    }))), \
                mock.patch.object(windows_adapter.win32file, "CloseHandle"):
            response = self.platform._broker_exchange(
                {"action": "status"}, timeout_ms=500
            )

        self.assertEqual(response, {"ok": True})
        self.assertEqual(wait_pipe.call_count, 2)

    def test_locked_down_scheduler_query_and_stop_fall_back_to_broker(self):
        self.platform._elevation_token = "session-token"
        failed = ScheduledTaskSnapshot(ScanStatus.FAILED)
        with mock.patch.object(
                self.platform, "_scheduled_tasks_direct",
                return_value=failed), \
                mock.patch.object(
                    self.platform, "_broker_scheduled_exchange",
                    side_effect=[{
                        "ok": True,
                        "status": "ok",
                        "tasks": {r"\memos-guard": {
                            "path": r"\Memos-Guard", "state": "running",
                        }},
                        "issues": [],
                    }, {
                        "ok": True, "operation": "stop",
                        "path": r"\Memos-Guard",
                    }]) as exchange, \
                mock.patch.object(
                    self.platform, "_stop_scheduled_task_direct",
                    return_value=ScheduledTaskRunResult(
                        False, r"\Memos-Guard", "access denied"
                    )):
            snapshot = self.platform.scheduled_tasks({r"\Memos-Guard"})
            stopped = self.platform.stop_scheduled_task(r"\Memos-Guard")

        self.assertIs(snapshot.status, ScanStatus.OK)
        self.assertEqual(snapshot.tasks[r"\memos-guard"]["state"], "running")
        self.assertTrue(stopped.ok)
        self.assertEqual(exchange.call_count, 2)

    def test_source_venv_runner_uses_base_process_with_venv_context(self):
        venv_python = r"C:\fixture\.venv\Scripts\python.exe"
        base_python = r"C:\Python312\python.exe"
        with mock.patch.object(sys, "executable", venv_python), \
                mock.patch.object(
                    sys, "_base_executable", base_python, create=True
                ), \
                mock.patch.object(sys, "frozen", False, create=True), \
                mock.patch.object(
                    windows_adapter, "resolve_windows_executable",
                    return_value=base_python,
                ) as resolve:
            executable, environment = windows_adapter._runner_process_settings()

        self.assertEqual(executable, base_python)
        self.assertIsNotNone(environment)
        self.assertEqual(environment["__PYVENV_LAUNCHER__"], venv_python)
        self.assertNotIn("PYINSTALLER_RESET_ENVIRONMENT", environment)
        resolve.assert_called_once_with(
            base_python, env=os.environ, cwd=os.getcwd()
        )

    @staticmethod
    def _create_recovery_record(platform, *, state="exited"):
        app_id = "a1b2c3d4"
        generation_id = "00000000-0000-4000-8000-000000000001"
        token = b"r" * 32
        paths = platform.runtime_paths()
        os.mkdir(paths.data_dir)
        platform.ensure_private_directory(paths.data_dir)
        os.mkdir(paths.runtime_dir)
        platform.ensure_private_directory(paths.runtime_dir)
        app_directory = os.path.join(paths.runtime_dir, app_id)
        os.mkdir(app_directory)
        platform.ensure_private_directory(app_directory)
        directory, request_path, token_path, receipt_path, _ = (
            platform._runtime_files(app_id, generation_id)
        )
        os.mkdir(directory)
        platform.ensure_private_directory(directory)
        platform._create_private_file(request_path, b"{}")
        platform.ensure_private_file(request_path)
        platform._create_private_file(token_path, token)
        platform.ensure_private_file(token_path)
        public = {
            "platform": "windows",
            "kind": "job",
            "ownerSid": platform.current_principal().identifier,
            "generationId": generation_id,
            "runnerPid": 2147483001,
            "runnerCreateTime": 1.0,
            "rootPid": 2147483002,
            "rootCreateTime": 2.0,
            "jobName": job_name(app_id, generation_id, token_digest(token)),
            "tokenDigest": token_digest(token),
            "startedAt": 3,
        }
        members = [public["rootPid"]] if state in {"prepared", "running"} else []
        receipt = sign_record({
            "version": PROTOCOL_VERSION,
            "sequence": 1,
            "state": state,
            "identity": public,
            "members": members,
            "updatedAt": 4,
            "code": None,
            "error": None,
            "exitCode": 0 if state == "exited" else None,
        }, token, "receipt")
        write_json_atomic(receipt_path, receipt)
        platform.ensure_private_file(receipt_path)
        return app_id, generation_id, directory, token_path, receipt_path

    def test_runtime_paths_use_local_app_data(self):
        paths = self.platform.runtime_paths()
        self.assertTrue(paths.data_dir.endswith(os.path.join("LocalOps")))
        self.assertEqual(paths.logs_dir, os.path.join(paths.data_dir, "logs"))
        self.assertEqual(paths.runtime_dir, os.path.join(paths.data_dir, "runtime"))
        self.assertNotEqual(
            os.path.normcase(paths.data_dir),
            os.path.normcase(self.platform.base_dir),
        )

    def test_runtime_paths_honor_absolute_controller_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            data = os.path.join(directory, "data")
            logs = os.path.join(directory, "logs")
            with mock.patch.dict(os.environ, {
                "CONSOLE_DATA_DIR": data,
                "CONSOLE_LOG_DIR": logs,
            }):
                paths = self.platform.runtime_paths()

            self.assertEqual(paths.data_dir, os.path.abspath(data))
            self.assertEqual(paths.logs_dir, os.path.abspath(logs))
            self.assertEqual(paths.runtime_dir, os.path.join(os.path.abspath(data), "runtime"))

        with mock.patch.dict(os.environ, {"CONSOLE_DATA_DIR": "relative"}):
            with self.assertRaises(ValueError):
                self.platform.runtime_paths()

    def test_runtime_path_rejects_roots_equivalents_and_junctions(self):
        with self.assertRaises(ValueError):
            self.platform.validate_runtime_path("C:\\", set())
        with self.assertRaises(ValueError):
            self.platform.validate_runtime_path(r"\\server\share", set())
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                self.platform.validate_runtime_path(
                    temp_dir.upper(), {temp_dir.lower()}
                )
            valid = os.path.join(temp_dir, "中文 folder", "LocalOps")
            self.assertEqual(
                self.platform.validate_runtime_path(valid, set()),
                os.path.abspath(valid),
            )
            with mock.patch.object(
                    self.platform, "_has_junction_component", return_value=True):
                with self.assertRaises(ValueError):
                    self.platform.validate_runtime_path(valid, set())

    def test_private_acl_has_only_current_user_system_and_administrators(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "config.json")
            with open(path, "w", encoding="utf-8") as file_object:
                file_object.write("{}")
            self.platform.ensure_private_directory(temp_dir)
            self.platform.ensure_private_file(path)
            descriptor = win32security.GetNamedSecurityInfo(
                path,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
            owner = win32security.ConvertSidToStringSid(
                descriptor.GetSecurityDescriptorOwner()
            )
            dacl = descriptor.GetSecurityDescriptorDacl()
            principals = {
                win32security.ConvertSidToStringSid(dacl.GetAce(index)[2])
                for index in range(dacl.GetAceCount())
            }
            self.assertEqual(owner, self.platform.current_principal().identifier)
            self.assertEqual(
                principals,
                {
                    self.platform.current_principal().identifier,
                    "S-1-5-18",
                    "S-1-5-32-544",
                },
            )

    def test_private_acl_never_attempts_to_change_owner(self):
        descriptor = mock.Mock()
        descriptor.GetSecurityDescriptorOwner.return_value = (
            win32security.ConvertStringSidToSid(
                self.platform.current_principal().identifier
            )
        )
        descriptor.GetSecurityDescriptorDacl.return_value = mock.Mock(
            GetAceCount=mock.Mock(return_value=3),
            GetAce=mock.Mock(side_effect=[
                ((win32security.ACCESS_ALLOWED_ACE_TYPE, 0), 0x1F01FF,
                 win32security.ConvertStringSidToSid(sid))
                for sid in (
                    self.platform.current_principal().identifier,
                    "S-1-5-18",
                    "S-1-5-32-544",
                )
            ]),
        )
        descriptor.GetSecurityDescriptorControl.return_value = (
            win32security.SE_DACL_PROTECTED, 0
        )
        with mock.patch.object(
                win32security, "GetNamedSecurityInfo", return_value=descriptor), \
                mock.patch.object(win32security, "SetNamedSecurityInfo") as setter, \
                mock.patch.object(self.platform, "_private_acl", return_value=object()):
            self.platform._apply_and_verify_acl("fixture", directory=False)

        self.assertIsNone(setter.call_args.args[3])
        self.assertFalse(
            setter.call_args.args[2] & win32security.OWNER_SECURITY_INFORMATION
        )

    def test_private_acl_normalizes_administrator_default_owner(self):
        before = mock.Mock()
        before.GetSecurityDescriptorOwner.return_value = (
            win32security.ConvertStringSidToSid("S-1-5-32-544")
        )
        after = mock.Mock()
        after.GetSecurityDescriptorOwner.return_value = (
            win32security.ConvertStringSidToSid(
                self.platform.current_principal().identifier
            )
        )
        after.GetSecurityDescriptorDacl.return_value = mock.Mock(
            GetAceCount=mock.Mock(return_value=3),
            GetAce=mock.Mock(side_effect=[
                ((win32security.ACCESS_ALLOWED_ACE_TYPE, 0), 0x1F01FF,
                 win32security.ConvertStringSidToSid(sid))
                for sid in (
                    self.platform.current_principal().identifier,
                    "S-1-5-18",
                    "S-1-5-32-544",
                )
            ]),
        )
        after.GetSecurityDescriptorControl.return_value = (
            win32security.SE_DACL_PROTECTED, 0
        )
        with mock.patch.object(
                self.platform, "_default_owner_sid", "S-1-5-32-544"), \
                mock.patch.object(
                    win32security, "GetNamedSecurityInfo",
                    side_effect=[before, after],
                ), mock.patch.object(
                    win32security, "SetNamedSecurityInfo"
                ) as setter, mock.patch.object(
                    self.platform, "_private_acl", return_value=object()
                ):
            self.platform._apply_and_verify_acl("fixture", directory=False)

        self.assertTrue(
            setter.call_args.args[2] & win32security.OWNER_SECURITY_INFORMATION
        )
        self.assertEqual(
            win32security.ConvertSidToStringSid(setter.call_args.args[3]),
            self.platform.current_principal().identifier,
        )

    def test_verify_only_acl_rejects_administrator_owned_record(self):
        descriptor = mock.Mock()
        descriptor.GetSecurityDescriptorOwner.return_value = (
            win32security.ConvertStringSidToSid("S-1-5-32-544")
        )
        descriptor.GetSecurityDescriptorDacl.return_value = (
            self.platform._private_acl(False)
        )
        descriptor.GetSecurityDescriptorControl.return_value = (
            win32security.SE_DACL_PROTECTED, 0
        )
        with mock.patch.object(
                self.platform, "_default_owner_sid", "S-1-5-32-544"), \
                mock.patch.object(
                    win32security, "GetNamedSecurityInfo", return_value=descriptor
                ):
            with self.assertRaises(PermissionError):
                self.platform.verify_private_file(__file__)

    def test_platform_rejects_an_unexpected_token_default_owner(self):
        current_sid = self.platform.current_principal().identifier
        with mock.patch.object(
                WindowsPlatform, "_current_token_sids",
                return_value=(current_sid, "S-1-5-32-545")):
            with self.assertRaises(PermissionError):
                WindowsPlatform(os.getcwd(), "server.py")

    def test_private_acl_rejects_a_path_owned_by_another_sid(self):
        descriptor = mock.Mock()
        descriptor.GetSecurityDescriptorOwner.return_value = (
            win32security.ConvertStringSidToSid("S-1-5-18")
        )
        with mock.patch.object(
                win32security, "GetNamedSecurityInfo", return_value=descriptor), \
                mock.patch.object(win32security, "SetNamedSecurityInfo") as setter:
            with self.assertRaises(PermissionError):
                self.platform._apply_and_verify_acl("fixture", directory=False)

        setter.assert_not_called()

    def test_verify_only_acl_rejects_widened_existing_record(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "token.bin")
            with open(path, "wb") as stream:
                stream.write(b"fixture")
            self.platform.ensure_private_file(path)
            descriptor = win32security.GetNamedSecurityInfo(
                path,
                win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION,
            )
            dacl = descriptor.GetSecurityDescriptorDacl()
            dacl.AddAccessAllowedAceEx(
                win32security.ACL_REVISION_DS,
                0,
                win32con.GENERIC_READ,
                win32security.ConvertStringSidToSid("S-1-1-0"),
            )
            win32security.SetNamedSecurityInfo(
                path,
                win32security.SE_FILE_OBJECT,
                win32security.DACL_SECURITY_INFORMATION
                | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                dacl,
                None,
            )

            with self.assertRaises(PermissionError):
                self.platform.verify_private_file(path)

            # Restore only so TemporaryDirectory can clean up on Windows.
            self.platform.ensure_private_file(path)

    def test_named_mutex_allows_only_one_writer_and_recovers_after_release(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            identity = os.path.join(temp_dir, "console.lock")
            first = self.platform.acquire_instance_lock(identity)
            self.assertIsNotNone(first)
            self.assertIsNone(self.platform.acquire_instance_lock(identity))
            first.release()
            replacement = self.platform.acquire_instance_lock(identity)
            self.assertIsNotNone(replacement)
            replacement.release()

    def test_instance_lock_is_not_inherited_by_child_processes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            identity = os.path.join(temp_dir, "console.lock")
            first = self.platform.acquire_instance_lock(identity)
            self.assertIsNotNone(first)
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                close_fds=False,
            )
            try:
                first.release()
                replacement = self.platform.acquire_instance_lock(identity)
                self.assertIsNotNone(replacement)
                replacement.release()
            finally:
                child.terminate()
                child.wait(timeout=10)

    def test_legacy_instance_mutex_does_not_block_current_console(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            identity = os.path.join(temp_dir, "console.lock")
            data_dir = self.platform._canonical_path(os.path.dirname(identity))
            digest = hashlib.sha256(
                (self.platform.current_principal().identifier + "\0" + data_dir)
                .encode("utf-8")
            ).hexdigest()[:32]
            legacy = windows_adapter.win32event.CreateMutex(
                self.platform._security_attributes(),
                False,
                "Local\\LocalOps-" + digest,
            )
            try:
                current = self.platform.acquire_instance_lock(identity)
                self.assertIsNotNone(current)
                current.release()
            finally:
                win32api.CloseHandle(legacy)

    def test_current_process_snapshot_contains_current_sid(self):
        snapshot = self.platform.process_snapshot({os.getpid()})
        self.assertIn(snapshot.status, (ScanStatus.OK, ScanStatus.PARTIAL))
        self.assertEqual(
            snapshot.processes[os.getpid()]["owner"],
            self.platform.current_principal().identifier,
        )

    def test_scoped_process_snapshots_report_cpu_after_the_baseline_sample(self):
        first = mock.Mock(pid=4242)
        first.as_dict.return_value = {
            "pid": 4242,
            "name": "worker.exe",
            "exe": r"C:\\Tools\\worker.exe",
            "cmdline": [r"C:\\Tools\\worker.exe"],
            "cpu_times": SimpleNamespace(user=1.0, system=0.5),
            "memory_percent": 2.0,
            "create_time": 100.0,
            "ppid": 1,
        }
        second = mock.Mock(pid=4242)
        second.as_dict.return_value = {
            **first.as_dict.return_value,
            "cpu_times": SimpleNamespace(user=1.2, system=0.55),
        }

        with mock.patch("psutil.Process", side_effect=[first, second]), \
                mock.patch("time.perf_counter", side_effect=[10.0, 12.0]):
            baseline = self.platform.process_snapshot({4242}, with_owner=False)
            sampled = self.platform.process_snapshot({4242}, with_owner=False)

        self.assertEqual(baseline.processes[4242]["cpu"], 0.0)
        self.assertEqual(sampled.processes[4242]["cpu"], 12.5)
        self.assertIn("cpu_times", first.as_dict.call_args.kwargs["attrs"])
        self.assertNotIn("cpu_percent", first.as_dict.call_args.kwargs["attrs"])

    def test_process_observation_treats_exited_object_as_absent(self):
        process = mock.Mock()
        process.create_time.return_value = 123.0
        handle = mock.Mock()
        with mock.patch("psutil.Process", return_value=process), \
                mock.patch.object(
                    self.platform, "_process_owner_sid",
                    return_value=self.platform.current_principal().identifier,
                ), mock.patch.object(
                    win32api, "OpenProcess", return_value=handle
                ), mock.patch.object(
                    win32process, "GetExitCodeProcess", return_value=0
                ):
            observation = self.platform._observe_process(4321)

        self.assertIsNone(observation)
        handle.Close.assert_called_once_with()

    def test_external_process_stop_revalidates_owner_path_and_creation_time(self):
        process = mock.Mock(pid=4321)
        process.exe.return_value = r"C:\Tools\AdminTool.exe"
        process.create_time.return_value = 1000.5
        process.wait.return_value = 0
        with mock.patch("psutil.Process", return_value=process), \
                mock.patch.object(
                    self.platform, "_process_owner_sid",
                    return_value=self.platform.current_principal().identifier,
                ):
            result = self.platform.stop_external_process(
                4321,
                False,
                expected_executable=r"C:\Tools\AdminTool.exe",
                expected_create_time=1000.5,
            )

        self.assertTrue(result.ok)
        process.terminate.assert_called_once_with()
        process.kill.assert_not_called()

    def test_external_process_stop_rejects_reused_pid(self):
        process = mock.Mock(pid=4321)
        process.exe.return_value = r"C:\Tools\AdminTool.exe"
        process.create_time.return_value = 2000.5
        with mock.patch("psutil.Process", return_value=process), \
                mock.patch.object(
                    self.platform, "_process_owner_sid",
                    return_value=self.platform.current_principal().identifier,
                ):
            result = self.platform.stop_external_process(
                4321,
                False,
                expected_executable=r"C:\Tools\AdminTool.exe",
                expected_create_time=1000.5,
            )

        self.assertFalse(result.ok)
        self.assertEqual(result.code, "EXTERNAL_PROCESS_IDENTITY_MISMATCH")
        process.terminate.assert_not_called()

    def test_listener_snapshot_preserves_ipv4_and_ipv6(self):
        connections = [
            SimpleNamespace(
                status=psutil.CONN_LISTEN,
                laddr=SimpleNamespace(ip="127.0.0.1", port=9600),
                pid=100,
            ),
            SimpleNamespace(
                status=psutil.CONN_LISTEN,
                laddr=SimpleNamespace(ip="::1", port=9601),
                pid=101,
            ),
        ]
        with mock.patch("psutil.net_connections", return_value=connections):
            snapshot = self.platform.scan_listeners()
        self.assertEqual(snapshot.status, ScanStatus.OK)
        self.assertEqual(snapshot.listeners[(100, 9600)], {"127.0.0.1"})
        self.assertEqual(snapshot.listeners[(101, 9601)], {"::1"})

    def test_listener_access_denied_is_failed_not_empty_success(self):
        with mock.patch("psutil.net_connections", side_effect=psutil.AccessDenied()):
            snapshot = self.platform.scan_listeners()
        self.assertEqual(snapshot.status, ScanStatus.FAILED)
        self.assertEqual(snapshot.listeners, {})
        self.assertEqual(snapshot.issues[0].code, "access_denied")

    def test_process_race_and_access_denied_are_nonfatal(self):
        vanished = mock.Mock()
        vanished.pid = 100
        vanished.as_dict.side_effect = psutil.NoSuchProcess(100)
        protected = mock.Mock()
        protected.pid = 101
        protected.as_dict.side_effect = psutil.AccessDenied(101)
        with mock.patch("psutil.process_iter", return_value=[vanished, protected]), \
                mock.patch.object(
                    self.platform,
                    "_process_owner_sid",
                    return_value=self.platform.current_principal().identifier,
                ):
            snapshot = self.platform.process_snapshot()
        self.assertEqual(snapshot.status, ScanStatus.PARTIAL)
        self.assertEqual(snapshot.processes, {})
        self.assertTrue(any(issue.code == "access_denied" for issue in snapshot.issues))
        self.assertTrue(all(not issue.degrades for issue in snapshot.issues))

    def test_keyword_scan_queries_only_wmi_matches(self):
        rows = [{
            "pid": os.getpid(),
            "name": "pwsh.exe",
            "command_line": "pwsh -File memos-guard.ps1",
            "session_id": 1,
        }]
        with mock.patch.object(
                self.platform, "_query_process_keyword_rows", return_value=rows
        ) as query, mock.patch.object(
                windows_adapter.win32ts, "ProcessIdToSessionId", return_value=1):
            snapshot = self.platform.processes_matching_keywords(
                ["memos-guard.ps1"]
            )

        query.assert_called_once_with(("memos-guard.ps1",))
        self.assertEqual(snapshot.status, ScanStatus.OK)
        self.assertIn(os.getpid(), snapshot.processes)
        self.assertIn("memos-guard.ps1", snapshot.processes[os.getpid()]["args"])

    def test_protected_process_cwd_is_advisory(self):
        with mock.patch("psutil.Process") as process:
            process.return_value.cwd.side_effect = psutil.AccessDenied(42)
            snapshot = self.platform.process_cwds({42})

        self.assertEqual(snapshot.status, ScanStatus.PARTIAL)
        self.assertFalse(snapshot.issues[0].degrades)

    def test_native_picker_returns_directory_from_windows_shell(self):
        selected = os.path.join(os.getcwd(), "中文 folder")
        pidl = object()
        owner_hwnd = 4242
        with mock.patch.object(
                windows_adapter.shell, "SHBrowseForFolder",
                return_value=(pidl, "中文 folder", 0)) as browse, \
                mock.patch.object(
                    windows_adapter.shell, "SHGetPathFromIDList",
                    return_value=selected), \
                mock.patch.object(
                    win32gui, "GetForegroundWindow", return_value=owner_hwnd), \
                mock.patch("tkinter.Tk", side_effect=AssertionError(
                    "Windows picker must not depend on Tk")):
            result = self.platform.pick_path("dir")

        self.assertEqual(result.path, os.path.abspath(selected))
        self.assertFalse(result.canceled)
        self.assertEqual(browse.call_args.args[0], owner_hwnd)

    def test_native_picker_filters_executables_and_reports_cancel(self):
        selected = os.path.join(os.getcwd(), "工具 program.exe")
        dialog = mock.Mock()
        owner_hwnd = 4242
        owner_window = object()
        dialog.DoModal.return_value = win32con.IDOK
        dialog.GetPathName.return_value = selected
        with mock.patch.object(
                win32ui, "CreateFileDialog", return_value=dialog) as create_dialog, \
                mock.patch.object(
                    win32gui, "GetForegroundWindow", return_value=owner_hwnd), \
                mock.patch.object(
                    win32ui, "CreateWindowFromHandle",
                    return_value=owner_window) as create_owner, \
                mock.patch("tkinter.Tk", side_effect=AssertionError(
                    "Windows picker must not depend on Tk")):
            result = self.platform.pick_path("exe")

        self.assertEqual(result.path, os.path.abspath(selected))
        self.assertFalse(result.canceled)
        self.assertIn("*.exe", create_dialog.call_args.args[4])
        create_owner.assert_called_once_with(owner_hwnd)
        self.assertIs(create_dialog.call_args.args[5], owner_window)

        dialog.DoModal.return_value = win32con.IDCANCEL
        with mock.patch.object(win32ui, "CreateFileDialog", return_value=dialog):
            result = self.platform.pick_path("exe")

        self.assertTrue(result.canceled)
        self.assertIsNone(result.path)

    def test_source_broker_install_is_rejected_before_package_or_uac(self):
        with mock.patch.object(
                windows_adapter.shell, "ShellExecuteEx") as shell_execute:
            result = self.platform.install_elevation_broker(
                {"verifier": "opaque"}, r"C:\Local Ops\LocalOps.exe"
            )

        self.assertFalse(result.ok)
        self.assertEqual(result.code, "BROKER_PACKAGED_REQUIRED")
        shell_execute.assert_not_called()

    def test_broker_task_security_accepts_scheduler_canonical_acl_only(self):
        owner_sid = self.platform._sid
        expected = broker_task_sddl(owner_sid)
        canonical = (
            "D:(A;;FA;;;SY)(A;;FA;;;BA)"
            f"(A;;FRFX;;;{owner_sid})(A;;FR;;;{owner_sid})"
        )
        task = SimpleNamespace(
            GetSecurityDescriptor=mock.Mock(return_value=canonical),
            Definition=SimpleNamespace(RegistrationInfo=SimpleNamespace(
                SecurityDescriptor=expected,
            )),
        )

        self.assertTrue(self.platform._broker_task_security_locked(task))

        task.GetSecurityDescriptor.return_value = canonical + "(A;;FR;;;WD)"
        self.assertFalse(self.platform._broker_task_security_locked(task))

    def test_executable_icon_uses_fixed_script_and_returns_png(self):
        png = b"\x89PNG\r\n\x1a\nfixture"
        completed = SimpleNamespace(
            returncode=0,
            stdout=base64.b64encode(png),
            stderr=b"",
        )
        with tempfile.TemporaryDirectory() as root:
            executable = os.path.join(root, "工具.exe")
            Path(executable).write_bytes(b"fixture")
            with mock.patch.object(
                    self.platform, "_windows_powershell",
                    return_value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"), \
                    mock.patch.object(
                        windows_adapter.subprocess, "run",
                        return_value=completed) as run:
                result = self.platform.extract_executable_icon(executable)

        self.assertEqual(result, png)
        command = run.call_args.args[0]
        self.assertNotIn(executable, " ".join(command))
        self.assertEqual(
            run.call_args.kwargs["env"]["LOCALOPS_ICON_SOURCE"], executable
        )

    def test_real_loopback_listener_is_observable(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            snapshot = self.platform.scan_listeners()
            self.assertIn((os.getpid(), port), snapshot.listeners)
        finally:
            listener.close()

    def test_recover_managed_cleanups_returns_only_exact_terminal_identity(self):
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.dict(
                os.environ, {
                    "CONSOLE_DATA_DIR": os.path.join(temp_dir, "data"),
                    "CONSOLE_LOG_DIR": os.path.join(temp_dir, "logs"),
                }):
            platform = WindowsPlatform(os.getcwd(), "server.py")
            app_id, generation_id, _, _, _ = self._create_recovery_record(platform)
            with mock.patch.object(platform, "_observe_process", return_value=None):
                recovered = platform.recover_managed_cleanups()

        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].app_id, app_id)
        self.assertEqual(recovered[0].generation_id, generation_id)
        self.assertEqual(recovered[0].members, ())

    def test_recover_managed_cleanups_skips_active_generation(self):
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.dict(
                os.environ, {
                    "CONSOLE_DATA_DIR": os.path.join(temp_dir, "data"),
                    "CONSOLE_LOG_DIR": os.path.join(temp_dir, "logs"),
                }):
            platform = WindowsPlatform(os.getcwd(), "server.py")
            self._create_recovery_record(platform, state="running")
            with mock.patch.object(platform, "_observe_process") as observe:
                recovered = platform.recover_managed_cleanups()

        self.assertEqual(recovered, ())
        observe.assert_not_called()

    def test_recover_managed_cleanups_skips_insecure_or_malformed_records(self):
        cases = ("widened", "malformed", "link")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp_dir, \
                    mock.patch.dict(os.environ, {
                        "CONSOLE_DATA_DIR": os.path.join(temp_dir, "data"),
                        "CONSOLE_LOG_DIR": os.path.join(temp_dir, "logs"),
                    }):
                platform = WindowsPlatform(os.getcwd(), "server.py")
                _, _, directory, token_path, receipt_path = (
                    self._create_recovery_record(platform)
                )
                link_patch = mock.patch.object(
                    platform, "_has_junction_component", wraps=platform._has_junction_component
                )
                if case == "widened":
                    descriptor = win32security.GetNamedSecurityInfo(
                        token_path,
                        win32security.SE_FILE_OBJECT,
                        win32security.DACL_SECURITY_INFORMATION,
                    )
                    dacl = descriptor.GetSecurityDescriptorDacl()
                    dacl.AddAccessAllowedAceEx(
                        win32security.ACL_REVISION_DS,
                        0,
                        win32con.GENERIC_READ,
                        win32security.ConvertStringSidToSid("S-1-1-0"),
                    )
                    win32security.SetNamedSecurityInfo(
                        token_path,
                        win32security.SE_FILE_OBJECT,
                        win32security.DACL_SECURITY_INFORMATION
                        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                        None,
                        None,
                        dacl,
                        None,
                    )
                elif case == "malformed":
                    with open(receipt_path, "wb") as stream:
                        stream.write(b"{")
                else:
                    original = platform._has_junction_component
                    expected = os.path.normcase(os.path.abspath(directory))
                    link_patch = mock.patch.object(
                        platform,
                        "_has_junction_component",
                        side_effect=lambda path: (
                            os.path.normcase(os.path.abspath(path)) == expected
                            or original(path)
                        ),
                    )
                try:
                    with link_patch, mock.patch.object(
                            platform, "_observe_process", return_value=None):
                        recovered = platform.recover_managed_cleanups()
                    self.assertEqual(recovered, ())
                finally:
                    if case == "widened":
                        platform.ensure_private_file(token_path)

    def test_release_managed_keeps_original_when_tombstone_rename_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.dict(
                os.environ, {
                    "CONSOLE_DATA_DIR": os.path.join(temp_dir, "data"),
                    "CONSOLE_LOG_DIR": os.path.join(temp_dir, "logs"),
                }):
            platform = WindowsPlatform(os.getcwd(), "server.py")
            app_id, generation_id, directory, _, _ = (
                self._create_recovery_record(platform)
            )
            with mock.patch.object(platform, "_observe_process", return_value=None):
                identity = platform.recover_managed_cleanups()[0]
            tombstone = platform._cleanup_tombstone_path(app_id, generation_id)

            with mock.patch.object(platform, "_observe_process", return_value=None), \
                    mock.patch(
                        "localops.platform.windows.os.rename",
                        side_effect=OSError("rename fixture"),
                    ), mock.patch("localops.platform.windows.os.unlink") as unlink:
                result = platform.release_managed(identity)

            self.assertFalse(result.ok)
            self.assertTrue(os.path.isdir(directory))
            self.assertEqual(
                set(os.listdir(directory)),
                {"request.json", "token.bin", "receipt.json"},
            )
            self.assertFalse(os.path.lexists(tombstone))
            unlink.assert_not_called()

    def test_release_managed_wakes_exact_terminal_runner_before_waiting(self):
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.dict(
                os.environ, {
                    "CONSOLE_DATA_DIR": os.path.join(temp_dir, "data"),
                    "CONSOLE_LOG_DIR": os.path.join(temp_dir, "logs"),
                }):
            platform = WindowsPlatform(os.getcwd(), "server.py")
            self._create_recovery_record(platform)
            with mock.patch.object(platform, "_observe_process", return_value=None):
                identity = platform.recover_managed_cleanups()[0]
            runner_alive = (identity.owner, float(identity.runner_create_time))
            pipe = mock.Mock()
            inspection = SimpleNamespace(
                verified=True,
                status="exited",
                members=(),
            )

            with mock.patch.object(platform, "_runtime_context"), \
                    mock.patch.object(
                        platform, "inspect_managed", return_value=inspection
                    ), mock.patch.object(
                        platform,
                        "_observe_process",
                        side_effect=(runner_alive, None),
                    ), mock.patch.object(
                        platform, "_connect_pipe", return_value=pipe
                    ) as connect:
                result = platform.release_managed(identity)

            self.assertTrue(result.ok, (result.code, result.error))
            connect.assert_called_once_with(identity, timeout=0.5)
            pipe.Close.assert_called_once_with()

    def test_release_managed_commits_before_rmdir_and_recovers_tombstone(self):
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.dict(
                os.environ, {
                    "CONSOLE_DATA_DIR": os.path.join(temp_dir, "data"),
                    "CONSOLE_LOG_DIR": os.path.join(temp_dir, "logs"),
                }):
            platform = WindowsPlatform(os.getcwd(), "server.py")
            app_id, generation_id, directory, _, _ = (
                self._create_recovery_record(platform)
            )
            with mock.patch.object(platform, "_observe_process", return_value=None):
                identity = platform.recover_managed_cleanups()[0]
            tombstone = platform._cleanup_tombstone_path(app_id, generation_id)
            real_rmdir = os.rmdir

            def fail_tombstone_rmdir(path):
                if os.path.normcase(path) == os.path.normcase(tombstone):
                    raise OSError("rmdir fixture")
                return real_rmdir(path)

            with mock.patch.object(platform, "_observe_process", return_value=None), \
                    mock.patch(
                        "localops.platform.windows.os.rmdir",
                        side_effect=fail_tombstone_rmdir,
                    ):
                result = platform.release_managed(identity)

            self.assertTrue(result.ok)
            self.assertFalse(os.path.lexists(directory))
            self.assertTrue(os.path.isdir(tombstone))
            self.assertEqual(os.listdir(tombstone), [])
            with mock.patch.object(platform, "_observe_process") as observe, \
                    mock.patch.object(platform, "_control") as control:
                self.assertEqual(platform.recover_managed_cleanups(), ())
            observe.assert_not_called()
            control.assert_not_called()
            self.assertFalse(os.path.lexists(tombstone))

    def test_release_managed_commits_before_unlink_and_recovers_tombstone(self):
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.dict(
                os.environ, {
                    "CONSOLE_DATA_DIR": os.path.join(temp_dir, "data"),
                    "CONSOLE_LOG_DIR": os.path.join(temp_dir, "logs"),
                }):
            platform = WindowsPlatform(os.getcwd(), "server.py")
            app_id, generation_id, directory, _, _ = (
                self._create_recovery_record(platform)
            )
            with mock.patch.object(platform, "_observe_process", return_value=None):
                identity = platform.recover_managed_cleanups()[0]
            tombstone = platform._cleanup_tombstone_path(app_id, generation_id)
            real_unlink = os.unlink
            failed = False

            def fail_one_unlink(path):
                nonlocal failed
                if not failed:
                    failed = True
                    raise OSError("unlink fixture")
                return real_unlink(path)

            with mock.patch.object(platform, "_observe_process", return_value=None), \
                    mock.patch(
                        "localops.platform.windows.os.unlink",
                        side_effect=fail_one_unlink,
                    ):
                result = platform.release_managed(identity)

            self.assertTrue(result.ok)
            self.assertFalse(os.path.lexists(directory))
            self.assertTrue(os.path.isdir(tombstone))
            self.assertTrue(os.listdir(tombstone))
            with mock.patch.object(platform, "_observe_process") as observe, \
                    mock.patch.object(platform, "_control") as control:
                self.assertEqual(platform.recover_managed_cleanups(), ())
            observe.assert_not_called()
            control.assert_not_called()
            self.assertFalse(os.path.lexists(tombstone))

    def test_tombstone_recovery_rejects_unexpected_link_or_insecure_entries(self):
        cases = ("unexpected", "link", "insecure")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp_dir, \
                    mock.patch.dict(os.environ, {
                        "CONSOLE_DATA_DIR": os.path.join(temp_dir, "data"),
                        "CONSOLE_LOG_DIR": os.path.join(temp_dir, "logs"),
                    }):
                platform = WindowsPlatform(os.getcwd(), "server.py")
                app_id, generation_id, directory, _, _ = (
                    self._create_recovery_record(platform)
                )
                tombstone = platform._cleanup_tombstone_path(app_id, generation_id)
                os.rename(directory, tombstone)
                link_patch = mock.patch.object(
                    platform,
                    "_has_junction_component",
                    wraps=platform._has_junction_component,
                )
                if case == "unexpected":
                    extra = os.path.join(tombstone, "extra.json")
                    platform._create_private_file(extra, b"{}")
                    platform.ensure_private_file(extra)
                elif case == "link":
                    original = platform._has_junction_component
                    expected = os.path.normcase(os.path.abspath(tombstone))
                    link_patch = mock.patch.object(
                        platform,
                        "_has_junction_component",
                        side_effect=lambda path: (
                            os.path.normcase(os.path.abspath(path)) == expected
                            or original(path)
                        ),
                    )
                else:
                    descriptor = win32security.GetNamedSecurityInfo(
                        tombstone,
                        win32security.SE_FILE_OBJECT,
                        win32security.DACL_SECURITY_INFORMATION,
                    )
                    dacl = descriptor.GetSecurityDescriptorDacl()
                    dacl.AddAccessAllowedAceEx(
                        win32security.ACL_REVISION_DS,
                        0,
                        win32con.GENERIC_READ,
                        win32security.ConvertStringSidToSid("S-1-1-0"),
                    )
                    win32security.SetNamedSecurityInfo(
                        tombstone,
                        win32security.SE_FILE_OBJECT,
                        win32security.DACL_SECURITY_INFORMATION
                        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                        None,
                        None,
                        dacl,
                        None,
                    )
                try:
                    with link_patch, mock.patch.object(
                            platform, "_observe_process") as observe, \
                            mock.patch.object(platform, "_control") as control:
                        self.assertEqual(platform.recover_managed_cleanups(), ())
                    observe.assert_not_called()
                    control.assert_not_called()
                    self.assertTrue(os.path.isdir(tombstone))
                finally:
                    if case == "insecure":
                        platform.ensure_private_directory(tombstone)

    def test_fake_platform_returns_configured_cleanup_recoveries(self):
        from localops.platform.fake import FakePlatform

        identity = mock.sentinel.identity
        platform = FakePlatform(cleanup_recoveries=[identity])

        self.assertEqual(platform.recover_managed_cleanups(), (identity,))
        self.assertIn(("recover_managed_cleanups", None), platform.calls)

    def test_launch_retains_exact_identity_until_abort_and_release_both_succeed(self):
        from localops.windows.runner_protocol import ProtocolError

        for abort_ok, release_ok, retains_identity in (
            (False, False, True),
            (True, False, True),
            (True, True, False),
        ):
            with self.subTest(abort_ok=abort_ok, release_ok=release_ok), \
                    tempfile.TemporaryDirectory() as temp_dir, \
                    mock.patch.dict(os.environ, {
                        "CONSOLE_DATA_DIR": os.path.join(temp_dir, "data"),
                        "CONSOLE_LOG_DIR": os.path.join(temp_dir, "logs"),
                    }):
                platform = WindowsPlatform(os.getcwd(), "server.py")
                app_id = "a1b2c3d4"
                generation_id = "00000000-0000-4000-8000-000000000001"
                receipt_path = platform._runtime_files(
                    app_id, generation_id
                )[3]
                process = mock.Mock(pid=4321)
                process.poll.return_value = None
                resolved_shell = os.path.join(
                    os.environ.get("SystemRoot", r"C:\Windows"),
                    "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
                )
                captured_invocations = []
                public = {
                    "jobName": "LocalOps-fixture",
                    "ownerSid": platform.current_principal().identifier,
                    "generationId": generation_id,
                    "runnerPid": process.pid,
                    "runnerCreateTime": 1.0,
                    "rootPid": 6543,
                    "rootCreateTime": 2.0,
                    "tokenDigest": "0" * 64,
                    "startedAt": 3,
                }

                def create_receipt(*_args, **_kwargs):
                    from localops.windows.runner_protocol import read_json

                    captured_invocations.append(
                        read_json(platform._runtime_files(
                            app_id, generation_id
                        )[1])["invocation"]
                    )
                    with open(receipt_path, "w", encoding="utf-8") as stream:
                        stream.write("{}")
                    platform.ensure_private_file(receipt_path)
                    return process

                with mock.patch.object(sys, "frozen", True, create=True), \
                        mock.patch(
                            "localops.platform.windows.resolve_windows_executable",
                            return_value=resolved_shell) as resolve, \
                        mock.patch(
                        "localops.platform.windows.subprocess.Popen",
                        side_effect=create_receipt) as popen, \
                        mock.patch(
                            "localops.platform.windows.validate_receipt",
                            return_value={"identity": public, "members": [6543]}), \
                        mock.patch.object(platform, "_runtime_context"), \
                        mock.patch.object(
                            platform, "_control",
                            side_effect=ProtocolError(
                                "RUNTIME_CONTROL_FAILED", "inspect fixture"
                            )), \
                        mock.patch.object(
                            platform, "abort_managed",
                            return_value=StopResult(abort_ok)), \
                        mock.patch.object(
                            platform, "release_managed",
                            return_value=StopResult(release_ok)) as release:
                    result = platform.launch(LaunchRequest(
                        app_id=app_id,
                        command="fixture",
                        cwd=temp_dir,
                        log_path=os.path.join(
                            platform.runtime_paths().logs_dir, app_id + ".log"
                        ),
                        command_spec=shell_command_spec(
                            "powershell", "exit 0", needs_review=False
                        ),
                        generation_id=generation_id,
                    ))

                self.assertFalse(result.ok)
                self.assertEqual(
                    result.runtime_identity is not None, retains_identity
                )
                self.assertEqual(release.called, abort_ok)
                self.assertEqual(captured_invocations[0][0], resolved_shell)
                self.assertEqual(resolve.call_args.args[0], "powershell.exe")
                self.assertEqual(
                    popen.call_args.kwargs["env"][
                        "PYINSTALLER_RESET_ENVIRONMENT"
                    ],
                    "1",
                )

    def test_elevated_controller_refuses_managed_launch_before_creating_runtime(self):
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.dict(
                os.environ, {
                    "CONSOLE_DATA_DIR": os.path.join(temp_dir, "data"),
                    "CONSOLE_LOG_DIR": os.path.join(temp_dir, "logs"),
                }):
            platform = WindowsPlatform(os.getcwd(), "server.py")
            platform.controller_elevated = True
            app_id = "a1b2c3d4"
            generation_id = "00000000-0000-4000-8000-000000000001"
            result = platform.launch(LaunchRequest(
                app_id=app_id,
                command="fixture",
                cwd=temp_dir,
                log_path=os.path.join(
                    platform.runtime_paths().logs_dir, app_id + ".log"
                ),
                command_spec=shell_command_spec(
                    "powershell", "exit 0", needs_review=False
                ),
                generation_id=generation_id,
            ))

            self.assertFalse(result.ok)
            self.assertEqual(result.code, "CONTROLLER_ELEVATED_UNSAFE")
            self.assertFalse(os.path.exists(platform.runtime_paths().runtime_dir))


if __name__ == "__main__":
    unittest.main()

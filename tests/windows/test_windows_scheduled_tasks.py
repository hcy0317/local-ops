import os
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

import server
from localops.command_spec import direct_command_spec
from localops.platform.contracts import (
    PlatformCapabilities,
    PlatformIssue,
    ScanStatus,
    ScheduledTaskEventSnapshot,
    ScheduledTaskHistoryResult,
    ScheduledTaskRunResult,
    ScheduledTaskSnapshot,
)
from localops.platform.fake import FakePlatform
from tests.windows.test_windows_server import HttpHarness


TASK_PATH = r"\Memos-Guard"


def task_row(state="running"):
    return {
        "path": TASK_PATH,
        "name": "Memos-Guard",
        "state": state,
        "enabled": True,
        "lastRunAt": 1_787_210_000,
        "nextRunAt": None,
        "lastResult": 0,
        "runLevel": "highest",
        "multipleInstances": "ignoreNew",
        "actions": [r"powershell.exe -File D:\.memos\memos-guard.ps1"],
        "enginePids": [4242] if state == "running" else [],
    }


def scheduled_app(kind="service"):
    app = dict(server.Config.APP_DEFAULT)
    app.update({
        "id": "deadbeef",
        "name": "Memos Guard",
        "command": 'schtasks.exe /Run /TN "Memos-Guard"',
        "commandSpec": direct_command_spec(
            r"C:\Windows\System32\schtasks.exe",
            ["/Run", "/TN", "Memos-Guard"],
        ),
        "importStatus": "ready",
        "scheduledTaskPath": TASK_PATH,
        "kind": kind,
        "createdAt": 1,
    })
    return app


class ScheduledTaskStateTests(unittest.TestCase):
    def setUp(self):
        self.log_dir = tempfile.TemporaryDirectory()
        self.log_patch = mock.patch.object(server, "LOGS_DIR", self.log_dir.name)
        self.log_patch.start()

    def tearDown(self):
        self.log_patch.stop()
        self.log_dir.cleanup()

    def fake_platform(self, state="running"):
        return FakePlatform(
            name="windows",
            capabilities=PlatformCapabilities(
                monitor_processes=True,
                monitor_scheduled_tasks=True,
                run_scheduled_tasks=True,
                stop_scheduled_tasks=True,
                toggle_scheduled_tasks=True,
            ),
            scheduled=ScheduledTaskSnapshot(
                ScanStatus.OK, {TASK_PATH.casefold(): task_row(state)}
            ),
            scheduled_events=ScheduledTaskEventSnapshot(
                ScanStatus.PARTIAL,
                events=(
                    {
                        "eventId": 102,
                        "recordId": 23,
                        "timestamp": 1_787_210_040,
                        "taskName": TASK_PATH,
                        "resultCode": 0,
                    },
                    {
                        "eventId": 100,
                        "recordId": 22,
                        "timestamp": 1_787_210_000,
                        "taskName": TASK_PATH,
                        "instanceId": "{fixture-run}",
                    },
                ),
                history_enabled=False,
                issues=(PlatformIssue(
                    "scheduled_task_events",
                    "history_disabled",
                    "Windows 计划任务历史记录未启用",
                    degrades=False,
                ),),
            ),
            scheduled_run_result=ScheduledTaskRunResult(True, TASK_PATH),
            scheduled_stop_result=ScheduledTaskRunResult(True, TASK_PATH),
            scheduled_history_result=ScheduledTaskHistoryResult(True, True),
        )

    def test_guard_uses_scheduler_running_state_and_stays_in_service_kind(self):
        fake = self.fake_platform("running")
        cfg = dict(server.Config.DEFAULT)
        cfg["apps"] = [scheduled_app("service")]

        with mock.patch.object(server, "PLATFORM", fake), \
                mock.patch.object(server, "build_services", return_value=([], set())), \
                mock.patch.object(server, "build_watched", return_value=[]):
            state = server.build_state(cfg, 9600, {})

        app = state["apps"][0]
        self.assertEqual(app["kind"], "service")
        self.assertTrue(app["running"])
        self.assertEqual(app["runtimeSource"], "windowsTaskScheduler")
        self.assertEqual(app["scheduledTask"]["state"], "running")
        self.assertTrue(app["controlAvailable"])
        self.assertTrue(app["scheduledTaskControlAvailable"])
        self.assertEqual(
            fake.calls.count(("scheduled_tasks", frozenset({TASK_PATH}))), 1
        )

    def test_ready_batch_task_can_be_run_without_becoming_a_managed_job(self):
        fake = self.fake_platform("ready")
        app = scheduled_app("task")
        result = server.start_scheduled_task_app(fake, app)

        self.assertTrue(result["ok"])
        self.assertEqual(result["taskPath"], TASK_PATH)
        self.assertEqual(fake.calls[-1], ("run_scheduled_task", TASK_PATH))

    def test_scheduled_task_control_failure_is_written_to_app_log(self):
        fake = self.fake_platform("ready")
        fake.scheduled_run_result = ScheduledTaskRunResult(
            False, TASK_PATH, "拒绝访问", "SCHEDULED_TASK_RUN_FAILED"
        )
        app = scheduled_app("task")
        result = server.start_scheduled_task_app(fake, app)
        text = server.read_log_tail(app["id"], 20)

        self.assertFalse(result["ok"])
        self.assertIn("Windows 计划任务启动失败", text)
        self.assertIn("SCHEDULED_TASK_RUN_FAILED", text)
        self.assertIn("拒绝访问", text)

    def test_scheduled_task_log_combines_audit_events_and_current_state(self):
        fake = self.fake_platform("ready")
        app = scheduled_app("task")
        server.append_app_log(app["id"], "人工审计记录")

        with mock.patch.object(server, "PLATFORM", fake):
            payload = server.read_app_log_payload(app, 50)

        text = payload["text"]
        self.assertIn("Local Ops 控制记录", text)
        self.assertIn("人工审计记录", text)
        self.assertIn("Windows 计划任务运行时间线", text)
        self.assertIn("任务已启动 (Event 100)", text)
        self.assertIn("任务已完成 (Event 102) · 结果 0x00000000", text)
        self.assertIn("Windows 计划任务当前状态", text)
        self.assertIn("状态：就绪", text)
        self.assertFalse(payload["taskHistory"]["enabled"])
        self.assertEqual(payload["taskHistory"]["eventCount"], 2)
        self.assertIn("history_disabled", {
            issue["code"] for issue in payload["taskHistory"]["issues"]
        })
        self.assertIn(
            ("scheduled_task_events", (TASK_PATH, 50)), fake.calls
        )

    def test_scheduled_task_history_can_be_enabled_and_is_audited(self):
        fake = self.fake_platform("ready")
        app = scheduled_app("task")

        result = server.set_scheduled_task_history_app(fake, app, True)

        self.assertTrue(result["ok"])
        self.assertTrue(result["enabled"])
        self.assertIn(("set_scheduled_task_history_enabled", True), fake.calls)
        self.assertIn("计划任务历史记录启用成功", server.read_log_tail(app["id"], 20))

    def test_running_guard_can_be_stopped_through_task_scheduler(self):
        fake = self.fake_platform("running")
        app = scheduled_app("service")

        result = server.stop_scheduled_task_app(fake, app)

        self.assertTrue(result["ok"])
        self.assertEqual(result["taskPath"], TASK_PATH)
        self.assertEqual(fake.calls[-1], ("stop_scheduled_task", TASK_PATH))

    def test_scheduled_task_enabled_state_can_be_changed_without_runtime_control(self):
        fake = self.fake_platform("ready")
        app = scheduled_app("service")

        result = server.set_scheduled_task_enabled_app(fake, app, False)

        self.assertTrue(result["ok"])
        self.assertFalse(result["enabled"])
        self.assertEqual(
            fake.calls[-1], ("set_scheduled_task_enabled", (TASK_PATH, False))
        )

    def test_scheduled_task_field_round_trips_through_validation(self):
        fields, error = server.validate_app_fields({
            "name": "Memos Guard",
            "command": 'schtasks.exe /Run /TN "Memos-Guard"',
            "commandSpec": scheduled_app()["commandSpec"],
            "cwd": None,
            "port": None,
            "kind": "service",
            "scheduledTaskPath": TASK_PATH,
        }, partial=False)

        self.assertIsNone(error)
        self.assertEqual(fields["scheduledTaskPath"], TASK_PATH)

    def test_invalid_scheduled_task_path_is_rejected(self):
        fields, error = server.validate_app_fields({
            "scheduledTaskPath": "Memos-Guard\x00bad",
        }, partial=True)

        self.assertIsNone(fields)
        self.assertIn("scheduledTaskPath", error)

    @unittest.skipUnless(os.name == "nt", "Windows Task Scheduler COM only")
    def test_windows_adapter_stops_exact_registered_task_instances(self):
        from localops.platform import windows as windows_platform

        platform = object.__new__(windows_platform.WindowsPlatform)
        instances = SimpleNamespace(Count=1, Item=lambda _index: object())
        task = mock.Mock()
        task.GetInstances.return_value = instances
        folder = mock.Mock()
        folder.GetTask.return_value = task
        service = mock.Mock()
        service.GetFolder.return_value = folder

        with mock.patch.object(
                windows_platform.win32com.client, "Dispatch", return_value=service), \
                mock.patch.object(windows_platform.pythoncom, "CoInitialize"), \
                mock.patch.object(windows_platform.pythoncom, "CoUninitialize"):
            result = platform.stop_scheduled_task(TASK_PATH)

        self.assertTrue(result.ok)
        service.GetFolder.assert_called_once_with("\\")
        folder.GetTask.assert_called_once_with("Memos-Guard")
        task.Stop.assert_called_once_with(0)

    @unittest.skipUnless(os.name == "nt", "Windows Task Scheduler COM only")
    def test_windows_adapter_only_changes_exact_registered_task_enabled_state(self):
        from localops.platform import windows as windows_platform

        platform = object.__new__(windows_platform.WindowsPlatform)
        task = mock.Mock()
        task.Enabled = True
        folder = mock.Mock()
        folder.GetTask.return_value = task
        service = mock.Mock()
        service.GetFolder.return_value = folder

        with mock.patch.object(
                windows_platform.win32com.client, "Dispatch", return_value=service), \
                mock.patch.object(windows_platform.pythoncom, "CoInitialize"), \
                mock.patch.object(windows_platform.pythoncom, "CoUninitialize"):
            result = platform.set_scheduled_task_enabled(TASK_PATH, False)

        self.assertTrue(result.ok)
        self.assertFalse(task.Enabled)
        service.GetFolder.assert_called_once_with("\\")
        folder.GetTask.assert_called_once_with("Memos-Guard")
        task.Run.assert_not_called()
        task.Stop.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows Event Log only")
    def test_windows_adapter_reads_structured_task_history_without_messages(self):
        from localops.platform import windows as windows_platform

        platform = object.__new__(windows_platform.WindowsPlatform)
        config_handle = mock.Mock()
        query_handle = mock.Mock()
        event_handle = mock.Mock()
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>102</EventID><Level>4</Level>"
            "<TimeCreated SystemTime='2026-08-23T01:02:03.1234567Z'/>"
            "<EventRecordID>77</EventRecordID></System>"
            "<EventData><Data Name='TaskName'>\\Memos-Guard</Data>"
            "<Data Name='InstanceId'>{run}</Data>"
            "<Data Name='ResultCode'>1</Data></EventData></Event>"
        )
        with mock.patch.object(
                windows_platform.win32evtlog, "EvtOpenChannelConfig",
                return_value=config_handle), mock.patch.object(
                windows_platform.win32evtlog, "EvtGetChannelConfigProperty",
                return_value=(False, 13)), mock.patch.object(
                windows_platform.win32evtlog, "EvtQuery",
                return_value=query_handle) as query, mock.patch.object(
                windows_platform.win32evtlog, "EvtNext",
                side_effect=[(event_handle,), ()]), mock.patch.object(
                windows_platform.win32evtlog, "EvtRender", return_value=xml):
            snapshot = platform.scheduled_task_events(TASK_PATH, 10)

        self.assertIs(snapshot.status, ScanStatus.PARTIAL)
        self.assertFalse(snapshot.history_enabled)
        self.assertEqual(snapshot.events[0]["eventId"], 102)
        self.assertEqual(snapshot.events[0]["resultCode"], 1)
        self.assertEqual(snapshot.events[0]["taskName"], TASK_PATH)
        self.assertIn(TASK_PATH, query.call_args.args[2])
        event_handle.Close.assert_called_once_with()
        query_handle.Close.assert_called_once_with()
        config_handle.Close.assert_called_once_with()

    @unittest.skipUnless(os.name == "nt", "Windows Event Log only")
    def test_windows_adapter_enables_history_with_fixed_wevtutil_arguments(self):
        from localops.platform import windows as windows_platform

        platform = object.__new__(windows_platform.WindowsPlatform)
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(
                windows_platform.subprocess, "run", return_value=completed) as run:
            result = platform.set_scheduled_task_history_enabled(True)

        self.assertTrue(result.ok)
        self.assertTrue(result.enabled)
        args = run.call_args.args[0]
        self.assertTrue(args[0].casefold().endswith(r"\system32\wevtutil.exe"))
        self.assertEqual(args[1:], [
            "sl", "Microsoft-Windows-TaskScheduler/Operational", "/e:true",
        ])
        self.assertNotIn("shell", run.call_args.kwargs)


class ScheduledTaskHttpTests(unittest.TestCase):
    def setUp(self):
        self.log_dir = tempfile.TemporaryDirectory()
        self.platform = FakePlatform(
            name="windows",
            capabilities=PlatformCapabilities(
                monitor_processes=True,
                monitor_scheduled_tasks=True,
                run_scheduled_tasks=True,
                stop_scheduled_tasks=True,
                toggle_scheduled_tasks=True,
                manage_scheduled_task_history=True,
            ),
            scheduled=ScheduledTaskSnapshot(
                ScanStatus.OK, {TASK_PATH.casefold(): task_row("running")}
            ),
            scheduled_events=ScheduledTaskEventSnapshot(
                ScanStatus.OK,
                events=({
                    "eventId": 102,
                    "recordId": 23,
                    "timestamp": 1_787_210_040,
                    "taskName": TASK_PATH,
                    "resultCode": 1,
                },),
                history_enabled=False,
            ),
            scheduled_history_result=ScheduledTaskHistoryResult(True, True),
            scheduled_stop_result=ScheduledTaskRunResult(True, TASK_PATH),
        )
        self.platform_patch = mock.patch.object(server, "PLATFORM", self.platform)
        self.principal_patch = mock.patch.object(
            server, "SELF_PRINCIPAL", self.platform.principal
        )
        self.logs_patch = mock.patch.object(server, "LOGS_DIR", self.log_dir.name)
        self.platform_patch.start()
        self.principal_patch.start()
        self.logs_patch.start()
        self.harness = HttpHarness()
        self.headers = self.harness.session_headers()
        self.harness.cfg.update(
            lambda data: data["apps"].append(scheduled_app("service"))
        )

    def tearDown(self):
        self.harness.close()
        self.logs_patch.stop()
        self.principal_patch.stop()
        self.platform_patch.stop()
        self.log_dir.cleanup()

    def test_stop_uses_scheduler_capability_without_managed_job_control(self):
        status, body, _ = self.harness.request(
            "POST",
            "/api/apps/deadbeef/stop",
            {"expectedGeneration": None, "force": False},
            self.headers,
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertIn(("stop_scheduled_task", TASK_PATH), self.platform.calls)
        self.assertEqual(len(self.harness.cfg.snapshot()["apps"]), 1)

    def test_disable_endpoint_changes_only_the_bound_scheduled_task(self):
        status, body, _ = self.harness.request(
            "POST",
            "/api/apps/deadbeef/scheduled-enabled",
            {"enabled": False},
            self.headers,
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertFalse(body["enabled"])
        self.assertIn(
            ("set_scheduled_task_enabled", (TASK_PATH, False)),
            self.platform.calls,
        )

    def test_enable_endpoint_rejects_non_boolean_value(self):
        status, body, _ = self.harness.request(
            "POST",
            "/api/apps/deadbeef/scheduled-enabled",
            {"enabled": "yes"},
            self.headers,
        )

        self.assertEqual(status, 400)
        self.assertEqual(body["code"], "INVALID_REQUEST")

    def test_logs_endpoint_includes_current_scheduler_result(self):
        failed = task_row("ready")
        failed["lastResult"] = 1
        self.platform.scheduled = ScheduledTaskSnapshot(
            ScanStatus.OK, {TASK_PATH.casefold(): failed}
        )

        status, body, _ = self.harness.request(
            "GET", "/api/apps/deadbeef/logs?tail=20", headers=self.headers,
        )

        self.assertEqual(status, 200)
        self.assertIn("Windows 计划任务：\\Memos-Guard", body["text"])
        self.assertIn("状态：就绪", body["text"])
        self.assertIn("最近结果：失败 (0x00000001)", body["text"])
        self.assertIn("任务已完成 (Event 102) · 结果 0x00000001", body["text"])
        self.assertFalse(body["taskHistory"]["enabled"])

    def test_diagnosis_reports_structured_scheduler_failure(self):
        failed = task_row("ready")
        failed["lastResult"] = 1
        self.platform.scheduled = ScheduledTaskSnapshot(
            ScanStatus.OK, {TASK_PATH.casefold(): failed}
        )

        status, body, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/diagnose", {}, self.headers,
        )

        self.assertEqual(status, 200)
        issue = next(
            item for item in body["issues"]
            if item["kind"] == "scheduled-task-failed"
        )
        self.assertIn("0x00000001", issue["detail"])
        self.assertNotIn("暂无日志", body["summary"])

    def test_history_endpoint_enables_windows_operational_log(self):
        status, body, _ = self.harness.request(
            "POST",
            "/api/apps/deadbeef/scheduled-history",
            {"enabled": True},
            self.headers,
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertTrue(body["enabled"])
        self.assertIn(
            ("set_scheduled_task_history_enabled", True), self.platform.calls
        )


class WindowsHealthTests(unittest.TestCase):
    def test_health_uses_windows_acl_verifiers_not_posix_mode_bits(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            icons = os.path.join(temp_dir, "icons")
            logs = os.path.join(temp_dir, "logs")
            os.mkdir(icons)
            os.mkdir(logs)
            config = os.path.join(temp_dir, "config.json")
            backup = config + ".bak"
            for path in (config, backup):
                with open(path, "w", encoding="utf-8") as stream:
                    stream.write("{}")
            platform = mock.Mock()
            platform.name = "windows"
            cfg = SimpleNamespace(
                health_info=lambda: {
                    "writable": True,
                    "recoveredFromBackup": False,
                    "migratedFromSchema": None,
                    "issues": [],
                },
                snapshot=lambda: {"schemaVersion": server.CURRENT_SCHEMA_VERSION},
            )

            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "DATA_DIR", temp_dir), \
                    mock.patch.object(server, "ICONS_DIR", icons), \
                    mock.patch.object(server, "LOGS_DIR", logs), \
                    mock.patch.object(server, "CONFIG_PATH", config):
                health = server.build_health(cfg)

        self.assertTrue(health["ok"])
        self.assertEqual(platform.verify_private_directory.call_count, 3)
        self.assertEqual(platform.verify_private_file.call_count, 2)
        platform.ensure_private_directory.assert_not_called()
        platform.ensure_private_file.assert_not_called()


class RuntimeReconciliationSchedulingTests(unittest.TestCase):
    def test_state_snapshot_never_runs_terminal_cleanup_inline(self):
        cfg = SimpleNamespace(
            snapshot=lambda: dict(server.Config.DEFAULT),
            health_info=lambda: {"issues": []},
        )
        cache = {"mono": 0.0, "state": None, "epoch": 0}
        with mock.patch.object(server, "_state_cache_lock", threading.Lock()), \
                mock.patch.object(server, "_state_build_lock", threading.Lock()), \
                mock.patch.object(server, "_state_cache", cache), \
                mock.patch.object(
                    server, "reconcile_windows_terminal_runtimes",
                    side_effect=AssertionError("cleanup blocked state response"),
                ), \
                mock.patch.object(
                    server, "build_state", return_value={"degraded": False}
                ):
            state = server.get_state_snapshot(cfg, 9600)

        self.assertEqual(state, {"degraded": False})

    def test_windows_reconciler_runs_outside_request_path(self):
        called = threading.Event()
        platform = SimpleNamespace(name="windows")
        with mock.patch.object(server, "PLATFORM", platform), \
                mock.patch.object(
                    server, "reconcile_windows_terminal_runtimes",
                    side_effect=lambda _cfg: called.set(),
                ):
            stop = server.start_windows_runtime_reconciler(object())
            self.assertTrue(called.wait(1))
            stop.set()


if __name__ == "__main__":
    unittest.main()

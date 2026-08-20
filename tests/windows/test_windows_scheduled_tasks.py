import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import server
from localops.command_spec import direct_command_spec
from localops.platform.contracts import (
    PlatformCapabilities,
    ScanStatus,
    ScheduledTaskRunResult,
    ScheduledTaskSnapshot,
)
from localops.platform.fake import FakePlatform


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
    def fake_platform(self, state="running"):
        return FakePlatform(
            name="windows",
            capabilities=PlatformCapabilities(
                monitor_processes=True,
                monitor_scheduled_tasks=True,
                run_scheduled_tasks=True,
            ),
            scheduled=ScheduledTaskSnapshot(
                ScanStatus.OK, {TASK_PATH.casefold(): task_row(state)}
            ),
            scheduled_run_result=ScheduledTaskRunResult(True, TASK_PATH),
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
        self.assertFalse(app["controlAvailable"])
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


if __name__ == "__main__":
    unittest.main()

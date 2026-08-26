import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import server
from localops.elevation_broker import broker_install_request_digest
from localops.command_spec import command_spec_for_executable, direct_command_spec
from localops.platform.contracts import (
    ElevationBrokerResult,
    ElevationBrokerStatus,
    ElevatedTaskResult,
    PlatformCapabilities,
    Principal,
    ProcessSnapshot,
    ScanStatus,
    ScheduledTaskRunResult,
    ScheduledTaskSnapshot,
    StopResult,
)
from localops.platform.fake import FakePlatform
from tests.windows.test_windows_server import HttpHarness
if sys.platform == "win32":
    from localops.windows import elevation_broker as broker_runtime
else:
    broker_runtime = None


APP_ID = "deadbeef"
OWNER_SID = "S-1-5-21-100-200-300-1001"
EXECUTABLE = r"C:\Tools\AdminTool.exe"
SYSTEM32 = Path(
    broker_runtime.os.environ.get("SystemRoot") or r"C:\Windows"
) / "System32" if broker_runtime is not None else Path(r"C:\Windows\System32")


def program_app():
    app = dict(server.Config.APP_DEFAULT)
    app.update({
        "id": APP_ID,
        "name": "Admin Tool",
        "command": '"C:\\Tools\\AdminTool.exe" --profile "alpha beta"',
        "commandSpec": direct_command_spec(
            EXECUTABLE, ["--profile", "alpha beta"]
        ),
        "cwd": r"C:\Tools",
        "kind": "program",
        "elevated": True,
        "importStatus": "ready",
        "createdAt": 1,
    })
    return app


def broker_platform(*, installed=True, verified=True, unlocked=True):
    status = ElevationBrokerStatus(
        installed=installed,
        verified=verified,
        running=unlocked,
        unlocked=unlocked,
        stop_supported=unlocked,
    )
    return FakePlatform(
        name="windows",
        principal=Principal(OWNER_SID),
        capabilities=PlatformCapabilities(
            monitor_processes=True,
            manage_elevation_broker=True,
            launch_elevated=True,
        ),
        elevation_status=status,
        elevation_install_result=ElevationBrokerResult(True),
        elevation_unlock_result=ElevationBrokerResult(True),
        elevation_lock_result=ElevationBrokerResult(True),
        elevation_launch_result=ElevationBrokerResult(True, process_id=4321),
    )


class ElevationBrokerStateTests(unittest.TestCase):
    def test_unlocked_broker_makes_program_launchable_without_managed_identity(self):
        platform = broker_platform(unlocked=True)
        cfg = dict(server.Config.DEFAULT)
        cfg["apps"] = [program_app()]

        with mock.patch.object(server, "PLATFORM", platform), \
                mock.patch.object(server, "SELF_PRINCIPAL", platform.principal), \
                mock.patch.object(server, "build_services", return_value=([], set())), \
                mock.patch.object(server, "build_watched", return_value=[]):
            state = server.build_state(cfg, 9600, {})

        app = state["apps"][0]
        self.assertEqual(app["runtimeSource"], "windowsElevationBroker")
        self.assertEqual(app["kind"], "program")
        self.assertIsNone(app["runtimeIdentity"])
        self.assertTrue(app["controlAvailable"])
        self.assertTrue(state["elevationBroker"]["unlocked"])

    def test_owned_program_running_is_observed_with_bounded_stop_control(self):
        platform = broker_platform(unlocked=True)
        platform.processes = ProcessSnapshot(ScanStatus.OK, {
            1200: {
                "owner": OWNER_SID, "comm": EXECUTABLE,
                "etime": 45, "createTime": 1000.5,
                "args": r'C:\Tools\AdminTool.exe --profile "alpha beta"',
            },
            1201: {
                "owner": OWNER_SID,
                "comm": r"C:\Tools\bin\AdminTool.exe",
                "etime": 30, "createTime": 1001.5,
                "args": r'C:\Tools\bin\AdminTool.exe --profile "alpha beta"',
            },
            1202: {
                "owner": OWNER_SID,
                "comm": r"C:\Other\AdminTool.exe",
                "etime": 90, "args": "",
            },
            1203: {
                "owner": "S-1-5-21-9-9-9-1001",
                "comm": EXECUTABLE,
                "etime": 90, "args": "",
            },
            1204: {
                "owner": OWNER_SID, "comm": EXECUTABLE,
                "etime": 90, "args": r"C:\Tools\AdminTool.exe --profile other",
            },
        })
        cfg = dict(server.Config.DEFAULT)
        cfg["apps"] = [program_app()]

        with mock.patch.object(server, "PLATFORM", platform), \
                mock.patch.object(server, "SELF_PRINCIPAL", platform.principal), \
                mock.patch.object(server, "build_services", return_value=([], set())), \
                mock.patch.object(server, "build_watched", return_value=[]):
            state = server.build_state(cfg, 9600, {})

        app = state["apps"][0]
        self.assertTrue(app["running"])
        self.assertEqual(app["pid"], 1200)
        self.assertEqual(app["uptimeSec"], 45)
        self.assertEqual(app["observedPids"], [1200, 1201])
        self.assertEqual(app["observedProcesses"], [
            {"pid": 1200, "createTime": 1000.5},
            {"pid": 1201, "createTime": 1001.5},
        ])
        self.assertFalse(app["observedOnly"])
        self.assertTrue(app["programStopAvailable"])
        self.assertEqual(app["lifecycleStatus"], "running")
        self.assertIsNone(app["runtimeIdentity"])

    def test_one_restricted_same_session_process_is_observed_without_control(self):
        platform = broker_platform(unlocked=True)
        platform.processes = ProcessSnapshot(ScanStatus.PARTIAL, {
            1300: {
                "owner": None, "uid": None, "comm": "AdminTool.exe",
                "args": r'AdminTool.exe --profile "alpha beta"',
                "etime": None, "restricted": True, "sessionId": 1,
            },
        })
        cfg = dict(server.Config.DEFAULT)
        cfg["apps"] = [program_app()]

        with mock.patch.object(server, "PLATFORM", platform), \
                mock.patch.object(server, "SELF_PRINCIPAL", platform.principal), \
                mock.patch.object(server, "build_services", return_value=([], set())), \
                mock.patch.object(server, "build_watched", return_value=[]):
            state = server.build_state(cfg, 9600, {})

        app = state["apps"][0]
        self.assertTrue(app["running"])
        self.assertEqual(app["observedPids"], [1300])
        self.assertTrue(app["observedRestricted"])
        self.assertTrue(app["observedOnly"])
        self.assertFalse(app["programStopAvailable"])
        self.assertIsNone(app["uptimeSec"])
        self.assertEqual(app["lifecycleStatus"], "running")
        self.assertIsNone(app["runtimeIdentity"])

    def test_broker_observation_restores_exact_stop_identity_for_protected_program(self):
        platform = broker_platform(unlocked=True)
        platform.processes = ProcessSnapshot(ScanStatus.PARTIAL, {
            1300: {
                "owner": None, "uid": None, "comm": "AdminTool.exe",
                "args": r'AdminTool.exe --profile "alpha beta"',
                "etime": 12, "createTime": None, "restricted": True,
                "sessionId": 1,
            },
        })
        platform.elevated_processes = ProcessSnapshot(ScanStatus.OK, {
            1300: {
                "owner": OWNER_SID, "uid": None, "comm": EXECUTABLE,
                "args": r'C:\Tools\AdminTool.exe --profile "alpha beta"',
                "etime": 12, "createTime": 1000.5, "restricted": False,
                "sessionId": 1,
            },
        })
        cfg = dict(server.Config.DEFAULT)
        cfg["apps"] = [program_app()]

        with mock.patch.object(server, "PLATFORM", platform), \
                mock.patch.object(server, "SELF_PRINCIPAL", platform.principal), \
                mock.patch.object(server, "build_services", return_value=([], set())), \
                mock.patch.object(server, "build_watched", return_value=[]):
            state = server.build_state(cfg, 9600, {})

        app = state["apps"][0]
        self.assertTrue(app["programIdentityVerified"])
        self.assertTrue(app["programStopAvailable"])
        self.assertIn(
            "observe_elevated", [call[0] for call in platform.calls]
        )

    def test_ambiguous_restricted_processes_are_not_observed(self):
        platform = broker_platform(unlocked=True)
        row = {
            "owner": None, "uid": None, "comm": "AdminTool.exe",
            "args": r'AdminTool.exe --profile "alpha beta"',
            "etime": None, "restricted": True, "sessionId": 1,
        }
        platform.processes = ProcessSnapshot(
            ScanStatus.PARTIAL, {1300: dict(row), 1301: dict(row)}
        )
        cfg = dict(server.Config.DEFAULT)
        cfg["apps"] = [program_app()]

        with mock.patch.object(server, "PLATFORM", platform), \
                mock.patch.object(server, "SELF_PRINCIPAL", platform.principal), \
                mock.patch.object(server, "build_services", return_value=([], set())), \
                mock.patch.object(server, "build_watched", return_value=[]):
            state = server.build_state(cfg, 9600, {})

        self.assertFalse(state["apps"][0]["running"])
        self.assertEqual(state["apps"][0]["observedPids"], [])

    def test_locked_broker_fails_closed_but_keeps_favorite_deletable(self):
        platform = broker_platform(unlocked=False)
        cfg = dict(server.Config.DEFAULT)
        cfg["apps"] = [program_app()]

        with mock.patch.object(server, "PLATFORM", platform), \
                mock.patch.object(server, "SELF_PRINCIPAL", platform.principal), \
                mock.patch.object(server, "build_services", return_value=([], set())), \
                mock.patch.object(server, "build_watched", return_value=[]):
            state = server.build_state(cfg, 9600, {})

        app = state["apps"][0]
        self.assertFalse(app["controlAvailable"])
        self.assertTrue(app["deleteAvailable"])
        self.assertEqual(app["health"]["issues"][0]["action"], "unlock-elevation-broker")


class ElevationBrokerHttpTests(unittest.TestCase):
    def setUp(self):
        self.log_dir = tempfile.TemporaryDirectory()
        self.platform = broker_platform(unlocked=True)
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
        self.harness.cfg.update(lambda data: data["apps"].append(program_app()))

    def tearDown(self):
        self.harness.close()
        self.logs_patch.stop()
        self.principal_patch.stop()
        self.platform_patch.stop()
        self.log_dir.cleanup()

    def unlock_browser_session(self):
        status, body, _ = self.harness.request(
            "POST", "/api/windows/elevation-broker/unlock",
            {"password": "correct horse battery staple"}, self.headers,
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_install_derives_password_verifier_before_platform_boundary(self):
        password = "correct horse battery staple"
        status, body, _ = self.harness.request(
            "POST", "/api/windows/elevation-broker/install",
            {"password": password}, self.headers,
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        call = self.platform.calls[-1]
        self.assertEqual(call[0], "install_elevation_broker")
        password_record, selected_executable = call[1]
        self.assertNotIn(password, repr(password_record))
        self.assertIn("verifier", password_record)
        self.assertIsNone(selected_executable)

    def test_unlock_is_session_only_and_not_written_to_config(self):
        before = self.harness.cfg.snapshot()
        status, body, _ = self.harness.request(
            "POST", "/api/windows/elevation-broker/unlock",
            {"password": "correct horse battery staple"}, self.headers,
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(self.harness.cfg.snapshot(), before)
        self.assertEqual(
            self.platform.calls[-1],
            ("unlock_elevation_broker", "correct horse battery staple"),
        )

    def test_special_keep_alive_is_authorized_only_for_unlocked_session(self):
        self.unlock_browser_session()
        status, armed, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/keep-alive",
            {"enabled": True, "expectedGeneration": None}, self.headers,
        )
        self.assertEqual(status, 200)
        self.assertTrue(armed["keepAlive"])
        grant = self.harness.cfg.snapshot()["apps"][0]["keepAliveGrant"]
        self.assertEqual(grant["grantId"], "fake-keepalive-grant-0001")
        backup_path = Path(self.harness.temp_dir.name) / "config.json.bak"
        backup = json.loads(backup_path.read_text(encoding="utf-8"))
        backup_app = server.find_app(backup, APP_ID)
        self.assertTrue(backup_app["keepAlive"])
        self.assertTrue(backup_app["desiredRunning"])
        self.assertEqual(backup_app["keepAliveGrant"], grant)

        status, state, _ = self.harness.request(
            "GET", "/api/state", headers=self.headers)
        self.assertEqual(status, 200)
        self.assertTrue(state["apps"][0]["keepAliveAuthorized"])

        status, locked, _ = self.harness.request(
            "POST", "/api/windows/elevation-broker/lock", {}, self.headers,
        )
        self.assertEqual(status, 200)
        self.assertTrue(locked["ok"])
        status, state, _ = self.harness.request(
            "GET", "/api/state", headers=self.headers)
        self.assertTrue(state["apps"][0]["keepAliveAuthorized"])
        self.assertTrue(self.harness.cfg.snapshot()["apps"][0]["keepAlive"])

        status, disabled, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/keep-alive",
            {"enabled": False, "expectedGeneration": None}, self.headers,
        )
        self.assertEqual(status, 200)
        self.assertFalse(disabled["keepAlive"])

    def test_failed_grant_revoke_rotates_paused_intent_into_backup(self):
        self.unlock_browser_session()
        status, armed, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/keep-alive",
            {"enabled": True, "expectedGeneration": None}, self.headers,
        )
        self.assertEqual(status, 200)
        self.assertTrue(armed["keepAlive"])
        self.platform.keep_alive_grant_revoke_result = {
            "ok": False,
            "code": "KEEP_ALIVE_REVOKE_FAILED",
            "error": "simulated revoke failure",
        }

        status, body, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/keep-alive",
            {"enabled": False, "expectedGeneration": None}, self.headers,
        )

        self.assertEqual(status, 409)
        self.assertEqual(body["code"], "KEEP_ALIVE_REVOKE_FAILED")
        current = self.harness.cfg.snapshot()["apps"][0]
        self.assertTrue(current["keepAlive"])
        self.assertFalse(current["desiredRunning"])
        backup_path = Path(self.harness.temp_dir.name) / "config.json.bak"
        backup = json.loads(backup_path.read_text(encoding="utf-8"))
        backup_app = server.find_app(backup, APP_ID)
        self.assertTrue(backup_app["keepAlive"])
        self.assertFalse(backup_app["desiredRunning"])

    def test_cli_bearer_cannot_unlock_or_reuse_browser_elevation(self):
        headers = {
            "Authorization": "Bearer " + self.harness.httpd.cli_token,
            "Content-Type": "application/json",
        }
        status, body, _ = self.harness.request(
            "POST", "/api/windows/elevation-broker/unlock",
            {"password": "correct horse battery staple"}, headers,
        )

        self.assertEqual(status, 403)
        self.assertEqual(body["code"], "BROWSER_SESSION_REQUIRED")
        self.assertNotIn(
            "unlock_elevation_broker", [call[0] for call in self.platform.calls]
        )

    def test_state_projects_elevation_control_to_current_browser_session(self):
        status, state, _ = self.harness.request(
            "GET", "/api/state", headers=self.headers)
        self.assertEqual(status, 200)
        self.assertFalse(state["elevationBroker"]["sessionAuthorized"])
        self.assertFalse(state["apps"][0]["controlAvailable"])

        self.unlock_browser_session()
        status, state, _ = self.harness.request(
            "GET", "/api/state", headers=self.headers)
        self.assertEqual(status, 200)
        self.assertTrue(state["elevationBroker"]["sessionAuthorized"])
        self.assertTrue(state["apps"][0]["controlAvailable"])

        cli_headers = {
            "Authorization": "Bearer " + self.harness.httpd.cli_token,
        }
        status, state, _ = self.harness.request(
            "GET", "/api/state", headers=cli_headers)
        self.assertEqual(status, 200)
        self.assertFalse(state["elevationBroker"]["sessionAuthorized"])
        self.assertFalse(state["apps"][0]["controlAvailable"])

    def test_state_revokes_stale_browser_elevation_when_broker_locks(self):
        self.unlock_browser_session()
        self.platform.elevation_status = ElevationBrokerStatus(
            installed=True,
            verified=True,
            running=False,
            unlocked=False,
            stop_supported=False,
        )
        server.invalidate_state_cache()

        status, state, _ = self.harness.request(
            "GET", "/api/state", headers=self.headers)

        self.assertEqual(status, 200)
        self.assertFalse(state["elevationBroker"]["sessionAuthorized"])
        self.assertFalse(state["apps"][0]["controlAvailable"])

    def test_install_rejects_source_package_override(self):
        status, body, _ = self.harness.request(
            "POST", "/api/windows/elevation-broker/install",
            {
                "password": "correct horse battery staple",
                "packageExecutable": r"C:\Local Ops\LocalOps.exe",
            }, self.headers,
        )

        self.assertEqual(status, 400)
        self.assertEqual(body["code"], "INVALID_REQUEST")
        self.assertNotIn(
            "install_elevation_broker", [call[0] for call in self.platform.calls]
        )

    def test_elevated_program_start_uses_structured_broker_launch(self):
        status, body, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/start",
            {"expectedGeneration": None}, self.headers,
        )

        self.assertEqual(status, 403)
        self.assertEqual(body["code"], "ELEVATION_SESSION_REQUIRED")
        self.assertNotIn(
            "launch_elevated", [call[0] for call in self.platform.calls]
        )

        self.unlock_browser_session()

        status, body, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/start",
            {"expectedGeneration": None}, self.headers,
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["pid"], 4321)
        self.assertIn((
            "launch_elevated", (program_app()["commandSpec"], r"C:\Tools"),
        ), self.platform.calls)

    def test_elevated_batch_uses_broker_job_and_preserves_task_outcome(self):
        task = program_app()
        task.update({
            "name": "Admin backup",
            "kind": "task",
            "command": "whoami.exe",
            "commandSpec": direct_command_spec(str(SYSTEM32 / "whoami.exe")),
            "cwd": str(SYSTEM32),
            "lastExit": {"status": "succeeded", "code": 0, "at": 10},
        })
        self.harness.cfg.update(
            lambda data: data.__setitem__("apps", [task])
        )
        self.unlock_browser_session()

        with mock.patch.object(server, "inspect_app_health", return_value={
            "status": "ok", "blocking": False, "issues": [],
        }):
            status, started, _ = self.harness.request(
                "POST", "/api/apps/deadbeef/start",
                {"expectedGeneration": None}, self.headers,
            )
        self.assertEqual(status, 200)
        self.assertTrue(started["ok"])
        self.assertIn(
            "launch_elevated_task", [call[0] for call in self.platform.calls]
        )

        self.platform.elevated_task_query_result = ElevatedTaskResult(
            True, found=True, running=True, process_id=4401,
            create_time=1000.25, started_at=1000,
        )
        status, state, _ = self.harness.request(
            "GET", "/api/state", headers=self.headers,
        )
        self.assertEqual(status, 200)
        row = state["apps"][0]
        self.assertEqual(row["runtimeSource"], "windowsElevationBrokerTask")
        self.assertTrue(row["running"])
        self.assertEqual(row["lastExit"]["status"], "succeeded")

        status, stopped, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/stop",
            {"expectedGeneration": None, "force": False}, self.headers,
        )
        self.assertEqual(status, 200)
        self.assertTrue(stopped["ok"])
        self.assertEqual(
            self.harness.cfg.snapshot()["apps"][0]["lastExit"]["status"],
            "stopped",
        )

    def test_elevated_batch_reconciler_persists_natural_failure(self):
        task = program_app()
        task.update({
            "kind": "task",
            "commandSpec": direct_command_spec(str(SYSTEM32 / "whoami.exe")),
            "cwd": str(SYSTEM32),
        })
        self.harness.cfg.update(
            lambda data: data.__setitem__("apps", [task])
        )
        self.platform.elevated_task_query_result = ElevatedTaskResult(
            True, found=True, running=False, process_id=4401,
            started_at=1000, completed_at=3500, exit_code=7,
        )

        server.reconcile_elevated_task_results(self.harness.cfg)

        last_exit = self.harness.cfg.snapshot()["apps"][0]["lastExit"]
        self.assertEqual(last_exit["status"], "failed")
        self.assertEqual(last_exit["code"], 7)
        self.assertEqual(last_exit["durationSec"], 2.5)

    def test_running_elevated_batch_must_stop_before_card_delete(self):
        task = program_app()
        task.update({
            "kind": "task",
            "commandSpec": direct_command_spec(str(SYSTEM32 / "whoami.exe")),
            "cwd": str(SYSTEM32),
        })
        self.harness.cfg.update(
            lambda data: data.__setitem__("apps", [task])
        )
        self.platform.elevated_task_query_result = ElevatedTaskResult(
            True, found=True, running=True, process_id=4401,
            create_time=1000.25, started_at=1000,
        )

        status, body, _ = self.harness.request(
            "DELETE", "/api/apps/deadbeef",
            {"expectedGeneration": None}, self.headers,
        )
        self.assertEqual(status, 403)
        self.assertEqual(body["code"], "ELEVATION_SESSION_REQUIRED")
        self.unlock_browser_session()
        status, body, _ = self.harness.request(
            "DELETE", "/api/apps/deadbeef",
            {"expectedGeneration": None}, self.headers,
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(self.harness.cfg.snapshot()["apps"], [])
        self.assertIn(
            "stop_elevated_task", [call[0] for call in self.platform.calls]
        )

    def test_owned_elevated_program_stop_requires_exact_observed_processes(self):
        self.platform.stop_result = StopResult(True)
        self.unlock_browser_session()
        self.platform.processes = ProcessSnapshot(ScanStatus.OK, {
            1200: {
                "owner": OWNER_SID,
                "comm": EXECUTABLE,
                "args": r'C:\Tools\AdminTool.exe --profile "alpha beta"',
                "etime": 45,
                "createTime": 1000.5,
            },
            1201: {
                "owner": OWNER_SID,
                "comm": r"C:\Tools\bin\AdminTool.exe",
                "args": r'C:\Tools\bin\AdminTool.exe --profile "alpha beta"',
                "etime": 30,
                "createTime": 1001.5,
            },
        })

        status, body, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/stop", {
                "expectedGeneration": None,
                "expectedProcesses": [
                    {"pid": 1200, "createTime": 1000.5},
                    {"pid": 1201, "createTime": 1001.5},
                ],
                "force": False,
            }, self.headers,
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertIn((
            "stop_elevated",
            (
                EXECUTABLE,
                (
                    (1200, 1000.5, EXECUTABLE),
                    (1201, 1001.5, r"C:\Tools\bin\AdminTool.exe"),
                ),
            ),
        ), self.platform.calls)

    def test_elevated_program_stop_rejects_stale_observation(self):
        self.unlock_browser_session()
        self.platform.processes = ProcessSnapshot(ScanStatus.OK, {
            1200: {
                "owner": OWNER_SID,
                "comm": EXECUTABLE,
                "args": r'C:\Tools\AdminTool.exe --profile "alpha beta"',
                "etime": 45,
                "createTime": 1000.5,
            },
        })

        status, body, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/stop", {
                "expectedGeneration": None,
                "expectedProcesses": [{"pid": 1200, "createTime": 999.0}],
                "force": False,
            }, self.headers,
        )

        self.assertEqual(status, 409)
        self.assertEqual(body["code"], "PROGRAM_OBSERVATION_MISMATCH")
        self.assertNotIn(
            "stop_elevated", [call[0] for call in self.platform.calls]
        )

    def test_delete_removes_only_favorite_without_broker_uac(self):
        status, body, _ = self.harness.request(
            "DELETE", "/api/apps/deadbeef",
            {"expectedGeneration": None}, self.headers,
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertNotIn(
            "uninstall_elevation_broker", [call[0] for call in self.platform.calls]
        )
        self.assertEqual(self.harness.cfg.snapshot()["apps"], [])


@unittest.skipUnless(sys.platform == "win32", "Windows broker runtime only")
class ElevationBrokerRuntimeTests(unittest.TestCase):
    @staticmethod
    def _scheduled_task_row(
            *, security_locked=True, run_level="highest",
            principal_sid=OWNER_SID):
        return {
            "path": r"\Memos-Guard",
            "state": "ready",
            "enabled": True,
            "principalSid": principal_sid,
            "runLevel": run_level,
            "multipleInstances": "ignoreNew",
            "triggerCount": 1,
            "principalLogonType": 3,
            "actionDetails": [{
                "type": "exec",
                "path": r"C:\Program Files\Memos\memos.exe",
                "arguments": "--serve",
                "workingDirectory": r"C:\Program Files\Memos",
            }],
            "actionTypes": [0],
            "actionCount": 1,
            "definitionFingerprint": "sha256:" + "a" * 64,
            "securityDescriptorFingerprint": "sha256:" + "b" * 64,
            "securityLocked": security_locked,
        }

    def test_limited_owner_task_can_prepare_persistent_scheduled_grant(self):
        task = self._scheduled_task_row(
            security_locked=False, run_level="limited"
        )
        with mock.patch.object(
                broker_runtime, "_scheduled", return_value={
                    "ok": True,
                    "tasks": {r"\memos-guard": task},
                }):
            record = broker_runtime._prepare_keepalive_grant({
                "appId": APP_ID,
                "kind": "scheduledService",
                "path": r"\Memos-Guard",
            }, OWNER_SID)

        self.assertEqual(record["kind"], "scheduledService")
        self.assertEqual(record["path"], r"\Memos-Guard")
        self.assertTrue(record["taskFingerprint"].startswith("sha256:"))
        self.assertIs(record["taskSecurityLocked"], False)

    def test_scheduled_grant_rejects_user_writable_security_descriptor(self):
        with self.assertRaises(ValueError):
            broker_runtime._task_security_record(
                self._scheduled_task_row(security_locked=False), OWNER_SID
            )

    def test_user_writable_limited_task_must_belong_to_broker_owner(self):
        with self.assertRaises(ValueError):
            broker_runtime._task_security_record(
                self._scheduled_task_row(
                    security_locked=False,
                    run_level="limited",
                    principal_sid="S-1-5-21-9-8-7-1001",
                ),
                OWNER_SID,
            )

    def test_locked_task_must_still_belong_to_broker_owner(self):
        with self.assertRaises(ValueError):
            broker_runtime._task_security_record(
                self._scheduled_task_row(
                    security_locked=True,
                    run_level="highest",
                    principal_sid="S-1-5-21-9-8-7-1001",
                ),
                OWNER_SID,
            )

    def test_locked_highest_owner_task_remains_supported(self):
        record = broker_runtime._task_security_record(
            self._scheduled_task_row(
                security_locked=True, run_level="highest"
            ),
            OWNER_SID,
        )

        self.assertEqual(record["runLevel"], "highest")
        self.assertIs(record["securityLocked"], True)

    def test_elevated_batch_manager_owns_one_exact_job_per_app(self):
        created = []

        class FakeRun:
            def __init__(self, app_id, run_id, owner_sid, invocation, cwd):
                self.app_id = app_id
                self.running = True
                self.closed = False
                created.append((app_id, run_id, owner_sid, invocation, cwd))

            def result(self):
                return {
                    "ok": True, "appId": self.app_id, "found": True,
                    "running": self.running, "pid": 4401,
                    "startedAt": 1000,
                    "completedAt": None if self.running else 2000,
                    "exitCode": None if self.running else 130,
                }

            def stop(self):
                self.running = False
                return self.result()

            def close(self):
                self.closed = True

        manager = broker_runtime._ElevatedBatchTaskManager(
            OWNER_SID, run_factory=FakeRun
        )
        with tempfile.TemporaryDirectory() as td:
            request = {
                "appId": APP_ID,
                "commandSpec": direct_command_spec(
                    str(SYSTEM32 / "whoami.exe")
                ),
                "cwd": td,
            }
            launched = manager.launch(request)
            duplicate = manager.launch(request)

        self.assertTrue(launched["running"])
        self.assertEqual(
            duplicate["code"], "BROKER_ELEVATED_TASK_ALREADY_RUNNING"
        )
        self.assertTrue(manager.query(APP_ID)["running"])
        self.assertFalse(manager.stop(APP_ID)["running"])
        self.assertEqual(created[0][0], APP_ID)
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                manager.launch({
                    "appId": APP_ID,
                    "commandSpec": {
                        "version": 1, "mode": "powershell",
                        "executable": None, "args": [],
                        "shell": "powershell.exe",
                        "text": "Remove-Item C:\\*", "needsReview": False,
                    },
                    "cwd": td,
                })
            with self.assertRaises(ValueError):
                manager.launch({
                    "appId": APP_ID,
                    "commandSpec": direct_command_spec(
                        "cmd.exe", ["/c", "Remove-Item C:\\*"]
                    ),
                    "cwd": td,
                })
            for interpreter in (
                    "bash.exe", "powershell_ise.exe", "pythonw.exe"):
                with self.subTest(interpreter=interpreter), \
                        self.assertRaises(ValueError):
                    manager.launch({
                        "appId": APP_ID,
                        "commandSpec": direct_command_spec(
                            str(SYSTEM32 / interpreter), ["-c", "exit 0"]
                        ),
                        "cwd": td,
                    })

    def test_elevated_batch_uses_fixed_system_interpreters_not_cwd_or_path(self):
        owner_sid = broker_runtime._owner_sid(broker_runtime.os.getpid())
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake_cmd = root / "cmd.exe"
            fake_powershell = root / "powershell.exe"
            cmd_script = root / "task.cmd"
            ps_script = root / "task.ps1"
            fake_cmd.write_bytes(b"not a system interpreter")
            fake_powershell.write_bytes(b"not a system interpreter")
            cmd_script.write_text("@exit /b 0\r\n", encoding="utf-8")
            ps_script.write_text("exit 0\r\n", encoding="utf-8")
            hostile_environment = {
                "PATH": td,
                "COMSPEC": str(fake_cmd),
            }
            with mock.patch.dict(
                    broker_runtime.os.environ,
                    hostile_environment,
                    clear=False):
                _, cmd_invocation, _ = (
                    broker_runtime._prepare_elevated_task_request({
                        "appId": APP_ID,
                        "commandSpec": command_spec_for_executable(
                            str(cmd_script), platform_name="windows"
                        ),
                        "cwd": td,
                    }, owner_sid)
                )
                _, powershell_invocation, _ = (
                    broker_runtime._prepare_elevated_task_request({
                        "appId": APP_ID,
                        "commandSpec": command_spec_for_executable(
                            str(ps_script), platform_name="windows"
                        ),
                        "cwd": td,
                    }, owner_sid)
                )

        windows = Path(broker_runtime.win32api.GetWindowsDirectory())
        self.assertEqual(
            Path(cmd_invocation["executable"]).resolve(),
            (windows / "System32" / "cmd.exe").resolve(),
        )
        self.assertEqual(
            Path(powershell_invocation["executable"]).resolve(),
            (windows / "System32" / "WindowsPowerShell" / "v1.0"
             / "powershell.exe").resolve(),
        )

    def test_elevated_batch_assign_failure_terminates_suspended_process(self):
        job = mock.Mock()
        job.assign.side_effect = OSError("fixture assign failure")
        process_handle = mock.Mock(name="process_handle")
        thread_handle = mock.Mock(name="thread_handle")
        with mock.patch.object(
                broker_runtime, "native_process_command",
                return_value=(str(SYSTEM32 / "whoami.exe"), "whoami.exe")), \
                mock.patch.object(
                    broker_runtime.win32process, "CreateProcess",
                    return_value=(process_handle, thread_handle, 4401, 0)), \
                mock.patch.object(broker_runtime, "OwnedJob", return_value=job), \
                mock.patch.object(
                    broker_runtime.win32process, "TerminateProcess"
                ) as terminate_process, \
                mock.patch.object(broker_runtime.win32api, "CloseHandle"):
            with self.assertRaisesRegex(OSError, "assign failure"):
                broker_runtime._ElevatedBatchRun(
                    APP_ID, "f" * 32, OWNER_SID,
                    [str(SYSTEM32 / "whoami.exe")], str(SYSTEM32),
                )

        terminate_process.assert_called_once_with(process_handle, 1)
        job.close.assert_called_once_with()

    def test_elevated_batch_closes_first_stream_if_second_open_fails(self):
        input_stream = mock.Mock()
        with mock.patch.object(
                broker_runtime, "native_process_command",
                return_value=(str(SYSTEM32 / "whoami.exe"), "whoami.exe")), \
                mock.patch(
                    "builtins.open",
                    side_effect=[input_stream, OSError("fixture open failure")],
                ):
            with self.assertRaisesRegex(OSError, "open failure"):
                broker_runtime._ElevatedBatchRun(
                    APP_ID, "f" * 32, OWNER_SID,
                    [str(SYSTEM32 / "whoami.exe")], str(SYSTEM32),
                )

        input_stream.close.assert_called_once_with()

    def test_elevated_batch_closes_streams_if_handle_conversion_fails(self):
        input_stream = mock.Mock()
        output_stream = mock.Mock()
        input_stream.fileno.return_value = 101
        output_stream.fileno.return_value = 102
        msvcrt = __import__("msvcrt")
        with mock.patch.object(
                broker_runtime, "native_process_command",
                return_value=(str(SYSTEM32 / "whoami.exe"), "whoami.exe")), \
                mock.patch(
                    "builtins.open", side_effect=[input_stream, output_stream]
                ), \
                mock.patch.object(
                    msvcrt, "get_osfhandle",
                    side_effect=[1001, OSError("fixture handle failure")],
                ), \
                mock.patch.object(
                    broker_runtime.os, "set_handle_inheritable"
                ) as set_inheritable:
            with self.assertRaisesRegex(OSError, "handle failure"):
                broker_runtime._ElevatedBatchRun(
                    APP_ID, "f" * 32, OWNER_SID,
                    [str(SYSTEM32 / "whoami.exe")], str(SYSTEM32),
                )

        set_inheritable.assert_not_called()
        input_stream.close.assert_called_once_with()
        output_stream.close.assert_called_once_with()

    def test_elevated_batch_restores_first_inheritable_handle_on_failure(self):
        input_stream = mock.Mock()
        output_stream = mock.Mock()
        input_stream.fileno.return_value = 101
        output_stream.fileno.return_value = 102
        calls = []

        def set_inheritable(handle, inheritable):
            calls.append((handle, inheritable))
            if handle == 1002 and inheritable:
                raise OSError("fixture inheritable failure")

        msvcrt = __import__("msvcrt")
        with mock.patch.object(
                broker_runtime, "native_process_command",
                return_value=(str(SYSTEM32 / "whoami.exe"), "whoami.exe")), \
                mock.patch(
                    "builtins.open", side_effect=[input_stream, output_stream]
                ), \
                mock.patch.object(
                    msvcrt, "get_osfhandle", side_effect=[1001, 1002]
                ), \
                mock.patch.object(
                    broker_runtime.os, "set_handle_inheritable",
                    side_effect=set_inheritable,
                ), \
                mock.patch.object(
                    broker_runtime.win32process, "CreateProcess"
                ) as create_process:
            with self.assertRaisesRegex(OSError, "inheritable failure"):
                broker_runtime._ElevatedBatchRun(
                    APP_ID, "f" * 32, OWNER_SID,
                    [str(SYSTEM32 / "whoami.exe")], str(SYSTEM32),
                )

        self.assertEqual(calls, [
            (1001, True), (1002, True), (1001, False),
        ])
        create_process.assert_not_called()
        input_stream.close.assert_called_once_with()
        output_stream.close.assert_called_once_with()

    def test_elevated_batch_capacity_prunes_terminal_records_first(self):
        class FakeRun:
            def __init__(self, app_id, run_id, owner_sid, invocation, cwd):
                self.app_id = app_id
                self.closed = False

            def result(self):
                return {
                    "ok": True, "appId": self.app_id, "found": True,
                    "running": False, "completedAt": int(self.app_id, 16),
                    "exitCode": 0,
                }

            def close(self):
                self.closed = True

        manager = broker_runtime._ElevatedBatchTaskManager(
            OWNER_SID, run_factory=FakeRun
        )
        manager.runs = {
            f"{index:08x}": FakeRun(
                f"{index:08x}", "f" * 32, OWNER_SID, [], str(SYSTEM32)
            )
            for index in range(256)
        }
        launched = manager.launch({
            "appId": "fffffffe",
            "commandSpec": direct_command_spec(str(SYSTEM32 / "whoami.exe")),
            "cwd": str(SYSTEM32),
        })

        self.assertTrue(launched["ok"])
        self.assertIn("fffffffe", manager.runs)
        self.assertEqual(len(manager.runs), 256)

    def test_elevated_batch_capacity_rejects_only_when_all_records_run(self):
        class ActiveRun:
            def __init__(self, app_id):
                self.app_id = app_id

            def result(self):
                return {
                    "ok": True, "appId": self.app_id, "found": True,
                    "running": True, "completedAt": None,
                }

            def close(self):
                raise AssertionError("active record must not be pruned")

        manager = broker_runtime._ElevatedBatchTaskManager(OWNER_SID)
        manager.runs = {
            f"{index:08x}": ActiveRun(f"{index:08x}")
            for index in range(256)
        }
        refused = manager.launch({
            "appId": "fffffffe",
            "commandSpec": direct_command_spec(str(SYSTEM32 / "whoami.exe")),
            "cwd": str(SYSTEM32),
        })

        self.assertFalse(refused["ok"])
        self.assertEqual(refused["code"], "BROKER_ELEVATED_TASK_CAPACITY")

    def test_elevated_batch_manager_runs_and_stops_fixture_job(self):
        owner_sid = broker_runtime._owner_sid(broker_runtime.os.getpid())
        manager = broker_runtime._ElevatedBatchTaskManager(owner_sid)
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / "wait.cmd"
            script.write_text(
                "@ping.exe 127.0.0.1 -n 31 >nul\r\n",
                encoding="utf-8",
            )
            launched = manager.launch({
                "appId": APP_ID,
                "commandSpec": command_spec_for_executable(
                    str(script), platform_name="windows"
                ),
                "cwd": td,
            })
            try:
                self.assertTrue(launched["running"])
                self.assertTrue(manager.query(APP_ID)["running"])
            finally:
                stopped = manager.stop(APP_ID)

        self.assertFalse(stopped["running"])
        self.assertEqual(stopped["exitCode"], 130)

    def test_elevated_batch_manager_reports_fixture_exit_code(self):
        owner_sid = broker_runtime._owner_sid(broker_runtime.os.getpid())
        manager = broker_runtime._ElevatedBatchTaskManager(owner_sid)
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / "fail.cmd"
            script.write_text("@exit /b 7\r\n", encoding="utf-8")
            manager.launch({
                "appId": APP_ID,
                "commandSpec": command_spec_for_executable(
                    str(script), platform_name="windows"
                ),
                "cwd": td,
            })
            deadline = broker_runtime.time.monotonic() + 5.0
            while broker_runtime.time.monotonic() < deadline:
                result = manager.query(APP_ID)
                if not result["running"]:
                    break
                broker_runtime.time.sleep(0.02)
            else:
                self.fail("fixture task did not exit")

        self.assertEqual(result["exitCode"], 7)
        self.assertIsNotNone(result["completedAt"])

    def test_client_image_attestation_cache_is_bounded_by_file_and_ttl(self):
        now = [0.0]
        verify = mock.Mock(return_value=True)
        with tempfile.TemporaryDirectory() as td:
            executable = Path(td) / "LocalOps.exe"
            executable.write_bytes(b"fixture")
            cache = broker_runtime._BoundedClientImageAttestation(
                OWNER_SID, "a" * 64,
                verify=verify, clock=lambda: now[0],
            )

            self.assertTrue(cache(executable))
            now[0] = 1.0
            self.assertTrue(cache(executable))
            self.assertEqual(verify.call_count, 1)
            now[0] = 31.0
            self.assertTrue(cache(executable))
            self.assertEqual(verify.call_count, 2)

    def test_client_pid_creation_is_rechecked_before_cached_image_proof(self):
        process = mock.Mock()
        process.create_time.side_effect = [88.5, 99.0]
        process.exe.return_value = EXECUTABLE
        token = mock.Mock()
        handle = mock.Mock()
        image_valid = mock.Mock(return_value=True)
        with mock.patch.object(
                broker_runtime.psutil, "Process", return_value=process), \
                mock.patch.object(
                    broker_runtime, "_owner_sid", return_value=OWNER_SID
                ), mock.patch.object(
                    broker_runtime.win32api, "OpenProcess", return_value=handle
                ), mock.patch.object(
                    broker_runtime.win32security, "OpenProcessToken",
                    return_value=token,
                ), mock.patch.object(
                    broker_runtime.win32security, "GetTokenInformation",
                    return_value=False,
                ):
            self.assertTrue(broker_runtime._keepalive_client_valid(
                1200, 88.5, OWNER_SID, "a" * 64,
                image_valid=image_valid,
            ))
            self.assertFalse(broker_runtime._keepalive_client_valid(
                1200, 88.5, OWNER_SID, "a" * 64,
                image_valid=image_valid,
            ))

        image_valid.assert_called_once_with(Path(EXECUTABLE))

    def test_scheduled_grant_uses_lightweight_runtime_query_within_ttl(self):
        now = [0.0]
        task = self._scheduled_task_row()
        fingerprint = broker_runtime._canonical_digest(
            broker_runtime._task_security_record(task, OWNER_SID)
        )
        record = {
            "kind": "scheduledService",
            "path": r"\Memos-Guard",
            "taskFingerprint": fingerprint,
        }
        full = {
            "ok": True,
            "tasks": {r"\memos-guard": task},
        }
        lightweight = {
            "ok": True,
            "tasks": {r"\memos-guard": {
                "path": r"\Memos-Guard",
                "state": "ready",
                "enabled": True,
            }},
        }
        executor = broker_runtime._KeepAliveGrantExecutor(
            OWNER_SID, clock=lambda: now[0]
        )
        with mock.patch.object(
                broker_runtime, "_scheduled", return_value=full
                ) as complete, mock.patch.object(
                    broker_runtime, "_scheduled_runtime", return_value=lightweight
                ) as runtime:
            self.assertTrue(executor("query", record)["ok"])
            now[0] = 1.0
            self.assertTrue(executor("query", record)["ok"])
            now[0] = 31.0
            self.assertTrue(executor("query", record)["ok"])

        self.assertEqual(complete.call_count, 2)
        runtime.assert_called_once_with(r"\Memos-Guard", OWNER_SID)

    def test_mutable_limited_task_rechecks_full_definition_before_run(self):
        now = [0.0]
        task = self._scheduled_task_row(
            security_locked=False, run_level="limited"
        )
        fingerprint = broker_runtime._canonical_digest(
            broker_runtime._task_security_record(task, OWNER_SID)
        )
        record = {
            "kind": "scheduledService",
            "path": r"\Memos-Guard",
            "taskFingerprint": fingerprint,
            "taskSecurityLocked": False,
        }
        drifted = self._scheduled_task_row(
            security_locked=False, run_level="limited"
        )
        drifted["definitionFingerprint"] = "sha256:" + "c" * 64
        drifted["actionDetails"][0]["path"] = r"C:\Fixtures\changed.exe"
        queries = iter((task, drifted))
        calls = []

        def scheduled(request, _owner_sid):
            calls.append(dict(request))
            if request["operation"] == "query":
                selected = next(queries)
                return {
                    "ok": True,
                    "tasks": {r"\memos-guard": selected},
                }
            return {"ok": True}

        executor = broker_runtime._KeepAliveGrantExecutor(
            OWNER_SID, clock=lambda: now[0]
        )
        with mock.patch.object(
                broker_runtime, "_scheduled", side_effect=scheduled), \
                mock.patch.object(
                    broker_runtime, "_scheduled_runtime", return_value={
                        "ok": True,
                        "tasks": {r"\memos-guard": {
                            "path": r"\Memos-Guard",
                            "state": "ready",
                            "enabled": True,
                        }},
                    },
                ) as runtime:
            self.assertTrue(executor("query", record)["ok"])
            now[0] = 1.0
            with self.assertRaisesRegex(ValueError, "definition changed"):
                executor("run", record)

        runtime.assert_not_called()
        self.assertEqual(
            [call["operation"] for call in calls], ["query", "query"]
        )

    def test_registry_write_failure_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(
                broker_runtime, "_protect_path"), mock.patch.object(
                    broker_runtime.os, "replace", side_effect=OSError("busy")
                ):
            target = Path(td) / "grants.json"
            with self.assertRaises(OSError):
                broker_runtime._write_json(
                    target, {"schema": "fixture"}, OWNER_SID, secret=True
                )
            self.assertEqual(list(Path(td).iterdir()), [])

    def test_registry_startup_cleans_only_verified_strict_temporaries(self):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            temporary = directory / ("grants.json.tmp-" + "a" * 32)
            temporary.write_bytes(b"fixture")
            administrators = broker_runtime.win32security.ConvertStringSidToSid(
                broker_runtime._ADMINISTRATORS_SID
            )
            system = broker_runtime.win32security.ConvertStringSidToSid(
                broker_runtime._SYSTEM_SID
            )
            dacl = mock.Mock()
            dacl.GetAceCount.return_value = 2
            inherited_aces = [
                ((broker_runtime.win32security.ACCESS_ALLOWED_ACE_TYPE,
                  broker_runtime.win32security.INHERITED_ACE),
                 broker_runtime.ntsecuritycon.FILE_ALL_ACCESS, system),
                ((broker_runtime.win32security.ACCESS_ALLOWED_ACE_TYPE,
                  broker_runtime.win32security.INHERITED_ACE),
                 broker_runtime.ntsecuritycon.FILE_ALL_ACCESS, administrators),
            ]
            dacl.GetAce.side_effect = lambda index: inherited_aces[index]
            descriptor = mock.Mock()
            descriptor.GetSecurityDescriptorOwner.return_value = administrators
            descriptor.GetSecurityDescriptorDacl.return_value = dacl
            descriptor.GetSecurityDescriptorControl.return_value = (0, 0)
            with mock.patch.object(
                    broker_runtime.win32security, "GetNamedSecurityInfo",
                    return_value=descriptor,
                ):
                with self.assertRaises(PermissionError):
                    broker_runtime._verify_broker_only_path(
                        temporary, directory=False
                    )
                broker_runtime._cleanup_capability_temporaries(directory)
            self.assertFalse(temporary.exists())

            unknown = directory / "grants.json.tmp-unsafe"
            unknown.write_bytes(b"fixture")
            with self.assertRaises(OSError):
                broker_runtime._cleanup_capability_temporaries(directory)
            self.assertTrue(unknown.exists())

    def test_persistent_program_rejects_inherited_low_privilege_writers(self):
        owner = broker_runtime.win32security.ConvertStringSidToSid(
            broker_runtime._ADMINISTRATORS_SID
        )
        low_privilege = broker_runtime.win32security.ConvertStringSidToSid(
            broker_runtime._AUTHENTICATED_USERS_SID
        )
        dacl = mock.Mock()
        dacl.GetAceCount.return_value = 1
        dacl.GetAce.return_value = (
            (
                broker_runtime.win32security.ACCESS_ALLOWED_ACE_TYPE,
                broker_runtime.win32con.OBJECT_INHERIT_ACE
                | broker_runtime.win32con.CONTAINER_INHERIT_ACE
                | broker_runtime.win32con.INHERIT_ONLY_ACE,
            ),
            broker_runtime.ntsecuritycon.FILE_GENERIC_WRITE,
            low_privilege,
        )
        descriptor = mock.Mock()
        descriptor.GetSecurityDescriptorOwner.return_value = owner
        descriptor.GetSecurityDescriptorDacl.return_value = dacl

        with mock.patch.object(
                broker_runtime.win32security,
                "GetNamedSecurityInfo",
                return_value=descriptor):
            with self.assertRaises(PermissionError):
                broker_runtime._reject_user_writable(
                    Path(r"C:\Program Files\Unsafe"),
                    OWNER_SID,
                    directory=True,
                )

    def test_persistent_program_rejects_executable_outside_program_files(self):
        with tempfile.TemporaryDirectory() as td:
            executable = Path(td) / "replaceable.exe"
            executable.write_bytes(b"fixture")

            with self.assertRaisesRegex(ValueError, "Program Files"):
                broker_runtime._protected_program_fingerprint(
                    str(executable), OWNER_SID
                )

    def test_broker_queries_and_stops_only_normalized_scheduled_task_path(self):
        platform = mock.Mock()
        platform.current_principal.return_value = Principal(OWNER_SID)
        platform.scheduled_tasks.return_value = ScheduledTaskSnapshot(
            ScanStatus.OK,
            {r"\memos-guard": {
                "path": r"\Memos-Guard", "state": "running",
            }},
        )
        platform.stop_scheduled_task.return_value = ScheduledTaskRunResult(
            True, r"\Memos-Guard"
        )
        with mock.patch(
                "localops.platform.windows.WindowsPlatform",
                return_value=platform):
            queried = broker_runtime._scheduled({
                "operation": "query", "paths": [r"\Memos-Guard"],
            }, OWNER_SID)
            stopped = broker_runtime._scheduled({
                "operation": "stop", "path": r"\Memos-Guard",
            }, OWNER_SID)

        self.assertTrue(queried["ok"])
        self.assertEqual(queried["tasks"][r"\memos-guard"]["state"], "running")
        self.assertTrue(stopped["ok"])
        platform.scheduled_tasks.assert_called_once_with({r"\Memos-Guard"})
        platform.stop_scheduled_task.assert_called_once_with(r"\Memos-Guard")

    def test_broker_observes_and_stops_only_exact_owned_process_identity(self):
        process = mock.Mock()
        process.pid = 4301
        process.name.return_value = "AdminTool.exe"
        process.exe.return_value = EXECUTABLE
        process.cmdline.return_value = [
            EXECUTABLE, "--profile", "alpha beta",
        ]
        process.create_time.return_value = 1000.25

        launch_request = {
            "executable": EXECUTABLE,
            "args": ["--profile", "alpha beta"],
            "cwd": r"C:\Tools",
        }
        with mock.patch.object(
                broker_runtime.psutil, "process_iter", return_value=[process]), \
                mock.patch.object(
                    broker_runtime, "_owner_sid", return_value=OWNER_SID):
            observed = broker_runtime._observe(launch_request, OWNER_SID)

        self.assertTrue(observed["ok"])
        self.assertEqual(observed["processes"][0]["pid"], 4301)

        stop_request = {
            "favoriteExecutable": EXECUTABLE,
            "processes": [{
                "pid": 4301,
                "createTime": 1000.25,
                "executable": EXECUTABLE,
            }],
        }
        with mock.patch.object(
                broker_runtime.psutil, "Process", return_value=process), \
                mock.patch.object(
                    broker_runtime, "_owner_sid", return_value=OWNER_SID):
            stopped = broker_runtime._stop(stop_request, OWNER_SID)

        self.assertTrue(stopped["ok"])
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5.0)

    def test_broker_observation_queries_owner_only_for_matching_executable_name(self):
        noise = mock.Mock()
        noise.pid = 4200
        noise.name.return_value = "unrelated.exe"
        noise.exe.side_effect = AssertionError(
            "noise process must be rejected before executable or owner queries"
        )
        match = mock.Mock()
        match.pid = 4301
        match.name.return_value = "AdminTool.exe"
        match.exe.return_value = EXECUTABLE
        match.cmdline.return_value = [EXECUTABLE]
        match.create_time.return_value = 1000.25

        with mock.patch.object(
                broker_runtime.psutil, "process_iter",
                return_value=[noise, match]), mock.patch.object(
                    broker_runtime, "_owner_sid",
                    return_value=OWNER_SID) as owner_sid:
            observed = broker_runtime._observe({
                "executable": EXECUTABLE,
                "args": [],
                "cwd": r"C:\Tools",
            }, OWNER_SID)

        self.assertTrue(observed["ok"])
        self.assertEqual([row["pid"] for row in observed["processes"]], [4301])
        owner_sid.assert_called_once_with(4301)

    def test_broker_rejects_stale_identity_before_termination(self):
        process = mock.Mock()
        process.exe.return_value = EXECUTABLE
        process.create_time.return_value = 1001.0
        request = {
            "favoriteExecutable": EXECUTABLE,
            "processes": [{
                "pid": 4301,
                "createTime": 1000.25,
                "executable": EXECUTABLE,
            }],
        }
        with mock.patch.object(
                broker_runtime.psutil, "Process", return_value=process), \
                mock.patch.object(
                    broker_runtime, "_owner_sid", return_value=OWNER_SID):
            result = broker_runtime._stop(request, OWNER_SID)

        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "BROKER_STOP_IDENTITY_MISMATCH")
        process.terminate.assert_not_called()


@unittest.skipUnless(sys.platform == "win32", "Windows installer helper only")
class ElevationBrokerInstallerTests(unittest.TestCase):
    def test_install_path_validation_ignores_custom_console_data_override(self):
        with tempfile.TemporaryDirectory() as root:
            local_app_data = Path(root) / "LocalAppData"
            transaction = (
                local_app_data / "LocalOps" / "runtime"
                / "elevation-install" / ("a" * 32)
            )
            request_path = transaction / "request.json"
            response_path = transaction / "response.json"

            with mock.patch.dict(
                    "os.environ",
                    {"CONSOLE_DATA_DIR": str(Path(root) / "CustomData")}), \
                    mock.patch.object(
                        broker_runtime.shell, "SHGetKnownFolderPath",
                        return_value=str(local_app_data)):
                broker_runtime._validate_install_paths(
                    request_path, response_path
                )

    def test_bundle_digest_changes_when_only_static_assets_change(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = Path(root) / "bundle"
            static = bundle / "_internal" / "static"
            static.mkdir(parents=True)
            (bundle / "LocalOps.exe").write_bytes(b"same executable")
            asset = static / "app.js"
            asset.write_text("const version = 1;", encoding="utf-8")
            before = broker_runtime._bundle_sha256(bundle)

            asset.write_text("const version = 2;", encoding="utf-8")
            after = broker_runtime._bundle_sha256(bundle)

        self.assertNotEqual(before, after)

    def test_bundle_digest_includes_empty_directories_and_creation_order(self):
        with tempfile.TemporaryDirectory() as root:
            first = Path(root) / "first"
            second = Path(root) / "second"
            for bundle, names in (
                    (first, ("z.txt", "A.txt")),
                    (second, ("A.txt", "z.txt"))):
                bundle.mkdir()
                for name in names:
                    (bundle / name).write_text(name, encoding="utf-8")
            baseline = broker_runtime._bundle_sha256(first)
            self.assertEqual(baseline, broker_runtime._bundle_sha256(second))

            (first / "empty").mkdir()
            self.assertNotEqual(
                baseline, broker_runtime._bundle_sha256(first)
            )

    def test_bundle_digest_rejects_file_identity_change(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = Path(root) / "bundle"
            bundle.mkdir()
            file_path = bundle / "LocalOps.exe"
            file_path.write_bytes(b"executable")
            actual_fstat = broker_runtime.os.fstat

            def changed_identity(descriptor):
                value = actual_fstat(descriptor)
                return type("ChangedIdentity", (), {
                    "st_dev": value.st_dev,
                    "st_ino": value.st_ino + 1,
                    "st_size": value.st_size,
                    "st_mtime_ns": value.st_mtime_ns,
                })()

            with mock.patch.object(
                    broker_runtime.os, "fstat", side_effect=changed_identity):
                with self.assertRaisesRegex(OSError, "changed before"):
                    broker_runtime._bundle_sha256(bundle)

    def test_archive_extraction_rejects_links_and_casefold_collisions(self):
        unsafe_names = (
            "LocalOps.exe:evil", "./evil", "C:/evil", "foo//bar",
            "foo/./bar", "evil.", "evil ", "CON", "COM¹", "bad\x01name",
        )
        cases = [
            (("link", b"target", 0o120777 << 16),),
            (("A.txt", b"A", 0), ("a.txt", b"a", 0)),
        ]
        cases.extend(
            ((name, b"data", broker_runtime.stat.S_IFREG << 16),)
            for name in unsafe_names
        )
        for entries in cases:
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w") as archive:
                for name, data, attributes in entries:
                    info = zipfile.ZipInfo(name)
                    info.external_attr = attributes
                    archive.writestr(info, data)
            payload.seek(0)
            with tempfile.TemporaryDirectory() as root:
                with self.assertRaises((OSError, ValueError)):
                    broker_runtime._extract_bundle_archive(
                        payload, Path(root) / "staging"
                    )

    def test_install_archive_handle_denies_concurrent_writers(self):
        with tempfile.TemporaryDirectory() as root:
            archive_path = Path(root) / "bundle.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("LocalOps.exe", b"executable")

            with broker_runtime._open_install_archive(archive_path):
                with self.assertRaises(OSError):
                    open(archive_path, "r+b")

            with open(archive_path, "r+b"):
                with self.assertRaises((OSError, broker_runtime.pywintypes.error)):
                    broker_runtime._open_install_archive(archive_path)

    def test_bundle_protection_sets_admin_owner_before_readback(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = Path(root) / "bundle"
            bundle.mkdir()
            (bundle / "LocalOps.exe").write_bytes(b"executable")
            events = []
            with mock.patch.object(
                    broker_runtime, "_protect_path",
                    side_effect=lambda path, *_args, **_kwargs: events.append(
                        ("protect", Path(path).name)
                    )), mock.patch.object(
                        broker_runtime, "_set_protected_bundle_owner",
                        side_effect=lambda path: events.append(
                            ("owner", Path(path).name)
                        )), mock.patch.object(
                            broker_runtime, "_verify_protected_bundle",
                            side_effect=lambda path, _owner: events.append(
                                ("verify", Path(path).name)
                            )):
                broker_runtime._protect_bundle(bundle, OWNER_SID)

        self.assertEqual(events[-1], ("verify", "bundle"))
        self.assertIn(("owner", "bundle"), events)
        self.assertIn(("owner", "LocalOps.exe"), events)

    def test_bundle_acl_verifier_rejects_extra_user_write_rights(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "LocalOps.exe"
            path.write_bytes(b"executable")
            allow = broker_runtime.win32security.ACCESS_ALLOWED_ACE_TYPE
            full = broker_runtime.ntsecuritycon.FILE_ALL_ACCESS
            read_execute = (
                broker_runtime.ntsecuritycon.FILE_GENERIC_READ
                | broker_runtime.ntsecuritycon.FILE_GENERIC_EXECUTE
            )
            descriptor = mock.Mock()
            dacl = mock.Mock()
            descriptor.GetSecurityDescriptorOwner.return_value = (
                broker_runtime._ADMINISTRATORS_SID
            )
            descriptor.GetSecurityDescriptorDacl.return_value = dacl
            descriptor.GetSecurityDescriptorControl.return_value = (
                broker_runtime.win32security.SE_DACL_PROTECTED, 0,
            )

            def verify_with(user_rights):
                aces = [
                    ((allow, 0), full, broker_runtime._SYSTEM_SID),
                    ((allow, 0), full, broker_runtime._ADMINISTRATORS_SID),
                    ((allow, 0), user_rights, OWNER_SID),
                ]
                dacl.GetAceCount.return_value = len(aces)
                dacl.GetAce.side_effect = lambda index: aces[index]
                with mock.patch.object(
                        broker_runtime.win32security, "GetNamedSecurityInfo",
                        return_value=descriptor), mock.patch.object(
                            broker_runtime.win32security,
                            "ConvertSidToStringSid", side_effect=lambda value: value):
                    broker_runtime._verify_protected_bundle_path(
                        path, OWNER_SID, directory=False
                    )

            verify_with(read_execute)
            with self.assertRaises(PermissionError):
                verify_with(
                    read_execute | broker_runtime.ntsecuritycon.FILE_WRITE_DATA
                )

    def test_install_versions_the_complete_bundle_not_only_the_executable(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            source = base / "source"
            static = source / "_internal" / "static"
            static.mkdir(parents=True)
            executable = source / "LocalOps.exe"
            executable.write_bytes(b"same executable")
            asset = static / "app.js"
            asset.write_text("const version = 1;", encoding="utf-8")
            bundle_archive = base / "bundle.zip"

            def write_archive():
                bundle_archive.unlink(missing_ok=True)
                with zipfile.ZipFile(
                        bundle_archive, "x", compression=zipfile.ZIP_DEFLATED
                        ) as archive:
                    archive.write(executable, "LocalOps.exe")
                    archive.write(asset, "_internal/static/app.js")

            write_archive()
            broker_root = base / "ProgramFiles" / "LocalOps" / "Broker"
            program_data = base / "ProgramData" / "LocalOps"
            request = {
                "schema": "localops-elevation-install.v1",
                "ownerSid": OWNER_SID,
                "passwordRecord": {"verifier": "opaque"},
                "bundleArchive": str(bundle_archive),
                "bundleSha256": hashlib.sha256(
                    bundle_archive.read_bytes()
                ).hexdigest(),
                "executableName": "LocalOps.exe",
            }
            registered = []
            protect_bundle = mock.Mock()
            verify_bundle = mock.Mock()
            write_config = mock.Mock()

            def task_spec(path, owner_sid):
                return {
                    "ownerSid": owner_sid,
                    "executable": path,
                    "arguments": "-m localops.windows.elevation_broker serve",
                    "workingDirectory": str(Path(path).parent),
                    "sddl": "D:P(A;;FA;;;SY)",
                }

            patches = (
                mock.patch.object(broker_runtime.sys, "frozen", True, create=True),
                mock.patch.object(broker_runtime.sys, "executable", str(executable)),
                mock.patch.object(
                    broker_runtime, "_program_files_broker_dir",
                    return_value=broker_root,
                ),
                mock.patch.object(
                    broker_runtime, "_program_data_dir",
                    return_value=program_data,
                ),
                mock.patch.object(
                    broker_runtime, "_protect_bundle",
                    side_effect=protect_bundle,
                ),
                mock.patch.object(
                    broker_runtime, "_verify_protected_bundle",
                    side_effect=verify_bundle,
                ),
                mock.patch.object(broker_runtime, "_protect_path"),
                mock.patch.object(broker_runtime, "_verify_broker_data_ancestors"),
                mock.patch.object(broker_runtime, "_verify_broker_public_directory"),
                mock.patch.object(
                    broker_runtime, "_write_json", side_effect=write_config
                ),
                mock.patch.object(broker_runtime, "_load_capability_registry"),
                mock.patch.object(
                    broker_runtime, "_register_task",
                    side_effect=lambda spec: registered.append(spec),
                ),
                mock.patch.object(
                    broker_runtime, "broker_task_spec", side_effect=task_spec,
                ),
                mock.patch.object(
                    broker_runtime, "_broker_task_state",
                    return_value=(False, False),
                ),
                mock.patch.object(broker_runtime, "_write_install_marker"),
                mock.patch.object(broker_runtime, "_clear_install_marker"),
            )
            with patches[0], patches[1], patches[2], patches[3], \
                    patches[4], patches[5], patches[6], patches[7], \
                    patches[8], patches[9], patches[10], patches[11], \
                    patches[12], patches[13], patches[14], patches[15]:
                broker_runtime.install(request)
                first_target = Path(registered[-1]["workingDirectory"])
                self.assertEqual(
                    (first_target / "_internal" / "static" / "app.js")
                    .read_text(encoding="utf-8"),
                    "const version = 1;",
                )

                asset.write_text("const version = 2;", encoding="utf-8")
                write_archive()
                request["bundleSha256"] = hashlib.sha256(
                    bundle_archive.read_bytes()
                ).hexdigest()
                broker_runtime.install(request)
                second_target = Path(registered[-1]["workingDirectory"])

                registered.clear()
                protect_bundle.reset_mock()
                write_config.reset_mock()
                verify_bundle.side_effect = PermissionError(
                    "existing target ACL is not trusted"
                )
                with self.assertRaisesRegex(PermissionError, "not trusted"):
                    broker_runtime.install(request)
                self.assertEqual(registered, [])
                write_config.assert_not_called()
                self.assertTrue(protect_bundle.called)
                self.assertTrue(all(
                    Path(call.args[0]).name.startswith(".install-")
                    for call in protect_bundle.call_args_list
                ))

                verify_bundle.side_effect = None
                protect_bundle.side_effect = PermissionError(
                    "staging ACL readback failed"
                )
                protect_bundle.reset_mock()
                write_config.reset_mock()
                asset.write_text("const version = 3;", encoding="utf-8")
                write_archive()
                request["bundleSha256"] = hashlib.sha256(
                    bundle_archive.read_bytes()
                ).hexdigest()
                with self.assertRaisesRegex(PermissionError, "readback"):
                    broker_runtime.install(request)
                write_config.assert_not_called()
                self.assertEqual(registered, [])
                self.assertEqual(
                    list(broker_root.glob(".install-*")), []
                )

            self.assertNotEqual(first_target, second_target)
            self.assertEqual(
                (second_target / "_internal" / "static" / "app.js")
                .read_text(encoding="utf-8"),
                "const version = 2;",
            )
            self.assertEqual(
                (first_target / "LocalOps.exe").read_bytes(),
                (second_target / "LocalOps.exe").read_bytes(),
            )

    def test_late_install_failures_restore_records_and_previous_task(self):
        previous = {
            "dataExists": True,
            "capabilityExists": True,
            "public": {"executable": r"C:\Program Files\LocalOps\old.exe"},
            "secret": {"passwordRecord": {"verifier": "old"}},
            "capabilityKey": b"k" * 32,
            "capabilityRegistry": {"schema": "registry"},
        }
        new_public = {"executable": r"C:\Program Files\LocalOps\new.exe"}
        new_secret = {"passwordRecord": {"verifier": "new"}}
        new_spec = {"executable": new_public["executable"]}

        for failure in ("public", "secret", "capability", "task"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as root:
                data_dir = Path(root) / "ProgramData" / "LocalOps"
                data_dir.mkdir(parents=True)
                write_count = 0
                register_count = 0
                events = []

                def write_json(*_args, **_kwargs):
                    nonlocal write_count
                    write_count += 1
                    if ((failure == "public" and write_count == 1)
                            or (failure == "secret" and write_count == 2)):
                        raise OSError(failure)

                def load_capability(*_args, **_kwargs):
                    if failure == "capability":
                        raise OSError(failure)
                    return b"k" * 32, "id", 0, {}

                def register_task(_spec):
                    nonlocal register_count
                    register_count += 1
                    events.append(
                        "register-new" if register_count == 1 else "register-old"
                    )
                    if failure == "task" and register_count == 1:
                        raise OSError(failure)

                rollback = mock.Mock(side_effect=lambda *_args: events.append("records"))
                run_previous = mock.Mock(side_effect=lambda: events.append("run"))
                with mock.patch.object(
                        broker_runtime, "_capture_install_records",
                        return_value=previous), mock.patch.object(
                            broker_runtime, "_broker_task_state",
                            return_value=(True, True)), mock.patch.object(
                                broker_runtime, "_program_data_dir",
                                return_value=data_dir), mock.patch.object(
                                    broker_runtime,
                                    "_verify_broker_data_ancestors"), \
                        mock.patch.object(
                            broker_runtime, "_verify_broker_public_directory"), \
                        mock.patch.object(
                            broker_runtime, "_write_json",
                            side_effect=write_json), mock.patch.object(
                                broker_runtime, "_load_capability_registry",
                                side_effect=load_capability), mock.patch.object(
                                    broker_runtime, "_register_task",
                                    side_effect=register_task), mock.patch.object(
                                        broker_runtime, "broker_task_spec",
                                        return_value={"executable": previous["public"]["executable"]}), \
                        mock.patch.object(
                            broker_runtime, "_run_broker_task",
                            side_effect=run_previous), mock.patch.object(
                                broker_runtime, "_rollback_install_records",
                                side_effect=rollback), mock.patch.object(
                                    broker_runtime, "_write_install_marker",
                                    side_effect=lambda *_args: events.append("marker")), \
                        mock.patch.object(
                            broker_runtime, "_clear_install_marker",
                            side_effect=lambda: events.append("clear")), \
                        mock.patch.object(
                            broker_runtime, "_stop_broker_task",
                            side_effect=lambda: events.append("stop")), \
                        mock.patch.object(
                            broker_runtime, "_cleanup_new_data_directory",
                            side_effect=lambda *_args: events.append("cleanup")):
                    with self.assertRaisesRegex(OSError, failure):
                        broker_runtime._commit_install_state(
                            OWNER_SID, new_public, new_secret, new_spec
                        )

                rollback.assert_called_once_with(previous, OWNER_SID)
                if failure == "task":
                    self.assertEqual(register_count, 2)
                    self.assertLess(events.index("records"), events.index("register-old"))
                else:
                    self.assertEqual(register_count, 0)
                self.assertLess(events.index("records"), events.index("clear"))
                self.assertLess(events.index("clear"), events.index("run"))
                run_previous.assert_called_once_with()

    def test_rollback_failure_keeps_marker_and_never_restarts_broker(self):
        previous = {
            "dataExists": True,
            "capabilityExists": True,
            "public": {"executable": r"C:\Program Files\LocalOps\old.exe"},
            "secret": {},
            "capabilityKey": b"k" * 32,
            "capabilityRegistry": {},
        }
        marker_statuses = []
        stop = mock.Mock()
        clear = mock.Mock()
        run = mock.Mock()
        register_count = 0

        def register(_spec):
            nonlocal register_count
            register_count += 1
            raise OSError("new task" if register_count == 1 else "old task")

        with tempfile.TemporaryDirectory() as root:
            data_dir = Path(root) / "ProgramData" / "LocalOps"
            data_dir.mkdir(parents=True)
            with mock.patch.object(
                    broker_runtime, "_capture_install_records",
                    return_value=previous), mock.patch.object(
                        broker_runtime, "_broker_task_state",
                        return_value=(True, True)), mock.patch.object(
                            broker_runtime, "_program_data_dir",
                            return_value=data_dir), mock.patch.object(
                                broker_runtime, "_verify_broker_data_ancestors"), \
                    mock.patch.object(
                        broker_runtime, "_verify_broker_public_directory"), \
                    mock.patch.object(broker_runtime, "_write_json"), \
                    mock.patch.object(
                        broker_runtime, "_load_capability_registry",
                        return_value=(b"k" * 32, "id", 0, {})), \
                    mock.patch.object(
                        broker_runtime, "_register_task", side_effect=register), \
                    mock.patch.object(
                        broker_runtime, "broker_task_spec", return_value={}), \
                    mock.patch.object(
                        broker_runtime, "_rollback_install_records",
                        side_effect=OSError("records")), mock.patch.object(
                            broker_runtime, "_write_install_marker",
                            side_effect=lambda _owner, _spec, status: marker_statuses.append(status)), \
                    mock.patch.object(
                        broker_runtime, "_clear_install_marker",
                        side_effect=clear), mock.patch.object(
                            broker_runtime, "_stop_broker_task",
                            side_effect=stop), mock.patch.object(
                                broker_runtime, "_run_broker_task",
                                side_effect=run):
                with self.assertRaisesRegex(OSError, "rollback failed"):
                    broker_runtime._commit_install_state(
                        OWNER_SID, {"executable": "new"}, {}, {"executable": "new"}
                    )

        self.assertEqual(marker_statuses, ["in_progress", "rollback_failed"])
        self.assertGreaterEqual(stop.call_count, 2)
        clear.assert_not_called()
        run.assert_not_called()

    def test_install_repairs_missing_task_when_public_record_exists(self):
        previous = {
            "dataExists": True,
            "capabilityExists": True,
            "public": {"executable": r"C:\Program Files\LocalOps\old.exe"},
            "secret": {},
            "capabilityKey": b"k" * 32,
            "capabilityRegistry": {},
        }
        register = mock.Mock()
        stop = mock.Mock()
        run = mock.Mock()
        with tempfile.TemporaryDirectory() as root:
            data_dir = Path(root) / "ProgramData" / "LocalOps"
            data_dir.mkdir(parents=True)
            with mock.patch.object(
                    broker_runtime, "_capture_install_records",
                    return_value=previous), mock.patch.object(
                        broker_runtime, "_broker_task_state",
                        return_value=(False, False)), mock.patch.object(
                            broker_runtime, "_program_data_dir",
                            return_value=data_dir), mock.patch.object(
                                broker_runtime, "_verify_broker_data_ancestors"), \
                    mock.patch.object(
                        broker_runtime, "_verify_broker_public_directory"), \
                    mock.patch.object(broker_runtime, "_write_json"), \
                    mock.patch.object(
                        broker_runtime, "_load_capability_registry",
                        return_value=(b"k" * 32, "id", 0, {})), \
                    mock.patch.object(
                        broker_runtime, "_register_task", side_effect=register), \
                    mock.patch.object(broker_runtime, "_write_install_marker"), \
                    mock.patch.object(broker_runtime, "_clear_install_marker"), \
                    mock.patch.object(
                        broker_runtime, "_stop_broker_task", side_effect=stop), \
                    mock.patch.object(
                        broker_runtime, "_run_broker_task", side_effect=run):
                broker_runtime._commit_install_state(
                    OWNER_SID, {"executable": "new"}, {}, {"executable": "new"}
                )

        register.assert_called_once_with({"executable": "new"})
        stop.assert_not_called()
        run.assert_not_called()

    def test_record_rollback_restores_existing_capability_state(self):
        previous = {
            "dataExists": True,
            "capabilityExists": True,
            "public": {"schema": "public"},
            "secret": {"schema": "secret"},
            "capabilityKey": b"k" * 32,
            "capabilityRegistry": {"schema": "registry"},
        }
        write_json = mock.Mock()
        write_key = mock.Mock()
        validate = mock.Mock()
        with mock.patch.object(
                broker_runtime, "_write_json", side_effect=write_json), \
                mock.patch.object(
                    broker_runtime, "_write_secret_bytes", side_effect=write_key), \
                mock.patch.object(
                    broker_runtime, "_load_capability_registry",
                    side_effect=validate):
            broker_runtime._rollback_install_records(previous, OWNER_SID)

        self.assertEqual(write_json.call_count, 3)
        write_key.assert_called_once_with(
            broker_runtime.capability_key_path(), b"k" * 32, OWNER_SID
        )
        validate.assert_called_once_with(OWNER_SID, create=False)

    def test_record_rollback_removes_new_install_state(self):
        with tempfile.TemporaryDirectory() as root:
            data_dir = Path(root) / "ProgramData" / "LocalOps"
            capability = data_dir / "capabilities"
            capability.mkdir(parents=True)
            public = data_dir / "elevation-broker.json"
            secret = data_dir / "elevation-password.json"
            key = capability / "key.bin"
            registry = capability / "grants.json"
            for path in (public, secret, key, registry):
                path.write_bytes(b"record")
            state = {
                "dataExists": False,
                "capabilityExists": False,
                "public": None,
                "secret": None,
                "capabilityKey": None,
                "capabilityRegistry": None,
            }
            with mock.patch.object(
                    broker_runtime, "_program_data_dir",
                    return_value=data_dir), mock.patch.object(
                        broker_runtime, "_verify_broker_public_file"), \
                    mock.patch.object(
                        broker_runtime, "_verify_broker_public_directory"), \
                    mock.patch.object(
                        broker_runtime, "_verify_broker_only_path"), \
                    mock.patch.object(
                        broker_runtime, "_cleanup_capability_temporaries"):
                broker_runtime._rollback_install_records(state, OWNER_SID)
                broker_runtime._cleanup_new_data_directory(state, OWNER_SID)

            self.assertFalse(data_dir.exists())

    def test_broker_serve_refuses_incomplete_install_marker(self):
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "elevation-install-incomplete.json"
            marker.write_text("{}", encoding="utf-8")
            verify = mock.Mock()
            with mock.patch.object(
                    broker_runtime, "install_incomplete_path",
                    return_value=marker), mock.patch.object(
                        broker_runtime, "_verify_broker_data_ancestors"), \
                    mock.patch.object(
                        broker_runtime, "_verify_broker_only_path",
                        side_effect=verify):
                result = broker_runtime.serve()

        self.assertEqual(result, 3)
        verify.assert_called_once_with(marker, directory=False)

    def test_running_broker_rejects_next_request_when_marker_appears(self):
        pipe = object()
        write = mock.Mock()
        flush = mock.Mock()
        with mock.patch.object(
                broker_runtime, "_runtime_install_blocked",
                return_value=True), mock.patch.object(
                    broker_runtime.win32file, "WriteFile",
                    side_effect=write), mock.patch.object(
                        broker_runtime.win32file, "FlushFileBuffers",
                        side_effect=flush):
            rejected = broker_runtime._reject_incomplete_install_request(pipe)

        self.assertTrue(rejected)
        payload = broker_runtime.decode_message(bytes(write.call_args.args[1]))
        self.assertEqual(payload["code"], "BROKER_INSTALL_INCOMPLETE")
        flush.assert_called_once_with(pipe)

    def test_restart_failure_leaves_restored_old_task_stopped(self):
        previous = {
            "dataExists": True,
            "capabilityExists": True,
            "public": {"executable": r"C:\Program Files\LocalOps\old.exe"},
            "secret": {},
            "capabilityKey": b"k" * 32,
            "capabilityRegistry": {},
        }
        marker_statuses = []
        clear = mock.Mock()
        stop = mock.Mock()
        disable = mock.Mock()
        with tempfile.TemporaryDirectory() as root:
            data_dir = Path(root) / "ProgramData" / "LocalOps"
            data_dir.mkdir(parents=True)
            with mock.patch.object(
                    broker_runtime, "_capture_install_records",
                    return_value=previous), mock.patch.object(
                        broker_runtime, "_broker_task_state",
                        return_value=(True, True)), mock.patch.object(
                            broker_runtime, "_program_data_dir",
                            return_value=data_dir), mock.patch.object(
                                broker_runtime, "_verify_broker_data_ancestors"), \
                    mock.patch.object(
                        broker_runtime, "_verify_broker_public_directory"), \
                    mock.patch.object(
                        broker_runtime, "_write_json",
                        side_effect=OSError("public")), mock.patch.object(
                            broker_runtime, "_write_install_marker",
                            side_effect=lambda _owner, _spec, status: marker_statuses.append(status)), \
                    mock.patch.object(
                        broker_runtime, "_clear_install_marker",
                        side_effect=clear), mock.patch.object(
                            broker_runtime, "_stop_broker_task",
                            side_effect=stop), mock.patch.object(
                                broker_runtime, "_disable_broker_task",
                                side_effect=disable), mock.patch.object(
                                broker_runtime, "_rollback_install_records"), \
                    mock.patch.object(
                        broker_runtime, "_cleanup_new_data_directory"), \
                    mock.patch.object(
                        broker_runtime, "_run_broker_task",
                        side_effect=OSError("restart")):
                with self.assertRaisesRegex(OSError, "restored.*restart"):
                    broker_runtime._commit_install_state(
                        OWNER_SID, {"executable": "new"}, {}, {"executable": "new"}
                    )

        self.assertEqual(marker_statuses, ["in_progress"])
        clear.assert_called_once_with()
        stop.assert_called_once_with()
        disable.assert_called_once_with()

    def test_task_upgrade_stops_the_previous_broker_instance(self):
        service = mock.Mock()
        folder = mock.Mock()
        definition = mock.Mock()
        action = mock.Mock()
        registered = mock.Mock()
        registered.State = 4
        registered.Stop.side_effect = lambda _flags: setattr(
            registered, "State", 3
        )
        service.GetFolder.return_value = folder
        service.NewTask.return_value = definition
        definition.Actions.Create.return_value = action
        folder.RegisterTaskDefinition.return_value = registered

        with mock.patch.object(
                broker_runtime.win32com.client, "Dispatch",
                return_value=service):
            broker_runtime._register_task({
                "ownerSid": OWNER_SID,
                "executable": r"C:\Program Files\LocalOps\Broker\v2\LocalOps.exe",
                "arguments": "-m localops.windows.elevation_broker serve",
                "workingDirectory": r"C:\Program Files\LocalOps\Broker\v2",
                "sddl": "D:P(A;;FA;;;SY)",
            })

        registered.Stop.assert_called_once_with(0)

    def test_restart_failure_guard_disables_registered_broker_task(self):
        service = mock.Mock()
        folder = mock.Mock()
        registered = mock.Mock()
        registered.State = 4
        registered.Stop.side_effect = lambda _flags: setattr(
            registered, "State", 3
        )
        service.GetFolder.return_value = folder
        folder.GetTask.return_value = registered

        with mock.patch.object(
                broker_runtime.win32com.client, "Dispatch",
                return_value=service):
            broker_runtime._disable_broker_task()

        registered.Stop.assert_called_once_with(0)
        self.assertFalse(registered.Enabled)

    def test_elevated_helper_rejects_a_modified_install_transaction(self):
        request = {
            "schema": "localops-elevation-install.v1",
            "ownerSid": OWNER_SID,
            "passwordRecord": {"verifier": "opaque"},
            "bundleArchive": r"C:\\Local Ops\\bundle.zip",
            "bundleSha256": "a" * 64,
            "executableName": "LocalOps.exe",
        }
        digest = broker_install_request_digest(request)
        request["ownerSid"] = "S-1-5-21-9-9-9-1001"

        with mock.patch.object(broker_runtime, "_validate_install_paths"), \
                mock.patch.object(broker_runtime, "_read_json", return_value=request), \
                mock.patch.object(broker_runtime, "install") as install, \
                mock.patch.object(broker_runtime, "_write_install_response"):
            result = broker_runtime.main([
                "install", "request.json", "response.json", digest,
            ])

        self.assertEqual(result, 1)
        install.assert_not_called()


if __name__ == "__main__":
    unittest.main()

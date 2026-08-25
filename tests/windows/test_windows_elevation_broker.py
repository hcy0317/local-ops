import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import server
from localops.elevation_broker import broker_install_request_digest
from localops.command_spec import direct_command_spec
from localops.platform.contracts import (
    ElevationBrokerResult,
    ElevationBrokerStatus,
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
    def _scheduled_task_row(*, security_locked=True):
        return {
            "path": r"\Memos-Guard",
            "state": "ready",
            "enabled": True,
            "principalSid": OWNER_SID,
            "runLevel": "highest",
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

    def test_scheduled_grant_rejects_user_writable_security_descriptor(self):
        with self.assertRaises(ValueError):
            broker_runtime._task_security_record(
                self._scheduled_task_row(security_locked=False)
            )

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
            broker_runtime._task_security_record(task)
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

    def test_elevated_helper_rejects_a_modified_install_transaction(self):
        request = {
            "schema": "localops-elevation-install.v1",
            "ownerSid": OWNER_SID,
            "passwordRecord": {"verifier": "opaque"},
            "bundleSource": r"C:\\Local Ops",
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

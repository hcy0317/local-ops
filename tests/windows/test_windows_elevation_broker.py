import sys
import tempfile
import unittest
from unittest import mock

import server
from localops.elevation_broker import broker_install_request_digest
from localops.command_spec import direct_command_spec
from localops.platform.contracts import (
    ElevationBrokerResult,
    ElevationBrokerStatus,
    PlatformCapabilities,
    Principal,
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

    def test_install_derives_password_verifier_before_platform_boundary(self):
        password = "correct horse battery staple"
        package_executable = r"C:\Local Ops\LocalOps.exe"
        status, body, _ = self.harness.request(
            "POST", "/api/windows/elevation-broker/install",
            {
                "password": password,
                "packageExecutable": package_executable,
            }, self.headers,
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        call = self.platform.calls[-1]
        self.assertEqual(call[0], "install_elevation_broker")
        password_record, selected_executable = call[1]
        self.assertNotIn(password, repr(password_record))
        self.assertIn("verifier", password_record)
        self.assertEqual(selected_executable, package_executable)

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

    def test_install_rejects_non_string_package_executable(self):
        status, body, _ = self.harness.request(
            "POST", "/api/windows/elevation-broker/install",
            {
                "password": "correct horse battery staple",
                "packageExecutable": 42,
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

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["pid"], 4321)
        self.assertIn((
            "launch_elevated", (program_app()["commandSpec"], r"C:\Tools"),
        ), self.platform.calls)

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


@unittest.skipUnless(sys.platform == "win32", "Windows installer helper only")
class ElevationBrokerInstallerTests(unittest.TestCase):
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

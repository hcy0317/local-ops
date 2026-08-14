import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import server
from localops.command_spec import direct_command_spec
from localops.platform.contracts import PickResult, PlatformIssue


class HttpHarness:
    def __init__(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cfg = server.Config(os.path.join(self.temp_dir.name, "config.json"))
        self.httpd = server.ConsoleServer(
            (server.HOST, 0), server.Handler, self.cfg, 0
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.temp_dir.cleanup()

    def request(self, method, path, payload=None, headers=None):
        body = None if payload is None else json.dumps(payload)
        conn = http.client.HTTPConnection(server.HOST, self.port, timeout=4)
        conn.request(method, path, body=body, headers=dict(headers or {}))
        response = conn.getresponse()
        result = json.loads(response.read().decode("utf-8"))
        response_headers = dict(response.getheaders())
        status = response.status
        conn.close()
        return status, result, response_headers

    def session_headers(self):
        status, _, headers = self.request("GET", "/api/state")
        if status != 200:
            raise AssertionError("cannot establish local session")
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        return {
            "Content-Type": "application/json",
            "Cookie": cookie,
            "Origin": "http://127.0.0.1:%d" % self.port,
            "Sec-Fetch-Site": "same-origin",
        }


@unittest.skipUnless(sys.platform == "win32", "Windows-only server tests")
class WindowsServerTests(unittest.TestCase):
    def setUp(self):
        self.harness = HttpHarness()
        self.headers = self.harness.session_headers()

    def tearDown(self):
        self.harness.close()

    def test_state_exposes_owned_job_lifecycle_capabilities(self):
        status, state, _ = self.harness.request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(state["platform"], "windows")
        self.assertTrue(state["capabilities"]["monitor_processes"])
        for capability in (
                "launch_managed", "stop_managed", "force_stop_managed"):
            self.assertTrue(state["capabilities"][capability])
        for capability in (
                "kill_external", "attach_external", "restart_console"):
            self.assertFalse(state["capabilities"][capability])

    def test_phase3_path_routes_use_stable_error_codes(self):
        status, body, _ = self.harness.request(
            "POST", "/api/project/detect", {"cwd": ""}, self.headers
        )
        self.assertEqual((status, body["code"]), (400, "INVALID_PATH"))

        issue = PlatformIssue("picker", "os_error", "sensitive detail")
        with mock.patch.object(
                server.PLATFORM, "pick_path",
                return_value=PickResult(issue=issue)):
            status, body, _ = self.harness.request(
                "POST", "/api/pick", {"what": "dir"}, self.headers
            )
        self.assertEqual((status, body["code"]), (500, "PICKER_UNAVAILABLE"))
        self.assertNotIn("sensitive detail", body["error"])

    def test_create_and_cwd_update_derive_import_status(self):
        runtime = os.path.join(self.harness.temp_dir.name, "runner.exe")
        with open(runtime, "wb") as handle:
            handle.write(b"static preflight only")
        payload = {
            "name": "Structured app",
            "command": runtime,
            "commandSpec": direct_command_spec(runtime),
            "cwd": self.harness.temp_dir.name,
            "port": None,
            "kind": "service",
        }
        status, created, _ = self.harness.request(
            "POST", "/api/apps", payload, self.headers
        )
        self.assertEqual(status, 200)
        self.assertEqual(created["importStatus"], "ready")

        missing_cwd = os.path.join(self.harness.temp_dir.name, "missing")
        status, updated, _ = self.harness.request(
            "PUT", "/api/apps/%s" % created["id"],
            {"cwd": missing_cwd, "expectedGeneration": None}, self.headers
        )
        self.assertEqual(status, 200)
        self.assertEqual(updated["importStatus"], "blocked")

    def test_config_import_http_preview_commit_and_rollback(self):
        source_root = "/Volumes/Workspace/Projects"
        target_root = self.harness.temp_dir.name
        mapped_cwd = os.path.join(target_root, "demo")
        os.mkdir(mapped_cwd)
        source_path = os.path.join(target_root, "macos-config.json")
        source = {
            "schemaVersion": 1,
            "apps": [{
                "id": "deadbeef",
                "name": "Imported demo",
                "command": "python3 app.py",
                "cwd": source_root + "/demo",
                "port": 8000,
                "kind": "service",
                "lastPid": 123,
                "lastPgid": 123,
                "runToken": "must-be-cleared",
                "attached": True,
            }],
        }
        with open(source_path, "w", encoding="utf-8") as handle:
            json.dump(source, handle)
        payload = {
            "sourcePath": source_path,
            "pathMappings": [{
                "sourceRoot": source_root,
                "targetRoot": target_root,
            }],
        }
        records_dir = os.path.join(target_root, "imports")
        with mock.patch.object(server, "IMPORT_RECORDS_DIR", records_dir):
            status, preview, _ = self.harness.request(
                "POST", "/api/config/import/preview", payload, self.headers
            )
            self.assertEqual(status, 200)
            self.assertFalse(os.path.exists(records_dir))
            self.assertEqual(preview["apps"][0]["status"], "needs_review")
            self.assertEqual(preview["apps"][0]["cwd"], mapped_cwd)

            status, committed, _ = self.harness.request(
                "POST",
                "/api/config/import/commit",
                {
                    **payload,
                    "previewId": preview["previewId"],
                    "selectedAppIds": ["deadbeef"],
                },
                self.headers,
            )
            self.assertEqual(status, 200)
            imported = self.harness.cfg.snapshot()["apps"][0]
            self.assertEqual(imported["cwd"], mapped_cwd)
            self.assertEqual(imported["importStatus"], "needs_review")
            self.assertIsNone(imported["lastPid"])
            self.assertIsNone(imported["lastPgid"])
            self.assertIsNone(imported["runToken"])
            self.assertFalse(imported["attached"])

            status, rolled_back, _ = self.harness.request(
                "POST",
                "/api/config/import/rollback",
                {"importId": committed["importId"]},
                self.headers,
            )
        self.assertEqual(status, 200)
        self.assertFalse(rolled_back["idempotent"])
        self.assertEqual(self.harness.cfg.snapshot()["apps"], [])

    def test_acl_failure_keeps_configuration_read_only(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
                mock.patch.object(server, "DATA_DIR", temp_dir), \
                mock.patch.object(server, "ICONS_DIR", os.path.join(temp_dir, "icons")), \
                mock.patch.object(server, "LOGS_DIR", os.path.join(temp_dir, "logs")), \
                mock.patch.object(server, "CONFIG_PATH", os.path.join(temp_dir, "config.json")), \
                mock.patch.object(server, "INSTANCE_LOCK_PATH", os.path.join(temp_dir, "console.lock")), \
                mock.patch.object(
                    server.PLATFORM,
                    "ensure_private_directory",
                    side_effect=PermissionError("denied"),
                ):
            storage = server.prepare_runtime_storage()
            self.assertTrue(storage["securityIssues"])
            config_path = os.path.join(temp_dir, "protected-config.json")
            cfg = server.Config(
                config_path,
                force_read_only_reason=storage["securityIssues"][0],
            )
            self.assertFalse(cfg.health_info()["writable"])
            self.assertFalse(os.path.exists(config_path))
            with self.assertRaises(OSError):
                cfg.update(lambda data: data.__setitem__("uiTheme", "ops"))

    def test_server_socket_uses_exclusive_address_semantics(self):
        value = self.harness.httpd.socket.getsockopt(
            socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE
        )
        self.assertEqual(value, 1)

    def test_external_control_routes_reject_before_process_or_config_side_effects(self):
        app_id = "deadbeef"
        app = dict(server.Config.APP_DEFAULT)
        app.update({
            "id": app_id,
            "name": "Read only app",
            "command": "echo safe",
            "cwd": self.harness.temp_dir.name,
            "port": 9608,
            "kind": "service",
        })
        self.harness.cfg.update(lambda config: config["apps"].append(app))
        before = self.harness.cfg.snapshot()
        with mock.patch.object(server, "kill_process") as kill_process, \
                mock.patch.object(server, "start_app") as start_app, \
                mock.patch.object(server, "attach_app_process") as attach_process, \
                mock.patch.object(server, "stop_app_and_clear") as stop_app, \
                mock.patch.object(server, "schedule_console_stop") as stop_console:
            requests = (
                ("POST", "/api/kill", {"pid": os.getpid()}),
                ("POST", f"/api/apps/{app_id}/attach", {"pid": os.getpid()}),
                ("POST", "/api/apps/facefeed/attach", {"pid": os.getpid()}),
                ("POST", "/api/console/restart", {}),
                ("POST", "/api/console/stop", {}),
            )
            for method, path, payload in requests:
                status, body, _ = self.harness.request(
                    method, path, payload, self.headers
                )
                self.assertEqual(status, 409, path)
                self.assertFalse(body["ok"], path)
            create_payload = {
                "name": "Must not persist",
                "command": "echo no",
                "cwd": self.harness.temp_dir.name,
                "port": 9607,
                "kind": "service",
                "attachPid": os.getpid(),
            }
            status, _, _ = self.harness.request(
                "POST", "/api/apps", create_payload, self.headers
            )
            self.assertEqual(status, 409)
        kill_process.assert_not_called()
        start_app.assert_not_called()
        attach_process.assert_not_called()
        stop_app.assert_not_called()
        stop_console.assert_not_called()
        self.assertEqual(self.harness.cfg.snapshot(), before)

    def test_disabled_attach_consumes_body_before_next_keep_alive_request(self):
        conn = http.client.HTTPConnection(server.HOST, self.harness.port, timeout=4)
        try:
            conn.request(
                "POST",
                "/api/apps/facefeed/attach",
                body=json.dumps({"pid": os.getpid()}),
                headers=self.headers,
            )
            response = conn.getresponse()
            self.assertEqual(response.status, 409)
            self.assertFalse(json.loads(response.read().decode("utf-8"))["ok"])

            conn.request(
                "POST",
                "/api/console/restart",
                body="{}",
                headers=self.headers,
            )
            response = conn.getresponse()
            self.assertEqual(response.status, 409)
            self.assertFalse(json.loads(response.read().decode("utf-8"))["ok"])
        finally:
            conn.close()

    def test_legacy_observation_never_triggers_windows_process_control(self):
        delete_id = "cafebabe"
        update_id = "facefeed"
        delete_app = dict(server.Config.APP_DEFAULT)
        delete_app.update({
            "id": delete_id,
            "name": "Delete stopped app",
            "command": "echo old",
            "cwd": self.harness.temp_dir.name,
            "port": 9606,
            "kind": "service",
        })
        update_app = {
            **delete_app,
            "id": update_id,
            "name": "Update stopped app",
            "port": 9607,
        }
        self.harness.cfg.update(
            lambda config: config["apps"].extend([delete_app, update_app])
        )
        updated_cwd = os.path.join(self.harness.temp_dir.name, "updated")
        os.mkdir(updated_cwd)
        with mock.patch.object(server, "app_running", return_value=True), \
                mock.patch.object(server, "app_alive_sign", return_value=True), \
                mock.patch.object(server, "stop_app_and_clear") as stop_app, \
                mock.patch.object(server, "stop_app_for_update") as stop_update:
            status, _, _ = self.harness.request(
                "DELETE", f"/api/apps/{delete_id}",
                {"expectedGeneration": None}, self.headers
            )
            self.assertEqual(status, 200)
            status, updated, _ = self.harness.request(
                "PUT",
                f"/api/apps/{update_id}",
                {"cwd": updated_cwd, "stopBeforeUpdate": True,
                 "expectedGeneration": None},
                self.headers,
            )
            self.assertEqual(status, 200)
            self.assertEqual(updated["cwd"], updated_cwd)
        stop_app.assert_not_called()
        stop_update.assert_not_called()
        apps = self.harness.cfg.snapshot()["apps"]
        self.assertEqual([app["id"] for app in apps], [update_id])
        self.assertIsNone(apps[0]["runtimeIdentity"])


class WindowsCiWorkflowTests(unittest.TestCase):
    def test_test_groups_are_separate_fail_fast_steps(self):
        workflow_path = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
        workflow = workflow_path.read_text(encoding="utf-8").replace("\r\n", "\n")
        windows_job = workflow.split("  windows-read-only:\n", 1)[1].split(
            "\n  check-and-release:\n", 1
        )[0]
        commands = (
            'run: python -m unittest discover -s tests/windows -p "test_*.py" -v',
            'run: python -m unittest discover -s tests/contract -p "test_*.py" -v',
            "run: python -m unittest tests.test_frontend "
            "tests.test_hardening.HttpSecurityTests -v",
        )
        self.assertEqual(windows_job.count("python -m unittest"), len(commands))
        for command in commands:
            self.assertIn(command, windows_job)
        self.assertNotIn("continue-on-error", windows_job)


if __name__ == "__main__":
    unittest.main()

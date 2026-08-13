import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

import server


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

    def test_state_exposes_read_only_capabilities(self):
        status, state, _ = self.harness.request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(state["platform"], "windows")
        self.assertTrue(state["capabilities"]["monitor_processes"])
        for capability in (
                "launch_managed", "stop_managed", "force_stop_managed",
                "kill_external", "attach_external", "restart_console"):
            self.assertFalse(state["capabilities"][capability])

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

    def test_destructive_routes_reject_before_process_or_config_side_effects(self):
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
                mock.patch.object(server, "stop_app_and_clear") as stop_app:
            requests = (
                ("POST", "/api/kill", {"pid": os.getpid()}),
                ("POST", f"/api/apps/{app_id}/start", {}),
                ("POST", f"/api/apps/{app_id}/stop", {}),
                ("POST", f"/api/apps/{app_id}/restart", {}),
                ("POST", f"/api/apps/{app_id}/attach", {"pid": os.getpid()}),
                ("POST", "/api/console/restart", {}),
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
        self.assertEqual(self.harness.cfg.snapshot(), before)

    def test_running_delete_and_update_do_not_stop_processes(self):
        app_id = "cafebabe"
        app = dict(server.Config.APP_DEFAULT)
        app.update({
            "id": app_id,
            "name": "Running app",
            "command": "echo old",
            "cwd": self.harness.temp_dir.name,
            "port": 9606,
            "kind": "service",
        })
        self.harness.cfg.update(lambda config: config["apps"].append(app))
        before = self.harness.cfg.snapshot()
        with mock.patch.object(server, "app_running", return_value=True), \
                mock.patch.object(server, "app_alive_sign", return_value=True), \
                mock.patch.object(server, "stop_app_and_clear") as stop_app, \
                mock.patch.object(server, "stop_app_for_update") as stop_update:
            status, _, _ = self.harness.request(
                "DELETE", f"/api/apps/{app_id}", None, self.headers
            )
            self.assertEqual(status, 409)
            status, _, _ = self.harness.request(
                "PUT",
                f"/api/apps/{app_id}",
                {"command": "echo new", "stopBeforeUpdate": True},
                self.headers,
            )
            self.assertEqual(status, 409)
        stop_app.assert_not_called()
        stop_update.assert_not_called()
        self.assertEqual(self.harness.cfg.snapshot(), before)


if __name__ == "__main__":
    unittest.main()

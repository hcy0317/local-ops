import os
import json
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

import server
from localops.docker_resources import DockerSnapshot
from localops.platform.contracts import PlatformCapabilities, ScanStatus
from localops.platform.fake import FakePlatform
from tests.test_hardening import HttpHarness


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeConsole:
    def __init__(self, cfg, armed=False):
        self.cfg = cfg
        self.armed = armed
        self._lock = threading.Lock()

    def try_app_operation(self, _app_id):
        return self._lock if self._lock.acquire(blocking=False) else None


class KeepAliveSupervisorTests(unittest.TestCase):
    def test_supervisor_thread_starts_and_stops_without_armed_apps(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = server.Config(os.path.join(td, "config.json"))
            supervisor = server.start_keep_alive_supervisor(FakeConsole(cfg))
            try:
                self.assertTrue(supervisor.is_alive())
            finally:
                supervisor.stop()
                supervisor.join(1.0)
            self.assertFalse(supervisor.is_alive())

    def test_read_only_config_never_crosses_process_start_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "config.json")
            payload = dict(server.Config.DEFAULT)
            payload["apps"] = [{
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Managed service",
                "command": "serve",
                "kind": "service",
                "keepAlive": True,
                "desiredRunning": True,
            }]
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            cfg = server.Config(path, force_read_only_reason="test read-only")
            supervisor = server.KeepAliveSupervisor(
                FakeConsole(cfg), clock=FakeClock(), jitter=lambda _delay: 0.0
            )
            platform = SimpleNamespace(name="macos")

            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "start_app") as start:
                supervisor.run_once()

            start.assert_not_called()
            self.assertEqual(supervisor.status("deadbeef")["state"], "blocked")

    def test_failed_start_retries_after_backoff_and_not_before(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = server.Config(os.path.join(td, "config.json"))
            app = {
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Managed service",
                "command": "serve",
                "cwd": td,
                "kind": "service",
                "keepAlive": True,
                "desiredRunning": True,
            }
            cfg.update(lambda data: data["apps"].append(app))
            clock = FakeClock()
            supervisor = server.KeepAliveSupervisor(
                FakeConsole(cfg), clock=clock, jitter=lambda _delay: 0.0
            )
            proc = mock.Mock(pid=43123)
            proc.poll.return_value = None
            starts = [
                (False, "boom", None, None, None),
                (True, None, proc, proc.pid, "token"),
            ]

            platform = SimpleNamespace(name="macos")
            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "managed_pids", return_value=[]), \
                    mock.patch.object(server, "inspect_app_health", return_value={
                        "status": "ok", "blocking": False, "issues": [],
                    }), \
                    mock.patch.object(server, "scan_listeners", return_value=set()), \
                    mock.patch.object(server, "start_app", side_effect=starts) as start, \
                    mock.patch.object(server, "persist_started_app", return_value=True):
                supervisor.run_once()
                supervisor.run_once()
                clock.advance(0.49)
                supervisor.run_once()
                self.assertEqual(start.call_count, 1)
                clock.advance(0.01)
                supervisor.run_once()

            self.assertEqual(start.call_count, 2)
            self.assertEqual(
                supervisor.status("deadbeef")["state"], "starting"
            )

    def test_short_lived_success_enters_backoff_before_relaunch(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = server.Config(os.path.join(td, "config.json"))
            cfg.update(lambda data: data["apps"].append({
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Crash loop",
                "command": "serve",
                "cwd": td,
                "kind": "service",
                "keepAlive": True,
                "desiredRunning": True,
            }))
            clock = FakeClock()
            supervisor = server.KeepAliveSupervisor(
                FakeConsole(cfg), clock=clock, jitter=lambda _delay: 0.0
            )
            proc = mock.Mock(pid=43123)
            proc.poll.return_value = None
            platform = SimpleNamespace(name="macos")
            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "managed_pids", return_value=[]), \
                    mock.patch.object(server, "inspect_app_health", return_value={
                        "status": "ok", "blocking": False, "issues": [],
                    }), \
                    mock.patch.object(server, "scan_listeners", return_value=set()), \
                    mock.patch.object(
                        server, "start_app",
                        return_value=(True, None, proc, proc.pid, "token"),
                    ) as start, \
                    mock.patch.object(server, "persist_started_app", return_value=True):
                supervisor.run_once()
                clock.advance(1.0)
                supervisor.run_once()
                self.assertEqual(start.call_count, 1)
                self.assertEqual(
                    supervisor.status("deadbeef")["state"], "backoff"
                )
                clock.advance(0.5)
                supervisor.run_once()

            self.assertEqual(start.call_count, 2)

    def test_armed_service_scheduled_task_restarts_only_through_exact_task_api(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = server.Config(os.path.join(td, "config.json"))
            app = {
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Long-running scheduled service",
                "command": "scheduled-task",
                "kind": "service",
                "scheduledTaskPath": r"\LocalOps\LongRunning",
                "keepAlive": True,
                "desiredRunning": True,
                "keepAliveGrant": {
                    "version": 1,
                    "grantId": "scheduled-grant-0001",
                    "kind": "scheduledService",
                    "bindingDigest": "sha256:" + "a" * 64,
                },
            }
            app["keepAliveGrant"]["configDigest"] = (
                server.keep_alive_config_digest(app)
            )
            cfg.update(lambda data: data["apps"].append(app))
            supervisor = server.KeepAliveSupervisor(
                FakeConsole(cfg, armed=True),
                clock=FakeClock(), jitter=lambda _delay: 0.0,
            )
            grant_use = mock.Mock(side_effect=[{
                "ok": True,
                "leaseId": "scheduled-lease-0001",
                "tasks": {r"\localops\longrunning": {
                    "path": r"\LocalOps\LongRunning",
                    "state": "ready",
                    "enabled": True,
                    "enginePids": [],
                }},
            }, {"ok": True}])
            platform = SimpleNamespace(
                name="windows",
                keep_alive_grant_use=grant_use,
            )

            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "start_scheduled_task_app") as scheduled_start, \
                    mock.patch.object(server, "start_app") as managed_start:
                supervisor.run_once()

            self.assertEqual(grant_use.call_args_list, [
                mock.call(
                    "scheduled-grant-0001", "deadbeef", "sha256:" + "a" * 64,
                    "query",
                ),
                mock.call(
                    "scheduled-grant-0001", "deadbeef", "sha256:" + "a" * 64,
                    "run", "scheduled-lease-0001",
                ),
            ])
            scheduled_start.assert_not_called()
            managed_start.assert_not_called()

    def test_armed_docker_service_restarts_only_its_exact_resource(self):
        with tempfile.TemporaryDirectory() as td:
            container_id = "c" * 64
            resource = {"kind": "container", "containerId": container_id}
            cfg = server.Config(os.path.join(td, "config.json"))
            app = {
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Redis",
                "command": "docker container start " + container_id,
                "kind": "service",
                "dockerResource": resource,
                "keepAlive": True,
                "desiredRunning": True,
            }
            cfg.update(lambda data: data["apps"].append(app))
            supervisor = server.KeepAliveSupervisor(
                FakeConsole(cfg, armed=True),
                clock=FakeClock(), jitter=lambda _delay: 0.0,
            )
            docker = mock.Mock()
            docker.discover.return_value = DockerSnapshot(
                ScanStatus.OK,
                containers=({
                    "id": container_id,
                    "running": False,
                    "state": "exited",
                },),
            )
            docker.inspect.return_value = docker.discover.return_value

            platform = SimpleNamespace(
                name="windows",
                capabilities=PlatformCapabilities(control_docker=True),
            )
            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "DOCKER", docker), \
                    mock.patch.object(
                        server, "control_docker_app", return_value={"ok": True}
                    ) as docker_start, \
                    mock.patch.object(server, "start_app") as managed_start:
                supervisor.run_once()
                supervisor.run_once()

            docker_start.assert_called_once_with(docker, mock.ANY, True)
            docker.inspect.assert_called_once_with(resource)
            self.assertEqual(
                docker_start.call_args.args[1]["dockerResource"], resource
            )
            managed_start.assert_not_called()

    def test_armed_elevated_program_launches_only_after_exact_empty_observation(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = server.Config(os.path.join(td, "config.json"))
            app = {
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Admin tool",
                "command": r"C:\Program Files\Admin Tool\tool.exe",
                "commandSpec": server.direct_command_spec(
                    r"C:\Program Files\Admin Tool\tool.exe", ["--serve"]
                ),
                "cwd": r"C:\Program Files\Admin Tool",
                "kind": "program",
                "elevated": True,
                "keepAlive": True,
                "desiredRunning": True,
                "keepAliveGrant": {
                    "version": 1,
                    "grantId": "elevated-grant-0001",
                    "kind": "elevatedProgram",
                    "bindingDigest": "sha256:" + "b" * 64,
                },
            }
            app["keepAliveGrant"]["configDigest"] = (
                server.keep_alive_config_digest(app)
            )
            cfg.update(lambda data: data["apps"].append(app))
            supervisor = server.KeepAliveSupervisor(
                FakeConsole(cfg, armed=True),
                clock=FakeClock(), jitter=lambda _delay: 0.0,
            )
            grant_use = mock.Mock(side_effect=[{
                "ok": True,
                "leaseId": "elevated-lease-0001",
                "processes": [],
            }, {"ok": True, "pid": 49152}])
            platform = SimpleNamespace(
                name="windows",
                keep_alive_grant_use=grant_use,
            )

            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "build_program_process_snapshot") as observe, \
                    mock.patch.object(server, "launch_elevated_program_app") as elevated_start, \
                    mock.patch.object(server, "start_windows_app") as managed_start:
                supervisor.run_once()

            observe.assert_not_called()
            elevated_start.assert_not_called()
            self.assertEqual(grant_use.call_args_list, [
                mock.call(
                    "elevated-grant-0001", "deadbeef", "sha256:" + "b" * 64,
                    "observe",
                ),
                mock.call(
                    "elevated-grant-0001", "deadbeef", "sha256:" + "b" * 64,
                    "launch", "elevated-lease-0001",
                ),
            ])
            managed_start.assert_not_called()

    def test_attached_service_requires_two_trusted_misses_before_managed_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = server.Config(os.path.join(td, "config.json"))
            app = {
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Attached service",
                "command": "serve",
                "cwd": td,
                "port": 8080,
                "kind": "service",
                "lastPid": 42000,
                "attached": True,
                "keepAlive": True,
                "desiredRunning": True,
            }
            cfg.update(lambda data: data["apps"].append(app))
            clock = FakeClock()
            supervisor = server.KeepAliveSupervisor(
                FakeConsole(cfg, armed=True),
                clock=clock, jitter=lambda _delay: 0.0,
            )
            platform = FakePlatform(name="windows")

            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "legacy_managed_pid", return_value=None), \
                    mock.patch.object(server, "scan_listeners", return_value=set()), \
                    mock.patch.object(server, "inspect_app_health", return_value={
                        "status": "ok", "blocking": False, "issues": [],
                    }), \
                    mock.patch.object(
                        server, "start_windows_app",
                        return_value={"ok": True, "lifecycleStatus": "running"},
                    ) as managed_start:
                supervisor.run_once()
                managed_start.assert_not_called()
                clock.advance(1.0)
                supervisor.run_once()

            managed_start.assert_called_once()

    def test_windows_terminal_generation_is_cleared_before_new_generation_starts(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = server.Config(os.path.join(td, "config.json"))
            app = {
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Windows service",
                "command": "serve",
                "cwd": td,
                "kind": "service",
                "runtimeIdentity": {"generationId": "old-generation"},
                "keepAlive": True,
                "desiredRunning": True,
            }
            cfg.update(lambda data: data["apps"].append(app))
            supervisor = server.KeepAliveSupervisor(
                FakeConsole(cfg), clock=FakeClock(), jitter=lambda _delay: 0.0
            )
            platform = FakePlatform(name="windows")
            identity = SimpleNamespace(generation_id="old-generation")
            terminal = object()

            def clear_generation(config, current, observed, **_kwargs):
                self.assertIs(observed, terminal)
                config.update(lambda data: server.find_app(
                    data, current["id"]
                ).__setitem__("runtimeIdentity", None))
                return True, "applied"

            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(
                        server, "native_runtime_identity", return_value=identity
                    ), \
                    mock.patch.object(
                        server, "_inspect_windows_terminal", return_value=terminal
                    ), \
                    mock.patch.object(
                        server, "_clear_windows_generation",
                        side_effect=clear_generation,
                    ) as clear, \
                    mock.patch.object(
                        server, "start_windows_app",
                        return_value={"ok": True, "lifecycleStatus": "running"},
                    ) as start:
                supervisor.run_once()

            clear.assert_called_once()
            start.assert_called_once()
            self.assertIsNone(start.call_args.args[1]["runtimeIdentity"])

    def test_duplicate_exact_resources_are_blocked_instead_of_double_started(self):
        with tempfile.TemporaryDirectory() as td:
            container_id = "d" * 64
            resource = {"kind": "container", "containerId": container_id}
            cfg = server.Config(os.path.join(td, "config.json"))
            for app_id in ("aaaa0001", "bbbb0002"):
                cfg.update(lambda data, current_id=app_id: data["apps"].append({
                    **server.Config.APP_DEFAULT,
                    "id": current_id,
                    "name": current_id,
                    "command": "docker container start " + container_id,
                    "kind": "service",
                    "dockerResource": resource,
                    "keepAlive": True,
                    "desiredRunning": True,
                }))
            supervisor = server.KeepAliveSupervisor(
                FakeConsole(cfg, armed=True),
                clock=FakeClock(), jitter=lambda _delay: 0.0,
            )
            platform = SimpleNamespace(
                name="windows",
                capabilities=PlatformCapabilities(control_docker=True),
            )

            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "control_docker_app") as start:
                supervisor.run_once()

            start.assert_not_called()
            self.assertEqual(supervisor.status("aaaa0001")["state"], "conflict")
            self.assertEqual(supervisor.status("bbbb0002")["state"], "conflict")

    def test_manual_stop_persists_paused_intent_before_signaling_process(self):
        harness = HttpHarness()
        try:
            harness.cfg.update(lambda data: data["apps"].append({
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Managed service",
                "command": "serve",
                "kind": "service",
                "lastPid": 42000,
                "lastPgid": 42000,
                "runToken": "token",
                "keepAlive": True,
                "desiredRunning": True,
            }))
            platform = FakePlatform(
                name="macos",
                capabilities=PlatformCapabilities(stop_managed=True),
            )

            def stop_after_pause(config, _app):
                current = server.find_app(config.snapshot(), "deadbeef")
                self.assertTrue(current["keepAlive"])
                self.assertFalse(current["desiredRunning"])
                return True, None

            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "app_alive_sign", return_value=True), \
                    mock.patch.object(
                        server, "stop_app_and_clear", side_effect=stop_after_pause
                    ):
                status, body, _ = harness.request(
                    "POST", "/api/apps/deadbeef/stop",
                    '{"force":false,"expectedGeneration":null}',
                    {"Content-Type": "application/json"},
                )

            self.assertEqual(status, 200)
            self.assertTrue(body["ok"])
        finally:
            harness.close()

    def test_manual_start_rearms_selected_keep_alive_before_launch(self):
        harness = HttpHarness()
        try:
            harness.cfg.update(lambda data: data["apps"].append({
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Managed service",
                "command": "serve",
                "kind": "service",
                "keepAlive": True,
                "desiredRunning": False,
            }))
            platform = FakePlatform(
                name="macos",
                capabilities=PlatformCapabilities(launch_managed=True),
            )
            proc = mock.Mock(pid=42001)
            proc.poll.return_value = None

            def start_after_rearm(_app):
                current = server.find_app(harness.cfg.snapshot(), "deadbeef")
                self.assertTrue(current["desiredRunning"])
                return True, None, proc, proc.pid, "token"

            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "app_alive_sign", return_value=False), \
                    mock.patch.object(server, "scan_listeners", return_value=set()), \
                    mock.patch.object(server, "inspect_app_health", return_value={
                        "status": "ok", "blocking": False, "issues": [],
                    }), \
                    mock.patch.object(server, "start_app", side_effect=start_after_rearm), \
                    mock.patch.object(server, "persist_started_app", return_value=True):
                status, body, _ = harness.request(
                    "POST", "/api/apps/deadbeef/start",
                    '{"expectedGeneration":null}',
                    {"Content-Type": "application/json"},
                )

            self.assertEqual(status, 200)
            self.assertTrue(body["ok"])
        finally:
            harness.close()

    def test_stop_before_update_pauses_keep_alive_before_stopping(self):
        harness = HttpHarness()
        try:
            harness.cfg.update(lambda data: data["apps"].append({
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Managed service",
                "command": "serve",
                "kind": "service",
                "keepAlive": True,
                "desiredRunning": True,
            }))
            platform = FakePlatform(
                name="macos",
                capabilities=PlatformCapabilities(stop_managed=True),
            )

            def stop_after_pause(config, _app):
                current = server.find_app(config.snapshot(), "deadbeef")
                self.assertFalse(current["desiredRunning"])
                return True, None, True

            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "app_alive_sign", return_value=True), \
                    mock.patch.object(
                        server, "stop_app_for_update", side_effect=stop_after_pause
                    ):
                status, body, _ = harness.request(
                    "PUT", "/api/apps/deadbeef",
                    '{"command":"serve-new","stopBeforeUpdate":true,'
                    '"expectedGeneration":null}',
                    {"Content-Type": "application/json"},
                )

            self.assertEqual(status, 200)
            self.assertTrue(body["stoppedForUpdate"])
        finally:
            harness.close()

    def test_editing_card_to_one_shot_task_disables_keep_alive(self):
        harness = HttpHarness()
        try:
            harness.cfg.update(lambda data: data["apps"].append({
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Managed service",
                "command": "serve",
                "kind": "service",
                "keepAlive": True,
                "desiredRunning": True,
                "keepAliveGrant": {
                    "version": 1,
                    "grantId": "edit-grant-deadbeef",
                    "kind": "scheduledService",
                    "bindingDigest": "sha256:" + "c" * 64,
                },
            }))
            platform = FakePlatform(name="macos")
            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "app_alive_sign", return_value=False):
                status, body, _ = harness.request(
                    "PUT", "/api/apps/deadbeef",
                    '{"kind":"task","expectedGeneration":null}',
                    {"Content-Type": "application/json"},
                )

            self.assertEqual(status, 200)
            self.assertEqual(body["kind"], "task")
            self.assertFalse(body["keepAlive"])
            self.assertFalse(body["desiredRunning"])
            self.assertIn(
                ("keep_alive_grant_revoke", (
                    "edit-grant-deadbeef", "deadbeef", "sha256:" + "c" * 64,
                )),
                platform.calls,
            )
        finally:
            harness.close()

    def test_deleting_card_revokes_persistent_keep_alive_grant_first(self):
        harness = HttpHarness()
        try:
            harness.cfg.update(lambda data: data["apps"].append({
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Admin tool",
                "command": "tool.exe",
                "kind": "program",
                "keepAlive": True,
                "desiredRunning": False,
                "keepAliveGrant": {
                    "version": 1,
                    "grantId": "delete-grant-deadbeef",
                    "kind": "elevatedProgram",
                    "bindingDigest": "sha256:" + "d" * 64,
                },
            }))
            platform = FakePlatform(name="macos")
            with mock.patch.object(server, "PLATFORM", platform), \
                    mock.patch.object(server, "app_running", return_value=False):
                status, body, _ = harness.request(
                    "DELETE", "/api/apps/deadbeef"
                )

            self.assertEqual(status, 200)
            self.assertTrue(body["ok"])
            self.assertIn(("keep_alive_grant_revoke", (
                "delete-grant-deadbeef", "deadbeef", "sha256:" + "d" * 64,
            )), platform.calls)
        finally:
            harness.close()


if __name__ == "__main__":
    unittest.main()

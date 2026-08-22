import tempfile
import unittest
from unittest import mock

import server
from localops.docker_resources import (
    DockerActionResult,
    DockerLogResult,
    DockerSnapshot,
)
from localops.platform.contracts import PlatformCapabilities, ScanStatus
from localops.platform.fake import FakePlatform
from tests.windows.test_windows_server import HttpHarness


CONTAINER_ID = "c" * 64


class FakeDocker:
    def __init__(self, running=True):
        self.calls = []
        self.snapshot = DockerSnapshot(
            ScanStatus.OK,
            containers=({
                "id": CONTAINER_ID,
                "name": "redis-cache",
                "image": "redis:latest",
                "state": "running" if running else "exited",
                "running": running,
                "startedAt": None,
                "composeProject": None,
                "composeService": None,
            },),
        )

    def discover(self):
        self.calls.append(("discover", None))
        return self.snapshot

    def start(self, resource):
        self.calls.append(("start", resource))
        return DockerActionResult(True)

    def stop(self, resource):
        self.calls.append(("stop", resource))
        return DockerActionResult(True)

    def logs(self, resource, tail):
        self.calls.append(("logs", (resource, tail)))
        return DockerLogResult(True, "2026-08-22T12:00:00Z 容器日志")


def docker_app():
    app = dict(server.Config.APP_DEFAULT)
    app.update({
        "id": "deadbeef",
        "name": "Redis container",
        "command": "docker container start " + CONTAINER_ID,
        "dockerResource": {"kind": "container", "containerId": CONTAINER_ID},
        "importStatus": "ready",
        "kind": "service",
        "createdAt": 1,
    })
    return app


class DockerStateTests(unittest.TestCase):
    def test_docker_resource_round_trips_through_app_validation(self):
        fields, error = server.validate_app_fields({
            "dockerResource": {"kind": "container", "containerId": CONTAINER_ID},
        }, partial=True)

        self.assertIsNone(error)
        self.assertEqual(fields["dockerResource"]["containerId"], CONTAINER_ID)

    def test_container_card_uses_docker_state_without_managed_identity(self):
        platform = FakePlatform(
            name="windows",
            capabilities=PlatformCapabilities(
                monitor_processes=True,
                monitor_docker=True,
                control_docker=True,
            ),
        )
        docker = FakeDocker(running=True)
        cfg = dict(server.Config.DEFAULT)
        cfg["apps"] = [docker_app()]

        with mock.patch.object(server, "PLATFORM", platform), \
                mock.patch.object(server, "DOCKER", docker), \
                mock.patch.object(server, "build_services", return_value=([], set())), \
                mock.patch.object(server, "build_watched", return_value=[]):
            state = server.build_state(cfg, 9600, {})

        app = state["apps"][0]
        self.assertTrue(app["running"])
        self.assertEqual(app["runtimeSource"], "dockerContainer")
        self.assertIsNone(app["runtimeIdentity"])
        self.assertTrue(app["controlAvailable"])
        self.assertEqual(docker.calls.count(("discover", None)), 1)


class DockerHttpTests(unittest.TestCase):
    def setUp(self):
        self.log_dir = tempfile.TemporaryDirectory()
        self.platform = FakePlatform(
            name="windows",
            capabilities=PlatformCapabilities(
                monitor_processes=True,
                monitor_docker=True,
                control_docker=True,
            ),
        )
        self.docker = FakeDocker(running=False)
        self.platform_patch = mock.patch.object(server, "PLATFORM", self.platform)
        self.docker_patch = mock.patch.object(server, "DOCKER", self.docker)
        self.principal_patch = mock.patch.object(
            server, "SELF_PRINCIPAL", self.platform.principal
        )
        self.logs_patch = mock.patch.object(server, "LOGS_DIR", self.log_dir.name)
        self.platform_patch.start()
        self.docker_patch.start()
        self.principal_patch.start()
        self.logs_patch.start()
        self.harness = HttpHarness()
        self.headers = self.harness.session_headers()
        self.harness.cfg.update(lambda data: data["apps"].append(docker_app()))

    def tearDown(self):
        self.harness.close()
        self.logs_patch.stop()
        self.principal_patch.stop()
        self.docker_patch.stop()
        self.platform_patch.stop()
        self.log_dir.cleanup()

    def test_discovery_endpoint_returns_compose_and_container_resources(self):
        status, body, _ = self.harness.request(
            "GET", "/api/docker/resources", headers=self.headers,
        )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["containers"][0]["id"], CONTAINER_ID)
        self.assertEqual(body["projects"], [])

    def test_start_and_stop_use_exact_favorited_docker_identity(self):
        status, body, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/start",
            {"expectedGeneration": None}, self.headers,
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(self.docker.calls[-1], (
            "start", {"kind": "container", "containerId": CONTAINER_ID},
        ))

        status, body, _ = self.harness.request(
            "POST", "/api/apps/deadbeef/stop",
            {"expectedGeneration": None, "force": False}, self.headers,
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(self.docker.calls[-1], (
            "stop", {"kind": "container", "containerId": CONTAINER_ID},
        ))

    def test_app_logs_endpoint_includes_live_docker_logs(self):
        status, body, _ = self.harness.request(
            "GET", "/api/apps/deadbeef/logs?tail=25", headers=self.headers,
        )

        self.assertEqual(status, 200)
        self.assertIn("容器日志", body["text"])
        self.assertEqual(self.docker.calls[-1], (
            "logs", ({"kind": "container", "containerId": CONTAINER_ID}, 25),
        ))


if __name__ == "__main__":
    unittest.main()

import json
import os
import tempfile
import unittest

from localops.docker_resources import (
    DockerController,
    normalize_docker_resource,
)
from localops.platform.contracts import ScanStatus


CONTAINER_A = "a" * 64
CONTAINER_B = "b" * 64


class Completed:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class DockerResourceTests(unittest.TestCase):
    def test_container_identity_requires_a_full_immutable_id(self):
        self.assertEqual(normalize_docker_resource({
            "kind": "container",
            "containerId": CONTAINER_A.upper(),
        }), {
            "kind": "container",
            "containerId": CONTAINER_A,
        })

        for value in (
            {"kind": "container", "containerId": "a" * 12},
            {"kind": "container", "containerId": "not-hex"},
            {"kind": "container", "containerId": CONTAINER_A, "name": "mutable"},
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_docker_resource(value)

    def test_compose_identity_keeps_exact_project_and_config_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            first = os.path.join(temp_dir, "compose.yml")
            second = os.path.join(temp_dir, "compose.override.yml")
            resource = normalize_docker_resource({
                "kind": "compose",
                "projectName": "local_ops-dev",
                "workingDir": temp_dir,
                "configFiles": [first, second],
            })

        self.assertEqual(resource["projectName"], "local_ops-dev")
        self.assertEqual(resource["workingDir"], os.path.abspath(temp_dir))
        self.assertEqual(
            resource["configFiles"],
            [os.path.abspath(first), os.path.abspath(second)],
        )

    def test_compose_identity_preserves_posix_paths_on_any_host(self):
        resource = normalize_docker_resource({
            "kind": "compose",
            "projectName": "sample",
            "workingDir": "/var/lib/sample",
            "configFiles": ["/var/lib/sample/compose.yml"],
        })

        self.assertEqual(resource["workingDir"], "/var/lib/sample")
        self.assertEqual(
            resource["configFiles"], ["/var/lib/sample/compose.yml"]
        )

    def test_discovery_groups_compose_project_and_preserves_all_containers(self):
        inspect_payload = [{
            "Id": CONTAINER_A,
            "Name": "/web",
            "Config": {
                "Image": "example/web:latest",
                "Labels": {
                    "com.docker.compose.project": "sample",
                    "com.docker.compose.project.working_dir": r"C:\work\sample",
                    "com.docker.compose.project.config_files": r"C:\work\sample\compose.yml",
                    "com.docker.compose.service": "web",
                },
            },
            "State": {"Status": "running", "Running": True, "StartedAt": "2026-01-01T00:00:00Z"},
        }, {
            "Id": CONTAINER_B,
            "Name": "/redis-cache",
            "Config": {"Image": "redis:latest", "Labels": {}},
            "State": {"Status": "exited", "Running": False, "StartedAt": "2026-01-01T00:00:00Z"},
        }]
        calls = []

        def run(args, timeout):
            calls.append((args, timeout))
            if args[1:5] == ["container", "ls", "--all", "-q"]:
                return Completed(CONTAINER_A + "\n" + CONTAINER_B + "\n")
            return Completed(json.dumps(inspect_payload))

        snapshot = DockerController(executable="docker", run=run).discover()

        self.assertEqual(snapshot.status, ScanStatus.OK)
        self.assertEqual(
            {row["id"] for row in snapshot.containers},
            {CONTAINER_A, CONTAINER_B},
        )
        self.assertEqual(snapshot.projects[0]["projectName"], "sample")
        self.assertEqual(snapshot.projects[0]["containerIds"], [CONTAINER_A])
        self.assertEqual(len(calls), 2)

    def test_control_uses_only_exact_identity_and_non_destructive_commands(self):
        calls = []

        def run(args, timeout):
            calls.append(args)
            return Completed()

        controller = DockerController(executable="docker", run=run)
        container = {"kind": "container", "containerId": CONTAINER_A}
        compose = {
            "kind": "compose",
            "projectName": "sample",
            "workingDir": r"C:\work\sample",
            "configFiles": [r"C:\work\sample\compose.yml"],
        }

        self.assertTrue(controller.start(container).ok)
        self.assertTrue(controller.stop(container).ok)
        self.assertTrue(controller.start(compose).ok)
        self.assertTrue(controller.stop(compose).ok)

        self.assertEqual(calls[0], ["docker", "container", "start", CONTAINER_A])
        self.assertEqual(calls[1], ["docker", "container", "stop", CONTAINER_A])
        self.assertEqual(calls[2], [
            "docker", "compose", "--project-name", "sample",
            "--project-directory", r"C:\work\sample",
            "--file", r"C:\work\sample\compose.yml", "up", "--detach",
        ])
        self.assertEqual(calls[3][-1], "stop")
        self.assertFalse({"down", "rm", "prune"} & {part for call in calls for part in call})

    def test_logs_use_exact_container_or_compose_identity(self):
        calls = []

        def run(args, timeout):
            calls.append((args, timeout))
            return Completed("标准输出\n", "错误输出\n")

        controller = DockerController(executable="docker", run=run)
        container = {"kind": "container", "containerId": CONTAINER_A}
        compose = {
            "kind": "compose",
            "projectName": "sample",
            "workingDir": r"C:\work\sample",
            "configFiles": [r"C:\work\sample\compose.yml"],
        }

        container_log = controller.logs(container, 25)
        compose_log = controller.logs(compose, 50)

        self.assertTrue(container_log.ok)
        self.assertEqual(container_log.text, "标准输出\n错误输出")
        self.assertEqual(calls[0][0], [
            "docker", "container", "logs", "--timestamps", "--tail", "25",
            CONTAINER_A,
        ])
        self.assertTrue(compose_log.ok)
        self.assertEqual(calls[1][0][-5:], [
            "logs", "--no-color", "--timestamps", "--tail", "50",
        ])


if __name__ == "__main__":
    unittest.main()

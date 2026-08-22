"""Structured Docker discovery and non-destructive lifecycle control."""

from __future__ import annotations

from dataclasses import dataclass
import json
import ntpath
import os
import posixpath
import re
import subprocess
from typing import Callable, Sequence

from .platform.contracts import PlatformIssue, ScanStatus


_CONTAINER_ID_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_COMPOSE_PROJECT = "com.docker.compose.project"
_COMPOSE_WORKING_DIR = "com.docker.compose.project.working_dir"
_COMPOSE_CONFIG_FILES = "com.docker.compose.project.config_files"
_COMPOSE_SERVICE = "com.docker.compose.service"


@dataclass(frozen=True)
class DockerSnapshot:
    status: ScanStatus
    containers: tuple[dict[str, object], ...] = ()
    projects: tuple[dict[str, object], ...] = ()
    issues: tuple[PlatformIssue, ...] = ()


@dataclass(frozen=True)
class DockerActionResult:
    ok: bool
    error: str | None = None
    code: str | None = None


def _absolute_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label} must be a non-empty absolute path")
    if posixpath.isabs(value):
        return posixpath.normpath(value)
    if ntpath.isabs(value):
        return ntpath.normpath(value)
    raise ValueError(f"{label} must be an absolute path")


def normalize_docker_resource(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("dockerResource must be an object")
    kind = value.get("kind")
    if kind == "container":
        if set(value) != {"kind", "containerId"}:
            raise ValueError("container identity contains unsupported fields")
        container_id = value.get("containerId")
        if not isinstance(container_id, str) or not _CONTAINER_ID_RE.fullmatch(
                container_id):
            raise ValueError("containerId must be a full 64-character hexadecimal ID")
        return {"kind": "container", "containerId": container_id.lower()}
    if kind == "compose":
        if set(value) != {"kind", "projectName", "workingDir", "configFiles"}:
            raise ValueError("Compose identity contains unsupported fields")
        project = value.get("projectName")
        if not isinstance(project, str) or not _PROJECT_RE.fullmatch(project):
            raise ValueError("projectName is invalid")
        working_dir = _absolute_path(value.get("workingDir"), "workingDir")
        config_files = value.get("configFiles")
        if (not isinstance(config_files, list) or not config_files
                or len(config_files) > 16):
            raise ValueError("configFiles must contain 1 to 16 absolute paths")
        normalized_files = [
            _absolute_path(path, "configFiles entry") for path in config_files
        ]
        if len(set(map(os.path.normcase, normalized_files))) != len(normalized_files):
            raise ValueError("configFiles contains duplicates")
        return {
            "kind": "compose",
            "projectName": project,
            "workingDir": working_dir,
            "configFiles": normalized_files,
        }
    raise ValueError("dockerResource kind must be compose or container")


def _issue(code: str, message: str) -> PlatformIssue:
    return PlatformIssue("docker", code, message)


def _default_run(args: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout, check=False,
    )


class DockerController:
    def __init__(
            self, executable: str = "docker",
            run: Callable[[Sequence[str], float], object] | None = None):
        self.executable = executable
        self._run = run or _default_run

    def _command(self, args: Sequence[str], timeout: float = 8.0) -> object:
        result = self._run([self.executable, *args], timeout)
        if int(getattr(result, "returncode", 1)) != 0:
            detail = str(getattr(result, "stderr", "") or "").strip()
            raise OSError(detail or "Docker command failed")
        return result

    def discover(self) -> DockerSnapshot:
        try:
            listed = self._command([
                "container", "ls", "--all", "-q", "--no-trunc",
            ])
            ids = [
                value.strip().lower()
                for value in str(getattr(listed, "stdout", "") or "").splitlines()
                if value.strip()
            ]
            if any(not _CONTAINER_ID_RE.fullmatch(value) for value in ids):
                raise ValueError("Docker returned an invalid container identity")
            if not ids:
                return DockerSnapshot(ScanStatus.OK)
            inspected = self._command(["container", "inspect", *ids])
            payload = json.loads(str(getattr(inspected, "stdout", "") or "[]"))
            if not isinstance(payload, list):
                raise ValueError("Docker inspect response is not an array")
            return self._snapshot_from_inspect(payload)
        except FileNotFoundError as exc:
            return DockerSnapshot(
                ScanStatus.FAILED,
                issues=(_issue("cli_missing", str(exc) or "Docker CLI is unavailable"),),
            )
        except subprocess.TimeoutExpired as exc:
            return DockerSnapshot(
                ScanStatus.FAILED,
                issues=(_issue("timeout", str(exc) or "Docker did not respond"),),
            )
        except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
            return DockerSnapshot(
                ScanStatus.FAILED,
                issues=(_issue("query_failed", str(exc) or "Docker query failed"),),
            )

    @staticmethod
    def _snapshot_from_inspect(payload: list[object]) -> DockerSnapshot:
        containers: list[dict[str, object]] = []
        projects: dict[str, dict[str, object]] = {}
        for raw in payload:
            if not isinstance(raw, dict):
                continue
            container_id = str(raw.get("Id") or "").lower()
            if not _CONTAINER_ID_RE.fullmatch(container_id):
                continue
            config = raw.get("Config") if isinstance(raw.get("Config"), dict) else {}
            state = raw.get("State") if isinstance(raw.get("State"), dict) else {}
            labels = config.get("Labels") if isinstance(config.get("Labels"), dict) else {}
            project = str(labels.get(_COMPOSE_PROJECT) or "")
            row = {
                "id": container_id,
                "name": str(raw.get("Name") or "").lstrip("/"),
                "image": str(config.get("Image") or ""),
                "state": str(state.get("Status") or "unknown"),
                "running": bool(state.get("Running")),
                "startedAt": str(state.get("StartedAt") or "") or None,
                "composeProject": project or None,
                "composeService": str(labels.get(_COMPOSE_SERVICE) or "") or None,
            }
            containers.append(row)
            if not project:
                continue
            item = projects.setdefault(project, {
                "projectName": project,
                "workingDir": str(labels.get(_COMPOSE_WORKING_DIR) or ""),
                "configFiles": [],
                "containerIds": [],
                "running": False,
                "states": [],
            })
            item["containerIds"].append(container_id)
            item["states"].append(row["state"])
            item["running"] = bool(item["running"] or row["running"])
            if not item["configFiles"]:
                item["configFiles"] = [
                    path.strip() for path in
                    str(labels.get(_COMPOSE_CONFIG_FILES) or "").split(",")
                    if path.strip()
                ]
        for item in projects.values():
            item["containerIds"].sort()
            item["states"] = sorted(set(item["states"]))
        containers.sort(key=lambda row: (str(row["name"]).casefold(), row["id"]))
        ordered_projects = sorted(
            projects.values(), key=lambda row: str(row["projectName"]).casefold()
        )
        return DockerSnapshot(
            ScanStatus.OK, tuple(containers), tuple(ordered_projects)
        )

    @staticmethod
    def _compose_args(resource: dict[str, object]) -> list[str]:
        args = [
            "compose", "--project-name", str(resource["projectName"]),
            "--project-directory", str(resource["workingDir"]),
        ]
        for path in resource["configFiles"]:
            args.extend(["--file", str(path)])
        return args

    def _control(self, value: object, start: bool) -> DockerActionResult:
        try:
            resource = normalize_docker_resource(value)
            if resource["kind"] == "container":
                args = [
                    "container", "start" if start else "stop",
                    str(resource["containerId"]),
                ]
            else:
                args = self._compose_args(resource)
                args.extend(["up", "--detach"] if start else ["stop"])
            self._command(args, timeout=120.0)
            return DockerActionResult(True)
        except FileNotFoundError as exc:
            return DockerActionResult(False, str(exc), "DOCKER_CLI_MISSING")
        except subprocess.TimeoutExpired as exc:
            return DockerActionResult(False, str(exc), "DOCKER_TIMEOUT")
        except (OSError, TypeError, ValueError) as exc:
            return DockerActionResult(False, str(exc), "DOCKER_CONTROL_FAILED")

    def start(self, resource: object) -> DockerActionResult:
        return self._control(resource, True)

    def stop(self, resource: object) -> DockerActionResult:
        return self._control(resource, False)

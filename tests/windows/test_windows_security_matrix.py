"""Executable Phase 4 security matrix for WIN-SEC-001 through WIN-SEC-014.

Every case is either pure/mocked or uses only temporary files and sockets
created by the test. No test discovers, attaches to, or controls a user process.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from types import SimpleNamespace
from unittest import mock

import server
from localops.command_spec import (
    direct_command_spec,
    normalize_command_spec,
    prepared_invocation,
)
from localops.platform.contracts import (
    CwdSnapshot,
    ListenerSnapshot,
    ManagedRuntime,
    PlatformCapabilities,
    PlatformIssue,
    Principal,
    ProcessSnapshot,
    RuntimeIdentity,
    ScanStatus,
    StopResult,
)
from localops.platform.fake import FakePlatform
from tests.windows.test_windows_server import HttpHarness


APP_ID = "deadbeef"
OLD_GENERATION = "3d6448f0-87a0-4ace-baad-3b80abca9e3e"
NEW_GENERATION = "4488592f-9454-4f9f-9d2d-ac4775688aa3"


def _windows_capabilities(**overrides):
    values = {
        "monitor_processes": True,
        "launch_managed": True,
        "stop_managed": True,
        "force_stop_managed": True,
        "kill_external": False,
        "attach_external": False,
        "pick_path": True,
        "restart_console": False,
    }
    values.update(overrides)
    return PlatformCapabilities(**values)


def _public_identity(
    generation=OLD_GENERATION,
    *,
    app_id=APP_ID,
    digest_character="a",
    owner=None,
):
    owner = owner or server.SELF_PRINCIPAL.identifier
    digest = "sha256:" + digest_character * 64
    return {
        "platform": "windows",
        "kind": "job",
        "ownerSid": owner,
        "generationId": generation,
        "runnerPid": 1234,
        "runnerCreateTime": 1780000000.123,
        "rootPid": 5678,
        "rootCreateTime": 1780000001.456,
        "jobName": "Local\\LocalOps-%s-%s-%s" % (
            app_id,
            generation,
            digest[7:23],
        ),
        "tokenDigest": digest,
        "startedAt": 1780000001456,
    }


def _native_identity(generation=OLD_GENERATION, **kwargs):
    public = _public_identity(generation, **kwargs)
    return RuntimeIdentity(
        platform="windows",
        kind="job",
        identifier=public["jobName"],
        owner=public["ownerSid"],
        members=(public["rootPid"],),
        app_id=kwargs.get("app_id", APP_ID),
        generation_id=public["generationId"],
        runner_pid=public["runnerPid"],
        runner_create_time=public["runnerCreateTime"],
        root_pid=public["rootPid"],
        root_create_time=public["rootCreateTime"],
        job_name=public["jobName"],
        token_digest=public["tokenDigest"],
        started_at=public["startedAt"],
    )


def _app(*, port=8123, cwd=None, identity=None):
    return {
        **server.Config.APP_DEFAULT,
        "id": APP_ID,
        "name": "fixture.exe",
        "command": "fixture.exe --serve",
        "commandSpec": direct_command_spec(sys.executable, ["-c", "pass"]),
        "runtimeIdentity": identity,
        "importStatus": "ready",
        "cwd": cwd,
        "port": port,
        "kind": "service",
    }


@unittest.skipUnless(sys.platform == "win32", "Windows-only security matrix")
class WindowsSecurityMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global NonceCache, ProtocolError, WindowsPlatform
        global native_process_command, reconnect_observations_valid
        global runner, verify_request, make_request
        import win32con
        import win32security

        from localops.platform.windows import WindowsPlatform
        from localops.windows import runner
        from localops.windows.runner_protocol import (
            NonceCache,
            ProtocolError,
            make_request,
            native_process_command,
            reconnect_observations_valid,
            verify_request,
        )

        cls.win32con = win32con
        cls.win32security = win32security

    def test_win_sec_001_pid_create_time_mismatch_refuses_control(self):
        platform = WindowsPlatform(os.getcwd(), "server.py")
        identity = _native_identity()
        context = SimpleNamespace(
            state="running",
            members=(identity.root_pid,),
            receipt={},
        )

        self.assertFalse(reconnect_observations_valid(
            _public_identity(),
            runner_observation=(identity.owner, identity.runner_create_time + 1.0),
            root_observation=(identity.owner, identity.root_create_time),
            members=(identity.root_pid,),
        ))

        def observation(pid):
            if pid == identity.runner_pid:
                return identity.owner, identity.runner_create_time + 1.0
            if pid == identity.root_pid:
                return identity.owner, identity.root_create_time
            return None

        with mock.patch.object(
                platform, "_runtime_context", return_value=context), \
                mock.patch.object(
                    platform, "_observe_process", side_effect=observation), \
                mock.patch.object(platform, "_control") as control:
            result = platform.stop_managed(identity, force=True)

        self.assertFalse(result.ok)
        self.assertEqual(result.code, "RUNTIME_IDENTITY_UNVERIFIED")
        control.assert_not_called()

    def test_win_sec_002_other_listener_is_not_claimed_or_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            pid, port = 42002, 8123
            fake = FakePlatform(
                name="windows",
                principal=Principal(server.SELF_PRINCIPAL.identifier),
                capabilities=_windows_capabilities(),
                listeners=ListenerSnapshot(
                    ScanStatus.OK, {(pid, port): {"127.0.0.1"}}
                ),
                processes=ProcessSnapshot(ScanStatus.OK, {
                    pid: {
                        "owner": server.SELF_PRINCIPAL.identifier,
                        "comm": "python.exe",
                        "args": "python.exe -m http.server",
                        "etime": 1,
                    },
                }),
                cwds=CwdSnapshot(ScanStatus.OK, {pid: directory}),
            )
            app = _app(port=port, cwd=directory)
            with mock.patch.object(server, "PLATFORM", fake):
                rendered = server.build_apps(
                    {"apps": [app]}, fake.listeners.listeners
                )[0]

        self.assertFalse(rendered["running"])
        self.assertTrue(rendered["portOccupied"])
        self.assertEqual(rendered["portOccupiedPid"], pid)
        self.assertNotIn(
            "stop_external_process", {name for name, _ in fake.calls}
        )

    def test_win_sec_003_same_name_and_cwd_are_not_ownership_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            pid, port = 42003, 8124
            app = _app(port=port, cwd=directory)
            listeners = {(pid, port): {"127.0.0.1"}}
            snapshot = {
                pid: {
                    "owner": server.SELF_PRINCIPAL.identifier,
                    "comm": "fixture.exe",
                    "args": app["command"],
                },
            }
            with mock.patch.object(
                    server.PLATFORM, "name", "windows", create=True):
                owners = server.listener_app_owners(
                    [app],
                    listeners,
                    snapshot,
                    {pid: directory},
                    managed_override={APP_ID: []},
                )

        self.assertEqual(owners, {})

    def test_win_sec_004_other_sid_rejected_before_cwd_or_control(self):
        with tempfile.TemporaryDirectory() as directory:
            pid, port = 42004, 8125
            fake = FakePlatform(
                name="windows",
                principal=Principal(server.SELF_PRINCIPAL.identifier),
                capabilities=_windows_capabilities(attach_external=True),
                listeners=ListenerSnapshot(
                    ScanStatus.OK, {(pid, port): {"127.0.0.1"}}
                ),
                processes=ProcessSnapshot(ScanStatus.OK, {
                    pid: {"owner": "S-1-5-21-999999", "comm": "fixture.exe"},
                }),
                cwds=CwdSnapshot(ScanStatus.OK, {pid: directory}),
            )
            config = mock.Mock()
            config.snapshot.side_effect = AssertionError(
                "configuration must not be read after an SID mismatch"
            )
            with mock.patch.object(server, "PLATFORM", fake):
                ok, _, info = server.inspect_attach_process(
                    config, _app(port=port, cwd=directory), pid
                )

        self.assertFalse(ok)
        self.assertEqual(info["status"], 403)
        self.assertNotIn("process_cwds", {name for name, _ in fake.calls})
        self.assertNotIn("stop_external_process", {name for name, _ in fake.calls})

    def test_win_sec_005_wrong_host_or_origin_is_rejected(self):
        harness = HttpHarness()
        try:
            headers = harness.session_headers()
            status, _, _ = harness.request(
                "POST",
                "/api/watch",
                {"keyword": "fixture", "action": "add"},
                {**headers, "Host": "evil.example:%d" % harness.port},
            )
            self.assertEqual(status, 421)

            status, _, _ = harness.request(
                "POST",
                "/api/watch",
                {"keyword": "fixture", "action": "add"},
                {**headers, "Origin": "http://evil.example:%d" % harness.port},
            )
            self.assertEqual(status, 403)
        finally:
            harness.close()

    def test_win_sec_006_missing_or_wrong_cookie_and_hmac_are_rejected(self):
        harness = HttpHarness()
        try:
            valid = harness.session_headers()
            for cookie in (None, "console_session=wrong"):
                headers = {
                    "Content-Type": "application/json",
                    "Origin": "http://127.0.0.1:%d" % harness.port,
                    "Sec-Fetch-Site": "same-origin",
                }
                if cookie is not None:
                    headers["Cookie"] = cookie
                with self.subTest(cookie=cookie):
                    status, _, _ = harness.request(
                        "POST",
                        "/api/watch",
                        {"keyword": "fixture", "action": "add"},
                        headers,
                    )
                    self.assertEqual(status, 403)
            self.assertIn("Cookie", valid)
        finally:
            harness.close()

        request = make_request("inspect", OLD_GENERATION, b"a" * 32)
        with self.assertRaises(ProtocolError) as raised:
            verify_request(
                request, b"b" * 32, OLD_GENERATION, NonceCache()
            )
        self.assertEqual(raised.exception.code, "RUNTIME_IDENTITY_UNVERIFIED")

    def test_win_sec_007_exclusive_socket_rejects_port_takeover(self):
        platform = WindowsPlatform(os.getcwd(), "server.py")
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        candidate = None
        try:
            platform.configure_server_socket(blocker)
            blocker.bind((server.HOST, 0))
            blocker.listen(1)
            port = blocker.getsockname()[1]
            self.assertEqual(
                blocker.getsockopt(
                    socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE
                ),
                1,
            )
            with mock.patch.object(server, "PLATFORM", platform):
                with self.assertRaises(OSError):
                    candidate = server.ConsoleServer(
                        (server.HOST, port), server.Handler, mock.Mock(), port
                    )
        finally:
            if candidate is not None:
                candidate.server_close()
            blocker.close()

    def test_win_sec_008_widened_acl_is_verify_only_and_control_fails_closed(self):
        platform = WindowsPlatform(os.getcwd(), "server.py")
        identity = _native_identity()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "token.bin")
            with open(path, "wb") as stream:
                stream.write(b"fixture")
            platform.ensure_private_file(path)
            descriptor = self.win32security.GetNamedSecurityInfo(
                path,
                self.win32security.SE_FILE_OBJECT,
                self.win32security.DACL_SECURITY_INFORMATION,
            )
            dacl = descriptor.GetSecurityDescriptorDacl()
            dacl.AddAccessAllowedAceEx(
                self.win32security.ACL_REVISION_DS,
                0,
                self.win32con.GENERIC_READ,
                self.win32security.ConvertStringSidToSid("S-1-1-0"),
            )
            self.win32security.SetNamedSecurityInfo(
                path,
                self.win32security.SE_FILE_OBJECT,
                self.win32security.DACL_SECURITY_INFORMATION
                | self.win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                dacl,
                None,
            )
            try:
                with self.assertRaises(PermissionError):
                    platform.verify_private_file(path)
                with mock.patch.object(
                        platform,
                        "_runtime_context",
                        side_effect=PermissionError(
                            "private Windows ACL verification failed"
                        )), mock.patch.object(platform, "_control") as control:
                    result = platform.stop_managed(identity, force=True)
                self.assertFalse(result.ok)
                self.assertEqual(result.code, "RUNTIME_IDENTITY_UNVERIFIED")
                control.assert_not_called()
            finally:
                platform.ensure_private_file(path)

    def test_win_sec_009_junction_runtime_path_is_rejected(self):
        platform = WindowsPlatform(os.getcwd(), "server.py")
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "runtime-junction")
            with mock.patch.object(
                    platform, "_has_junction_component", return_value=True), \
                    mock.patch.object(platform, "_canonical_path") as canonical:
                with self.assertRaises(ValueError):
                    platform.validate_runtime_path(target, set())
            canonical.assert_not_called()

    def test_win_sec_010_cmd_and_powershell_special_args_do_not_inject(self):
        values = ["&", "|", "<", ">", "^", "(", ")", "space value", "中文"]
        cmd_spec = normalize_command_spec({
            "version": 1,
            "mode": "cmd",
            "executable": r"D:\project & tools\start.cmd",
            "args": values,
            "shell": "cmd.exe",
            "text": None,
            "needsReview": False,
        })
        cmd_invocation = prepared_invocation(
            cmd_spec, {"COMSPEC": r"C:\Windows\System32\cmd.exe"}
        )
        application, command_line = native_process_command(cmd_invocation)
        self.assertEqual(application, r"C:\Windows\System32\cmd.exe")
        for value in [cmd_spec["executable"], *values]:
            self.assertIn('"' + value + '"', command_line)

        ps_spec = normalize_command_spec({
            "version": 1,
            "mode": "powershell",
            "executable": r"D:\project & tools\run.ps1",
            "args": ["$Env:USERPROFILE", "; Write-Output injected", *values],
            "shell": "powershell.exe",
            "text": None,
            "needsReview": False,
        })
        ps_invocation = prepared_invocation(ps_spec)
        ps_application, ps_line = native_process_command(ps_invocation)
        expected = [
            ps_invocation["executable"],
            *ps_invocation["prefixArgs"],
            ps_invocation["script"],
            *ps_invocation["args"],
        ]
        self.assertEqual(ps_application, "powershell.exe")
        self.assertEqual(ps_line, subprocess.list2cmdline(expected))
        self.assertIn("-File", ps_invocation["prefixArgs"])
        self.assertNotIn("-Command", ps_invocation["prefixArgs"])

    def test_win_sec_011_concurrent_generation_cas_has_one_winner(self):
        fake = FakePlatform(
            name="windows",
            principal=Principal(server.SELF_PRINCIPAL.identifier),
            capabilities=_windows_capabilities(),
        )
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(server, "PLATFORM", fake):
            path = os.path.join(directory, "config.json")
            config = server.Config(path)
            config.update(lambda data: data["apps"].append(
                _app(cwd=directory, identity=_public_identity())
            ))
            barrier = threading.Barrier(3)
            results = []
            result_lock = threading.Lock()

            def mutate(generation, digest_character):
                candidate = _public_identity(
                    generation, digest_character=digest_character
                )
                barrier.wait()
                status, result, actual = config.mutate_app_if_generation(
                    APP_ID,
                    OLD_GENERATION,
                    lambda _data, app: (
                        app.__setitem__("runtimeIdentity", candidate)
                        or generation
                    ),
                )
                with result_lock:
                    results.append((status, result, actual, candidate))

            threads = [
                threading.Thread(
                    target=mutate,
                    args=(NEW_GENERATION, "b"),
                ),
                threading.Thread(
                    target=mutate,
                    args=("57a71cbf-42fd-4262-a2ad-c9170c475208", "c"),
                ),
            ]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

            applied = [item for item in results if item[0] == "applied"]
            mismatches = [item for item in results if item[0] == "mismatch"]
            persisted = config.snapshot()["apps"][0]["runtimeIdentity"]
            with open(path, encoding="utf-8") as stream:
                on_disk = json.load(stream)["apps"][0]["runtimeIdentity"]

        self.assertEqual(len(applied), 1)
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(persisted, applied[0][3])
        self.assertEqual(on_disk, applied[0][3])

    def test_win_sec_012_partial_scan_is_degraded_and_control_fails_closed(self):
        issue = PlatformIssue(
            "listeners", "owner_unavailable", "fixture listener owner missing"
        )
        fake = FakePlatform(
            name="windows",
            principal=Principal(server.SELF_PRINCIPAL.identifier),
            capabilities=_windows_capabilities(
                launch_managed=False,
                stop_managed=False,
                force_stop_managed=False,
            ),
            listeners=ListenerSnapshot(
                ScanStatus.PARTIAL, {}, (issue,)
            ),
        )
        with mock.patch.object(server, "PLATFORM", fake):
            server.invalidate_state_cache()
            state = server.build_state(server.Config.DEFAULT, 9600)
            self.assertTrue(state["degraded"])
            self.assertIn("listeners", {
                reason.get("component") for reason in state["degradedReasons"]
            })

            harness = HttpHarness()
            try:
                headers = harness.session_headers()
                status, body, _ = harness.request(
                    "POST", "/api/kill", {"pid": 424242}, headers
                )
            finally:
                harness.close()
                server.invalidate_state_cache()

        self.assertEqual(status, 409)
        self.assertEqual(body["code"], "CAPABILITY_DISABLED")
        self.assertNotIn("stop_external_process", {name for name, _ in fake.calls})

    def test_win_sec_013_stale_generation_cannot_stop_new_instance(self):
        fake = FakePlatform(
            name="windows",
            principal=Principal(server.SELF_PRINCIPAL.identifier),
            capabilities=_windows_capabilities(),
            stop_result=StopResult(True),
        )
        with mock.patch.object(server, "PLATFORM", fake):
            server.invalidate_state_cache()
            harness = HttpHarness()
            try:
                harness.cfg.update(lambda data: data["apps"].append(
                    _app(
                        cwd=harness.temp_dir.name,
                        identity=_public_identity(NEW_GENERATION),
                    )
                ))
                headers = harness.session_headers()
                for force in (False, True):
                    with self.subTest(force=force):
                        status, body, _ = harness.request(
                            "POST",
                            "/api/apps/%s/stop" % APP_ID,
                            {
                                "expectedGeneration": OLD_GENERATION,
                                "force": force,
                            },
                            headers,
                        )
                        self.assertEqual(status, 409)
                        self.assertEqual(body["code"], "GENERATION_MISMATCH")
                persisted = harness.cfg.snapshot()["apps"][0]["runtimeIdentity"]
            finally:
                harness.close()
                server.invalidate_state_cache()

        self.assertEqual(persisted["generationId"], NEW_GENERATION)
        self.assertNotIn("stop_managed", {name for name, _ in fake.calls})

    def test_win_sec_014_assign_or_persist_failure_never_resumes(self):
        suspended = SimpleNamespace(
            process_handle=mock.sentinel.process_handle,
            close=mock.Mock(),
        )
        job = mock.Mock()
        job.assign.side_effect = OSError("assign fixture")
        publish = mock.Mock()
        with mock.patch.object(
                runner, "create_suspended_process", return_value=suspended), \
                mock.patch.object(
                    runner.win32process, "TerminateProcess"
                ) as terminate:
            with self.assertRaisesRegex(OSError, "assign fixture"):
                runner.prepare_runtime(
                    job,
                    [sys.executable, "-c", "pass"],
                    os.getcwd(),
                    os.devnull,
                    publish_prepared=publish,
                )
        terminate.assert_called_once_with(suspended.process_handle, 1)
        suspended.close.assert_called_once_with()
        publish.assert_not_called()

        identity = _native_identity()
        fake = FakePlatform(
            name="windows",
            principal=Principal(server.SELF_PRINCIPAL.identifier),
            capabilities=_windows_capabilities(),
            launch_result=ManagedRuntime(
                True, runtime_identity=identity, status="prepared"
            ),
            stop_result=StopResult(True),
        )
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(server, "PLATFORM", fake), \
                mock.patch.object(server, "LOGS_DIR", os.path.join(directory, "logs")), \
                mock.patch.object(
                    server.uuid, "uuid4", return_value=uuid.UUID(OLD_GENERATION)
                ):
            config = server.Config(os.path.join(directory, "config.json"))
            app = _app(cwd=directory)
            config.update(lambda data: data["apps"].append(app))
            with mock.patch.object(
                    config,
                    "mutate_app_if_generation",
                    side_effect=OSError("persist fixture"),
                ):
                result = server.start_windows_app(config, app)
            persisted = config.snapshot()["apps"][0]["runtimeIdentity"]

        calls = [name for name, _ in fake.calls]
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "LAUNCH_COMMIT_FAILED")
        self.assertIsNone(persisted)
        self.assertIn("abort_managed", calls)
        self.assertIn("release_managed", calls)
        self.assertNotIn("activate_managed", calls)


if __name__ == "__main__":
    unittest.main()

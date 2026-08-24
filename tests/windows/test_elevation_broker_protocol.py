import unittest

from localops.elevation_broker import (
    BROKER_TASK_PATH,
    ElevationBrokerProtocol,
    broker_install_request_digest,
    broker_task_spec,
    new_password_record,
    normalize_elevated_launch,
    normalize_elevated_stop,
    normalize_scheduled_request,
    verify_broker_task,
    verify_password,
)


class PasswordVerifierTests(unittest.TestCase):
    def test_password_record_never_contains_plaintext_and_verifies_exact_input(self):
        record = new_password_record(
            "correct horse battery staple",
            salt=b"0123456789abcdef",
            iterations=10_000,
        )

        self.assertNotIn("correct horse battery staple", repr(record))
        self.assertTrue(verify_password("correct horse battery staple", record))
        self.assertFalse(verify_password("wrong password", record))

    def test_short_password_is_rejected(self):
        with self.assertRaises(ValueError):
            new_password_record("short")

    def test_install_request_digest_detects_any_transaction_tampering(self):
        request = {
            "schema": "localops-elevation-install.v1",
            "ownerSid": "S-1-5-21-1-2-3-1001",
            "passwordRecord": {"verifier": "opaque"},
            "bundleSource": r"C:\\Local Ops",
            "executableName": "LocalOps.exe",
        }

        digest = broker_install_request_digest(request)
        changed = dict(request, ownerSid="S-1-5-21-9-9-9-1001")

        self.assertEqual(len(digest), 64)
        self.assertNotEqual(digest, broker_install_request_digest(changed))


class StructuredLaunchTests(unittest.TestCase):
    def test_absolute_exe_args_and_cwd_are_normalized_without_shell(self):
        launch = normalize_elevated_launch({
            "executable": r"C:\Tools\Admin Tool.exe",
            "args": ["--profile", "alpha beta"],
            "cwd": r"C:\Tools",
        })

        self.assertEqual(launch, {
            "executable": r"C:\Tools\Admin Tool.exe",
            "args": ["--profile", "alpha beta"],
            "cwd": r"C:\Tools",
        })
        self.assertNotIn("shell", launch)

    def test_relative_non_exe_and_shell_requests_are_rejected(self):
        invalid = (
            {"executable": "tool.exe", "args": [], "cwd": r"C:\Tools"},
            {"executable": r"C:\Tools\script.cmd", "args": [], "cwd": r"C:\Tools"},
            {"executable": r"C:\Tools\tool.exe", "args": "--bad", "cwd": r"C:\Tools"},
            {"executable": r"C:\Tools\tool.exe", "args": [], "cwd": "."},
            {"executable": r"C:\Tools\tool.exe", "args": [], "cwd": r"C:\Tools", "shell": True},
        )
        for request in invalid:
            with self.subTest(request=request), self.assertRaises(ValueError):
                normalize_elevated_launch(request)

    def test_elevated_stop_requires_exact_bounded_process_identities(self):
        request = normalize_elevated_stop({
            "favoriteExecutable": r"C:\Tools\Admin Tool.exe",
            "processes": [
                {
                    "pid": 4301,
                    "createTime": 1000.25,
                    "executable": r"C:\Tools\Admin Tool.exe",
                },
                {
                    "pid": 4302,
                    "createTime": 1001.5,
                    "executable": r"C:\Tools\bin\Admin Tool.exe",
                },
            ],
        })

        self.assertEqual([row["pid"] for row in request["processes"]], [4301, 4302])
        invalid = dict(request)
        invalid["processes"] = [{
            "pid": 4303,
            "createTime": 1002.0,
            "executable": r"C:\Other\Admin Tool.exe",
        }]
        with self.assertRaises(ValueError):
            normalize_elevated_stop(invalid)

        invalid["processes"][0]["executable"] = r"C:\Tools\Other.exe"
        with self.assertRaises(ValueError):
            normalize_elevated_stop(invalid)

    def test_scheduled_requests_are_exact_and_path_bounded(self):
        self.assertEqual(normalize_scheduled_request({
            "operation": "query",
            "paths": [r"\Memos-Guard", r"\Folder\Backup"],
        }), {
            "operation": "query",
            "paths": [r"\Memos-Guard", r"\Folder\Backup"],
        })
        self.assertEqual(normalize_scheduled_request({
            "operation": "toggle",
            "path": r"\Memos-Guard",
            "enabled": False,
        })["enabled"], False)
        for invalid in (
            {"operation": "query", "paths": []},
            {"operation": "run", "path": r"\..\unsafe"},
            {"operation": "toggle", "path": r"\Task", "enabled": 1},
            {"operation": "shell", "path": r"\Task"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_scheduled_request(invalid)

class BrokerTaskContractTests(unittest.TestCase):
    def test_broker_task_is_fixed_to_installed_executable_and_module(self):
        spec = broker_task_spec(
            r"C:\Program Files\LocalOps\Broker\abc\LocalOps.exe",
            "S-1-5-21-1-2-3-1001",
        )

        self.assertEqual(spec["taskPath"], BROKER_TASK_PATH)
        self.assertEqual(
            spec["arguments"], "-m localops.windows.elevation_broker serve"
        )
        self.assertEqual(
            spec["workingDirectory"],
            r"C:\Program Files\LocalOps\Broker\abc",
        )

    def test_broker_task_verification_rejects_action_or_acl_drift(self):
        spec = broker_task_spec(
            r"C:\Program Files\LocalOps\Broker\abc\LocalOps.exe",
            "S-1-5-21-1-2-3-1001",
        )
        row = {
            "path": BROKER_TASK_PATH,
            "enabled": True,
            "runLevel": "highest",
            "principalUserId": "fixture-user",
            "principalSid": "S-1-5-21-1-2-3-1001",
            "multipleInstances": "ignoreNew",
            "triggerCount": 0,
            "securityLocked": True,
            "actionDetails": [{
                "type": "exec",
                "path": spec["executable"],
                "arguments": spec["arguments"],
                "workingDirectory": spec["workingDirectory"],
            }],
        }
        self.assertEqual(verify_broker_task(row, spec), (True, None))

        row["securityLocked"] = False
        self.assertEqual(
            verify_broker_task(row, spec),
            (False, "BROKER_TASK_MISMATCH"),
        )


class BrokerSessionTests(unittest.TestCase):
    def setUp(self):
        self.launches = []
        self.observations = []
        self.stops = []
        self.scheduled = []
        self.alive = {(1200, 77.25, "S-1-5-21-1-2-3-1001")}
        self.record = new_password_record(
            "correct horse battery staple",
            salt=b"0123456789abcdef",
            iterations=10_000,
        )
        self.protocol = ElevationBrokerProtocol(
            self.record,
            owner_sid="S-1-5-21-1-2-3-1001",
            process_matches=lambda pid, created, owner: (
                pid, created, owner
            ) in self.alive,
            launch=lambda request: self.launches.append(request) or 4321,
            observe=lambda request: self.observations.append(request) or {
                "ok": True,
                "processes": [{
                    "pid": 4301,
                    "createTime": 1000.25,
                    "executable": r"C:\Tools\Admin Tool.exe",
                    "commandLine": r'"C:\Tools\Admin Tool.exe" --profile "alpha beta"',
                    "etime": 12,
                }],
            },
            stop=lambda request: self.stops.append(request) or {
                "ok": True, "stopped": [4301, 4302],
            },
            scheduled=lambda request: self.scheduled.append(request) or {
                "ok": True, "operation": request["operation"],
            },
            token_factory=lambda: "session-token",
        )

    def test_scheduled_task_request_requires_bound_token_and_exact_operation(self):
        self.protocol.handle({
            "action": "unlock",
            "password": "correct horse battery staple",
            "consolePid": 1200,
            "consoleCreateTime": 77.25,
        }, client_pid=1200)

        result = self.protocol.handle({
            "action": "scheduled",
            "token": "session-token",
            "request": {
                "operation": "stop",
                "path": r"\Memos-Guard",
            },
        }, client_pid=1200)

        self.assertTrue(result["ok"])
        self.assertEqual(self.scheduled, [{
            "operation": "stop", "path": r"\Memos-Guard",
        }])

    def test_unlock_binds_token_to_actual_client_pid_and_process_identity(self):
        result = self.protocol.handle({
            "action": "unlock",
            "password": "correct horse battery staple",
            "consolePid": 1200,
            "consoleCreateTime": 77.25,
        }, client_pid=1200)

        self.assertEqual(result, {
            "ok": True, "token": "session-token", "unlocked": True,
        })
        rejected = self.protocol.handle({
            "action": "status", "token": "session-token",
        }, client_pid=1300)
        self.assertEqual(rejected["code"], "BROKER_SESSION_INVALID")

    def test_launch_requires_bound_token_and_passes_only_structured_values(self):
        self.protocol.handle({
            "action": "unlock",
            "password": "correct horse battery staple",
            "consolePid": 1200,
            "consoleCreateTime": 77.25,
        }, client_pid=1200)
        result = self.protocol.handle({
            "action": "launch",
            "token": "session-token",
            "request": {
                "executable": r"C:\Tools\Admin Tool.exe",
                "args": ["--profile", "alpha beta"],
                "cwd": r"C:\Tools",
            },
        }, client_pid=1200)

        self.assertEqual(result, {"ok": True, "pid": 4321})
        self.assertEqual(self.launches, [{
            "executable": r"C:\Tools\Admin Tool.exe",
            "args": ["--profile", "alpha beta"],
            "cwd": r"C:\Tools",
        }])

    def test_stop_requires_bound_token_and_passes_exact_process_identities(self):
        self.protocol.handle({
            "action": "unlock",
            "password": "correct horse battery staple",
            "consolePid": 1200,
            "consoleCreateTime": 77.25,
        }, client_pid=1200)
        request = {
            "favoriteExecutable": r"C:\Tools\Admin Tool.exe",
            "processes": [{
                "pid": 4301,
                "createTime": 1000.25,
                "executable": r"C:\Tools\Admin Tool.exe",
            }, {
                "pid": 4302,
                "createTime": 1001.5,
                "executable": r"C:\Tools\bin\Admin Tool.exe",
            }],
        }
        result = self.protocol.handle({
            "action": "stop",
            "token": "session-token",
            "request": request,
        }, client_pid=1200)

        self.assertEqual(result, {"ok": True, "stopped": [4301, 4302]})
        self.assertEqual(self.stops, [normalize_elevated_stop(request)])

    def test_observe_requires_bound_token_and_uses_structured_favorite(self):
        self.protocol.handle({
            "action": "unlock",
            "password": "correct horse battery staple",
            "consolePid": 1200,
            "consoleCreateTime": 77.25,
        }, client_pid=1200)
        request = {
            "executable": r"C:\Tools\Admin Tool.exe",
            "args": ["--profile", "alpha beta"],
            "cwd": r"C:\Tools",
        }
        result = self.protocol.handle({
            "action": "observe",
            "token": "session-token",
            "request": request,
        }, client_pid=1200)

        self.assertTrue(result["ok"])
        self.assertEqual(result["processes"][0]["pid"], 4301)
        self.assertEqual(self.observations, [normalize_elevated_launch(request)])

    def test_dead_console_invalidates_session_and_requires_password_again(self):
        self.protocol.handle({
            "action": "unlock",
            "password": "correct horse battery staple",
            "consolePid": 1200,
            "consoleCreateTime": 77.25,
        }, client_pid=1200)
        self.alive.clear()

        result = self.protocol.handle({
            "action": "status", "token": "session-token",
        }, client_pid=1200)

        self.assertEqual(result["code"], "BROKER_SESSION_INVALID")
        self.assertFalse(self.protocol.unlocked)


if __name__ == "__main__":
    unittest.main()

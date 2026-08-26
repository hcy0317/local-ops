import unittest

from localops.elevation_broker import (
    BROKER_TASK_PATH,
    ElevationBrokerProtocol,
    broker_install_request_digest,
    broker_task_spec,
    make_keepalive_registry,
    new_password_record,
    normalize_elevated_launch,
    normalize_elevated_stop,
    normalize_scheduled_request,
    verify_broker_task,
    verify_password,
    validate_keepalive_registry,
)


class PasswordVerifierTests(unittest.TestCase):
    def test_keep_alive_registry_hmac_rejects_tampering(self):
        key = b"k" * 32
        owner = "S-1-5-21-1-2-3-1001"
        key_id = "a" * 32
        registry = make_keepalive_registry(
            owner, key_id, 1, {"grant-deadbeef-01": {
                "appId": "deadbeef", "kind": "scheduledService",
                "path": r"\LocalOps\LongRunning", "active": True,
            }}, key,
        )
        revision, grants = validate_keepalive_registry(
            registry, key, owner_sid=owner, key_id=key_id
        )
        self.assertEqual(revision, 1)
        self.assertIn("grant-deadbeef-01", grants)

        registry["grants"]["grant-deadbeef-01"]["path"] = r"\Other"
        with self.assertRaises(ValueError):
            validate_keepalive_registry(
                registry, key, owner_sid=owner, key_id=key_id
            )

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
            "bundleArchive": r"C:\\Local Ops\\bundle.zip",
            "bundleSha256": "a" * 64,
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
        self.elevated_tasks = []
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
            elevated_task_launch=lambda request: (
                self.elevated_tasks.append(("launch", request)) or {
                    "ok": True, "appId": request["appId"], "running": True,
                    "pid": 4401, "startedAt": 1000,
                }
            ),
            elevated_task_query=lambda app_id: (
                self.elevated_tasks.append(("query", app_id)) or {
                    "ok": True, "appId": app_id, "found": True,
                    "running": True, "pid": 4401, "startedAt": 1000,
                }
            ),
            elevated_task_stop=lambda app_id: (
                self.elevated_tasks.append(("stop", app_id)) or {
                    "ok": True, "appId": app_id, "running": False,
                    "exitCode": 130, "completedAt": 2000,
                }
            ),
            grant_client_valid=lambda pid, created: (
                pid, created
            ) == (1200, 77.25),
            token_factory=lambda: "session-token",
        )

    def test_elevated_batch_launch_query_and_stop_have_separate_authority(self):
        request = {
            "appId": "deadbeef",
            "commandSpec": {
                "version": 1, "mode": "direct",
                "executable": r"C:\Tools\backup.exe", "args": ["--once"],
                "shell": None, "text": None, "needsReview": False,
            },
            "cwd": r"C:\Tools",
        }
        rejected = self.protocol.handle({
            "action": "elevated-task-launch", "request": request,
        }, client_pid=1200)
        self.assertEqual(rejected["code"], "BROKER_SESSION_INVALID")

        self.protocol.handle({
            "action": "unlock", "password": "correct horse battery staple",
            "consolePid": 1200, "consoleCreateTime": 77.25,
        }, client_pid=1200)
        launched = self.protocol.handle({
            "action": "elevated-task-launch", "token": "session-token",
            "request": request,
        }, client_pid=1200)
        self.assertTrue(launched["ok"])

        self.protocol.handle({
            "action": "lock", "token": "session-token",
        }, client_pid=1200)
        queried = self.protocol.handle({
            "action": "elevated-task-query", "appId": "deadbeef",
            "clientCreateTime": 77.25,
        }, client_pid=1200)
        self.assertTrue(queried["running"])
        stopped_while_locked = self.protocol.handle({
            "action": "elevated-task-stop", "appId": "deadbeef",
        }, client_pid=1200)
        self.assertEqual(stopped_while_locked["code"], "BROKER_SESSION_INVALID")

        self.protocol.handle({
            "action": "unlock", "password": "correct horse battery staple",
            "consolePid": 1200, "consoleCreateTime": 77.25,
        }, client_pid=1200)
        stopped = self.protocol.handle({
            "action": "elevated-task-stop", "token": "session-token",
            "appId": "deadbeef",
        }, client_pid=1200)
        self.assertEqual(stopped["exitCode"], 130)

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

    def test_exact_keep_alive_grant_survives_lock_and_controller_restart(self):
        persisted = []
        uses = []
        protocol = ElevationBrokerProtocol(
            self.record,
            owner_sid="S-1-5-21-1-2-3-1001",
            process_matches=lambda pid, created, owner: (
                pid, created, owner
            ) in self.alive,
            launch=lambda _request: 4321,
            observe=lambda _request: {"ok": True, "processes": []},
            stop=lambda _request: {"ok": True},
            scheduled=lambda request: {"ok": True, "operation": request["operation"]},
            token_factory=lambda: "session-token",
            grant_id_factory=lambda: "grant-deadbeef-01",
            grant_prepare=lambda request: {
                "appId": request["appId"],
                "kind": "elevatedProgram",
                "request": normalize_elevated_launch(request["request"]),
                "executableSha256": "a" * 64,
            },
            grant_execute=lambda operation, record: (
                uses.append((operation, record["appId"]))
                or ({"ok": True, "processes": []}
                    if operation == "observe" else {"ok": True, "pid": 4321})
            ),
            grant_client_valid=lambda pid, created: (
                pid, created
            ) in {(1200, 77.25), (1300, 88.5)},
            persist_grants=lambda records: persisted.append(dict(records)),
        )
        protocol.handle({
            "action": "unlock",
            "password": "correct horse battery staple",
            "consolePid": 1200,
            "consoleCreateTime": 77.25,
        }, client_pid=1200)
        issued = protocol.handle({
            "action": "keepalive-grant-issue",
            "token": "session-token",
            "request": {
                "appId": "deadbeef",
                "kind": "elevatedProgram",
                "request": {
                    "executable": r"C:\Tools\Admin Tool.exe",
                    "args": ["--profile", "alpha beta"],
                    "cwd": r"C:\Tools",
                },
            },
        }, client_pid=1200)
        self.assertEqual(issued["grantId"], "grant-deadbeef-01")
        activated = protocol.handle({
            "action": "keepalive-grant-activate",
            "token": "session-token",
            "grantId": issued["grantId"],
            "appId": "deadbeef",
            "bindingDigest": issued["resourceDigest"],
        }, client_pid=1200)
        self.assertTrue(activated["ok"])

        protocol.handle({
            "action": "lock", "token": "session-token",
        }, client_pid=1200)
        used = protocol.handle({
            "action": "keepalive-grant-use",
            "grantId": issued["grantId"],
            "appId": "deadbeef",
            "bindingDigest": issued["resourceDigest"],
            "operation": "observe",
            "clientCreateTime": 88.5,
        }, client_pid=1300)
        self.assertTrue(used["ok"])
        self.assertEqual(uses, [("observe", "deadbeef")])
        self.assertIn("leaseId", used)
        launched = protocol.handle({
            "action": "keepalive-grant-use",
            "grantId": issued["grantId"],
            "appId": "deadbeef",
            "bindingDigest": issued["resourceDigest"],
            "operation": "launch",
            "leaseId": used["leaseId"],
            "clientCreateTime": 88.5,
        }, client_pid=1300)
        self.assertTrue(launched["ok"])
        replay = protocol.handle({
            "action": "keepalive-grant-use",
            "grantId": issued["grantId"],
            "appId": "deadbeef",
            "bindingDigest": issued["resourceDigest"],
            "operation": "launch",
            "leaseId": used["leaseId"],
            "clientCreateTime": 88.5,
        }, client_pid=1300)
        self.assertEqual(replay["code"], "BROKER_KEEPALIVE_LEASE_INVALID")

        revoked = protocol.handle({
            "action": "keepalive-grant-revoke",
            "grantId": issued["grantId"],
            "appId": "deadbeef",
            "bindingDigest": issued["resourceDigest"],
            "clientCreateTime": 88.5,
        }, client_pid=1300)
        self.assertTrue(revoked["ok"])
        already_absent = protocol.handle({
            "action": "keepalive-grant-revoke",
            "grantId": issued["grantId"],
            "appId": "deadbeef",
            "bindingDigest": issued["resourceDigest"],
            "clientCreateTime": 88.5,
        }, client_pid=1300)
        self.assertTrue(already_absent["alreadyAbsent"])
        rejected = protocol.handle({
            "action": "keepalive-grant-use",
            "grantId": issued["grantId"],
            "appId": "deadbeef",
            "bindingDigest": issued["resourceDigest"],
            "operation": "observe",
            "clientCreateTime": 88.5,
        }, client_pid=1300)
        self.assertEqual(rejected["code"], "BROKER_KEEPALIVE_GRANT_INVALID")
        self.assertGreaterEqual(len(persisted), 2)


if __name__ == "__main__":
    unittest.main()

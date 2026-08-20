import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
import uuid
from unittest import mock

import server

from localops.command_spec import direct_command_spec
from localops.platform.contracts import (
    ManagedActivation,
    ManagedInspection,
    ManagedRuntime,
    PlatformCapabilities,
    Principal,
    RuntimeIdentity,
    StopResult,
)
from localops.platform.fake import FakePlatform
from tests.windows.test_windows_server import HttpHarness


def runtime_identity(app_id="deadbeef", generation=None):
    generation = generation or str(uuid.uuid4())
    owner = (
        server.SELF_PRINCIPAL.identifier
        if server.PLATFORM.name == "windows"
        else "S-1-5-21-1000"
    )
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
            app_id, generation, "a" * 16
        ),
        "tokenDigest": "sha256:" + "a" * 64,
        "startedAt": 1780000001456,
    }


def windows_capabilities(**overrides):
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


def native_identity(app_id="deadbeef", generation=None):
    public = runtime_identity(app_id, generation)
    return RuntimeIdentity(
        platform="windows",
        kind="job",
        identifier=public["jobName"],
        owner=public["ownerSid"],
        members=(public["rootPid"],),
        app_id=app_id,
        generation_id=public["generationId"],
        runner_pid=public["runnerPid"],
        runner_create_time=public["runnerCreateTime"],
        root_pid=public["rootPid"],
        root_create_time=public["rootCreateTime"],
        job_name=public["jobName"],
        token_digest=public["tokenDigest"],
        started_at=public["startedAt"],
    )


class RuntimeIdentityConfigTests(unittest.TestCase):
    def test_runtime_identity_round_trips_through_config(self):
        identity = runtime_identity()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.json")
            payload = {
                **server.Config.DEFAULT,
                "apps": [{
                    **server.Config.APP_DEFAULT,
                    "id": "deadbeef",
                    "name": "Managed",
                    "command": "python.exe -m http.server",
                    "runtimeIdentity": identity,
                }],
            }
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)

            config = server.Config(path)

        self.assertEqual(
            config.snapshot()["apps"][0]["runtimeIdentity"], identity
        )

    def test_runtime_identity_rejects_unknown_or_unbound_fields(self):
        identity = runtime_identity()
        with self.assertRaises(server.ConfigSchemaError):
            server.normalize_runtime_identity(
                {**identity, "receiptPath": "C:\\secret"}, "deadbeef"
            )
        with self.assertRaises(server.ConfigSchemaError):
            server.normalize_runtime_identity(identity, "facefeed")

    def test_runtime_identity_rejects_job_name_not_derived_from_digest(self):
        identity = runtime_identity()
        identity["jobName"] = identity["jobName"][:-16] + "b" * 16
        with self.assertRaises(server.ConfigSchemaError):
            server.normalize_runtime_identity(identity, "deadbeef")

    def test_config_load_rejects_invalid_persisted_runtime_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.json")
            payload = {
                **server.Config.DEFAULT,
                "apps": [{
                    **server.Config.APP_DEFAULT,
                    "id": "deadbeef",
                    "name": "Invalid",
                    "command": "echo safe",
                    "runtimeIdentity": {"pid": 123},
                }],
            }
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            config = server.Config(path)
        self.assertFalse(config.health_info()["writable"])
        self.assertEqual(config.snapshot()["apps"], [])

    def test_generation_mismatch_does_not_write_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.json")
            config = server.Config(path)
            config.update(lambda data: data["apps"].append({
                **server.Config.APP_DEFAULT,
                "id": "deadbeef",
                "name": "Stopped",
                "command": "echo safe",
            }))
            with open(path, "rb") as handle:
                before = handle.read()

            status, result, actual = config.mutate_app_if_generation(
                "deadbeef",
                str(uuid.uuid4()),
                lambda _data, app: app.__setitem__("name", "changed"),
            )

            with open(path, "rb") as handle:
                after = handle.read()
        self.assertEqual((status, result, actual), ("mismatch", None, None))
        self.assertEqual(after, before)
        self.assertEqual(config.snapshot()["apps"][0]["name"], "Stopped")

    def test_public_serializer_does_not_expose_internal_runtime_context(self):
        identity = runtime_identity()
        native = server.RuntimeIdentity(
            platform="windows",
            kind="job",
            identifier=identity["jobName"],
            owner=identity["ownerSid"],
            token=None,
            app_id="deadbeef",
            generation_id=identity["generationId"],
            runner_pid=identity["runnerPid"],
            runner_create_time=identity["runnerCreateTime"],
            root_pid=identity["rootPid"],
            root_create_time=identity["rootCreateTime"],
            job_name=identity["jobName"],
            token_digest=identity["tokenDigest"],
            started_at=identity["startedAt"],
        )
        with mock.patch.object(server.PLATFORM, "name", "windows"), \
                mock.patch.object(
                    server, "SELF_PRINCIPAL",
                    SimplePrincipal(identity["ownerSid"])
                ):
            public = server.public_runtime_identity(native, "deadbeef")
        self.assertEqual(public, identity)
        self.assertNotIn("appId", public)
        self.assertNotIn("token", public)


class SimplePrincipal:
    def __init__(self, identifier):
        self.identifier = identifier


class LifecycleStateTests(unittest.TestCase):
    def test_unverified_runtime_is_not_rendered_as_stopped(self):
        identity = runtime_identity()
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef",
            "name": "Managed",
            "command": "echo safe",
            "runtimeIdentity": identity,
        }
        inspection = ManagedInspection(
            running=False,
            verified=False,
            status="unknown",
            code="RUNTIME_IDENTITY_UNVERIFIED",
        )
        with mock.patch.object(server.PLATFORM, "name", "windows"), \
                mock.patch.object(
                    server, "SELF_PRINCIPAL",
                    SimplePrincipal(identity["ownerSid"])
                ), \
                mock.patch.object(
                    server.PLATFORM, "inspect_managed", return_value=inspection
                ):
            row = server.build_apps({"apps": [app]}, set())[0]
        self.assertEqual(row["lifecycleStatus"], "unknown")
        self.assertFalse(row["running"])
        self.assertFalse(row["controlAvailable"])
        self.assertEqual(
            row["runtimeIssue"]["code"], "RUNTIME_IDENTITY_UNVERIFIED"
        )

    def test_verified_running_runtime_is_controllable(self):
        identity = runtime_identity()
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef",
            "name": "Managed",
            "command": "echo safe",
            "runtimeIdentity": identity,
        }
        inspection = ManagedInspection(
            running=True,
            verified=True,
            members=(identity["rootPid"],),
            status="running",
            identity=native_identity("deadbeef", identity["generationId"]),
        )
        with mock.patch.object(server.PLATFORM, "name", "windows"), \
                mock.patch.object(
                    server, "SELF_PRINCIPAL",
                    SimplePrincipal(identity["ownerSid"])
                ), \
                mock.patch.object(
                    server.PLATFORM, "inspect_managed", return_value=inspection
                ):
            row = server.build_apps({"apps": [app]}, set())[0]
        self.assertEqual(row["lifecycleStatus"], "running")
        self.assertTrue(row["running"])
        self.assertTrue(row["controlAvailable"])
        self.assertEqual(row["runtimeIdentity"], identity)

    def test_verified_terminal_runtime_is_deletable_without_process_control(self):
        identity = runtime_identity()
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef",
            "name": "Completed task",
            "command": "echo safe",
            "runtimeIdentity": identity,
        }
        inspection = ManagedInspection(
            running=False,
            verified=True,
            members=(),
            status="exited",
            identity=native_identity("deadbeef", identity["generationId"]),
        )
        with mock.patch.object(server.PLATFORM, "name", "windows"), \
                mock.patch.object(
                    server, "SELF_PRINCIPAL", SimplePrincipal(identity["ownerSid"])
                ), \
                mock.patch.object(
                    server.PLATFORM, "inspect_managed", return_value=inspection
                ):
            row = server.build_apps({"apps": [app]}, set())[0]

        self.assertEqual(row["lifecycleStatus"], "unknown")
        self.assertFalse(row["controlAvailable"])
        self.assertTrue(row["deleteAvailable"])

    def test_prepared_runtime_is_starting_but_not_legacy_running(self):
        identity = runtime_identity()
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef",
            "name": "Managed",
            "command": "echo safe",
            "runtimeIdentity": identity,
        }
        inspection = ManagedInspection(
            running=True,
            verified=True,
            members=(identity["rootPid"],),
            status="prepared",
            identity=native_identity("deadbeef", identity["generationId"]),
        )
        with mock.patch.object(server.PLATFORM, "name", "windows"), \
                mock.patch.object(
                    server, "SELF_PRINCIPAL",
                    SimplePrincipal(identity["ownerSid"])
                ), \
                mock.patch.object(
                    server.PLATFORM, "inspect_managed", return_value=inspection
                ):
            row = server.build_apps({"apps": [app]}, set())[0]
        self.assertEqual(row["lifecycleStatus"], "starting")
        self.assertFalse(row["running"])
        self.assertFalse(row["controlAvailable"])

    def test_insecure_runtime_record_is_orphaned_and_not_controllable(self):
        identity = runtime_identity()
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef",
            "name": "Managed",
            "command": "echo safe",
            "runtimeIdentity": identity,
        }
        inspection = ManagedInspection(
            running=False,
            verified=False,
            status="unknown",
            code="RUNTIME_RECORD_INSECURE",
        )
        with mock.patch.object(server.PLATFORM, "name", "windows"), \
                mock.patch.object(
                    server, "SELF_PRINCIPAL",
                    SimplePrincipal(identity["ownerSid"])
                ), \
                mock.patch.object(
                    server.PLATFORM, "inspect_managed", return_value=inspection
                ):
            row = server.build_apps({"apps": [app]}, set())[0]
        self.assertEqual(row["lifecycleStatus"], "orphaned")
        self.assertFalse(row["running"])
        self.assertFalse(row["controlAvailable"])
        self.assertEqual(row["runtimeIssue"]["code"], "RUNTIME_RECORD_INSECURE")

    def test_verified_flag_without_exact_identity_is_not_controllable(self):
        identity = runtime_identity()
        app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef",
            "name": "Managed",
            "command": "echo safe",
            "runtimeIdentity": identity,
        }
        inspection = ManagedInspection(
            running=True,
            verified=True,
            members=(identity["rootPid"],),
            status="running",
            identity=None,
        )
        with mock.patch.object(server.PLATFORM, "name", "windows"), \
                mock.patch.object(
                    server, "SELF_PRINCIPAL",
                    SimplePrincipal(identity["ownerSid"])
                ), \
                mock.patch.object(
                    server.PLATFORM, "inspect_managed", return_value=inspection
                ):
            row = server.build_apps({"apps": [app]}, set())[0]
        self.assertEqual(row["lifecycleStatus"], "unknown")
        self.assertFalse(row["running"])
        self.assertFalse(row["controlAvailable"])


class WindowsLifecycleTransactionTests(unittest.TestCase):
    generation = "3d6448f0-87a0-4ace-baad-3b80abca9e3e"

    def setUp(self):
        with server._WINDOWS_RELEASE_LOCK:
            server._WINDOWS_PENDING_RELEASES.clear()
        self.directory = tempfile.TemporaryDirectory()
        self.cfg = server.Config(
            os.path.join(self.directory.name, "config.json")
        )
        self.app = {
            **server.Config.APP_DEFAULT,
            "id": "deadbeef",
            "name": "Managed",
            "command": sys.executable,
            "commandSpec": direct_command_spec(sys.executable),
            "cwd": self.directory.name,
            "importStatus": "ready",
        }
        self.cfg.update(lambda data: data["apps"].append(self.app))
        self.identity = native_identity("deadbeef", self.generation)
        self.platform = FakePlatform(
            name="windows",
            principal=Principal(self.identity.owner),
            capabilities=windows_capabilities(),
            launch_result=ManagedRuntime(
                ok=True,
                runtime_identity=self.identity,
                status="prepared",
            ),
            activation_result=ManagedActivation(
                ok=True, status="running", process_id=self.identity.root_pid
            ),
            inspection=ManagedInspection(
                running=True,
                verified=True,
                members=(self.identity.root_pid,),
                status="running",
                identity=self.identity,
            ),
            stop_result=StopResult(ok=True, status="exited"),
        )
        self.platform_patch = mock.patch.object(server, "PLATFORM", self.platform)
        self.principal_patch = mock.patch.object(
            server, "SELF_PRINCIPAL", self.platform.principal
        )
        self.uid_patch = mock.patch.object(
            server, "SELF_UID", self.platform.principal.numeric_id
        )
        self.logs_patch = mock.patch.object(
            server, "LOGS_DIR", os.path.join(self.directory.name, "logs")
        )
        self.uuid_patch = mock.patch.object(
            server.uuid, "uuid4", return_value=uuid.UUID(self.generation)
        )
        self.platform_patch.start()
        self.principal_patch.start()
        self.uid_patch.start()
        self.logs_patch.start()
        self.uuid_patch.start()

    def tearDown(self):
        with server._WINDOWS_RELEASE_LOCK:
            server._WINDOWS_PENDING_RELEASES.clear()
        self.uuid_patch.stop()
        self.logs_patch.stop()
        self.uid_patch.stop()
        self.principal_patch.stop()
        self.platform_patch.stop()
        self.directory.cleanup()

    def current_app(self):
        return self.cfg.snapshot()["apps"][0]

    def test_start_persists_prepared_identity_before_activate(self):
        result = server.start_windows_app(self.cfg, self.current_app())

        self.assertTrue(result["ok"])
        self.assertEqual(result["generationId"], self.generation)
        self.assertEqual(
            self.current_app()["runtimeIdentity"],
            server.public_runtime_identity(self.identity, "deadbeef"),
        )
        call_names = [name for name, _ in self.platform.calls]
        self.assertLess(call_names.index("launch"), call_names.index("activate_managed"))
        self.assertLess(
            call_names.index("activate_managed"), call_names.index("inspect_managed")
        )
        launch_request = next(
            value for name, value in self.platform.calls if name == "launch"
        )
        self.assertEqual(launch_request.generation_id, self.generation)
        self.assertEqual(launch_request.command_spec, self.app["commandSpec"])

    def test_commit_failure_aborts_before_activation(self):
        with mock.patch.object(
                self.cfg, "mutate_app_if_generation",
                side_effect=OSError("write failed")):
            result = server.start_windows_app(self.cfg, self.current_app())

        self.assertEqual(result["code"], "LAUNCH_COMMIT_FAILED")
        call_names = [name for name, _ in self.platform.calls]
        self.assertIn("abort_managed", call_names)
        self.assertIn("release_managed", call_names)
        self.assertNotIn("activate_managed", call_names)
        self.assertIsNone(self.current_app()["runtimeIdentity"])

    def test_post_commit_acl_failure_aborts_before_activation(self):
        original_ensure = self.platform.ensure_private_file

        def fail_final_config_verification(path):
            if os.path.abspath(path) == os.path.abspath(self.cfg._path):
                raise OSError("final ACL verification failed")
            return original_ensure(path)

        with mock.patch.object(
                self.platform, "ensure_private_file",
                side_effect=fail_final_config_verification):
            result = server.start_windows_app(self.cfg, self.current_app())

        self.assertEqual(result["code"], "LAUNCH_COMMIT_FAILED")
        self.assertFalse(self.cfg.health_info()["writable"])
        call_names = [name for name, _ in self.platform.calls]
        self.assertIn("abort_managed", call_names)
        self.assertNotIn("release_managed", call_names)
        self.assertNotIn("activate_managed", call_names)
        self.assertEqual(
            server.runtime_generation(self.current_app()), self.generation
        )

    def test_partial_prepare_failure_with_identity_is_aborted(self):
        self.platform.launch_result = ManagedRuntime(
            ok=False,
            code="LAUNCH_PREPARE_FAILED",
            runtime_identity=self.identity,
            status="prepared",
        )

        result = server.start_windows_app(self.cfg, self.current_app())

        self.assertEqual(result["code"], "LAUNCH_PREPARE_FAILED")
        call_names = [name for name, _ in self.platform.calls]
        self.assertIn("abort_managed", call_names)
        self.assertIn("release_managed", call_names)
        self.assertNotIn("activate_managed", call_names)
        self.assertIsNone(self.current_app()["runtimeIdentity"])

    def test_read_only_config_rejects_before_prepare(self):
        self.cfg._writable = False

        result = server.start_windows_app(self.cfg, self.current_app())

        self.assertEqual(result["code"], "LAUNCH_COMMIT_FAILED")
        self.assertNotIn("launch", [name for name, _ in self.platform.calls])

    def test_unexpected_prepared_status_retains_ambiguous_identity(self):
        self.platform.launch_result = ManagedRuntime(
            ok=True,
            runtime_identity=self.identity,
            status="unknown",
        )
        self.platform.stop_result = StopResult(
            False, "abort response unavailable", still_running=True,
            status="unknown", code="RUNTIME_CONTROL_FAILED",
        )

        result = server.start_windows_app(self.cfg, self.current_app())

        self.assertEqual(result["code"], "LAUNCH_PREPARE_FAILED")
        self.assertEqual(
            server.runtime_generation(self.current_app()), self.generation
        )
        self.assertNotIn(
            "activate_managed", [name for name, _ in self.platform.calls]
        )

    def test_ambiguous_partial_prepare_is_reconciled_after_controller_restart(self):
        self.platform.launch_result = ManagedRuntime(
            ok=False,
            code="LAUNCH_PREPARE_FAILED",
            runtime_identity=self.identity,
            status="failed",
        )
        self.platform.stop_result = StopResult(
            False, "abort response unavailable", still_running=True,
            status="unknown", code="RUNTIME_CONTROL_FAILED",
        )

        result = server.start_windows_app(self.cfg, self.current_app())

        self.assertEqual(result["code"], "LAUNCH_PREPARE_FAILED")
        self.assertEqual(
            server.runtime_generation(self.current_app()), self.generation
        )

        # The in-memory retry queue disappears with the controller. The exact
        # identity retained in config is the durable reconciliation source.
        with server._WINDOWS_RELEASE_LOCK:
            server._WINDOWS_PENDING_RELEASES.clear()
        self.platform.stop_result = StopResult(True, status="failed")
        self.platform.inspection = ManagedInspection(
            running=False,
            verified=True,
            members=(),
            status="failed",
            identity=self.identity,
        )

        server.reconcile_windows_terminal_runtimes(self.cfg)

        self.assertIsNone(self.current_app()["runtimeIdentity"])
        self.assertIn(
            "release_managed", [name for name, _ in self.platform.calls]
        )

    def test_terminal_cleanup_is_recovered_without_config_identity_after_restart(self):
        self.platform.cleanup_recoveries = [self.identity]
        with server._WINDOWS_RELEASE_LOCK:
            server._WINDOWS_PENDING_RELEASES.clear()

        server.reconcile_windows_terminal_runtimes(self.cfg)

        self.assertIn(
            "recover_managed_cleanups", [name for name, _ in self.platform.calls]
        )
        self.assertIn(
            "release_managed", [name for name, _ in self.platform.calls]
        )
        with server._WINDOWS_RELEASE_LOCK:
            self.assertNotIn(
                ("deadbeef", self.generation), server._WINDOWS_PENDING_RELEASES
            )

    def test_ambiguous_unpersisted_abort_is_queued_for_safe_release_retry(self):
        self.platform.stop_result = StopResult(
            False, "abort response unavailable", still_running=True,
            status="unknown", code="RUNTIME_CONTROL_FAILED",
        )
        with mock.patch.object(
                self.cfg, "mutate_app_if_generation",
                side_effect=OSError("write failed")):
            result = server.start_windows_app(self.cfg, self.current_app())

        self.assertEqual(result["code"], "LAUNCH_COMMIT_FAILED")
        self.assertNotIn(
            "release_managed", [name for name, _ in self.platform.calls]
        )
        with server._WINDOWS_RELEASE_LOCK:
            pending = server._WINDOWS_PENDING_RELEASES[
                ("deadbeef", self.generation)
            ]
            self.assertEqual(pending["identity"], self.identity)

    def test_retry_waits_for_ambiguous_identity_persistence(self):
        key = ("deadbeef", self.generation)
        persist_entered = threading.Event()
        allow_persist = threading.Event()
        retry_started = threading.Event()
        release_entered = threading.Event()
        release_calls = []
        decisions = []
        thread_errors = []
        original_mutate = self.cfg.mutate_app_if_generation

        def fail_abort(_identity):
            return StopResult(
                False, "abort response unavailable", still_running=True,
                status="unknown", code="RUNTIME_CONTROL_FAILED",
            )

        def block_identity_persist(app_id, expected_generation, fn):
            with server._WINDOWS_RELEASE_LOCK:
                server._WINDOWS_PENDING_RELEASES[key]["nextAttempt"] = 0.0
            persist_entered.set()
            if not allow_persist.wait(2):
                raise AssertionError("identity persist gate timed out")
            return original_mutate(app_id, expected_generation, fn)

        def release(identity):
            release_calls.append(identity.generation_id)
            release_entered.set()
            return StopResult(True, status="failed")

        def capture(action):
            try:
                action()
            except BaseException as exc:  # surface worker-thread assertions
                thread_errors.append(exc)

        with mock.patch.object(
                self.platform, "abort_managed", side_effect=fail_abort), \
                mock.patch.object(
                    self.platform, "release_managed", side_effect=release), \
                mock.patch.object(
                    self.cfg, "mutate_app_if_generation",
                    side_effect=block_identity_persist):
            decision_thread = threading.Thread(
                target=lambda: capture(lambda: decisions.append(
                    server._abort_or_retain_windows_runtime(
                        self.cfg, "deadbeef", self.identity
                    )
                )),
                name="windows-identity-decision",
            )
            decision_thread.start()
            self.assertTrue(persist_entered.wait(1))

            retry_thread = threading.Thread(
                target=lambda: (
                    retry_started.set(),
                    capture(lambda: server._retry_windows_pending_releases(
                        self.cfg
                    )),
                ),
                name="windows-identity-retry",
            )
            retry_thread.start()
            self.assertTrue(retry_started.wait(1))
            released_before_persist = release_entered.wait(0.5)
            allow_persist.set()
            decision_thread.join(2)
            retry_thread.join(2)

        self.assertFalse(decision_thread.is_alive())
        self.assertFalse(retry_thread.is_alive())
        self.assertEqual(thread_errors, [])
        self.assertFalse(released_before_persist)
        self.assertEqual(release_calls, [])
        self.assertEqual(decisions, [True])
        self.assertEqual(
            server.runtime_generation(self.current_app()), self.generation
        )
        with server._WINDOWS_RELEASE_LOCK:
            self.assertIn(key, server._WINDOWS_PENDING_RELEASES)

    def test_state_snapshot_does_not_invert_config_and_cache_locks(self):
        config_locked = threading.Event()
        allow_update = threading.Event()
        snapshot_attempted = threading.Event()
        snapshot_timed_out = threading.Event()
        update_finished = threading.Event()
        results = []
        thread_errors = []
        stale_snapshot = self.cfg.snapshot()
        health = self.cfg.health_info()
        original_snapshot = self.cfg.snapshot
        cache = {"mono": 0.0, "state": None, "epoch": 0}

        def hold_config(data):
            data["watchedKeywords"] = ["updated"]
            config_locked.set()
            if not allow_update.wait(2):
                raise AssertionError("config update gate timed out")

        def coordinated_snapshot():
            snapshot_attempted.set()
            acquired = self.cfg._lock.acquire(timeout=0.5)
            if not acquired:
                snapshot_timed_out.set()
                return stale_snapshot
            try:
                return original_snapshot()
            finally:
                self.cfg._lock.release()

        def build(data, _console_port, _health):
            return {"watchedKeywords": list(data["watchedKeywords"])}

        def capture(action):
            try:
                action()
            except BaseException as exc:  # surface worker-thread assertions
                thread_errors.append(exc)

        def run_update():
            capture(lambda: self.cfg.update(hold_config))
            update_finished.set()

        def run_snapshot():
            capture(lambda: results.append(
                server.get_state_snapshot(self.cfg, 9600)
            ))

        with mock.patch.object(server, "_state_cache_lock", threading.Lock()), \
                mock.patch.object(
                    server, "_state_build_lock", threading.Lock(), create=True), \
                mock.patch.object(server, "_state_cache", cache), \
                mock.patch.object(
                    server, "reconcile_windows_terminal_runtimes",
                    return_value=None), \
                mock.patch.object(server, "build_state", side_effect=build), \
                mock.patch.object(
                    self.cfg, "snapshot", side_effect=coordinated_snapshot), \
                mock.patch.object(
                    self.cfg, "health_info", return_value=health):
            update_thread = threading.Thread(
                target=run_update, name="config-update"
            )
            update_thread.start()
            self.assertTrue(config_locked.wait(1))

            snapshot_thread = threading.Thread(
                target=run_snapshot, name="state-snapshot"
            )
            snapshot_thread.start()
            self.assertTrue(snapshot_attempted.wait(1))
            allow_update.set()
            update_thread.join(2)
            snapshot_thread.join(2)

        self.assertFalse(update_thread.is_alive())
        self.assertFalse(snapshot_thread.is_alive())
        self.assertTrue(update_finished.is_set())
        self.assertFalse(snapshot_timed_out.is_set())
        self.assertEqual(thread_errors, [])
        self.assertEqual(results, [{"watchedKeywords": ["updated"]}])

    def test_invalidated_state_build_never_publishes_stale_snapshot(self):
        build_started = threading.Event()
        allow_build = threading.Event()
        update_finished = threading.Event()
        build_inputs = []
        results = []
        thread_errors = []
        cache_lock = threading.Lock()
        cache = {"mono": 0.0, "state": None, "epoch": 0}

        def build(data, _console_port, _health):
            keywords = list(data["watchedKeywords"])
            build_inputs.append(keywords)
            if len(build_inputs) == 1:
                build_started.set()
                if not allow_build.wait(2):
                    raise AssertionError("state build gate timed out")
            return {"watchedKeywords": keywords}

        def capture(action):
            try:
                action()
            except BaseException as exc:  # surface worker-thread assertions
                thread_errors.append(exc)

        def run_snapshot():
            capture(lambda: results.append(
                server.get_state_snapshot(self.cfg, 9600)
            ))

        def run_update():
            capture(lambda: self.cfg.update(
                lambda data: data.__setitem__(
                    "watchedKeywords", ["fresh"]
                )
            ))
            update_finished.set()

        with mock.patch.object(server, "_state_cache_lock", cache_lock), \
                mock.patch.object(
                    server, "_state_build_lock", threading.Lock()), \
                mock.patch.object(server, "_state_cache", cache), \
                mock.patch.object(
                    server, "reconcile_windows_terminal_runtimes",
                    return_value=None), \
                mock.patch.object(server, "build_state", side_effect=build):
            snapshot_thread = threading.Thread(
                target=run_snapshot, name="stale-state-build"
            )
            snapshot_thread.start()
            self.assertTrue(build_started.wait(1))

            update_thread = threading.Thread(
                target=run_update, name="state-invalidating-update"
            )
            update_thread.start()
            update_finished_before_release = update_finished.wait(0.5)
            allow_build.set()
            update_thread.join(2)
            snapshot_thread.join(2)

        self.assertFalse(update_thread.is_alive())
        self.assertFalse(snapshot_thread.is_alive())
        self.assertTrue(update_finished_before_release)
        self.assertEqual(thread_errors, [])
        self.assertEqual(build_inputs, [[], ["fresh"]])
        self.assertEqual(results, [{"watchedKeywords": ["fresh"]}])
        with cache_lock:
            self.assertEqual(
                cache["state"], {"watchedKeywords": ["fresh"]}
            )

    def test_ambiguous_activation_keeps_identity_for_reconciliation(self):
        self.platform.activation_result = ManagedActivation(
            ok=False, code="LAUNCH_ACTIVATE_FAILED"
        )
        self.platform.inspection = ManagedInspection(
            running=False,
            verified=False,
            status="unknown",
            code="RUNTIME_IDENTITY_UNVERIFIED",
        )

        result = server.start_windows_app(self.cfg, self.current_app())

        self.assertEqual(result["code"], "LAUNCH_ACTIVATE_FAILED")
        self.assertEqual(
            server.runtime_generation(self.current_app()), self.generation
        )
        self.assertNotIn(
            "abort_managed", [name for name, _ in self.platform.calls]
        )

    def test_stop_timeout_retains_same_generation(self):
        self._persist_identity()
        self.platform.stop_result = StopResult(
            ok=False,
            still_running=True,
            status="stopping",
            code="STOP_TIMEOUT",
        )

        result = server.stop_windows_app(
            self.cfg, self.current_app(), force=False, timeout=0.25
        )

        self.assertEqual(result["code"], "STOP_TIMEOUT")
        self.assertEqual(
            server.runtime_generation(self.current_app()), self.generation
        )
        stop_call = next(
            value for name, value in self.platform.calls if name == "stop_managed"
        )
        self.assertEqual(stop_call[1:], (False, 0.25))

    def test_stop_clears_only_after_verified_terminal_empty_job(self):
        self._persist_identity()
        running = self.platform.inspection
        terminal = ManagedInspection(
            running=False,
            verified=True,
            members=(),
            status="exited",
            identity=self.identity,
        )
        with mock.patch.object(
                self.platform, "inspect_managed",
                side_effect=[running, terminal]):
            result = server.stop_windows_app(
                self.cfg, self.current_app(), force=True, timeout=1.0
            )

        self.assertTrue(result["ok"])
        self.assertIsNone(self.current_app()["runtimeIdentity"])
        self.assertIn(
            "release_managed", [name for name, _ in self.platform.calls]
        )

    def test_terminal_cleanup_failure_retains_identity_and_retries(self):
        self._persist_identity()
        running = self.platform.inspection
        terminal = ManagedInspection(
            running=False,
            verified=True,
            members=(),
            status="exited",
            identity=self.identity,
        )
        release_results = iter((
            StopResult(False, "cleanup unavailable", status="unknown"),
            StopResult(True, status="exited"),
        ))
        with mock.patch.object(
                self.platform, "inspect_managed",
                side_effect=[running, terminal, terminal]), \
                mock.patch.object(
                    self.platform, "release_managed",
                    side_effect=release_results):
            result = server.stop_windows_app(
                self.cfg, self.current_app(), force=True, timeout=1.0
            )
            self.assertEqual(result["code"], "RUNTIME_CONTROL_FAILED")
            self.assertEqual(
                server.runtime_generation(self.current_app()), self.generation
            )
            with server._WINDOWS_RELEASE_LOCK:
                pending = server._WINDOWS_PENDING_RELEASES[
                    ("deadbeef", self.generation)
                ]
                pending["nextAttempt"] = 0.0
            server.reconcile_windows_terminal_runtimes(self.cfg)

        self.assertIsNone(self.current_app()["runtimeIdentity"])
        with server._WINDOWS_RELEASE_LOCK:
            self.assertNotIn(
                ("deadbeef", self.generation), server._WINDOWS_PENDING_RELEASES
            )

    def test_reconcile_cannot_release_during_generation_clear_transaction(self):
        self._persist_identity()
        terminal = ManagedInspection(
            running=False,
            verified=True,
            members=(),
            status="exited",
            identity=self.identity,
        )
        first_entered = threading.Event()
        allow_first = threading.Event()
        release_finished = threading.Event()
        release_calls = []
        thread_errors = []

        def release(identity):
            release_calls.append(identity.generation_id)
            first_entered.set()
            if not allow_first.wait(2):
                raise AssertionError("release gate timed out")
            release_finished.set()
            return StopResult(True, status="exited")

        def recover():
            return () if release_finished.is_set() else (self.identity,)

        def capture(action):
            try:
                action()
            except BaseException as exc:  # surface worker-thread assertions
                thread_errors.append(exc)

        with mock.patch.object(
                self.platform, "release_managed", side_effect=release), \
                mock.patch.object(
                    self.platform, "recover_managed_cleanups", side_effect=recover):
            clear_thread = threading.Thread(
                target=lambda: capture(lambda: server._clear_windows_generation(
                    self.cfg, self.current_app(), terminal
                )),
                name="windows-generation-clear",
            )
            clear_thread.start()
            self.assertTrue(first_entered.wait(1))

            retry_thread = threading.Thread(
                target=lambda: capture(
                    lambda: server._retry_windows_pending_releases(self.cfg)
                ),
                name="windows-generation-recovery",
            )
            retry_thread.start()
            self.assertFalse(release_finished.wait(0.1))
            self.assertEqual(release_calls, [self.generation])
            allow_first.set()
            clear_thread.join(2)
            retry_thread.join(2)

        self.assertFalse(clear_thread.is_alive())
        self.assertFalse(retry_thread.is_alive())
        self.assertEqual(thread_errors, [])
        self.assertEqual(release_calls, [self.generation])
        self.assertIsNone(self.current_app()["runtimeIdentity"])
        with server._WINDOWS_RELEASE_LOCK:
            self.assertNotIn(
                ("deadbeef", self.generation), server._WINDOWS_PENDING_RELEASES
            )

    def test_terminal_cleanup_retries_when_identity_restore_is_unavailable(self):
        self._persist_identity()
        running = self.platform.inspection
        terminal = ManagedInspection(
            running=False,
            verified=True,
            members=(),
            status="exited",
            identity=self.identity,
        )
        original_mutate = self.cfg.mutate_app_if_generation

        def fail_identity_restore(app_id, expected_generation, fn):
            if expected_generation is None:
                raise OSError("config is read only after terminal commit")
            return original_mutate(app_id, expected_generation, fn)

        with mock.patch.object(
                self.platform, "inspect_managed",
                side_effect=[running, terminal]), \
                mock.patch.object(
                    self.platform, "release_managed",
                    return_value=StopResult(
                        False, "cleanup unavailable", status="unknown"
                    )), \
                mock.patch.object(
                    self.cfg, "mutate_app_if_generation",
                    side_effect=fail_identity_restore):
            result = server.stop_windows_app(
                self.cfg, self.current_app(), force=True, timeout=1.0
            )

        self.assertEqual(result["code"], "RUNTIME_CONTROL_FAILED")
        self.assertIsNone(self.current_app()["runtimeIdentity"])
        key = ("deadbeef", self.generation)
        with server._WINDOWS_RELEASE_LOCK:
            pending = server._WINDOWS_PENDING_RELEASES[key]
            self.assertEqual(pending["identity"], self.identity)
            pending["nextAttempt"] = 0.0
        with mock.patch.object(
                self.platform, "release_managed",
                return_value=StopResult(True, status="exited")):
            server.reconcile_windows_terminal_runtimes(self.cfg)
        with server._WINDOWS_RELEASE_LOCK:
            self.assertNotIn(key, server._WINDOWS_PENDING_RELEASES)

    def test_explicit_force_can_finish_same_verified_stopping_generation(self):
        self._persist_identity()
        stopping = ManagedInspection(
            running=True,
            verified=True,
            members=(self.identity.root_pid,),
            status="stopping",
            identity=self.identity,
        )
        terminal = ManagedInspection(
            running=False,
            verified=True,
            members=(),
            status="exited",
            identity=self.identity,
        )
        with mock.patch.object(
                self.platform, "inspect_managed",
                side_effect=[stopping, terminal]):
            result = server.stop_windows_app(
                self.cfg, self.current_app(), force=True, timeout=1.0
            )

        self.assertTrue(result["ok"])
        stop_call = next(
            value for name, value in self.platform.calls if name == "stop_managed"
        )
        self.assertTrue(stop_call[1])

    def test_terminal_receipt_cannot_clear_a_newer_generation(self):
        self._persist_identity()
        newer_identity = native_identity(
            "deadbeef", "4488592f-9454-4f9f-9d2d-ac4775688aa3"
        )
        running = self.platform.inspection
        terminal = ManagedInspection(
            running=False,
            verified=True,
            members=(),
            status="exited",
            identity=self.identity,
        )
        inspections = iter((running, terminal))

        def inspect_with_generation_race(_identity):
            value = next(inspections)
            if value is terminal:
                newer = server.public_runtime_identity(
                    newer_identity, "deadbeef"
                )
                self.cfg.mutate_app_if_generation(
                    "deadbeef",
                    self.generation,
                    lambda _data, target: target.__setitem__(
                        "runtimeIdentity", newer
                    ),
                )
            return value

        with mock.patch.object(
                self.platform, "inspect_managed",
                side_effect=inspect_with_generation_race):
            result = server.stop_windows_app(
                self.cfg, self.current_app(), force=False, timeout=1.0
            )

        self.assertEqual(result["code"], "GENERATION_MISMATCH")
        self.assertEqual(
            server.runtime_generation(self.current_app()),
            newer_identity.generation_id,
        )

    def test_unbound_verified_status_never_reaches_job_control(self):
        self._persist_identity()
        self.platform.inspection = ManagedInspection(
            running=True,
            verified=True,
            members=(self.identity.root_pid,),
            status="running",
            identity=None,
        )

        result = server.stop_windows_app(self.cfg, self.current_app())

        self.assertEqual(result["code"], "RUNTIME_IDENTITY_UNVERIFIED")
        self.assertNotIn(
            "stop_managed", [name for name, _ in self.platform.calls]
        )
        self.assertEqual(
            server.runtime_generation(self.current_app()), self.generation
        )

    def test_verified_terminal_task_receipt_reconciles_last_exit(self):
        self.cfg.update(
            lambda data: data["apps"][0].__setitem__("kind", "task")
        )
        self._persist_identity()
        terminal = ManagedInspection(
            running=False,
            verified=True,
            members=(),
            status="exited",
            identity=self.identity,
            exit_code=0,
            updated_at=1780000002456,
        )
        self.platform.inspection = terminal

        server.reconcile_windows_terminal_runtimes(self.cfg)

        app = self.current_app()
        self.assertIsNone(app["runtimeIdentity"])
        self.assertEqual(app["lastExit"], {
            "status": "succeeded",
            "code": 0,
            "at": 1780000002,
        })

    def _persist_identity(self):
        public = server.public_runtime_identity(self.identity, "deadbeef")
        self.cfg.mutate_app_if_generation(
            "deadbeef",
            None,
            lambda _data, target: target.__setitem__("runtimeIdentity", public),
        )


class LifecycleGenerationHttpTests(unittest.TestCase):
    def setUp(self):
        self.harness = HttpHarness()
        self.headers = self.harness.session_headers()
        self.harness.cfg.update(lambda data: data["apps"].append({
            **server.Config.APP_DEFAULT,
            "id": "deadbeef",
            "name": "Managed",
            "command": "echo safe",
            "cwd": self.harness.temp_dir.name,
        }))
        self.platform = mock.patch.object(server.PLATFORM, "name", "windows")
        self.capabilities = mock.patch.object(
            server.PLATFORM, "capabilities", windows_capabilities()
        )
        self.platform.start()
        self.capabilities.start()

    def tearDown(self):
        self.capabilities.stop()
        self.platform.stop()
        self.harness.close()

    def test_missing_generation_rejects_before_launch(self):
        before = self.harness.cfg.snapshot()
        with mock.patch.object(server, "start_app") as launch:
            status, body, _ = self.harness.request(
                "POST", "/api/apps/deadbeef/start", {}, self.headers
            )
        self.assertEqual((status, body["code"]), (400, "GENERATION_REQUIRED"))
        launch.assert_not_called()
        self.assertEqual(self.harness.cfg.snapshot(), before)

    def test_stale_generation_rejects_before_launch(self):
        before = self.harness.cfg.snapshot()
        with mock.patch.object(server, "start_app") as launch:
            status, body, _ = self.harness.request(
                "POST",
                "/api/apps/deadbeef/start",
                {"expectedGeneration": str(uuid.uuid4())},
                self.headers,
            )
        self.assertEqual((status, body["code"]), (409, "GENERATION_MISMATCH"))
        launch.assert_not_called()
        self.assertEqual(self.harness.cfg.snapshot(), before)

    def test_malformed_generation_rejects_before_stop(self):
        before = self.harness.cfg.snapshot()
        with mock.patch.object(server, "stop_app_and_clear") as stop:
            status, body, _ = self.harness.request(
                "POST",
                "/api/apps/deadbeef/stop",
                {"expectedGeneration": True},
                self.headers,
            )
        self.assertEqual((status, body["code"]), (400, "GENERATION_REQUIRED"))
        stop.assert_not_called()
        self.assertEqual(self.harness.cfg.snapshot(), before)

    def test_stale_update_and_delete_have_no_config_side_effect(self):
        stale = str(uuid.uuid4())
        before = self.harness.cfg.snapshot()
        status, body, _ = self.harness.request(
            "PUT",
            "/api/apps/deadbeef",
            {"name": "Changed", "expectedGeneration": stale},
            self.headers,
        )
        self.assertEqual((status, body["code"]), (409, "GENERATION_MISMATCH"))
        self.assertEqual(self.harness.cfg.snapshot(), before)

        status, body, _ = self.harness.request(
            "DELETE",
            "/api/apps/deadbeef",
            {"expectedGeneration": stale},
            self.headers,
        )
        self.assertEqual((status, body["code"]), (409, "GENERATION_MISMATCH"))
        self.assertEqual(self.harness.cfg.snapshot(), before)

    def test_busy_operation_consumes_body_and_returns_stable_code(self):
        lock = self.harness.httpd.try_app_operation("deadbeef")
        self.assertIsNotNone(lock)
        connection = http.client.HTTPConnection(
            server.HOST, self.harness.port, timeout=4
        )
        try:
            connection.request(
                "POST",
                "/api/apps/deadbeef/start",
                body=json.dumps({"expectedGeneration": None}),
                headers=self.headers,
            )
            response = connection.getresponse()
            body = json.loads(response.read().decode("utf-8"))
            self.assertEqual(
                (response.status, body["code"]),
                (409, "APP_OPERATION_IN_PROGRESS"),
            )

            connection.request("GET", "/api/state")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
        finally:
            lock.release()
            connection.close()

    def test_delete_consumes_generation_body_on_keep_alive_connection(self):
        connection = http.client.HTTPConnection(
            server.HOST, self.harness.port, timeout=4
        )
        try:
            connection.request(
                "DELETE",
                "/api/apps/deadbeef",
                body=json.dumps({"expectedGeneration": None}),
                headers=self.headers,
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertTrue(json.loads(response.read().decode("utf-8"))["ok"])

            connection.request("GET", "/api/state")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            state = json.loads(response.read().decode("utf-8"))
            self.assertEqual(state["apps"], [])
        finally:
            connection.close()


class WindowsLifecycleHttpTransactionTests(unittest.TestCase):
    old_generation = "3d6448f0-87a0-4ace-baad-3b80abca9e3e"
    new_generation = "4488592f-9454-4f9f-9d2d-ac4775688aa3"

    def setUp(self):
        self.harness = HttpHarness()
        self.headers = self.harness.session_headers()
        self.identity = native_identity("deadbeef", self.old_generation)
        self.platform = FakePlatform(
            name="windows",
            principal=Principal(self.identity.owner),
            capabilities=windows_capabilities(),
            inspection=self._running(self.identity),
            stop_result=StopResult(ok=True, status="exited"),
        )
        self.platform_patch = mock.patch.object(server, "PLATFORM", self.platform)
        self.principal_patch = mock.patch.object(
            server, "SELF_PRINCIPAL", self.platform.principal
        )
        self.uid_patch = mock.patch.object(
            server, "SELF_UID", self.platform.principal.numeric_id
        )
        self.logs_patch = mock.patch.object(
            server, "LOGS_DIR", os.path.join(self.harness.temp_dir.name, "logs")
        )
        self.platform_patch.start()
        self.principal_patch.start()
        self.uid_patch.start()
        self.logs_patch.start()
        self.harness.cfg.update(lambda data: data["apps"].append({
            **server.Config.APP_DEFAULT,
            "id": "deadbeef",
            "name": "Managed",
            "command": sys.executable,
            "commandSpec": direct_command_spec(sys.executable),
            "cwd": self.harness.temp_dir.name,
            "importStatus": "ready",
        }))
        self.health = mock.patch.object(
            server,
            "inspect_app_health",
            return_value={"status": "ok", "blocking": False, "issues": []},
        )
        self.listeners = mock.patch.object(
            server, "scan_listeners", return_value=set()
        )
        self.health.start()
        self.listeners.start()

    def tearDown(self):
        self.listeners.stop()
        self.health.stop()
        self.logs_patch.stop()
        self.uid_patch.stop()
        self.principal_patch.stop()
        self.platform_patch.stop()
        self.harness.close()

    @staticmethod
    def _running(identity):
        return ManagedInspection(
            running=True,
            verified=True,
            members=(identity.root_pid,),
            status="running",
            identity=identity,
        )

    @staticmethod
    def _terminal(identity):
        return ManagedInspection(
            running=False,
            verified=True,
            members=(),
            status="exited",
            identity=identity,
        )

    def _persist_old_identity(self):
        public = server.public_runtime_identity(self.identity, "deadbeef")
        status, _, _ = self.harness.cfg.mutate_app_if_generation(
            "deadbeef",
            None,
            lambda _data, target: target.__setitem__("runtimeIdentity", public),
        )
        self.assertEqual(status, "applied")

    def test_start_and_explicit_force_use_exact_generation_transaction(self):
        self.platform.launch_result = ManagedRuntime(
            ok=True, runtime_identity=self.identity, status="prepared"
        )
        self.platform.activation_result = ManagedActivation(
            ok=True, status="running", process_id=self.identity.root_pid
        )
        with mock.patch.object(
                server.uuid, "uuid4", return_value=uuid.UUID(self.old_generation)):
            status, body, _ = self.harness.request(
                "POST",
                "/api/apps/deadbeef/start",
                {"expectedGeneration": None},
                self.headers,
            )
        self.assertEqual(status, 200)
        self.assertEqual(body["generationId"], self.old_generation)

        with mock.patch.object(
                self.platform, "inspect_managed",
                side_effect=[self._running(self.identity), self._terminal(self.identity)]):
            status, body, _ = self.harness.request(
                "POST",
                "/api/apps/deadbeef/stop",
                {"expectedGeneration": self.old_generation, "force": True},
                self.headers,
            )
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertIsNone(
            self.harness.cfg.snapshot()["apps"][0]["runtimeIdentity"]
        )
        stop_call = next(
            value for name, value in self.platform.calls if name == "stop_managed"
        )
        self.assertTrue(stop_call[1])

    def test_stop_timeout_keeps_identity_and_stable_http_code(self):
        self._persist_old_identity()
        self.platform.stop_result = StopResult(
            ok=False,
            still_running=True,
            status="stopping",
            code="STOP_TIMEOUT",
        )

        status, body, _ = self.harness.request(
            "POST",
            "/api/apps/deadbeef/stop",
            {"expectedGeneration": self.old_generation, "force": False},
            self.headers,
        )

        self.assertEqual((status, body["code"]), (409, "STOP_TIMEOUT"))
        self.assertEqual(
            server.runtime_generation(self.harness.cfg.snapshot()["apps"][0]),
            self.old_generation,
        )

    def test_running_delete_gracefully_stops_then_deletes(self):
        self._persist_old_identity()
        with mock.patch.object(
                self.platform, "inspect_managed",
                side_effect=[self._running(self.identity), self._terminal(self.identity)]):
            status, body, _ = self.harness.request(
                "DELETE",
                "/api/apps/deadbeef",
                {"expectedGeneration": self.old_generation},
                self.headers,
            )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(self.harness.cfg.snapshot()["apps"], [])
        stop_call = next(
            value for name, value in self.platform.calls if name == "stop_managed"
        )
        self.assertFalse(stop_call[1])

    def test_terminal_delete_does_not_wait_for_stuck_runner_cleanup(self):
        self._persist_old_identity()
        self.platform.inspection = self._terminal(self.identity)
        self.platform.stop_result = StopResult(
            ok=False,
            still_running=False,
            status="unknown",
            code="RUNTIME_CONTROL_FAILED",
        )

        with mock.patch.object(server, "_defer_windows_release") as defer:
            status, body, _ = self.harness.request(
                "DELETE",
                "/api/apps/deadbeef",
                {"expectedGeneration": self.old_generation},
                self.headers,
            )

        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertTrue(body["cleanupPending"])
        self.assertEqual(self.harness.cfg.snapshot()["apps"], [])
        self.assertNotIn(
            "stop_managed", [name for name, _ in self.platform.calls]
        )
        self.assertNotIn(
            "release_managed", [name for name, _ in self.platform.calls]
        )
        defer.assert_called_once_with(self.identity)

    def test_prepared_identity_delete_fails_closed_without_control(self):
        self._persist_old_identity()
        self.platform.inspection = ManagedInspection(
            running=False,
            verified=True,
            members=(self.identity.root_pid,),
            status="prepared",
            identity=self.identity,
        )

        status, body, _ = self.harness.request(
            "DELETE",
            "/api/apps/deadbeef",
            {"expectedGeneration": self.old_generation},
            self.headers,
        )

        self.assertEqual(
            (status, body["code"]), (409, "RUNTIME_IDENTITY_UNVERIFIED")
        )
        self.assertEqual(len(self.harness.cfg.snapshot()["apps"]), 1)
        self.assertNotIn(
            "stop_managed", [name for name, _ in self.platform.calls]
        )

    def test_running_update_stops_then_commits_against_null_generation(self):
        self._persist_old_identity()
        updated_cwd = os.path.join(self.harness.temp_dir.name, "updated")
        os.mkdir(updated_cwd)
        with mock.patch.object(
                self.platform, "inspect_managed",
                side_effect=[self._running(self.identity), self._terminal(self.identity)]):
            status, body, _ = self.harness.request(
                "PUT",
                "/api/apps/deadbeef",
                {
                    "cwd": updated_cwd,
                    "stopBeforeUpdate": True,
                    "expectedGeneration": self.old_generation,
                },
                self.headers,
            )

        self.assertEqual(status, 200)
        self.assertTrue(body["stoppedForUpdate"])
        app = self.harness.cfg.snapshot()["apps"][0]
        self.assertEqual(app["cwd"], updated_cwd)
        self.assertIsNone(app["runtimeIdentity"])

    def test_restart_stops_old_generation_before_starting_new_generation(self):
        self._persist_old_identity()
        new_identity = native_identity("deadbeef", self.new_generation)
        self.platform.launch_result = ManagedRuntime(
            ok=True, runtime_identity=new_identity, status="prepared"
        )
        self.platform.activation_result = ManagedActivation(
            ok=True, status="running", process_id=new_identity.root_pid
        )
        with mock.patch.object(
                self.platform,
                "inspect_managed",
                side_effect=[
                    self._running(self.identity),
                    self._terminal(self.identity),
                    self._running(new_identity),
                ]), mock.patch.object(
                    server.uuid, "uuid4", return_value=uuid.UUID(self.new_generation)
                ):
            status, body, _ = self.harness.request(
                "POST",
                "/api/apps/deadbeef/restart",
                {"expectedGeneration": self.old_generation},
                self.headers,
            )

        self.assertEqual(status, 200)
        self.assertEqual(body["generationId"], self.new_generation)
        self.assertEqual(
            server.runtime_generation(self.harness.cfg.snapshot()["apps"][0]),
            self.new_generation,
        )


class MacAdditiveLifecycleCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.harness = HttpHarness()
        self.headers = self.harness.session_headers()
        self.harness.cfg.update(lambda data: data["apps"].append({
            **server.Config.APP_DEFAULT,
            "id": "deadbeef",
            "name": "Legacy Mac",
            "command": "echo safe",
            "cwd": self.harness.temp_dir.name,
        }))
        self.platform = mock.patch.object(server.PLATFORM, "name", "macos")
        self.capabilities = mock.patch.object(
            server.PLATFORM, "capabilities", windows_capabilities()
        )
        self.platform.start()
        self.capabilities.start()

    def tearDown(self):
        self.capabilities.stop()
        self.platform.stop()
        self.harness.close()

    def test_legacy_put_does_not_require_generation(self):
        status, body, _ = self.harness.request(
            "PUT",
            "/api/apps/deadbeef",
            {"name": "Renamed"},
            self.headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["name"], "Renamed")

    def test_legacy_empty_delete_body_is_accepted(self):
        status, body, _ = self.harness.request(
            "DELETE", "/api/apps/deadbeef", None, self.headers
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_legacy_start_payload_does_not_require_generation(self):
        process = mock.Mock(pid=43210)
        process.poll.return_value = None
        healthy = {"status": "ok", "blocking": False, "issues": []}
        with mock.patch.object(
                server, "app_alive_sign", return_value=False), \
                mock.patch.object(
                    server, "inspect_app_health", return_value=healthy
                ), \
                mock.patch.object(server, "scan_listeners", return_value=set()), \
                mock.patch.object(
                    server, "start_app",
                    return_value=(True, None, process, process.pid, "token")
                ), \
                mock.patch.object(
                    server, "persist_started_app", return_value=True
                ):
            status, body, _ = self.harness.request(
                "POST", "/api/apps/deadbeef/start", {}, self.headers
            )
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

if __name__ == "__main__":
    unittest.main()

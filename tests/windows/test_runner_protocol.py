import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid

from localops.platform.contracts import (
    RuntimeIdentity,
    WINDOWS_RUNTIME_IDENTITY_FIELDS,
    windows_runtime_identity_public,
)
from localops.windows.runner_protocol import (
    MAX_RECORD_BYTES,
    NonceCache,
    ProtocolError,
    decode_message,
    encode_message,
    job_name,
    make_request,
    make_response,
    native_process_command,
    pipe_name,
    reconnect_observations_valid,
    runner_command,
    runtime_directory,
    sign_record,
    terminal_observations_valid,
    token_digest,
    validate_public_identity,
    validate_receipt,
    validate_transition,
    verify_request,
    verify_response,
    write_json_atomic,
)


APP_ID = "deadbeef"
GENERATION = "3d6448f0-87a0-4ace-baad-3b80abca9e3e"
OWNER_SID = "S-1-5-21-111-222-333-1001"
TOKEN = bytes(range(32))
DIGEST = token_digest(TOKEN)


def public_identity():
    return {
        "platform": "windows",
        "kind": "job",
        "ownerSid": OWNER_SID,
        "generationId": GENERATION,
        "runnerPid": 1234,
        "runnerCreateTime": 1780000000.123,
        "rootPid": 5678,
        "rootCreateTime": 1780000001.456,
        "jobName": job_name(APP_ID, GENERATION, DIGEST),
        "tokenDigest": DIGEST,
        "startedAt": 1780000001456,
    }


class PublicIdentityTests(unittest.TestCase):
    def test_public_identity_validator_rejects_unknown_fields(self):
        self.assertEqual(validate_public_identity(
            public_identity(), app_id=APP_ID, generation_id=GENERATION,
            owner_sid=OWNER_SID, digest=DIGEST,
        ), public_identity())
        expanded = {**public_identity(), "pipeName": "not-public"}

        with self.assertRaises(ProtocolError) as caught:
            validate_public_identity(
                expanded, app_id=APP_ID, generation_id=GENERATION,
                owner_sid=OWNER_SID, digest=DIGEST,
            )

        self.assertEqual(caught.exception.code, "RUNTIME_IDENTITY_INVALID")

    def test_atomic_record_is_protected_before_replacement_becomes_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "receipt.json")
            with open(path, "w", encoding="utf-8") as stream:
                json.dump({"state": "old"}, stream)
            observed = []

            def protect(temporary):
                with open(path, encoding="utf-8") as stream:
                    observed.append(json.load(stream))
                with open(temporary, encoding="utf-8") as stream:
                    self.assertEqual(json.load(stream), {"state": "new"})

            write_json_atomic(path, {"state": "new"}, protect)

            with open(path, encoding="utf-8") as stream:
                current = json.load(stream)
        self.assertEqual(observed, [{"state": "old"}])
        self.assertEqual(current, {"state": "new"})

    def test_public_mapper_is_an_exact_allowlist(self):
        identity = RuntimeIdentity(
            "windows", "job", public_identity()["jobName"], OWNER_SID,
            app_id=APP_ID,
            generation_id=GENERATION,
            runner_pid=1234,
            runner_create_time=1780000000.123,
            root_pid=5678,
            root_create_time=1780000001.456,
            job_name=public_identity()["jobName"],
            token_digest=DIGEST,
            started_at=1780000001456,
        )

        serialized = windows_runtime_identity_public(identity)

        self.assertEqual(tuple(serialized), WINDOWS_RUNTIME_IDENTITY_FIELDS)
        self.assertEqual(serialized, public_identity())
        encoded = json.dumps(serialized)
        for forbidden in ("token", "rawToken", "receiptPath", "pipeName", "runtimeDir"):
            self.assertNotIn(forbidden, serialized)
        for secret in (TOKEN.hex(), "token.bin", "receipt.json", r"\\.\pipe"):
            self.assertNotIn(secret, encoded)

    def test_public_mapper_rejects_a_raw_token_without_echoing_it(self):
        identity = RuntimeIdentity(
            "windows", "job", "job", OWNER_SID, token="never-print-this"
        )

        with self.assertRaises(ValueError) as caught:
            windows_runtime_identity_public(identity)

        self.assertNotIn("never-print-this", str(caught.exception))

    def test_runner_cli_contains_only_public_coordinates(self):
        command = runner_command(sys.executable, APP_ID, GENERATION)
        rendered = " ".join(command)

        self.assertIn(APP_ID, rendered)
        self.assertIn(GENERATION, rendered)
        for forbidden in (TOKEN.hex(), "token.bin", "receipt.json", r"\\.\pipe", "runtime-dir"):
            self.assertNotIn(forbidden, rendered)


class AuthenticationTests(unittest.TestCase):
    def test_request_response_round_trip_and_nonce_replay_rejection(self):
        request = make_request("inspect", GENERATION, TOKEN)
        cache = NonceCache()
        verified = verify_request(request, TOKEN, GENERATION, cache)
        response = make_response(
            verified, TOKEN, ok=True, status="running", payload={"members": [5678]}
        )

        self.assertTrue(verify_response(response, TOKEN, request)["ok"])
        with self.assertRaises(ProtocolError) as caught:
            verify_request(request, TOKEN, GENERATION, cache)
        self.assertEqual(caught.exception.code, "RUNTIME_CONTROL_FAILED")

    def test_tampering_and_cross_generation_messages_fail_closed(self):
        request = make_request("stop", GENERATION, TOKEN, {"timeout": 1.0})
        tampered = copy.deepcopy(request)
        tampered["payload"]["timeout"] = 30.0

        with self.assertRaises(ProtocolError) as caught:
            verify_request(tampered, TOKEN, GENERATION, NonceCache())
        self.assertEqual(caught.exception.code, "RUNTIME_IDENTITY_UNVERIFIED")

        other_generation = str(uuid.uuid4())
        with self.assertRaises(ProtocolError) as caught:
            verify_request(request, TOKEN, other_generation, NonceCache())
        self.assertEqual(caught.exception.code, "GENERATION_MISMATCH")

    def test_response_is_bound_to_request_nonce(self):
        first = make_request("inspect", GENERATION, TOKEN)
        second = make_request("inspect", GENERATION, TOKEN)
        response = make_response(first, TOKEN, ok=True, status="running")

        with self.assertRaises(ProtocolError) as caught:
            verify_response(response, TOKEN, second)
        self.assertEqual(caught.exception.code, "RUNTIME_IDENTITY_UNVERIFIED")

    def test_messages_are_bounded_and_non_json_values_are_rejected(self):
        with self.assertRaises(ProtocolError):
            decode_message(b"{" + b"x" * MAX_RECORD_BYTES + b"}")
        with self.assertRaises(ProtocolError):
            encode_message({"bad": float("nan")})


class ReceiptTests(unittest.TestCase):
    def _receipt(self, state="running"):
        return sign_record({
            "version": 1,
            "sequence": 2,
            "state": state,
            "identity": public_identity(),
            "members": [5678, 6789],
            "updatedAt": 1780000002456,
            "code": None,
            "error": None,
            "exitCode": None,
        }, TOKEN, "receipt")

    def test_receipt_validates_hmac_identity_job_and_transition(self):
        receipt = validate_receipt(
            self._receipt(), TOKEN, app_id=APP_ID, generation_id=GENERATION,
            owner_sid=OWNER_SID, previous_state="prepared",
        )
        self.assertEqual(receipt["state"], "running")

    def test_running_receipt_is_valid_as_a_cold_reconnect_snapshot(self):
        receipt = validate_receipt(
            self._receipt(), TOKEN, app_id=APP_ID, generation_id=GENERATION,
            owner_sid=OWNER_SID,
        )

        self.assertEqual(receipt["state"], "running")

    def test_receipt_state_members_and_diagnostics_are_consistent(self):
        cases = [
            ("running", [], None, None, None),
            ("exited", [5678], None, None, 0),
            ("failed", [], 7, None, None),
            ("failed", [], None, {"secret": True}, None),
        ]
        for state, members, code, error, exit_code in cases:
            with self.subTest(state=state, members=members):
                unsigned = {
                    "version": 1, "sequence": 2, "state": state,
                    "identity": public_identity(), "members": members,
                    "updatedAt": 1780000002456, "code": code,
                    "error": error, "exitCode": exit_code,
                }
                with self.assertRaises(ProtocolError):
                    validate_receipt(
                        sign_record(unsigned, TOKEN, "receipt"), TOKEN,
                        app_id=APP_ID, generation_id=GENERATION,
                        owner_sid=OWNER_SID,
                    )

    def test_receipt_tamper_duplicate_members_and_stale_transition_fail(self):
        tampered = self._receipt()
        tampered["state"] = "exited"
        with self.assertRaises(ProtocolError):
            validate_receipt(
                tampered, TOKEN, app_id=APP_ID, generation_id=GENERATION,
                owner_sid=OWNER_SID,
            )

        duplicate = self._receipt()
        unsigned = {key: value for key, value in duplicate.items() if key != "hmac"}
        unsigned["members"] = [5678, 5678]
        with self.assertRaises(ProtocolError):
            validate_receipt(
                sign_record(unsigned, TOKEN, "receipt"), TOKEN,
                app_id=APP_ID, generation_id=GENERATION, owner_sid=OWNER_SID,
                previous_state="prepared",
            )

        with self.assertRaises(ProtocolError):
            validate_transition("exited", "running")

    def test_root_wrapper_may_exit_while_authenticated_job_remains_controllable(self):
        identity = public_identity()

        self.assertTrue(reconnect_observations_valid(
            identity,
            runner_observation=(OWNER_SID, identity["runnerCreateTime"]),
            root_observation=None,
            members=[6789],
        ))
        self.assertTrue(reconnect_observations_valid(
            identity,
            runner_observation=(OWNER_SID, identity["runnerCreateTime"]),
            root_observation=(OWNER_SID, identity["rootCreateTime"] + 99),
            members=[6789],
        ))
        self.assertFalse(reconnect_observations_valid(
            identity,
            runner_observation=(OWNER_SID, identity["runnerCreateTime"]),
            root_observation=(OWNER_SID, identity["rootCreateTime"] + 99),
            members=[identity["rootPid"], 6789],
        ))

    def test_terminal_snapshot_survives_console_reopen_and_rejects_live_root(self):
        identity = public_identity()

        self.assertTrue(terminal_observations_valid(
            identity, runner_observation=None, root_observation=None, members=[]
        ))
        self.assertTrue(terminal_observations_valid(
            identity,
            runner_observation=(OWNER_SID, identity["runnerCreateTime"] + 99),
            root_observation=(OWNER_SID, identity["rootCreateTime"] + 99),
            members=[],
        ))
        self.assertFalse(terminal_observations_valid(
            identity,
            runner_observation=None,
            root_observation=(OWNER_SID, identity["rootCreateTime"]),
            members=[],
        ))


class NamingAndQuotingTests(unittest.TestCase):
    def test_job_name_uses_exactly_the_first_sixteen_digest_characters(self):
        name = job_name(APP_ID, GENERATION, DIGEST)

        self.assertEqual(name.rsplit("-", 1)[-1], DIGEST[7:23])
        self.assertEqual(len(name.rsplit("-", 1)[-1]), 16)

    def test_names_and_runtime_path_are_deterministic_and_traversal_free(self):
        root = os.path.abspath(os.path.join("C:\\", "LocalOps", "runtime"))
        directory = runtime_directory(root, APP_ID, GENERATION)

        self.assertEqual(os.path.basename(directory), GENERATION)
        self.assertEqual(os.path.basename(os.path.dirname(directory)), APP_ID)
        self.assertEqual(
            pipe_name(APP_ID, GENERATION),
            rf"\\.\pipe\LocalOps-{APP_ID}-{GENERATION}",
        )
        with self.assertRaises(ProtocolError):
            runtime_directory(root, "../escape", GENERATION)

    def test_structured_cmd_quotes_every_value_at_native_boundary(self):
        invocation = {
            "mode": "cmd",
            "executable": r"C:\Windows\System32\cmd.exe",
            "prefixArgs": ["/d", "/s", "/c"],
            "script": r"D:\project & tools\start.cmd",
            "args": ["&", "|", "<", ">", "^", "(", ")", "space value"],
        }

        application, line = native_process_command(invocation)

        self.assertEqual(application, invocation["executable"])
        for value in [invocation["script"], *invocation["args"]]:
            self.assertIn('"' + value + '"', line)
        self.assertTrue(line.endswith('""'))

    def test_structured_cmd_rechecks_expansion_and_quote_controls(self):
        base = {
            "mode": "cmd", "executable": "cmd.exe",
            "prefixArgs": ["/d", "/s", "/c"], "script": "start.cmd", "args": [],
        }
        for unsafe in ('embedded"quote', "%PATH%", "delayed!", "line\nbreak"):
            with self.subTest(unsafe=unsafe), self.assertRaises(ProtocolError):
                native_process_command({**base, "args": [unsafe]})


@unittest.skipUnless(
    sys.platform == "win32" and os.environ.get("LOCALOPS_RUN_WINDOWS_LIFECYCLE_TESTS") == "1",
    "real Windows lifecycle fixtures are explicitly gated",
)
class RealCmdBoundaryTests(unittest.TestCase):
    def test_metacharacters_arrive_literal_and_do_not_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            script = os.path.join(directory, "capture args.cmd")
            output = os.path.join(directory, "args.txt")
            marker = os.path.join(directory, "injected.txt")
            with open(script, "w", encoding="utf-8", newline="\r\n") as stream:
                stream.write(
                    "@echo off\n"
                    ">\"%~1\" echo(%2\n"
                    ">>\"%~1\" echo(%3\n"
                    ">>\"%~1\" echo(%4\n"
                    ">>\"%~1\" echo(%5\n"
                    ">>\"%~1\" echo(%6\n"
                    ">>\"%~1\" echo(%7\n"
                    ">>\"%~1\" echo(%8\n"
                )
            attack = "& echo injected > " + marker
            values = ["&", "|", "<", ">", "^", "(", attack]
            invocation = {
                "mode": "cmd", "executable": os.environ["COMSPEC"],
                "prefixArgs": ["/d", "/s", "/c"], "script": script,
                "args": [output, *values],
            }
            application, line = native_process_command(invocation)

            result = subprocess.run(
                line, executable=application, check=False, timeout=10,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True,
            )

            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertFalse(os.path.exists(marker))
            with open(output, encoding="utf-8") as stream:
                captured = [item.strip().strip('"') for item in stream]
            self.assertEqual(captured, values)


if __name__ == "__main__":
    unittest.main()

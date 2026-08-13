import subprocess
import unittest
from unittest import mock

from localops.platform.contracts import (
    ListenerSnapshot,
    PlatformIssue,
    ProcessSnapshot,
    ScanStatus,
)
from localops.platform.fake import FakePlatform
from localops.platform.macos import MacOSPlatform
import server
from tools.check_platform_leaks import ROOT, platform_leaks


class FakePlatformContractTests(unittest.TestCase):
    def test_shared_core_has_no_direct_native_process_calls(self):
        self.assertEqual(platform_leaks(ROOT / "server.py"), [])

    def test_success_records_calls_and_returns_configured_data(self):
        fake = FakePlatform(listeners=ListenerSnapshot(
            ScanStatus.OK, {(101, 5173): {"::1"}}
        ))

        snapshot = fake.scan_listeners()

        self.assertEqual(snapshot.listeners[(101, 5173)], {"::1"})
        self.assertEqual(fake.calls, [("scan_listeners", None)])

    def test_permission_denial_is_an_explicit_failure(self):
        issue = PlatformIssue("processes", "access_denied", "denied")
        fake = FakePlatform(processes=ProcessSnapshot(
            ScanStatus.FAILED, issues=(issue,)
        ))

        snapshot = fake.process_snapshot()

        self.assertIs(snapshot.status, ScanStatus.FAILED)
        self.assertEqual(snapshot.issues, (issue,))

    def test_timeout_is_not_converted_to_an_empty_success(self):
        issue = PlatformIssue("listeners", "timeout", "scan timed out")
        fake = FakePlatform(listeners=ListenerSnapshot(
            ScanStatus.FAILED, issues=(issue,)
        ))

        snapshot = fake.scan_listeners()

        self.assertIs(snapshot.status, ScanStatus.FAILED)
        self.assertEqual(snapshot.issues[0].code, "timeout")

    def test_partial_snapshot_keeps_data_and_issue(self):
        issue = PlatformIssue("process_args", "access_denied", "args hidden")
        fake = FakePlatform(processes=ProcessSnapshot(
            ScanStatus.PARTIAL,
            {42: {"uid": 1000, "comm": "python", "args": ""}},
            (issue,),
        ))

        snapshot = fake.process_snapshot({42})

        self.assertIs(snapshot.status, ScanStatus.PARTIAL)
        self.assertIn(42, snapshot.processes)
        self.assertEqual(snapshot.issues, (issue,))

    def test_shared_state_reports_partial_scan_as_degraded(self):
        issue = PlatformIssue("listeners", "access_denied", "one row hidden")
        fake = FakePlatform(listeners=ListenerSnapshot(
            ScanStatus.PARTIAL, {}, (issue,)
        ))

        with mock.patch.object(server, "PLATFORM", fake):
            state = server.build_state(dict(server.Config.DEFAULT), 9600, {})

        self.assertTrue(state["degraded"])
        self.assertIn({
            "component": "listeners",
            "code": "access_denied",
            "error": "one row hidden",
        }, state["degradedReasons"])


class MacOSPlatformParsingTests(unittest.TestCase):
    def setUp(self):
        with mock.patch("os.getuid", return_value=501, create=True):
            self.platform = MacOSPlatform("/project", "/project/server.py")

    def test_listener_scan_preserves_ipv6_loopback(self):
        output = """COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
node 101 user 1u IPv6 0x0 0t0 TCP [::1]:5173 (LISTEN)
node 202 user 2u IPv4 0x0 0t0 TCP 127.0.0.1:8000 (LISTEN)
"""
        completed = subprocess.CompletedProcess([], 0, output, "")
        with mock.patch("subprocess.run", return_value=completed):
            snapshot = self.platform.scan_listeners()

        self.assertIs(snapshot.status, ScanStatus.OK)
        self.assertEqual(snapshot.listeners[(101, 5173)], {"::1"})
        self.assertEqual(snapshot.listeners[(202, 8000)], {"127.0.0.1"})

    def test_missing_scan_tool_is_failed_not_empty_ok(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            snapshot = self.platform.scan_listeners()

        self.assertIs(snapshot.status, ScanStatus.FAILED)
        self.assertEqual(snapshot.issues[0].code, "tool_missing")

    def test_process_args_failure_returns_partial_snapshot(self):
        details = subprocess.CompletedProcess(
            [], 0, " PID UID ELAPSED %CPU %MEM COMM\n 42 501 00:03 0.1 0.2 python3\n", ""
        )
        denied = subprocess.CompletedProcess([], 1, "", "permission denied")
        with mock.patch("subprocess.run", side_effect=[details, denied]):
            snapshot = self.platform.process_snapshot({42})

        self.assertIs(snapshot.status, ScanStatus.PARTIAL)
        self.assertEqual(snapshot.processes[42]["comm"], "python3")
        self.assertEqual(snapshot.issues[0].code, "command_failed")

    def test_missing_requested_pid_is_not_a_scan_failure(self):
        missing = subprocess.CompletedProcess(
            [], 1, "", "ps: process id too large: 99999999"
        )
        with mock.patch("subprocess.run", side_effect=[missing, missing]):
            result = self.platform.stop_external_process(99999999)

        self.assertFalse(result.ok)
        self.assertEqual(result.error, "进程不存在")


if __name__ == "__main__":
    unittest.main()

import os
import socket
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from localops.platform.contracts import ScanStatus

if sys.platform == "win32":
    import psutil
    import win32security

    from localops.platform.windows import WindowsPlatform


@unittest.skipUnless(sys.platform == "win32", "Windows-only adapter tests")
class WindowsPlatformTests(unittest.TestCase):
    def setUp(self):
        self.platform = WindowsPlatform(os.getcwd(), "server.py")

    def test_runtime_paths_use_local_app_data(self):
        paths = self.platform.runtime_paths()
        self.assertTrue(paths.data_dir.endswith(os.path.join("LocalOps")))
        self.assertEqual(paths.logs_dir, os.path.join(paths.data_dir, "logs"))
        self.assertEqual(paths.runtime_dir, os.path.join(paths.data_dir, "runtime"))
        self.assertNotEqual(
            os.path.normcase(paths.data_dir),
            os.path.normcase(self.platform.base_dir),
        )

    def test_runtime_path_rejects_roots_equivalents_and_junctions(self):
        with self.assertRaises(ValueError):
            self.platform.validate_runtime_path("C:\\", set())
        with self.assertRaises(ValueError):
            self.platform.validate_runtime_path(r"\\server\share", set())
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                self.platform.validate_runtime_path(
                    temp_dir.upper(), {temp_dir.lower()}
                )
            valid = os.path.join(temp_dir, "中文 folder", "LocalOps")
            self.assertEqual(
                self.platform.validate_runtime_path(valid, set()),
                os.path.abspath(valid),
            )
            with mock.patch.object(
                    self.platform, "_has_junction_component", return_value=True):
                with self.assertRaises(ValueError):
                    self.platform.validate_runtime_path(valid, set())

    def test_private_acl_has_only_current_user_system_and_administrators(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "config.json")
            with open(path, "w", encoding="utf-8") as file_object:
                file_object.write("{}")
            self.platform.ensure_private_directory(temp_dir)
            self.platform.ensure_private_file(path)
            descriptor = win32security.GetNamedSecurityInfo(
                path,
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
            owner = win32security.ConvertSidToStringSid(
                descriptor.GetSecurityDescriptorOwner()
            )
            dacl = descriptor.GetSecurityDescriptorDacl()
            principals = {
                win32security.ConvertSidToStringSid(dacl.GetAce(index)[2])
                for index in range(dacl.GetAceCount())
            }
            self.assertEqual(owner, self.platform.current_principal().identifier)
            self.assertEqual(
                principals,
                {
                    self.platform.current_principal().identifier,
                    "S-1-5-18",
                    "S-1-5-32-544",
                },
            )

    def test_named_mutex_allows_only_one_writer_and_recovers_after_release(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            identity = os.path.join(temp_dir, "console.lock")
            first = self.platform.acquire_instance_lock(identity)
            self.assertIsNotNone(first)
            self.assertIsNone(self.platform.acquire_instance_lock(identity))
            first.release()
            replacement = self.platform.acquire_instance_lock(identity)
            self.assertIsNotNone(replacement)
            replacement.release()

    def test_current_process_snapshot_contains_current_sid(self):
        snapshot = self.platform.process_snapshot({os.getpid()})
        self.assertIn(snapshot.status, (ScanStatus.OK, ScanStatus.PARTIAL))
        self.assertEqual(
            snapshot.processes[os.getpid()]["owner"],
            self.platform.current_principal().identifier,
        )

    def test_listener_snapshot_preserves_ipv4_and_ipv6(self):
        connections = [
            SimpleNamespace(
                status=psutil.CONN_LISTEN,
                laddr=SimpleNamespace(ip="127.0.0.1", port=9600),
                pid=100,
            ),
            SimpleNamespace(
                status=psutil.CONN_LISTEN,
                laddr=SimpleNamespace(ip="::1", port=9601),
                pid=101,
            ),
        ]
        with mock.patch("psutil.net_connections", return_value=connections):
            snapshot = self.platform.scan_listeners()
        self.assertEqual(snapshot.status, ScanStatus.OK)
        self.assertEqual(snapshot.listeners[(100, 9600)], {"127.0.0.1"})
        self.assertEqual(snapshot.listeners[(101, 9601)], {"::1"})

    def test_listener_access_denied_is_failed_not_empty_success(self):
        with mock.patch("psutil.net_connections", side_effect=psutil.AccessDenied()):
            snapshot = self.platform.scan_listeners()
        self.assertEqual(snapshot.status, ScanStatus.FAILED)
        self.assertEqual(snapshot.listeners, {})
        self.assertEqual(snapshot.issues[0].code, "access_denied")

    def test_process_race_and_access_denied_are_nonfatal(self):
        vanished = mock.Mock()
        vanished.pid = 100
        vanished.as_dict.side_effect = psutil.NoSuchProcess(100)
        protected = mock.Mock()
        protected.pid = 101
        protected.as_dict.side_effect = psutil.AccessDenied(101)
        with mock.patch("psutil.process_iter", return_value=[vanished, protected]), \
                mock.patch.object(
                    self.platform,
                    "_process_owner_sid",
                    return_value=self.platform.current_principal().identifier,
                ):
            snapshot = self.platform.process_snapshot()
        self.assertEqual(snapshot.status, ScanStatus.PARTIAL)
        self.assertEqual(snapshot.processes, {})
        self.assertTrue(any(issue.code == "access_denied" for issue in snapshot.issues))

    def test_native_picker_returns_path_and_cancel_without_side_effects(self):
        root = mock.Mock()
        selected = os.path.join(os.getcwd(), "中文 folder")
        with mock.patch("tkinter.Tk", return_value=root), \
                mock.patch("tkinter.filedialog.askdirectory", return_value=selected):
            result = self.platform.pick_path("dir")
        self.assertEqual(result.path, os.path.abspath(selected))
        self.assertFalse(result.canceled)
        root.withdraw.assert_called_once_with()
        root.destroy.assert_called_once_with()
        with mock.patch("tkinter.Tk", return_value=mock.Mock()), \
                mock.patch("tkinter.filedialog.askopenfilename", return_value=""):
            result = self.platform.pick_path("script")
        self.assertTrue(result.canceled)
        self.assertIsNone(result.path)

    def test_real_loopback_listener_is_observable(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            snapshot = self.platform.scan_listeners()
            self.assertIn((os.getpid(), port), snapshot.listeners)
        finally:
            listener.close()


if __name__ == "__main__":
    unittest.main()

import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from localops.windows import packaged_entry
from tools import build_release
from tools import build_windows


VERSION = build_windows.release.version()


def fake_windowed_x64_pe():
    payload = bytearray(512)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (128).to_bytes(4, "little")
    payload[128:132] = b"PE\x00\x00"
    payload[132:134] = (0x8664).to_bytes(2, "little")
    payload[152:154] = (0x20B).to_bytes(2, "little")
    payload[220:222] = (2).to_bytes(2, "little")
    return (
        bytes(payload)
        + VERSION.encode("utf-16le")
        + build_windows.SIGNING_STATUS.encode("utf-16le")
    )


def fake_256_icon():
    entry = bytearray(16)
    entry[0] = 0
    entry[1] = 0
    entry[8:12] = (1).to_bytes(4, "little")
    entry[12:16] = (22).to_bytes(4, "little")
    return b"\x00\x00\x01\x00\x01\x00" + bytes(entry) + b"x"


def fake_version_resources():
    numeric = build_windows._numeric_version(VERSION)
    return ({
        "FileDescription": "Local Ops Console",
        "FileVersion": VERSION,
        "InternalName": "LocalOps",
        "OriginalFilename": "LocalOps.exe",
        "ProductName": "Local Ops Console",
        "ProductVersion": VERSION,
        "SpecialBuild": build_windows.SIGNING_STATUS,
    }, numeric, numeric)


class PackagedEntryTests(unittest.TestCase):
    def test_frozen_runner_dispatch_preserves_non_secret_source_cli(self):
        calls = []

        result = packaged_entry.main(
            [
                "-m",
                "localops.windows.runner",
                "--app-id",
                "a1b2c3d4",
                "--generation-id",
                "0" * 32,
            ],
            runner_main=lambda argv: calls.append(argv) or 7,
        )

        self.assertEqual(result, 7)
        self.assertEqual(calls, [[
            "--app-id", "a1b2c3d4", "--generation-id", "0" * 32
        ]])

    def test_frozen_entry_rejects_other_python_modules(self):
        runner = mock.Mock()
        self.assertEqual(
            packaged_entry.main(["-m", "http.server"], runner_main=runner),
            2,
        )
        runner.assert_not_called()

    def test_frozen_elevation_broker_dispatch_is_fixed_to_broker_module(self):
        calls = []

        result = packaged_entry.main(
            ["-m", "localops.windows.elevation_broker", "serve"],
            broker_main=lambda argv: calls.append(argv) or 9,
        )

        self.assertEqual(result, 9)
        self.assertEqual(calls, [["serve"]])

    def test_windowed_none_streams_bind_to_private_utf8_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            calls = []
            server = SimpleNamespace(
                LOGS_DIR=temporary,
                PLATFORM=SimpleNamespace(
                    ensure_private_file=lambda path: calls.append(("ensure", path)),
                    verify_private_directory=lambda path: calls.append(
                        ("verify_dir", path)
                    ),
                    verify_private_file=lambda path: calls.append(
                        ("verify_file", path)
                    ),
                ),
                prepare_runtime_storage=lambda: {"securityIssues": []},
            )
            original_stdout, original_stderr = os.sys.stdout, os.sys.stderr
            os.sys.stdout = None
            os.sys.stderr = None
            stream = None
            try:
                stream = packaged_entry._bind_private_console_log(server)
                print("总控台 packaged log", flush=True)
                self.assertIs(os.sys.stdout, stream)
                self.assertIs(os.sys.stderr, stream)
                self.assertEqual(stream.encoding.casefold(), "utf-8")
            finally:
                if stream is not None:
                    stream.close()
                os.sys.stdout, os.sys.stderr = original_stdout, original_stderr
            path = Path(temporary) / "console.log"
            self.assertEqual(calls, [
                ("verify_dir", temporary),
                ("ensure", str(path)),
            ])
            self.assertIn("总控台 packaged log", path.read_text(encoding="utf-8"))

    def test_windowed_log_binding_fails_closed_on_storage_acl_issue(self):
        with tempfile.TemporaryDirectory() as temporary:
            server = SimpleNamespace(
                LOGS_DIR=temporary,
                PLATFORM=SimpleNamespace(
                    verify_private_directory=lambda path: None,
                    verify_private_file=lambda path: None,
                ),
                prepare_runtime_storage=lambda: {
                    "securityIssues": ["ACL verification failed"]
                },
            )
            with self.assertRaisesRegex(PermissionError, "ACL verification failed"):
                packaged_entry._bind_private_console_log(server)

    def test_existing_log_is_verified_without_acl_repair(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "console.log"
            path.write_text("existing\n", encoding="utf-8")
            calls = []
            server = SimpleNamespace(
                LOGS_DIR=temporary,
                PLATFORM=SimpleNamespace(
                    ensure_private_file=lambda value: calls.append(("ensure", value)),
                    verify_private_directory=lambda value: calls.append(
                        ("verify_dir", value)
                    ),
                    verify_private_file=lambda value: calls.append(
                        ("verify_file", value)
                    ),
                ),
                prepare_runtime_storage=lambda: {"securityIssues": []},
            )
            original_stdout, original_stderr = os.sys.stdout, os.sys.stderr
            try:
                stream = packaged_entry._bind_private_console_log(server)
            finally:
                os.sys.stdout, os.sys.stderr = original_stdout, original_stderr
            stream.close()
            self.assertEqual(calls, [
                ("verify_dir", temporary),
                ("verify_file", str(path)),
                ("verify_file", str(path)),
            ])

    def test_widened_existing_log_fails_before_storage_can_repair_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "console.log"
            path.write_text("existing\n", encoding="utf-8")
            prepare = mock.Mock(return_value={"securityIssues": []})
            server = SimpleNamespace(
                LOGS_DIR=temporary,
                PLATFORM=SimpleNamespace(
                    verify_private_directory=lambda value: None,
                    verify_private_file=mock.Mock(
                        side_effect=PermissionError("private ACL verification failed")
                    ),
                ),
                prepare_runtime_storage=prepare,
            )
            with self.assertRaisesRegex(PermissionError, "private ACL"):
                packaged_entry._bind_private_console_log(server)
            prepare.assert_not_called()


class WindowsBuildContractTests(unittest.TestCase):
    def test_pyinstaller_command_is_onedir_windowed_and_uses_packaged_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            command = build_windows.pyinstaller_command(
                temp, temp / "version_info.txt"
            )
        self.assertIn("--onedir", command)
        self.assertIn("--windowed", command)
        self.assertIn("--noupx", command)
        self.assertNotIn("--onefile", command)
        self.assertEqual(command[-1], str(build_windows.ENTRYPOINT))
        self.assertIn("localops.windows.runner", command)
        self.assertIn("localops.windows.elevation_broker", command)
        self.assertIn("win32timezone", command)

    def test_pyinstaller_environment_freezes_hash_order_and_build_epoch(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            environment = build_windows.pyinstaller_environment()
        self.assertEqual(environment["PYTHONHASHSEED"], "0")
        self.assertEqual(environment["SOURCE_DATE_EPOCH"], "1704067200")

        with mock.patch.dict(
            os.environ, {"SOURCE_DATE_EPOCH": "1710000001"}, clear=True
        ):
            environment = build_windows.pyinstaller_environment()
        self.assertEqual(environment["SOURCE_DATE_EPOCH"], "1710000000")

    def test_version_resource_marks_unsigned_special_build(self):
        resource = build_windows.version_resource("1.2.3-beta.1")
        self.assertIn("filevers=(1, 2, 3, 0)", resource)
        self.assertIn("UNSIGNED DEVELOPMENT BUILD", resource)
        self.assertIn("LocalOps.exe", resource)

    def test_windows_icon_requires_256_pixel_entry(self):
        build_windows.validate_windows_icon_bytes(fake_256_icon())
        with self.assertRaisesRegex(SystemExit, "256x256"):
            build_windows.validate_windows_icon_bytes(
                b"\x00\x00\x01\x00\x01\x00"
                + b"\x10\x10" + b"\x00" * 14 + b"x"
            )

    def test_build_dependency_is_in_source_release_allowlist(self):
        self.assertIn("requirements-build-windows.txt", build_release.INCLUDE)

    def test_runtime_and_build_dependency_graph_is_fully_pinned(self):
        lines = set()
        for filename in ("requirements-windows.txt", "requirements-build-windows.txt"):
            lines.update(
                line.strip()
                for line in (build_windows.ROOT / filename).read_text(
                    encoding="utf-8"
                ).splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
        self.assertEqual(
            lines,
            {
                f"{name}=={version}"
                for name, version in build_windows.REQUIRED_DISTRIBUTIONS.items()
            },
        )

    def test_pe_audit_requires_real_fixed_and_string_version_resources(self):
        executable = fake_windowed_x64_pe()
        with mock.patch.object(
            build_windows, "_pe_version_fields", return_value=fake_version_resources()
        ):
            build_windows._validate_pe(executable, VERSION)
        with mock.patch.object(
            build_windows,
            "_pe_version_fields",
            return_value=(
                {},
                build_windows._numeric_version(VERSION),
                build_windows._numeric_version(VERSION),
            ),
        ):
            with self.assertRaisesRegex(SystemExit, "string version resources"):
                build_windows._validate_pe(executable, VERSION)

    def test_build_info_requires_supported_python_without_host_version_binding(self):
        value = {
            "architecture": "x64",
            "entrypoint": "localops.windows.packaged_entry",
            "packaging": "PyInstaller onedir windowed",
            "product": "Local Ops Console",
            "pyinstallerVersion": build_windows.PYINSTALLER_VERSION,
            "pythonVersion": "3.12.11",
            "runtimeDistributions": {"psutil": "7.2.2", "pywin32": "312"},
            "runnerDispatch": "-m localops.windows.runner",
            "elevationBrokerDispatch": "-m localops.windows.elevation_broker",
            "schemaVersion": 1,
            "signingStatus": build_windows.SIGNING_STATUS,
            "version": VERSION,
        }
        build_windows._validate_build_info(value, VERSION)
        value["pythonVersion"] = "3.13.13"
        with self.assertRaisesRegex(SystemExit, "Python 3.12"):
            build_windows._validate_build_info(value, VERSION)

    def test_windows_archive_member_names_reject_drive_ads_and_devices(self):
        root = build_windows.bundle_name(VERSION)
        for relative in (
            "D:/escape.txt",
            "data:stream",
            "CON",
            "COM¹.txt",
            "LPT³.tar.gz",
            "trailing. ",
            "control\x01name",
        ):
            with self.subTest(relative=relative):
                with self.assertRaisesRegex(SystemExit, "member path is unsafe"):
                    build_windows._validate_windows_archive_member(
                        f"{root}/{relative}", root
                    )

    def test_binary_path_scan_rejects_local_home_but_tolerates_upstream_metadata(self):
        relative = build_windows.PurePosixPath("_internal/_bz2.pyd")
        self.assertIsNone(
            build_windows._find_package_path_leak(
                relative, b"C:/Users/" + b"Administrator/cpython-build"
            )
        )
        local_home = str(Path.home().resolve()).replace("\\", "/").encode("utf-8")
        self.assertIsNotNone(
            build_windows._find_package_path_leak(relative, local_home + b"/private")
        )


class WindowsArtifactAuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bundle = self.root / build_windows.bundle_name(VERSION)
        self.archive = self.root / build_windows.archive_name(VERSION)
        self._write_required_bundle()

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, relative, payload=b"fixture"):
        path = self.bundle / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    def _write_required_bundle(self):
        self.bundle.mkdir()
        self.write("LocalOps.exe", fake_windowed_x64_pe())
        for relative, payload in build_windows.expected_bundled_data().items():
            self.write(relative, payload)
        self.write("_internal/python312.dll")
        self.write("_internal/psutil/_psutil_windows.pyd")
        for name in (
            "win32api",
            "win32console",
            "win32event",
            "win32file",
            "win32gui",
            "win32job",
            "win32pipe",
            "win32process",
            "win32security",
        ):
            self.write(f"_internal/win32/{name}.pyd")
        self.write("_internal/win32com/shell/shell.pyd")
        self.write("_internal/pythonwin/win32ui.pyd")
        self.write("_internal/pywin32_system32/pywintypes312.dll")
        self.write("THIRD-PARTY-LICENSES/Python-LICENSE.txt")
        self.write("THIRD-PARTY-LICENSES/psutil/LICENSE")
        self.write("THIRD-PARTY-LICENSES/pywin32/win32/License.txt")
        self.write("THIRD-PARTY-LICENSES/PyInstaller/COPYING.txt")
        with (
            mock.patch.object(
                build_windows.metadata,
                "version",
                side_effect=build_windows.REQUIRED_DISTRIBUTIONS.__getitem__,
            ),
            mock.patch.object(
                build_windows.platform, "python_version", return_value="3.12.11"
            ),
        ):
            build_windows._write_build_metadata(self.bundle, VERSION)

    def package(self):
        build_windows._zip_bundle(self.bundle, self.archive, VERSION)
        build_windows._write_sidecars(self.archive, VERSION)

    def audit(self):
        with (
            mock.patch.object(
                build_windows,
                "_pe_version_fields",
                return_value=fake_version_resources(),
            ),
            mock.patch.object(
                build_windows.metadata,
                "version",
                side_effect=build_windows.REQUIRED_DISTRIBUTIONS.__getitem__,
            ),
        ):
            return build_windows.audit_archive(self.archive)

    def test_archive_audit_verifies_payload_hashes_manifest_and_contract(self):
        self.package()
        manifest = self.audit()
        self.assertEqual(manifest["version"], VERSION)
        self.assertEqual(manifest["signingStatus"], "UNSIGNED DEVELOPMENT BUILD")
        payload = {item["path"] for item in manifest["payload"]}
        self.assertIn(
            f"{build_windows.bundle_name(VERSION)}/LocalOps.exe", payload
        )

    def test_archive_audit_detects_manifest_tampering(self):
        self.package()
        path = build_windows.manifest_path(self.archive)
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["signingStatus"] = "SIGNED"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "manifest sidecar"):
            self.audit()

    def test_archive_audit_rejects_missing_static_or_native_runtime_files(self):
        static_path = "_internal/static/themes/ops.css"
        (self.bundle / static_path).unlink()
        self.package()
        with self.assertRaisesRegex(SystemExit, "source-controlled package data"):
            self.audit()

        self.write(
            static_path,
            build_windows.expected_bundled_data()[static_path],
        )
        (self.bundle / "_internal/win32/win32job.pyd").unlink()
        self.package()
        with self.assertRaisesRegex(SystemExit, "native runtime files"):
            self.audit()

    def test_archive_audit_rejects_wrong_python_runtime(self):
        (self.bundle / "_internal/python312.dll").unlink()
        self.write("_internal/python313.dll")
        self.package()
        with self.assertRaisesRegex(SystemExit, "Python 3.12 runtime DLL"):
            self.audit()

    def test_bundle_rejects_user_runtime_state_before_archiving(self):
        self.write("config.json", b"{}")
        with self.assertRaisesRegex(SystemExit, "user runtime state"):
            build_windows._zip_bundle(self.bundle, self.archive, VERSION)

    def test_bundle_rejects_absolute_user_path_before_archiving(self):
        leaked = b"C:" + b"\\" + b"Users" + b"\\realperson\\private"
        self.write("_internal/leaked.bin", leaked)
        with self.assertRaisesRegex(SystemExit, "absolute user path"):
            build_windows._zip_bundle(self.bundle, self.archive, VERSION)

    def test_bundle_rejects_secret_marker_before_archiving(self):
        secret = b"AK" + b"IA" + b"A" * 16
        self.write("_internal/leaked.bin", secret)
        with self.assertRaisesRegex(SystemExit, "sensitive content"):
            build_windows._zip_bundle(self.bundle, self.archive, VERSION)

    def test_audit_rejects_non_windowed_or_non_x64_executable(self):
        self.write("LocalOps.exe", b"not a PE")
        self.package()
        with self.assertRaisesRegex(SystemExit, "not a PE"):
            build_windows.audit_archive(self.archive)


if __name__ == "__main__":
    unittest.main()

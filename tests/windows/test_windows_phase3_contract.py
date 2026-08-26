import json
import os
import tempfile
import unittest
from unittest import mock

import server
from localops.command_spec import direct_command_spec


@unittest.skipUnless(os.name == "nt", "Windows-only Phase 3 contracts")
class WindowsPhase3ContractTests(unittest.TestCase):
    def test_normalization_recomputes_stale_import_status(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime = os.path.join(temp_dir, "python.exe")
            with open(runtime, "wb") as handle:
                handle.write(b"static preflight only")
            normalized = server.Config._normalize({
                **server.Config.DEFAULT,
                "apps": [
                    {
                        "id": "deadbeef",
                        "name": "Missing runtime",
                        "command": "missing.exe",
                        "commandSpec": direct_command_spec("missing.exe"),
                        "cwd": temp_dir,
                        "importStatus": "ready",
                    },
                    {
                        "id": "facefeed",
                        "name": "Existing runtime",
                        "command": runtime,
                        "commandSpec": direct_command_spec(runtime),
                        "cwd": temp_dir,
                        "importStatus": "needs_review",
                    },
                ],
            })

        self.assertEqual(normalized["apps"][0]["importStatus"], "blocked")
        self.assertEqual(normalized["apps"][1]["importStatus"], "ready")

    def test_picker_payload_uses_native_components_and_structured_command(self):
        with tempfile.TemporaryDirectory(prefix="D 盘 中文 ") as temp_dir:
            path = os.path.join(temp_dir, "run & inspect.ps1")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("Write-Output 'not executed'\n")

            payload = server.picker_payload(path, "script")

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["path"], os.path.abspath(path))
        self.assertEqual(payload["dir"], os.path.dirname(os.path.abspath(path)))
        self.assertEqual(payload["stem"], "run & inspect")
        self.assertEqual(payload["commandSpec"]["mode"], "powershell")
        self.assertEqual(payload["commandSpec"]["executable"], payload["path"])
        self.assertIn(payload["platformCompatibility"]["status"],
                      ("ready", "blocked"))

    def test_project_detection_adds_windows_script_modes_without_execution(self):
        with tempfile.TemporaryDirectory(prefix="D 盘 中文 ") as temp_dir:
            marker = os.path.join(temp_dir, "executed.txt")
            scripts = {
                "start.cmd": "@echo off\r\necho ran>\"%s\"\r\n" % marker,
                "dev.ps1": "Set-Content -Path %r -Value ran\n" % marker,
            }
            for name, text in scripts.items():
                with open(os.path.join(temp_dir, name), "w",
                          encoding="utf-8") as handle:
                    handle.write(text)

            result, error = server.detect_project(temp_dir)

        self.assertIsNone(error)
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(
            [(item["source"], item["commandSpec"]["mode"])
             for item in result["candidates"]],
            [("start.cmd", "cmd"), ("dev.ps1", "powershell")],
        )
        self.assertEqual(result["candidates"][0]["commandSpec"]["executable"],
                         os.path.join(temp_dir, "start.cmd"))
        self.assertTrue(all("platformCompatibility" in item
                            for item in result["candidates"]))

    def test_project_detection_rejects_unc_without_filesystem_probe(self):
        with mock.patch.object(server.os.path, "isdir") as isdir:
            result, error = server.detect_project(
                r"\\example.invalid\share\project"
            )

        self.assertIsNone(result)
        self.assertEqual(error, "项目文件夹不存在或不可访问")
        isdir.assert_not_called()

    def test_jekyll_detection_classifies_windows_bundle_shim(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "Gemfile"), "w",
                      encoding="utf-8") as handle:
                handle.write("gem 'jekyll'\n")
            shim = os.path.join(temp_dir, "bundle.CMD")
            with open(shim, "w", encoding="utf-8") as handle:
                handle.write("@echo off\n")
            with mock.patch.dict(os.environ, {
                "PATH": temp_dir,
                "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            }, clear=False):
                result, error = server.detect_project(temp_dir)

        self.assertIsNone(error)
        candidate = next(item for item in result["candidates"]
                         if item["source"] == "Gemfile")
        self.assertEqual(candidate["commandSpec"]["mode"], "cmd")
        self.assertTrue(candidate["commandSpec"]["executable"].lower().endswith(
            "bundle.cmd"))
        self.assertEqual(candidate["command"], server.display_command(
            candidate["commandSpec"]))

    def test_app_field_round_trip_preserves_command_spec_and_legacy_command(self):
        spec = direct_command_spec(
            r"C:\Program Files\Python312\python.exe",
            ["-m", "http.server", "8000", "中文 & literal"],
        )
        fields, error = server.validate_app_fields({
            "name": "Structured",
            "command": "display only",
            "commandSpec": spec,
            "cwd": r"D:\Projects\中文 app",
            "port": 8000,
            "kind": "service",
        }, partial=False)

        self.assertIsNone(error)
        self.assertEqual(fields["command"], "display only")
        self.assertEqual(fields["commandSpec"], spec)

    def test_legacy_command_update_replaces_stale_structured_spec(self):
        fields, error = server.validate_app_fields(
            {"command": "python3 app.py"}, partial=True)

        self.assertIsNone(error)
        self.assertEqual(fields["commandSpec"]["mode"], "legacy-posix")
        self.assertTrue(fields["commandSpec"]["needsReview"])

    def test_elevated_batch_requires_a_reviewed_structured_script(self):
        structured = {
            "version": 1,
            "mode": "powershell",
            "executable": r"C:\Tasks\backup.ps1",
            "args": [],
            "shell": "powershell.exe",
            "text": None,
            "needsReview": False,
        }
        fields, error = server.validate_app_fields({
            "name": "Admin backup",
            "command": "powershell.exe -File C:\\Tasks\\backup.ps1",
            "commandSpec": structured,
            "cwd": r"C:\Tasks",
            "kind": "task",
            "elevated": True,
        }, partial=False)

        self.assertIsNone(error)
        self.assertEqual(fields["kind"], "task")
        self.assertTrue(fields["elevated"])

        raw = dict(structured, executable=None, text="Remove-Item C:\\*")
        _, error = server.validate_app_fields({
            "name": "Unsafe admin shell",
            "command": "raw",
            "commandSpec": raw,
            "cwd": r"C:\Tasks",
            "kind": "task",
            "elevated": True,
        }, partial=False)
        self.assertIn("管理员批处理", error)

        for executable, args in (
                (r"C:\Windows\System32\cmd.exe", ["/c", "exit 0"]),
                (r"C:\Tools\bash.exe", ["-c", "exit 0"]),
                (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe",
                 ["-File", r"C:\Tasks\raw.ps1"]),
                (r"C:\Python312\pythonw.exe", ["-c", "raise SystemExit(0)"])):
            with self.subTest(executable=executable):
                _, error = server.validate_app_fields({
                    "name": "Disguised shell", "command": "display only",
                    "commandSpec": direct_command_spec(executable, args),
                    "cwd": r"C:\Tasks", "kind": "task", "elevated": True,
                }, partial=False)
                self.assertIn("结构化脚本", error)

    def test_schema_migration_never_executes_or_accesses_network(self):
        schema_v1 = {
            "schemaVersion": 1,
            "apps": [{
                "id": "deadbeef",
                "name": "Do not run",
                "command": "echo must-not-run",
            }],
            "hidden": [],
            "pinned": [],
            "promoted": [],
            "watchedKeywords": [],
            "uiTheme": "ops",
        }
        with mock.patch("subprocess.run") as run, \
                mock.patch("urllib.request.urlopen") as urlopen:
            migrated, source_version = server.migrate_config(schema_v1)

        self.assertEqual(source_version, 1)
        self.assertEqual(migrated["schemaVersion"], server.CURRENT_SCHEMA_VERSION)
        run.assert_not_called()
        urlopen.assert_not_called()
        json.dumps(migrated)


if __name__ == "__main__":
    unittest.main()

import os
import tempfile
import unittest
from unittest import mock

from localops.command_spec import (
    COMMAND_SPEC_KEYS,
    CommandSpecError,
    command_spec_for_executable,
    command_spec_for_script,
    direct_command_spec,
    display_command,
    legacy_command_spec,
    normalize_command_spec,
    platform_compatibility,
    prepared_invocation,
    python_command_spec,
    resolve_windows_executable,
    shell_command_spec,
    static_preflight,
)


SPECIAL_ARGUMENTS = [
    "space value",
    "中文路径",
    "&",
    "|",
    "<",
    ">",
    "^",
    "(",
    ")",
    "%",
    "!",
    "'",
    '"',
    "`",
    "$",
    ";",
    "",
]


class CommandSpecValidationTests(unittest.TestCase):
    def test_normalize_returns_only_fixed_keys_and_copies_args(self):
        value = {
            **direct_command_spec("python.exe", ["-m", "http.server"]),
            "ignoredFutureField": True,
        }

        normalized = normalize_command_spec(value)

        self.assertEqual(tuple(normalized), COMMAND_SPEC_KEYS)
        self.assertNotIn("ignoredFutureField", normalized)
        self.assertIsNot(value["args"], normalized["args"])

    def test_invalid_union_shapes_are_rejected(self):
        valid = direct_command_spec("tool.exe")
        invalid = (
            {**valid, "version": True},
            {**valid, "args": [1]},
            {**valid, "shell": "cmd.exe"},
            {**valid, "executable": "bad\x00.exe"},
            {
                "version": 1,
                "mode": "cmd",
                "executable": "start.cmd",
                "args": [],
                "shell": "cmd.exe",
                "text": "echo duplicate",
                "needsReview": False,
            },
            {
                "version": 1,
                "mode": "powershell",
                "executable": "start.cmd",
                "args": [],
                "shell": "powershell.exe",
                "text": None,
                "needsReview": False,
            },
            {
                "version": 1,
                "mode": "legacy-posix",
                "executable": None,
                "args": [],
                "shell": None,
                "text": "python3 app.py",
                "needsReview": False,
            },
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(CommandSpecError):
                normalize_command_spec(value)

    def test_structured_and_raw_shell_shapes_are_mutually_exclusive(self):
        structured_cmd = normalize_command_spec({
            "version": 1,
            "mode": "cmd",
            "executable": r"C:\Projects\start.cmd",
            "args": ["dev"],
            "shell": "CMD.EXE",
            "text": None,
            "needsReview": False,
        })
        raw_powershell = shell_command_spec("powershell", "Get-Date")

        self.assertEqual(structured_cmd["shell"], "cmd.exe")
        self.assertIsNone(structured_cmd["text"])
        self.assertIsNone(raw_powershell["executable"])
        self.assertEqual(raw_powershell["args"], [])
        self.assertTrue(raw_powershell["needsReview"])

        reviewed = shell_command_spec("cmd", "echo raw", needs_review=False)
        self.assertFalse(reviewed["needsReview"])

    def test_raw_shell_compatibility_requires_review(self):
        compatibility = platform_compatibility(
            shell_command_spec("cmd", "echo %PATH%")
        )

        self.assertEqual(compatibility, {
            "status": "needs_review",
            "reasons": [{
                "code": "COMMAND_SPEC_INVALID",
                "message": "The command requires review before execution.",
            }],
        })

    def test_legacy_command_is_preserved_exactly_and_needs_review(self):
        command = "python3 '$HOME/中文 app.py' && echo done"

        spec = legacy_command_spec(command)

        self.assertEqual(spec["text"], command)
        self.assertTrue(spec["needsReview"])
        self.assertEqual(
            platform_compatibility(spec),
            {
                "status": "needs_review",
                "reasons": [{
                    "code": "LEGACY_POSIX_COMMAND",
                    "message": "Review this command for Windows.",
                }],
            },
        )

    def test_empty_legacy_command_is_preserved_but_blocked(self):
        spec = legacy_command_spec("")

        self.assertEqual(spec["text"], "")
        self.assertEqual(platform_compatibility(spec), {
            "status": "blocked",
            "reasons": [{
                "code": "COMMAND_SPEC_INVALID",
                "message": "The legacy command is empty.",
            }],
        })

        with self.assertRaises(CommandSpecError):
            legacy_command_spec("bad\x00command")


class PreparedInvocationTests(unittest.TestCase):
    def test_direct_preserves_every_special_argument_as_a_literal_element(self):
        spec = direct_command_spec(
            r"C:\Program Files\工具\runner.exe",
            SPECIAL_ARGUMENTS,
        )

        invocation = prepared_invocation(spec)

        self.assertEqual(
            invocation,
            [r"C:\Program Files\工具\runner.exe", *SPECIAL_ARGUMENTS],
        )

    def test_structured_powershell_uses_file_and_preserves_literal_args(self):
        spec = normalize_command_spec({
            "version": 1,
            "mode": "powershell",
            "executable": r"D:\项目 & tools\run.ps1",
            "args": SPECIAL_ARGUMENTS,
            "shell": "powershell.exe",
            "text": None,
            "needsReview": False,
        })

        invocation = prepared_invocation(spec)

        self.assertEqual(invocation, {
            "mode": "powershell",
            "executable": "powershell.exe",
            "prefixArgs": [
                "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
            ],
            "script": spec["executable"],
            "args": SPECIAL_ARGUMENTS,
        })
        self.assertNotIn("-ExecutionPolicy", invocation["prefixArgs"])

    def test_raw_shell_prefixes_are_fixed_and_text_is_one_element(self):
        cmd_text = "echo %USERPROFILE% & echo done"
        powershell_text = "Write-Output $Env:USERPROFILE; Write-Output 'done'"

        cmd = prepared_invocation(
            shell_command_spec("cmd", cmd_text, needs_review=False),
            {"COMSPEC": r"C:\Windows\System32\cmd.exe"},
        )
        powershell = prepared_invocation(
            shell_command_spec("powershell", powershell_text, needs_review=False)
        )

        self.assertEqual(cmd, [
            r"C:\Windows\System32\cmd.exe", "/d", "/s", "/c", cmd_text,
        ])
        self.assertEqual(powershell[-2:], ["-Command", powershell_text])

    def test_prepared_invocation_rejects_unreviewed_shell_text(self):
        with self.assertRaises(CommandSpecError):
            prepared_invocation(shell_command_spec("cmd", "echo raw"))

    def test_structured_cmd_quotes_safe_values_but_rejects_unprovable_values(self):
        safe = normalize_command_spec({
            "version": 1,
            "mode": "cmd",
            "executable": r"D:\项目 & tools\start.cmd",
            "args": ["space value", "中文", "&|<>()^", "'`$;"],
            "shell": "cmd.exe",
            "text": None,
            "needsReview": False,
        })

        invocation = prepared_invocation(
            safe, {"COMSPEC": r"C:\Windows\System32\cmd.exe"}
        )

        self.assertEqual(invocation, {
            "mode": "cmd",
            "executable": r"C:\Windows\System32\cmd.exe",
            "prefixArgs": ["/d", "/s", "/c"],
            "script": safe["executable"],
            "args": safe["args"],
        })
        for unsafe in ("%PATH%", "bang!", 'embedded"quote'):
            spec = {**safe, "args": [unsafe]}
            with self.subTest(unsafe=unsafe), self.assertRaises(CommandSpecError):
                prepared_invocation(spec)

    def test_legacy_posix_has_no_windows_prepared_invocation(self):
        with self.assertRaises(CommandSpecError):
            prepared_invocation(legacy_command_spec("python3 app.py"))

    def test_display_string_is_not_used_to_prepare_direct_invocation(self):
        spec = direct_command_spec("runner.exe", SPECIAL_ARGUMENTS)

        displayed = display_command(spec)

        self.assertIsInstance(displayed, str)
        self.assertEqual(prepared_invocation(spec), ["runner.exe", *SPECIAL_ARGUMENTS])


@unittest.skipUnless(os.name == "nt", "Windows PATH/PATHEXT tests")
class WindowsDetectionAndPreflightTests(unittest.TestCase):
    def test_pathext_resolves_npm_and_pnpm_cmd_shims(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            npm = os.path.join(temp_dir, "npm.CMD")
            pnpm = os.path.join(temp_dir, "pnpm.cmd")
            for path in (npm, pnpm):
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("@echo off\n")
            env = {"PATH": temp_dir, "PATHEXT": ".COM;.EXE;.BAT;.CMD"}

            resolved_npm = resolve_windows_executable("npm", env=env)
            resolved_pnpm = resolve_windows_executable("pnpm", env=env)
            npm_spec = command_spec_for_executable(
                "npm", ["run", "dev"], env=env
            )
            pnpm_spec = command_spec_for_executable(
                "pnpm", ["run", "dev"], env=env
            )

        self.assertEqual(os.path.normcase(resolved_npm), os.path.normcase(npm))
        self.assertEqual(os.path.normcase(resolved_pnpm), os.path.normcase(pnpm))
        self.assertEqual(npm_spec["mode"], "cmd")
        self.assertEqual(pnpm_spec["mode"], "cmd")
        self.assertTrue(str(npm_spec["executable"]).lower().endswith("npm.cmd"))

    def test_script_suffixes_choose_windows_modes_and_python_launcher(self):
        with tempfile.TemporaryDirectory(prefix="D 盘 中文 ") as temp_dir:
            specs = {
                suffix: command_spec_for_script(
                    os.path.join(temp_dir, "run file" + suffix), "windows"
                )
                for suffix in (".cmd", ".bat", ".ps1", ".exe", ".com", ".py", ".sh")
            }

        self.assertEqual(specs[".cmd"]["mode"], "cmd")
        self.assertEqual(specs[".bat"]["mode"], "cmd")
        self.assertEqual(specs[".ps1"]["mode"], "powershell")
        self.assertEqual(specs[".exe"]["mode"], "direct")
        self.assertEqual(specs[".com"]["mode"], "direct")
        self.assertEqual(specs[".py"]["executable"], "py.exe")
        self.assertEqual(specs[".py"]["args"][0], "-3.12")
        self.assertEqual(specs[".sh"]["mode"], "legacy-posix")

    def test_explicit_python_executable_does_not_add_py_launcher_selector(self):
        spec = command_spec_for_script(
            r"D:\项目\app.py",
            "windows",
            python_executable=r"C:\Python312\python.exe",
        )

        self.assertEqual(spec["executable"], r"C:\Python312\python.exe")
        self.assertEqual(spec["args"], [r"D:\项目\app.py"])

    def test_python_command_uses_supported_current_source_interpreter(self):
        spec = python_command_spec(
            ["-m", "http.server", "8000"],
            platform_name="windows",
            current_executable=os.path.abspath(__import__("sys").executable),
            current_version=(3, 12),
        )

        self.assertEqual(spec["executable"],
                         os.path.abspath(__import__("sys").executable))
        self.assertEqual(spec["args"], ["-m", "http.server", "8000"])

    def test_python_command_rejects_unsupported_current_interpreter(self):
        spec = python_command_spec(
            ["-m", "http.server", "8000"],
            platform_name="windows",
            current_executable=os.path.abspath(__import__("sys").executable),
            current_version=(3, 13),
            env={"PATH": "", "PATHEXT": ".EXE;.CMD"},
        )

        self.assertEqual(spec["executable"], "py.exe")
        self.assertEqual(spec["args"], ["-3.12", "-m", "http.server", "8000"])

    def test_non_windows_legacy_command_remains_ready(self):
        compatibility = platform_compatibility(
            legacy_command_spec("python3 app.py"),
            platform_name="macos",
        )

        self.assertEqual(compatibility, {"status": "ready", "reasons": []})

    def test_static_preflight_checks_files_without_running_them(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            script = os.path.join(temp_dir, "must not run.py")
            marker = os.path.join(temp_dir, "executed.txt")
            with open(script, "w", encoding="utf-8") as handle:
                handle.write(
                    "from pathlib import Path\n"
                    f"Path({marker!r}).write_text('ran', encoding='utf-8')\n"
                )
            python_copy = os.path.join(temp_dir, "python.EXE")
            with open(python_copy, "wb") as handle:
                handle.write(b"not an executable and must not run")
            env = {"PATH": temp_dir, "PATHEXT": ".EXE"}
            spec = direct_command_spec("python", [script])

            health = static_preflight(spec, temp_dir, "windows", env)

            self.assertEqual(health, {
                "status": "ok", "blocking": False, "issues": [],
            })
            self.assertFalse(os.path.exists(marker))

    def test_static_preflight_reports_missing_cwd_script_and_runtime(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_cwd = os.path.join(temp_dir, "gone")
            direct = static_preflight(
                direct_command_spec("missing-runtime"),
                temp_dir,
                "windows",
                {"PATH": temp_dir, "PATHEXT": ".EXE"},
            )
            script = normalize_command_spec({
                "version": 1,
                "mode": "powershell",
                "executable": os.path.join(temp_dir, "missing.ps1"),
                "args": [],
                "shell": "powershell.exe",
                "text": None,
                "needsReview": False,
            })
            missing_script = static_preflight(
                script,
                temp_dir,
                "windows",
                {"PATH": temp_dir, "PATHEXT": ".EXE"},
            )
            missing_directory = static_preflight(
                legacy_command_spec("python3 app.py"), missing_cwd, "windows"
            )

        self.assertEqual(direct["issues"][0]["kind"], "runtime-missing")
        self.assertTrue(direct["blocking"])
        self.assertEqual(
            {issue["kind"] for issue in missing_script["issues"]},
            {"runtime-missing", "script-missing"},
        )
        self.assertEqual(missing_directory["issues"][0]["kind"], "cwd-missing")

    def test_unsafe_structured_cmd_is_review_only_not_ready(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            script = os.path.join(temp_dir, "start.cmd")
            with open(script, "w", encoding="utf-8") as handle:
                handle.write("@echo off\n")
            spec = normalize_command_spec({
                "version": 1,
                "mode": "cmd",
                "executable": script,
                "args": ["%PATH%"],
                "shell": "cmd.exe",
                "text": None,
                "needsReview": False,
            })

            compatibility = platform_compatibility(spec)

        self.assertEqual(compatibility["status"], "needs_review")
        self.assertEqual(
            compatibility["reasons"][0]["code"], "COMMAND_SPEC_INVALID"
        )

    def test_unc_and_device_paths_are_rejected_without_filesystem_probe(self):
        remote_paths = (
            r"\\example.invalid\tools",
            r"\\?\UNC\example.invalid\tools",
            r"\\.\C:\device-path",
            r"\??\C:\native-device-path",
        )
        for path in remote_paths:
            with self.subTest(path=path), \
                    mock.patch("localops.command_spec.os.path.isfile") as isfile, \
                    mock.patch("localops.command_spec.os.path.isdir") as isdir:
                self.assertIsNone(resolve_windows_executable(
                    "tool", env={"PATH": path, "PATHEXT": ".EXE"}
                ))
                health = static_preflight(
                    direct_command_spec(path + r"\tool.exe"),
                    path,
                    "windows",
                    {"PATH": path, "PATHEXT": ".EXE"},
                )
                self.assertTrue(health["blocking"])
                self.assertEqual(health["issues"][0]["kind"], "cwd-missing")
                isfile.assert_not_called()
                isdir.assert_not_called()


if __name__ == "__main__":
    unittest.main()

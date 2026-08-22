import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import server
import localops.config_import as config_import_module
from localops.config_import import (
    ConfigImportError,
    MAX_SOURCE_BYTES,
    commit_import,
    config_hash,
    preview_import,
    rollback_import,
)


def _direct_spec(executable="python.exe"):
    return {
        "version": 1,
        "mode": "direct",
        "executable": executable,
        "args": ["-m", "http.server", "8000"],
        "shell": None,
        "text": None,
        "needsReview": False,
    }


def _compatibility(spec, cwd, platform_name):
    if platform_name != "windows":
        raise AssertionError("import compatibility must target Windows")
    if spec["mode"] == "legacy-posix":
        return {
            "status": "needs_review",
            "reasons": [{
                "code": "LEGACY_POSIX_COMMAND",
                "message": "Review this command for Windows.",
            }],
        }
    if spec["executable"] == "missing.exe":
        return {
            "status": "blocked",
            "reasons": [{
                "code": "PATH_NOT_FOUND",
                "message": "A required command or path was not found.",
            }],
        }
    return {"status": "ready", "reasons": []}


def _normalize_config(value):
    def import_status(spec, cwd):
        return _compatibility(spec, cwd, "windows")["status"]

    with mock.patch.object(
        server, "command_import_status", side_effect=import_status
    ):
        return server.Config._normalize(value)


class _ConfigStore:
    def __init__(self, initial):
        self.value = _normalize_config(initial)
        self.replace_calls = 0

    def get(self):
        return copy.deepcopy(self.value)

    def replace(self, expected_hash, replacement):
        self.replace_calls += 1
        if config_hash(_normalize_config(self.value)) != expected_hash:
            return False
        self.value = _normalize_config(replacement)
        return True


class ConfigImportContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(self._make_records_writable)
        self.source = self.root / "macos-config.json"
        self.records = self.root / "imports"
        self.mappings = [{
            "sourceRoot": "/Volumes/Workspace/Projects",
            "targetRoot": r"D:\Projects",
        }]
        self.source_data = {
            "schemaVersion": 2,
            "apps": [
                {
                    "id": "deadbeef",
                    "name": "Legacy",
                    "kind": "service",
                    "cwd": "/Volumes/Workspace/Projects/legacy app",
                    "port": 3000,
                    "command": "python3 app.py",
                    "commandSpec": {
                        "version": 1,
                        "mode": "legacy-posix",
                        "executable": None,
                        "args": [],
                        "shell": None,
                        "text": "python3 app.py",
                        "needsReview": True,
                    },
                    "lastPid": 123,
                    "lastPgid": 456,
                    "runToken": "old-token",
                    "attached": True,
                    "runtimeIdentity": {"pid": 123},
                    "lastExit": {"code": 1},
                },
                {
                    "id": "cafebabe",
                    "name": "Ready",
                    "kind": "service",
                    "cwd": "/Volumes/Workspace/Projects/ready",
                    "command": "python.exe -m http.server 8000",
                    "commandSpec": _direct_spec(),
                },
                {
                    "id": "badc0ffe",
                    "name": "Unmapped",
                    "cwd": "/opt/unmapped",
                    "command": "python.exe -m http.server 8000",
                    "commandSpec": _direct_spec(),
                },
                {
                    "id": "feedface",
                    "name": "Conflict",
                    "cwd": "/Volumes/Workspace/Projects/conflict",
                    "command": "python.exe -m http.server 8000",
                    "commandSpec": _direct_spec(),
                },
            ],
            "hidden": ["old-process-key"],
            "pinned": ["old-process-key"],
            "promoted": ["old-process-key"],
        }
        self.source_bytes = self._write_source(self.source_data)
        self.initial_target = {
            "schemaVersion": 2,
            "apps": [{
                "id": "feedface",
                "name": "Existing",
                "cwd": None,
                "command": "",
            }],
            "hidden": ["keep-hidden"],
            "pinned": ["keep-pinned"],
            "promoted": ["keep-promoted"],
        }
        self.store = _ConfigStore(self.initial_target)

    def _make_records_writable(self):
        if not self.records.exists():
            return
        for root, directories, files in os.walk(self.records):
            for name in [*directories, *files]:
                try:
                    os.chmod(
                        os.path.join(root, name),
                        stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC,
                    )
                except OSError:
                    pass

    def _write_source(self, value):
        payload = (
            json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8")
        self.source.write_bytes(payload)
        return payload

    def _preview(self, *, source=None, mappings=None, target=None):
        with mock.patch(
            "localops.config_import.platform_compatibility",
            side_effect=_compatibility,
        ):
            return preview_import(
                str(source or self.source),
                self.mappings if mappings is None else mappings,
                self.store.get() if target is None else target,
                normalize_config=_normalize_config,
                path_exists=lambda _path: True,
            )

    def _commit(self, preview, selected, *, private_file=None):
        with mock.patch(
            "localops.config_import.platform_compatibility",
            side_effect=_compatibility,
        ):
            return commit_import(
                str(self.source),
                self.mappings,
                preview["previewId"],
                selected,
                records_dir=str(self.records),
                get_target=self.store.get,
                replace_target=self.store.replace,
                normalize_config=_normalize_config,
                ensure_private_file=private_file,
                path_exists=lambda _path: True,
            )

    def test_preview_is_deterministic_and_has_no_write_side_effect(self):
        before_target = self.store.get()
        before_files = sorted(
            str(path.relative_to(self.root))
            for path in self.root.rglob("*")
        )

        first = self._preview()
        second = self._preview()

        self.assertEqual(first, second)
        self.assertEqual(self.store.get(), before_target)
        self.assertEqual(
            sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*")),
            before_files,
        )
        self.assertFalse(self.records.exists())
        self.assertEqual(
            first["sourceHash"],
            "sha256:" + hashlib.sha256(self.source_bytes).hexdigest(),
        )
        self.assertRegex(
            first["previewId"],
            r"^sha256:[0-9a-f]{64}\.[0-9a-f]{64}$",
        )
        self.assertEqual(first["summary"], {
            "ready": 1,
            "needs_review": 1,
            "blocked": 1,
            "conflict": 1,
        })
        apps = {app["id"]: app for app in first["apps"]}
        self.assertEqual(apps["deadbeef"]["status"], "needs_review")
        self.assertEqual(apps["deadbeef"]["cwd"], r"D:\Projects\legacy app")
        self.assertIsNone(apps["deadbeef"]["lastPid"])
        self.assertIsNone(apps["deadbeef"]["lastPgid"])
        self.assertIsNone(apps["deadbeef"]["runToken"])
        self.assertIsNone(apps["deadbeef"]["runtimeIdentity"])
        self.assertIsNone(apps["deadbeef"]["lastExit"])
        self.assertFalse(apps["deadbeef"]["attached"])
        self.assertEqual(apps["badc0ffe"]["status"], "blocked")
        self.assertEqual(
            apps["badc0ffe"]["reasons"][0]["code"],
            "PATH_MAPPING_REQUIRED",
        )
        self.assertEqual(apps["feedface"]["status"], "conflict")

    def test_preview_blocks_a_direct_command_with_missing_runtime(self):
        value = copy.deepcopy(self.source_data)
        value["apps"] = [copy.deepcopy(value["apps"][1])]
        value["apps"][0]["commandSpec"] = _direct_spec("missing.exe")
        self._write_source(value)

        preview = self._preview()

        self.assertEqual(preview["apps"][0]["status"], "blocked")
        self.assertEqual(
            preview["apps"][0]["reasons"][0]["code"], "PATH_NOT_FOUND"
        )

    def test_preview_rejects_non_contract_app_id(self):
        value = copy.deepcopy(self.source_data)
        value["apps"] = [copy.deepcopy(value["apps"][1])]
        value["apps"][0]["id"] = "not-an-id"
        self._write_source(value)

        with self.assertRaises(ConfigImportError) as raised:
            self._preview()

        self.assertEqual(raised.exception.code, "IMPORT_SOURCE_INVALID")
        self.assertEqual(raised.exception.http_status, 400)

    def test_preview_rejects_oversized_source_and_unsafe_app_fields(self):
        self.source.write_bytes(b"x" * (MAX_SOURCE_BYTES + 1))
        with self.assertRaises(ConfigImportError) as oversized:
            self._preview()
        self.assertEqual(oversized.exception.code, "IMPORT_SOURCE_INVALID")

        invalid_values = {
            "id": "DEADBEEF",
            "name": " ",
            "command": "bad\x00command",
            "cwd": 123,
            "kind": "daemon",
            "port": True,
            "icon": {"path": "unexpected"},
        }
        for field, invalid in invalid_values.items():
            with self.subTest(field=field):
                value = copy.deepcopy(self.source_data)
                value["apps"] = [copy.deepcopy(value["apps"][0])]
                value["apps"][0][field] = invalid
                self._write_source(value)
                with self.assertRaises(ConfigImportError) as malformed:
                    self._preview()
                self.assertEqual(
                    malformed.exception.code, "IMPORT_SOURCE_INVALID"
                )

    def test_preview_rejects_source_symlink(self):
        target = self.root / "source-target.json"
        target.write_bytes(self.source_bytes)
        link = self.root / "source-link.json"
        try:
            link.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        with self.assertRaises(ConfigImportError) as raised:
            self._preview(source=link)

        self.assertEqual(raised.exception.code, "INVALID_PATH")

    def test_commit_records_source_before_receipt_and_clears_runtime(self):
        preview = self._preview()
        private_paths = []

        result = self._commit(
            preview,
            ["cafebabe", "deadbeef"],
            private_file=lambda path: private_paths.append(Path(path).name),
        )

        self.assertFalse(result["idempotent"])
        self.assertEqual(result["importedAppIds"], ["deadbeef", "cafebabe"])
        apps = {app["id"]: app for app in self.store.value["apps"]}
        self.assertEqual(set(apps), {"feedface", "deadbeef", "cafebabe"})
        self.assertEqual(apps["deadbeef"]["importStatus"], "needs_review")
        self.assertEqual(apps["cafebabe"]["importStatus"], "ready")
        for app_id in ("deadbeef", "cafebabe"):
            self.assertIsNone(apps[app_id]["lastPid"])
            self.assertIsNone(apps[app_id]["lastPgid"])
            self.assertIsNone(apps[app_id]["runToken"])
            self.assertIsNone(apps[app_id]["runtimeIdentity"])
            self.assertFalse(apps[app_id]["attached"])
        self.assertEqual(self.store.value["hidden"], ["keep-hidden"])
        self.assertEqual(self.store.value["pinned"], ["keep-pinned"])
        self.assertEqual(self.store.value["promoted"], ["keep-promoted"])

        record = self.records / result["importId"]
        self.assertEqual((record / "source.json").read_bytes(), self.source_bytes)
        receipt = json.loads((record / "receipt.json").read_text("utf-8"))
        self.assertEqual(receipt["status"], "committed")
        self.assertEqual(receipt["postHash"], config_hash(self.store.value))
        self.assertTrue({"source.json", "before.json", "receipt.json"}
                        .issubset(private_paths))

    def test_commit_is_idempotent_only_while_post_hash_matches(self):
        preview = self._preview()
        first = self._commit(preview, ["deadbeef"])
        replace_calls = self.store.replace_calls

        repeated = self._commit(preview, ["deadbeef"])

        self.assertTrue(repeated["idempotent"])
        self.assertEqual(repeated["importId"], first["importId"])
        self.assertEqual(self.store.replace_calls, replace_calls)
        self.store.value["watchedKeywords"] = ["later-edit"]
        with self.assertRaises(ConfigImportError) as raised:
            self._commit(preview, ["deadbeef"])
        self.assertEqual(raised.exception.code, "IMPORT_PREVIEW_STALE")

    def test_commit_idempotency_does_not_reprobe_changed_environment(self):
        preview = self._preview()
        first = self._commit(preview, ["deadbeef"])
        replace_calls = self.store.replace_calls
        normalize_calls = 0
        path_calls = 0

        def changed_environment_normalizer(value):
            nonlocal normalize_calls
            normalize_calls += 1
            with mock.patch.object(
                server, "command_import_status", return_value="blocked"
            ):
                return server.Config._normalize(value)

        changed = changed_environment_normalizer(self.store.get())
        self.assertNotEqual(config_hash(changed), config_hash(self.store.get()))
        normalize_calls = 0

        def missing_path(_path):
            nonlocal path_calls
            path_calls += 1
            return False

        repeated = commit_import(
            str(self.source),
            self.mappings,
            preview["previewId"],
            ["deadbeef"],
            records_dir=str(self.records),
            get_target=self.store.get,
            replace_target=self.store.replace,
            normalize_config=changed_environment_normalizer,
            path_exists=missing_path,
        )

        self.assertTrue(repeated["idempotent"])
        self.assertEqual(repeated["importId"], first["importId"])
        self.assertEqual(normalize_calls, 0)
        self.assertEqual(path_calls, 0)
        self.assertEqual(self.store.replace_calls, replace_calls)

    def test_new_commit_still_runs_dynamic_normalization(self):
        preview = self._preview()
        normalize_calls = 0

        def tracking_normalizer(value):
            nonlocal normalize_calls
            normalize_calls += 1
            return _normalize_config(value)

        with mock.patch(
            "localops.config_import.platform_compatibility",
            side_effect=_compatibility,
        ):
            committed = commit_import(
                str(self.source),
                self.mappings,
                preview["previewId"],
                ["deadbeef"],
                records_dir=str(self.records),
                get_target=self.store.get,
                replace_target=self.store.replace,
                normalize_config=tracking_normalizer,
                path_exists=lambda _path: True,
            )

        self.assertFalse(committed["idempotent"])
        self.assertGreater(normalize_calls, 0)

    def test_commit_recovers_prepared_receipt_after_double_failure(self):
        preview = self._preview()
        original_write = config_import_module._write_private
        write_calls = 0

        def fail_final_receipt(*args, **kwargs):
            nonlocal write_calls
            write_calls += 1
            if write_calls == 4:
                raise OSError("receipt unavailable")
            return original_write(*args, **kwargs)

        original_replace = self.store.replace
        replace_calls = 0

        def fail_compensation(expected_hash, replacement):
            nonlocal replace_calls
            replace_calls += 1
            if replace_calls == 2:
                raise OSError("compensation unavailable")
            return original_replace(expected_hash, replacement)

        self.store.replace = fail_compensation
        with mock.patch.object(
            config_import_module, "_write_private", side_effect=fail_final_receipt
        ), self.assertRaises(ConfigImportError) as raised:
            self._commit(preview, ["deadbeef"])
        self.assertEqual(raised.exception.code, "IMPORT_COMMIT_FAILED")
        self.store.replace = original_replace

        recovered = self._commit(preview, ["deadbeef"])

        self.assertTrue(recovered["idempotent"])
        receipt = json.loads(
            (self.records / recovered["importId"] / "receipt.json")
            .read_text("utf-8")
        )
        self.assertEqual(receipt["status"], "committed")

    def test_commit_rejects_changed_source_and_blocked_selection(self):
        preview = self._preview()
        changed = copy.deepcopy(self.source_data)
        changed["apps"][0]["name"] = "Changed"
        self._write_source(changed)

        with self.assertRaises(ConfigImportError) as changed_error:
            self._commit(preview, ["deadbeef"])
        self.assertEqual(changed_error.exception.code, "IMPORT_SOURCE_CHANGED")
        self.assertFalse(self.records.exists())

        self.source_bytes = self._write_source(self.source_data)
        preview = self._preview()
        with self.assertRaises(ConfigImportError) as selection_error:
            self._commit(preview, ["badc0ffe"])
        self.assertEqual(
            selection_error.exception.code, "IMPORT_SELECTION_INVALID"
        )

    def test_commit_compare_and_swap_rejects_concurrent_target_change(self):
        preview = self._preview()

        def concurrent_replace(_expected_hash, _replacement):
            self.store.value["watchedKeywords"] = ["concurrent"]
            return False

        self.store.replace = concurrent_replace
        with self.assertRaises(ConfigImportError) as raised:
            self._commit(preview, ["deadbeef"])

        self.assertEqual(raised.exception.code, "IMPORT_PREVIEW_STALE")
        self.assertEqual(self.store.value["watchedKeywords"], ["concurrent"])
        self.assertEqual(list(self.records.iterdir()), [])

    def test_rollback_uses_post_hash_cas_and_is_idempotent(self):
        before = self.store.get()
        preview = self._preview()
        committed = self._commit(preview, ["deadbeef"])

        rolled_back = rollback_import(
            committed["importId"],
            records_dir=str(self.records),
            get_target=self.store.get,
            replace_target=self.store.replace,
            normalize_config=_normalize_config,
        )
        repeated = rollback_import(
            committed["importId"],
            records_dir=str(self.records),
            get_target=self.store.get,
            replace_target=self.store.replace,
            normalize_config=_normalize_config,
        )

        self.assertFalse(rolled_back["idempotent"])
        self.assertTrue(repeated["idempotent"])
        self.assertEqual(self.store.value, before)

    def test_rollback_preserves_later_user_changes(self):
        preview = self._preview()
        committed = self._commit(preview, ["deadbeef"])
        self.store.value["watchedKeywords"] = ["later-edit"]

        with self.assertRaises(ConfigImportError) as raised:
            rollback_import(
                committed["importId"],
                records_dir=str(self.records),
                get_target=self.store.get,
                replace_target=self.store.replace,
                normalize_config=_normalize_config,
            )

        self.assertEqual(raised.exception.code, "IMPORT_ROLLBACK_CONFLICT")
        self.assertEqual(self.store.value["watchedKeywords"], ["later-edit"])

    def test_rollback_retries_after_transient_compare_and_swap_failure(self):
        before = self.store.get()
        preview = self._preview()
        committed = self._commit(preview, ["deadbeef"])
        original_replace = self.store.replace
        failures = 0

        def fail_once(expected_hash, replacement):
            nonlocal failures
            if failures == 0:
                failures += 1
                raise OSError("temporary write failure")
            return original_replace(expected_hash, replacement)

        with self.assertRaises(ConfigImportError) as raised:
            rollback_import(
                committed["importId"],
                records_dir=str(self.records),
                get_target=self.store.get,
                replace_target=fail_once,
                normalize_config=_normalize_config,
            )
        self.assertEqual(raised.exception.code, "IMPORT_ROLLBACK_FAILED")

        retried = rollback_import(
            committed["importId"],
            records_dir=str(self.records),
            get_target=self.store.get,
            replace_target=fail_once,
            normalize_config=_normalize_config,
        )

        self.assertFalse(retried["idempotent"])
        self.assertEqual(self.store.value, before)

    def test_rollback_maps_missing_private_backup_to_server_failure(self):
        preview = self._preview()
        committed = self._commit(preview, ["deadbeef"])
        before_path = self.records / committed["importId"] / "before.json"
        os.chmod(before_path, stat.S_IWRITE | stat.S_IREAD)
        before_path.unlink()

        with self.assertRaises(ConfigImportError) as raised:
            rollback_import(
                committed["importId"],
                records_dir=str(self.records),
                get_target=self.store.get,
                replace_target=self.store.replace,
                normalize_config=_normalize_config,
            )

        self.assertEqual(raised.exception.code, "IMPORT_ROLLBACK_FAILED")
        self.assertEqual(raised.exception.http_status, 500)

    def test_rollback_does_not_reprobe_changed_path_environment(self):
        before = self.store.get()
        preview = self._preview()
        committed = self._commit(preview, ["deadbeef"])
        normalize_calls = 0

        def changed_environment_normalizer(value):
            nonlocal normalize_calls
            normalize_calls += 1
            with mock.patch.object(
                server, "command_import_status", return_value="blocked"
            ):
                return server.Config._normalize(value)

        changed = changed_environment_normalizer(self.store.get())
        self.assertNotEqual(config_hash(changed), config_hash(self.store.get()))
        normalize_calls = 0

        def replace_normalized(expected_hash, replacement):
            if config_hash(self.store.value) != expected_hash:
                return False
            self.store.value = copy.deepcopy(replacement)
            return True

        rolled_back = rollback_import(
            committed["importId"],
            records_dir=str(self.records),
            get_target=self.store.get,
            replace_target=replace_normalized,
            normalize_config=changed_environment_normalizer,
        )

        self.assertFalse(rolled_back["idempotent"])
        self.assertEqual(normalize_calls, 0)
        self.assertEqual(self.store.value, before)

    def test_rollback_rejects_malformed_private_backup_shape(self):
        preview = self._preview()
        committed = self._commit(preview, ["deadbeef"])
        before_path = self.records / committed["importId"] / "before.json"

        for malformed in (
            {"schemaVersion": server.CURRENT_SCHEMA_VERSION + 1, "apps": []},
            {"schemaVersion": 2, "apps": {}},
            {"schemaVersion": 2, "apps": [None]},
        ):
            with self.subTest(malformed=malformed):
                os.chmod(before_path, stat.S_IWRITE | stat.S_IREAD)
                before_path.write_text(json.dumps(malformed), encoding="utf-8")
                with self.assertRaises(ConfigImportError) as raised:
                    rollback_import(
                        committed["importId"],
                        records_dir=str(self.records),
                        get_target=self.store.get,
                        replace_target=self.store.replace,
                        normalize_config=_normalize_config,
                    )
                self.assertEqual(
                    raised.exception.code, "IMPORT_ROLLBACK_FAILED"
                )
                self.assertEqual(raised.exception.http_status, 500)

    def test_preview_rejects_unc_and_device_mapping_roots(self):
        for target_root in (
            r"\\example.invalid\share\Projects",
            r"\\?\C:\Projects",
            r"\\.\C:\Projects",
            r"\??\C:\Projects",
        ):
            with self.subTest(target_root=target_root), \
                    self.assertRaises(ConfigImportError) as raised:
                self._preview(mappings=[{
                    "sourceRoot": "/Volumes/Workspace/Projects",
                    "targetRoot": target_root,
                }])
            self.assertEqual(raised.exception.code, "INVALID_PATH")

    def test_preview_and_commit_do_not_spawn_or_access_network(self):
        preview = self._preview()
        with mock.patch("subprocess.Popen", side_effect=AssertionError("spawn")), \
                mock.patch("socket.create_connection",
                           side_effect=AssertionError("network")), \
                mock.patch(
                    "localops.config_import.platform_compatibility",
                    side_effect=_compatibility,
                ):
            result = commit_import(
                str(self.source),
                self.mappings,
                preview["previewId"],
                ["deadbeef"],
                records_dir=str(self.records),
                get_target=self.store.get,
                replace_target=self.store.replace,
                normalize_config=_normalize_config,
                path_exists=lambda _path: True,
            )
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()

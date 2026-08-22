import unittest

from tools import check_project


class JavaScriptBindingCheckTests(unittest.TestCase):
    def test_missing_shared_callable_import_is_reported(self):
        source = """
            import { post } from './core.js';
            function removeApp() {
              post('/prepare');
              return del('/api/apps/one');
            }
        """
        self.assertEqual(
            check_project.find_unbound_shared_calls(
                source, {"post", "del"}),
            ["del"],
        )

    def test_import_alias_local_declaration_comments_and_strings_are_allowed(self):
        source = """
            import { del as remove, post } from './core.js';
            function del() { return remove('/local'); }
            // missing('/comment-only')
            const example = "missing('/string-only')";
            post('/prepare');
            del();
        """
        self.assertEqual(
            check_project.find_unbound_shared_calls(
                source, {"post", "del", "missing"}),
            [],
        )

    def test_core_callable_exports_include_functions_and_arrow_functions(self):
        source = """
            export function regular() {}
            export async function later() {}
            export const arrow = value => value;
            export const grouped = (value, other) => value + other;
            export const data = {};
        """
        self.assertEqual(
            check_project.javascript_exported_callables(source),
            {"regular", "later", "arrow", "grouped"},
        )

    def test_project_modules_have_no_unbound_core_calls(self):
        detail = check_project.check_javascript_bindings()
        self.assertIn("公共可调用导出", detail)


class ProjectCheckScopeTests(unittest.TestCase):
    def test_auto_scope_selects_common_and_only_the_native_platform(self):
        self.assertEqual(
            check_project.scopes_for_request("auto", "darwin"),
            ("common", "macos"),
        )
        self.assertEqual(
            check_project.scopes_for_request("auto", "win32"),
            ("common", "windows"),
        )
        self.assertEqual(
            check_project.scopes_for_request("auto", "linux"),
            ("common",),
        )

    def test_platform_required_files_do_not_pull_foreign_runtime_artifacts(self):
        common = check_project.required_files_for_scope("common")
        macos = check_project.required_files_for_scope("macos")
        windows = check_project.required_files_for_scope("windows")
        self.assertNotIn("总控台.app/Contents/Info.plist", common)
        self.assertNotIn("tools/build_windows.py", common)
        self.assertIn("总控台.app/Contents/Info.plist", macos)
        self.assertNotIn("requirements-windows.txt", macos)
        self.assertIn("tools/build_windows.py", windows)
        self.assertIn("requirements-build-windows.txt", windows)
        self.assertIn("tests/windows/test_windows_package_smoke.py", windows)
        self.assertIn("tests/windows/test_windows_packaging.py", windows)
        self.assertNotIn("start.command", windows)


if __name__ == "__main__":
    unittest.main()

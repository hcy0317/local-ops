import inspect
import sys
import unittest
from unittest import mock


@unittest.skipUnless(sys.platform == "win32", "Windows-only runner tests")
class RunnerUnitTests(unittest.TestCase):
    def test_prepare_assigns_job_before_publishing_and_never_resumes(self):
        from localops.windows import runner

        owned_job = mock.Mock()
        process = mock.Mock(process_handle=object(), thread_handle=object())
        receipt = mock.Mock()
        with mock.patch.object(runner, "create_suspended_process", return_value=process):
            prepared = runner.prepare_runtime(
                owned_job, ["fixture.exe"], "C:\\fixture", "C:\\fixture.log",
                publish_prepared=receipt,
            )

        owned_job.assign.assert_called_once_with(process.process_handle)
        receipt.assert_called_once_with(process)
        self.assertIs(prepared.thread_handle, process.thread_handle)
        self.assertNotIn("ResumeThread", inspect.getsource(runner.prepare_runtime))

    def test_resume_is_a_separate_authenticated_action(self):
        from localops.windows import runner

        runtime = mock.Mock(state="prepared", thread_handle=object())
        thread_handle = runtime.thread_handle
        request = {"action": "resume"}
        with mock.patch.object(runner.win32process, "ResumeThread", return_value=1) as resume:
            runner.apply_authenticated_action(runtime, request)

        resume.assert_called_once_with(thread_handle)
        self.assertEqual(runtime.state, "running")

    def test_post_create_failure_terminates_exact_suspended_process(self):
        from localops.windows import runner

        process_handle = object()
        thread_handle = object()
        with mock.patch.object(
                runner.win32process, "CreateProcess",
                return_value=(process_handle, thread_handle, 123, 456)), \
                mock.patch.object(
                    runner, "_process_create_time", side_effect=OSError("fixture")), \
                mock.patch.object(runner.win32console, "AllocConsole"), \
                mock.patch.object(runner.win32console, "FreeConsole"), \
                mock.patch.object(runner.os, "set_handle_inheritable"), \
                mock.patch.object(runner.win32process, "TerminateProcess") as terminate, \
                mock.patch.object(runner, "_close_handle") as close:
            with self.assertRaises(OSError):
                runner.create_suspended_process(
                    ["fixture.exe"], "C:\\fixture", "NUL"
                )

        terminate.assert_called_once_with(process_handle, 1)
        close.assert_any_call(thread_handle)
        close.assert_any_call(process_handle)

    def test_cleanup_failure_terminates_exact_suspended_process(self):
        from localops.windows import runner

        process_handle = object()
        thread_handle = object()
        inherit_calls = 0

        def set_inheritable(_handle, _inheritable):
            nonlocal inherit_calls
            inherit_calls += 1
            if inherit_calls == 3:
                raise OSError("cleanup fixture")

        with mock.patch.object(
                runner.win32process, "CreateProcess",
                return_value=(process_handle, thread_handle, 123, 456)), \
                mock.patch.object(runner, "_process_create_time", return_value=1.0), \
                mock.patch.object(runner.win32console, "AllocConsole"), \
                mock.patch.object(runner.win32console, "FreeConsole"), \
                mock.patch.object(
                    runner.os, "set_handle_inheritable", side_effect=set_inheritable), \
                mock.patch.object(runner.win32process, "TerminateProcess") as terminate, \
                mock.patch.object(runner, "_close_handle") as close:
            with self.assertRaisesRegex(OSError, "cleanup fixture"):
                runner.create_suspended_process(
                    ["fixture.exe"], "C:\\fixture", "NUL"
                )

        terminate.assert_called_once_with(process_handle, 1)
        close.assert_any_call(thread_handle)
        close.assert_any_call(process_handle)

    def test_assign_failure_closes_handles_when_terminate_fails(self):
        from localops.windows import runner

        owned_job = mock.Mock()
        owned_job.assign.side_effect = OSError("assign fixture")
        process = mock.Mock(process_handle=object())
        terminate_error = runner.pywintypes.error(
            5, "TerminateProcess", "Access is denied."
        )
        with mock.patch.object(
                runner, "create_suspended_process", return_value=process), \
                mock.patch.object(
                    runner.win32process, "TerminateProcess",
                    side_effect=terminate_error):
            with self.assertRaisesRegex(OSError, "assign fixture"):
                runner.prepare_runtime(
                    owned_job, ["fixture.exe"], "C:\\fixture", "NUL"
                )

        process.close.assert_called_once_with()

    def test_forbidden_process_tree_fallbacks_are_absent(self):
        from localops.windows import runner

        source = inspect.getsource(runner)
        for forbidden in ("taskkill", "os.kill", "psutil.children"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("TerminateProcess", inspect.getsource(
            runner.apply_authenticated_action
        ))


if __name__ == "__main__":
    unittest.main()

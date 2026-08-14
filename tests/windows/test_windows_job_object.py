import inspect
import os
import sys
import unittest
from unittest import mock

if sys.platform == "win32":
    import win32job

    from localops.windows import job_object


@unittest.skipUnless(sys.platform == "win32", "Windows-only Job Object tests")
class JobObjectUnitTests(unittest.TestCase):
    def test_job_and_pipe_security_attributes_are_not_inheritable(self):
        attributes = job_object.private_security_attributes(
            job_object.SYSTEM_SID, 0x10000000
        )

        self.assertFalse(attributes.bInheritHandle)

    @mock.patch.object(job_object.win32api, "GetLastError", return_value=0)
    @mock.patch.object(job_object.win32job, "SetInformationJobObject")
    @mock.patch.object(job_object.win32job, "QueryInformationJobObject")
    @mock.patch.object(job_object.win32job, "CreateJobObject", return_value=object())
    @mock.patch.object(job_object, "private_security_attributes", return_value=object())
    def test_job_is_created_kill_on_close_without_opening_a_second_handle(
        self, _attributes, create, query, set_information, _last_error,
    ):
        query.return_value = {"BasicLimitInformation": {"LimitFlags": 0}}

        job = job_object.OwnedJob("Local\\LocalOps-test", "S-1-5-18")

        create.assert_called_once()
        information = set_information.call_args.args[2]
        self.assertTrue(
            information["BasicLimitInformation"]["LimitFlags"]
            & win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        self.assertNotIn("OpenJobObject", inspect.getsource(job_object))
        job._handle = None

    @mock.patch.object(job_object.win32job, "QueryInformationJobObject")
    def test_members_come_only_from_job_accounting(self, query):
        instance = object.__new__(job_object.OwnedJob)
        instance.name = "test"
        instance._handle = object()
        query.return_value = {"ProcessIdList": [9, 2, 5]}

        self.assertEqual(instance.members(), (2, 5, 9))

        query.return_value = (7, 3)
        self.assertEqual(instance.members(), (3, 7))

    @mock.patch.object(job_object.win32job, "TerminateJobObject")
    def test_force_uses_only_the_owned_job_handle(self, terminate):
        instance = object.__new__(job_object.OwnedJob)
        instance.name = "test"
        instance._handle = object()

        instance.terminate(73)

        terminate.assert_called_once_with(instance._handle, 73)

    def test_forbidden_ownership_and_kill_fallbacks_are_absent(self):
        source = inspect.getsource(job_object)
        for forbidden in ("taskkill", "os.kill", "psutil.children", "OpenJobObject"):
            self.assertNotIn(forbidden, source)


@unittest.skipUnless(
    sys.platform == "win32" and os.environ.get("LOCALOPS_RUN_WINDOWS_LIFECYCLE_TESTS") == "1",
    "real Windows lifecycle fixtures are explicitly gated",
)
class RealJobObjectTests(unittest.TestCase):
    def test_kill_on_close_uses_only_fixture_owned_processes(self):
        import subprocess
        import uuid
        import win32api
        import win32con
        import win32event
        import win32process
        import win32security

        current_token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        try:
            current_sid = win32security.ConvertSidToStringSid(
                win32security.GetTokenInformation(
                    current_token, win32security.TokenUser
                )[0]
            )
        finally:
            current_token.Close()

        sentinel = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            creationflags=win32process.CREATE_NO_WINDOW,
        )
        process_handle = thread_handle = None
        try:
            job = job_object.OwnedJob(
                "Local\\LocalOps-fixture-" + uuid.uuid4().hex,
                current_sid,
            )
            process_handle, thread_handle, _, _ = win32process.CreateProcess(
                sys.executable,
                subprocess.list2cmdline([
                    sys.executable, "-c", "import time; time.sleep(30)"
                ]),
                None, None, False,
                win32process.CREATE_SUSPENDED | win32process.CREATE_NO_WINDOW,
                None, os.getcwd(), win32process.STARTUPINFO(),
            )
            job.assign(process_handle)
            win32process.ResumeThread(thread_handle)
            job.close()
            self.assertEqual(
                win32event.WaitForSingleObject(process_handle, 5000),
                win32con.WAIT_OBJECT_0,
            )
            self.assertIsNone(sentinel.poll())
        finally:
            if thread_handle is not None:
                win32api.CloseHandle(thread_handle)
            if process_handle is not None:
                win32api.CloseHandle(process_handle)
            if sentinel.poll() is None:
                sentinel.terminate()
                sentinel.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()

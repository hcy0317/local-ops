"""Small pywin32 wrapper for the runner-owned Job Object."""

from __future__ import annotations

import time

import win32api
import win32con
import win32job
import win32security
import winerror


SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"


def private_security_attributes(owner_sid: str, access: int) -> object:
    owner = win32security.ConvertStringSidToSid(owner_sid)
    acl = win32security.ACL()
    for sid_text in (owner_sid, SYSTEM_SID, ADMINISTRATORS_SID):
        acl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION_DS,
            0,
            access,
            win32security.ConvertStringSidToSid(sid_text),
        )
    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(owner, False)
    descriptor.SetSecurityDescriptorDacl(True, acl, False)
    descriptor.SetSecurityDescriptorControl(
        win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED
    )
    attributes = win32security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    # CreateProcess must inherit only redirected stdio, never the sole Job handle.
    attributes.bInheritHandle = False
    return attributes


class OwnedJob:
    """The runner is the sole long-lived holder of this kill-on-close Job."""

    def __init__(self, name: str, owner_sid: str):
        attributes = private_security_attributes(owner_sid, win32con.GENERIC_ALL)
        handle = win32job.CreateJobObject(attributes, name)
        if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
            win32api.CloseHandle(handle)
            raise RuntimeError("Job Object already exists")
        self.name = name
        self._handle = handle
        information = win32job.QueryInformationJobObject(
            handle, win32job.JobObjectExtendedLimitInformation
        )
        basic = information["BasicLimitInformation"]
        basic["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(
            handle, win32job.JobObjectExtendedLimitInformation, information
        )

    @property
    def handle(self) -> object:
        if self._handle is None:
            raise RuntimeError("Job Object is closed")
        return self._handle

    def assign(self, process_handle: object) -> None:
        win32job.AssignProcessToJobObject(self.handle, process_handle)

    def members(self) -> tuple[int, ...]:
        information = win32job.QueryInformationJobObject(
            self.handle, win32job.JobObjectBasicProcessIdList
        )
        # pywin32 returns a PID tuple on current builds; retain dict support for
        # older builds and deterministic unit doubles.
        process_ids = (
            information.get("ProcessIdList", ())
            if isinstance(information, dict) else information
        )
        return tuple(sorted(int(pid) for pid in process_ids))

    def terminate(self, exit_code: int = 1) -> None:
        win32job.TerminateJobObject(self.handle, int(exit_code))

    def wait_empty(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, float(timeout))
        while self.members():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
        return True

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            win32api.CloseHandle(handle)

    def __enter__(self) -> OwnedJob:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

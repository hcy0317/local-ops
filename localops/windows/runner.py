"""Independent Windows runner that exclusively owns one managed Job Object."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Mapping

import pywintypes
import win32api
import win32con
import win32console
import win32file
import win32pipe
import win32process
import win32security
import winerror

from localops.platform.windows import WindowsPlatform
from localops.windows.job_object import OwnedJob, private_security_attributes
from localops.windows.runner_protocol import (
    PIPE_BUFFER_BYTES,
    PROTOCOL_VERSION,
    NonceCache,
    ProtocolError,
    decode_message,
    encode_message,
    job_name,
    make_response,
    native_process_command,
    pipe_name,
    read_json,
    runtime_directory,
    sign_record,
    token_digest,
    validate_app_id,
    validate_generation_id,
    validate_launch_request,
    verify_request,
    write_json_atomic,
)


PREPARED_TTL_SECONDS = 30.0
TERMINAL_RECEIPT_SECONDS = 0.5
_PIPE_FIRST_INSTANCE = 0x00080000


def _ignore_ctrl_break(event: int) -> bool:
    return event == win32con.CTRL_BREAK_EVENT


def _current_sid() -> str:
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
    )
    try:
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        return win32security.ConvertSidToStringSid(sid)
    finally:
        token.Close()


def _process_owner_sid(pid: int) -> str:
    handle = win32api.OpenProcess(
        win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid)
    )
    try:
        token = win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)
        try:
            sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            return win32security.ConvertSidToStringSid(sid)
        finally:
            token.Close()
    finally:
        handle.Close()


def _process_create_time(handle: object) -> float:
    return float(win32process.GetProcessTimes(handle)["CreationTime"].timestamp())


def _close_handle(handle: object | None) -> None:
    if handle is not None:
        try:
            win32api.CloseHandle(handle)
        except (pywintypes.error, TypeError):
            pass


@dataclass
class SuspendedProcess:
    process_handle: object
    thread_handle: object
    process_id: int
    thread_id: int
    create_time: float

    def close(self) -> None:
        _close_handle(self.thread_handle)
        _close_handle(self.process_handle)
        self.thread_handle = None
        self.process_handle = None


def create_suspended_process(
    invocation: object,
    cwd: str,
    log_path: str,
) -> SuspendedProcess:
    """Create an inert root process with an isolated, hidden console group."""
    application, command_line = native_process_command(invocation)
    log_stream = open(log_path, "ab", buffering=0)
    null_stream = open(os.devnull, "rb", buffering=0)
    log_handle = int(__import__("msvcrt").get_osfhandle(log_stream.fileno()))
    null_handle = int(__import__("msvcrt").get_osfhandle(null_stream.fileno()))
    os.set_handle_inheritable(log_handle, True)
    os.set_handle_inheritable(null_handle, True)
    startup = win32process.STARTUPINFO()
    startup.dwFlags = win32con.STARTF_USESTDHANDLES | win32con.STARTF_USESHOWWINDOW
    startup.wShowWindow = win32con.SW_HIDE
    startup.hStdInput = null_handle
    startup.hStdOutput = log_handle
    startup.hStdError = log_handle
    flags = (
        win32process.CREATE_SUSPENDED
        | win32process.CREATE_NEW_PROCESS_GROUP
        | win32process.CREATE_UNICODE_ENVIRONMENT
    )
    process_handle = thread_handle = None
    process_id = thread_id = 0
    create_time = 0.0
    console_allocated = False
    creation_error: BaseException | None = None
    try:
        # The detached runner allocates a private console only long enough for
        # the target process group to inherit it. The target is the sole member
        # after the runner detaches, so later CTRL_BREAK can address rootPid.
        win32console.AllocConsole()
        console_allocated = True
        process_handle, thread_handle, process_id, thread_id = win32process.CreateProcess(
            application,
            command_line,
            None,
            None,
            True,
            flags,
            None,
            cwd,
            startup,
        )
        create_time = _process_create_time(process_handle)
    except BaseException as exc:
        creation_error = exc

    cleanup_error: BaseException | None = None
    if console_allocated:
        try:
            win32console.FreeConsole()
        except BaseException as exc:
            cleanup_error = exc
    try:
        os.set_handle_inheritable(log_handle, False)
    except BaseException as exc:
        cleanup_error = cleanup_error or exc
    try:
        os.set_handle_inheritable(null_handle, False)
    except BaseException as exc:
        cleanup_error = cleanup_error or exc
    try:
        log_stream.close()
    except BaseException as exc:
        cleanup_error = cleanup_error or exc
    try:
        null_stream.close()
    except BaseException as exc:
        cleanup_error = cleanup_error or exc

    failure = creation_error or cleanup_error
    if failure is not None:
        if process_handle is not None:
            try:
                win32process.TerminateProcess(process_handle, 1)
            except pywintypes.error:
                pass
        _close_handle(thread_handle)
        _close_handle(process_handle)
        raise failure

    return SuspendedProcess(
        process_handle=process_handle,
        thread_handle=thread_handle,
        process_id=int(process_id),
        thread_id=int(thread_id),
        create_time=create_time,
    )


def prepare_runtime(
    owned_job: OwnedJob,
    invocation: object,
    cwd: str,
    log_path: str,
    *,
    publish_prepared: Callable[[SuspendedProcess], None] | None = None,
) -> SuspendedProcess:
    """Create suspended, assign to the owned Job, then permit publication."""
    process = create_suspended_process(invocation, cwd, log_path)
    try:
        owned_job.assign(process.process_handle)
    except Exception:
        # This exact, unpublished handle is the only rollback before Job ownership.
        # It is never used by stop/force and user code is still suspended.
        try:
            win32process.TerminateProcess(process.process_handle, 1)
        except pywintypes.error:
            pass
        finally:
            process.close()
        raise
    if publish_prepared is not None:
        publish_prepared(process)
    return process


@dataclass(frozen=True)
class ActionResult:
    ok: bool
    status: str
    payload: dict[str, object]
    code: str | None = None
    error: str | None = None
    shutdown: bool = False


class RunnerRuntime:
    def __init__(
        self,
        *,
        app_id: str,
        generation_id: str,
        owner_sid: str,
        token: bytes,
        receipt_path: str,
        protect_receipt: Callable[[str], None],
        job: OwnedJob,
        root: SuspendedProcess,
    ):
        self.app_id = app_id
        self.generation_id = generation_id
        self.owner_sid = owner_sid
        self.token = token
        self.receipt_path = receipt_path
        self.protect_receipt = protect_receipt
        self.job = job
        self.root = root
        self.thread_handle = root.thread_handle
        self.state = "prepared"
        self.sequence = 0
        self.code: str | None = None
        self.error: str | None = None
        self.exit_code: int | None = None
        self._last_members: tuple[int, ...] = ()
        self.lock = threading.RLock()
        runner_handle = win32api.GetCurrentProcess()
        self.identity = {
            "platform": "windows",
            "kind": "job",
            "ownerSid": owner_sid,
            "generationId": generation_id,
            "runnerPid": os.getpid(),
            "runnerCreateTime": _process_create_time(runner_handle),
            "rootPid": root.process_id,
            "rootCreateTime": root.create_time,
            "jobName": job.name,
            "tokenDigest": token_digest(token),
            "startedAt": int(time.time() * 1000),
        }

    def members(self) -> tuple[int, ...]:
        return self.job.members()

    def _root_exit_code(self) -> int | None:
        if self.root.process_handle is None:
            return self.exit_code
        try:
            value = int(win32process.GetExitCodeProcess(self.root.process_handle))
        except pywintypes.error:
            return self.exit_code
        return None if value == win32con.STILL_ACTIVE else value

    def publish(self) -> None:
        with self.lock:
            self.sequence += 1
            members = self.members()
            self._last_members = members
            receipt = sign_record({
                "version": PROTOCOL_VERSION,
                "sequence": self.sequence,
                "state": self.state,
                "identity": dict(self.identity),
                "members": list(members),
                "updatedAt": int(time.time() * 1000),
                "code": self.code,
                "error": self.error,
                "exitCode": self.exit_code,
            }, self.token, "receipt")
            write_json_atomic(
                self.receipt_path, receipt, self.protect_receipt
            )
            self.protect_receipt(self.receipt_path)

    def set_state(
        self,
        state: str,
        *,
        code: str | None = None,
        error: str | None = None,
        exit_code: int | None = None,
    ) -> None:
        self.state = state
        self.code = code
        self.error = error
        self.exit_code = exit_code
        self.publish()

    def refresh_terminal(self) -> None:
        with self.lock:
            if self.state in {"running", "stopping"} and not self.members():
                exit_code = self._root_exit_code()
                self.root.close()
                self.thread_handle = None
                self.set_state("exited", exit_code=exit_code)

    def resume(self) -> ActionResult:
        with self.lock:
            if self.state != "prepared" or self.thread_handle is None:
                raise ProtocolError("LAUNCH_ACTIVATE_FAILED", "runtime is not prepared")
            previous = int(win32process.ResumeThread(self.thread_handle))
            if previous != 1:
                raise ProtocolError("LAUNCH_ACTIVATE_FAILED", "unexpected suspend count")
            _close_handle(self.thread_handle)
            self.thread_handle = None
            self.root.thread_handle = None
            self.set_state("running")
            return self.result(True)

    def _send_ctrl_break(self) -> bool:
        members = self.members()
        if not members:
            return True
        attach_pid = self.root.process_id if self.root.process_id in members else members[0]
        try:
            try:
                win32console.FreeConsole()
            except pywintypes.error:
                pass
            win32console.AttachConsole(int(attach_pid))
            # AttachConsole resets the handler table. Ignore the broadcast in
            # the runner while the target receives it in its private console.
            win32api.SetConsoleCtrlHandler(_ignore_ctrl_break, True)
            win32console.GenerateConsoleCtrlEvent(
                win32console.CTRL_BREAK_EVENT, self.root.process_id
            )
            return True
        except pywintypes.error:
            return False
        finally:
            try:
                win32api.SetConsoleCtrlHandler(_ignore_ctrl_break, False)
            except pywintypes.error:
                pass
            try:
                win32console.FreeConsole()
            except pywintypes.error:
                pass

    def stop(self, timeout: float) -> ActionResult:
        with self.lock:
            if self.state != "running":
                raise ProtocolError("RUNTIME_CONTROL_FAILED", "runtime is not running")
            self.set_state("stopping")
            self._send_ctrl_break()
            if self.job.wait_empty(timeout):
                exit_code = self._root_exit_code()
                self.root.close()
                self.thread_handle = None
                self.set_state("exited", exit_code=exit_code)
                return self.result(True, shutdown=True)
            self.set_state("running", code="STOP_TIMEOUT", error="graceful stop timed out")
            return self.result(
                False,
                code="STOP_TIMEOUT",
                error="graceful stop timed out",
            )

    def force(self, *, failed: bool = False) -> ActionResult:
        with self.lock:
            if self.members():
                self.job.terminate(1)
                if not self.job.wait_empty(5.0):
                    raise ProtocolError("RUNTIME_CONTROL_FAILED", "Job did not terminate")
            exit_code = self._root_exit_code()
            self.root.close()
            self.thread_handle = None
            state = "failed" if failed else "exited"
            code = "LAUNCH_COMMIT_FAILED" if failed else None
            error = "prepared launch was aborted" if failed else None
            self.set_state(state, code=code, error=error, exit_code=exit_code)
            return self.result(True, shutdown=True)

    def result(
        self,
        ok: bool,
        *,
        code: str | None = None,
        error: str | None = None,
        shutdown: bool = False,
    ) -> ActionResult:
        # Every response is paired with an atomic receipt containing the exact
        # same Job snapshot; process membership can change between syscalls.
        self.publish()
        return ActionResult(
            ok=ok,
            status=self.state,
            payload={"identity": dict(self.identity), "members": list(self._last_members),
                     "exitCode": self.exit_code},
            code=code,
            error=error,
            shutdown=shutdown,
        )

    def close(self) -> None:
        self.root.close()


def apply_authenticated_action(
    runtime: RunnerRuntime,
    request: Mapping[str, object],
) -> ActionResult:
    action = request.get("action")
    if action == "inspect":
        runtime.refresh_terminal()
        return runtime.result(True, shutdown=runtime.state in {"exited", "failed"})
    if action == "resume":
        # Keep ResumeThread visibly inside the authenticated action boundary.
        if runtime.state != "prepared" or runtime.thread_handle is None:
            raise ProtocolError("LAUNCH_ACTIVATE_FAILED", "runtime is not prepared")
        previous = int(win32process.ResumeThread(runtime.thread_handle))
        if previous != 1:
            raise ProtocolError("LAUNCH_ACTIVATE_FAILED", "unexpected suspend count")
        _close_handle(runtime.thread_handle)
        runtime.thread_handle = None
        if hasattr(runtime, "root"):
            runtime.root.thread_handle = None
        runtime.state = "running"
        if hasattr(runtime, "publish"):
            runtime.publish()
        return runtime.result(True) if hasattr(runtime, "result") else ActionResult(
            True, "running", {}
        )
    if action == "stop":
        payload = request.get("payload") or {}
        timeout = payload.get("timeout", 5.0) if isinstance(payload, dict) else 5.0
        if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
                or not 0.0 <= float(timeout) <= 30.0):
            raise ProtocolError("RUNTIME_CONTROL_FAILED", "invalid stop timeout")
        return runtime.stop(float(timeout))
    if action == "force":
        return runtime.force()
    if action == "abort":
        if runtime.state != "prepared":
            raise ProtocolError("RUNTIME_CONTROL_FAILED", "only prepared runtime may abort")
        return runtime.force(failed=True)
    raise ProtocolError("RUNTIME_CONTROL_FAILED", "unsupported control action")


class PipeServer:
    def __init__(self, runtime: RunnerRuntime, stop_event: threading.Event):
        self.runtime = runtime
        self.stop_event = stop_event
        self.nonces = NonceCache()
        self.handle: object | None = None
        self.lock = threading.Lock()

    def _new_pipe(self) -> object:
        access = win32pipe.PIPE_ACCESS_DUPLEX | _PIPE_FIRST_INSTANCE
        mode = (
            win32pipe.PIPE_TYPE_MESSAGE
            | win32pipe.PIPE_READMODE_MESSAGE
            | win32pipe.PIPE_WAIT
            | win32pipe.PIPE_REJECT_REMOTE_CLIENTS
        )
        attributes = private_security_attributes(
            self.runtime.owner_sid, win32con.GENERIC_ALL
        )
        return win32pipe.CreateNamedPipe(
            pipe_name(self.runtime.app_id, self.runtime.generation_id),
            access,
            mode,
            1,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            1000,
            attributes,
        )

    def serve(self) -> None:
        while not self.stop_event.is_set():
            pipe = self._new_pipe()
            with self.lock:
                self.handle = pipe
            try:
                try:
                    win32pipe.ConnectNamedPipe(pipe, None)
                except pywintypes.error as exc:
                    if exc.winerror != winerror.ERROR_PIPE_CONNECTED:
                        raise
                client_pid = int(win32pipe.GetNamedPipeClientProcessId(pipe))
                if _process_owner_sid(client_pid) != self.runtime.owner_sid:
                    continue
                _, data = win32file.ReadFile(pipe, PIPE_BUFFER_BYTES)
                request = verify_request(
                    decode_message(bytes(data)),
                    self.runtime.token,
                    self.runtime.generation_id,
                    self.nonces,
                )
                try:
                    result = apply_authenticated_action(self.runtime, request)
                except ProtocolError as exc:
                    result = ActionResult(
                        False, self.runtime.state, {}, exc.code, str(exc)
                    )
                response = make_response(
                    request,
                    self.runtime.token,
                    ok=result.ok,
                    status=result.status,
                    payload=result.payload,
                    code=result.code,
                    error=result.error,
                )
                win32file.WriteFile(pipe, encode_message(response))
                win32file.FlushFileBuffers(pipe)
                if result.shutdown:
                    self.stop_event.set()
            except (OSError, pywintypes.error, ProtocolError):
                pass
            finally:
                try:
                    win32pipe.DisconnectNamedPipe(pipe)
                except pywintypes.error:
                    pass
                _close_handle(pipe)
                with self.lock:
                    if self.handle == pipe:
                        self.handle = None

    def close(self) -> None:
        with self.lock:
            handle, self.handle = self.handle, None
        _close_handle(handle)


def _runtime_files(platform: WindowsPlatform, app_id: str, generation_id: str):
    paths = platform.runtime_paths()
    directory = runtime_directory(paths.runtime_dir, app_id, generation_id)
    return (
        directory,
        os.path.join(directory, "request.json"),
        os.path.join(directory, "token.bin"),
        os.path.join(directory, "receipt.json"),
        os.path.join(paths.logs_dir, app_id + ".log"),
    )


def run(app_id: str, generation_id: str) -> int:
    app_id = validate_app_id(app_id)
    generation_id = validate_generation_id(generation_id)
    platform = WindowsPlatform(os.getcwd(), __file__)
    owner_sid = _current_sid()
    directory, request_path, token_path, receipt_path, expected_log = _runtime_files(
        platform, app_id, generation_id
    )
    for path, directory_flag in (
        (directory, True), (request_path, False), (token_path, False),
    ):
        (platform.verify_private_directory if directory_flag
         else platform.verify_private_file)(path)
    with open(token_path, "rb") as stream:
        token = stream.read(33)
    if len(token) != 32:
        raise ProtocolError("RUNTIME_RECORD_INSECURE", "invalid runtime token")
    request = validate_launch_request(
        read_json(request_path),
        token,
        app_id=app_id,
        generation_id=generation_id,
        owner_sid=owner_sid,
        expected_log_path=expected_log,
    )
    platform.verify_private_file(expected_log)
    job = OwnedJob(job_name(app_id, generation_id, token_digest(token)), owner_sid)
    runtime: RunnerRuntime | None = None
    stop_event = threading.Event()
    server: PipeServer | None = None
    try:
        root = prepare_runtime(
            job, request["invocation"], str(request["cwd"]), expected_log
        )
        runtime = RunnerRuntime(
            app_id=app_id,
            generation_id=generation_id,
            owner_sid=owner_sid,
            token=token,
            receipt_path=receipt_path,
            protect_receipt=platform.ensure_private_file,
            job=job,
            root=root,
        )
        runtime.publish()
        server = PipeServer(runtime, stop_event)
        thread = threading.Thread(target=server.serve, daemon=True)
        thread.start()
        prepared_deadline = time.monotonic() + PREPARED_TTL_SECONDS
        terminal_at: float | None = None
        while not stop_event.wait(0.1):
            runtime.refresh_terminal()
            if runtime.state == "prepared" and time.monotonic() >= prepared_deadline:
                runtime.force(failed=True)
                stop_event.set()
                break
            if runtime.state in {"exited", "failed"}:
                terminal_at = terminal_at or time.monotonic()
                if time.monotonic() - terminal_at >= TERMINAL_RECEIPT_SECONDS:
                    stop_event.set()
        return 0
    finally:
        if server is not None:
            server.close()
        if runtime is not None:
            runtime.close()
        job.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--generation-id", required=True)
    try:
        arguments = parser.parse_args(argv)
        return run(arguments.app_id, arguments.generation_id)
    except ProtocolError as exc:
        print(exc.code, file=sys.stderr)
        return 1
    except Exception:
        print("RUNNER_START_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

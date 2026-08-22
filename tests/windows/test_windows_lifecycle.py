import json
import gc
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import uuid
from dataclasses import replace
from unittest import mock


RUN_REAL = (
    sys.platform == "win32"
    and os.environ.get("LOCALOPS_RUN_WINDOWS_LIFECYCLE_TESTS") == "1"
)

if sys.platform == "win32":
    import psutil
    import win32api
    import win32con
    import win32event
    import win32process

    from localops.command_spec import command_spec_for_executable, direct_command_spec
    from localops.platform.contracts import LaunchRequest
    from localops.platform import windows as windows_adapter
    from localops.platform.windows import WindowsPlatform


@unittest.skipUnless(RUN_REAL, "real Windows lifecycle fixtures are explicitly gated")
class IsolatedWindowsLifecycleTests(unittest.TestCase):
    """WIN-LIFE-001..012; controls are limited to identities each test creates."""

    def setUp(self):
        self.repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.temp = tempfile.TemporaryDirectory(prefix="localops-phase4-")
        self.addCleanup(self.temp.cleanup)
        self.environment = mock.patch.dict(os.environ, {
            "CONSOLE_DATA_DIR": os.path.join(self.temp.name, "data"),
            "CONSOLE_LOG_DIR": os.path.join(self.temp.name, "logs"),
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.platform = WindowsPlatform(self.repo, os.path.join(self.repo, "server.py"))
        self.identities = []
        self.fixture_app_ids = set()
        self.sentinels = []
        self.runners = []
        self.runner_processes = {}

    def tearDown(self):
        # Stop only exact controller/sentinel processes created by this test
        # before reading the now-stable fixture config. Managed Jobs survive a
        # controller exit by design and are released below through identity proof.
        for process in self.sentinels:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        self.sentinels.clear()
        self._load_persisted_fixture_identities()
        for identity in self.identities:
            if identity.app_id not in self.fixture_app_ids:
                continue
            inspection = self.platform.inspect_managed(identity)
            if inspection.verified and inspection.status not in {"exited", "failed"}:
                self.platform.stop_managed(identity, force=True, timeout=2.0)
            self._wait(lambda: not psutil.pid_exists(identity.root_pid), timeout=5.0)
            terminal = self.platform.inspect_managed(identity)
            if (terminal.verified and terminal.status in {"exited", "failed"}
                    and not terminal.members):
                self.platform.release_managed(identity)
        for process in self.runners:
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                # Only a runner created by this exact test may be cleaned up.
                process.terminate()
                process.wait(timeout=5.0)
        for app_id in self.fixture_app_ids:
            paths = self.platform.runtime_paths()
            log_path = os.path.abspath(os.path.join(paths.logs_dir, app_id + ".log"))
            if (os.path.basename(log_path) == app_id + ".log"
                    and os.path.normcase(os.path.dirname(log_path))
                    == os.path.normcase(os.path.abspath(paths.logs_dir))):
                try:
                    os.unlink(log_path)
                except FileNotFoundError:
                    pass

    def _load_persisted_fixture_identities(self):
        config_path = os.path.join(
            self.platform.runtime_paths().data_dir, "config.json"
        )
        try:
            with open(config_path, encoding="utf-8") as stream:
                apps = json.load(stream).get("apps", [])
        except (FileNotFoundError, OSError, ValueError, AttributeError):
            return
        known = {
            (identity.app_id, identity.generation_id)
            for identity in self.identities
        }
        for app in apps:
            if not isinstance(app, dict) or app.get("id") not in self.fixture_app_ids:
                continue
            public = app.get("runtimeIdentity")
            if not isinstance(public, dict):
                continue
            try:
                identity = WindowsPlatform._identity_from_public(public, app["id"])
            except (KeyError, TypeError, ValueError):
                continue
            key = (identity.app_id, identity.generation_id)
            if key not in known:
                self.identities.append(identity)
                known.add(key)

    @staticmethod
    def _wait(predicate, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return False

    def _launch(self, code):
        return self._launch_spec(direct_command_spec(
            sys.executable, ["-c", code]
        ))

    def _launch_spec(self, command_spec, *, app_id=None):
        app_id = app_id or uuid.uuid4().hex[:8]
        generation_id = str(uuid.uuid4())
        self.fixture_app_ids.add(app_id)
        log_path = os.path.join(self.platform.runtime_paths().logs_dir, app_id + ".log")
        result = self.platform.launch(LaunchRequest(
            app_id=app_id,
            command="fixture",
            cwd=self.temp.name,
            log_path=log_path,
            command_spec=command_spec,
            generation_id=generation_id,
        ))
        self.assertTrue(
            result.ok,
            (result.code, result.error, self._console_output_tail(log_path)),
        )
        self.assertEqual(result.status, "prepared")
        self.assertIsNotNone(result.runtime_identity)
        self.runners.append(result.process)
        self.runner_processes[generation_id] = result.process
        self.identities.append(result.runtime_identity)
        return result.runtime_identity

    def _reap_runner(self, identity):
        process = self.runner_processes.pop(identity.generation_id, None)
        if process is None:
            return
        process.wait(timeout=5.0)
        if process in self.runners:
            self.runners.remove(process)
        handle = getattr(process, "_handle", None)
        if handle is not None:
            handle.Close()
            process._handle = None

    def _release(self, identity):
        self._reap_runner(identity)
        return self.platform.release_managed(identity)

    @staticmethod
    def _free_port():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(
                socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1
            )
            listener.bind(("127.0.0.1", 0))
            return listener.getsockname()[1]
        finally:
            listener.close()

    def _activate(self, identity):
        result = self.platform.activate_managed(identity)
        self.assertTrue(result.ok, (result.code, result.error))
        self.assertEqual(result.status, "running")

    def _launch_from_external_controller(self):
        app_id = uuid.uuid4().hex[:8]
        generation_id = str(uuid.uuid4())
        handoff = os.path.join(self.temp.name, "controller-handoff.json")
        log_path = os.path.join(self.platform.runtime_paths().logs_dir, app_id + ".log")
        controller = "\n".join((
            "import json, os, sys",
            "from localops.command_spec import direct_command_spec",
            "from localops.platform.contracts import LaunchRequest, windows_runtime_identity_public",
            "from localops.platform.windows import WindowsPlatform",
            "platform = WindowsPlatform(os.environ['LOCALOPS_FIXTURE_REPO'], os.path.join(os.environ['LOCALOPS_FIXTURE_REPO'], 'server.py'))",
            "result = platform.launch(LaunchRequest(app_id=os.environ['LOCALOPS_FIXTURE_APP_ID'], command='fixture', cwd=os.environ['LOCALOPS_FIXTURE_CWD'], log_path=os.environ['LOCALOPS_FIXTURE_LOG'], command_spec=direct_command_spec(sys.executable, ['-c', 'import time; time.sleep(60)']), generation_id=os.environ['LOCALOPS_FIXTURE_GENERATION']))",
            "assert result.ok and result.runtime_identity is not None, (result.code, result.error)",
            "activated = platform.activate_managed(result.runtime_identity)",
            "assert activated.ok, (activated.code, activated.error)",
            "with open(os.environ['LOCALOPS_FIXTURE_HANDOFF'], 'w', encoding='utf-8') as stream: json.dump(windows_runtime_identity_public(result.runtime_identity), stream)",
        ))
        environment = dict(os.environ)
        environment.update({
            "LOCALOPS_FIXTURE_REPO": self.repo,
            "LOCALOPS_FIXTURE_APP_ID": app_id,
            "LOCALOPS_FIXTURE_GENERATION": generation_id,
            "LOCALOPS_FIXTURE_CWD": self.temp.name,
            "LOCALOPS_FIXTURE_LOG": log_path,
            "LOCALOPS_FIXTURE_HANDOFF": handoff,
        })
        completed = subprocess.run(
            [sys.executable, "-c", controller],
            cwd=self.repo,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        with open(handoff, encoding="utf-8") as stream:
            public = json.load(stream)
        identity = WindowsPlatform._identity_from_public(public, app_id)
        self.fixture_app_ids.add(app_id)
        self.identities.append(identity)
        return identity

    def _console_port(self):
        for port in range(9600, 9610):
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(0.2)
            try:
                occupied = probe.connect_ex(("127.0.0.1", port)) == 0
            finally:
                probe.close()
            if occupied:
                continue
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.setsockopt(
                    socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1
                )
                listener.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
            finally:
                listener.close()
        self.fail("no isolated Local Ops console port is available")

    @staticmethod
    def _api_json(port, path, payload=None, *, timeout=15.0):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=body,
            headers=({"Content-Type": "application/json"} if body else {}),
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)

    @staticmethod
    def _console_output_tail(path, limit=4096):
        """Return bounded fixture output without exposing the process environment."""
        try:
            with open(path, "rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                stream.seek(max(0, size - limit))
                output = stream.read().decode("utf-8", errors="replace")
        except OSError as exc:
            return "<unavailable: %s>" % type(exc).__name__
        output = "".join(
            character if character in "\n\r\t" or character.isprintable() else "?"
            for character in output
        ).strip()
        return output or "<empty>"

    def _start_console(self, port):
        output_id = uuid.uuid4().hex
        stdout_path = os.path.join(self.temp.name, "console-%s.stdout.log" % output_id)
        stderr_path = os.path.join(self.temp.name, "console-%s.stderr.log" % output_id)
        executable, environment = windows_adapter._runner_process_settings()
        with open(stdout_path, "wb") as stdout_stream, open(stderr_path, "wb") as stderr_stream:
            process = subprocess.Popen(
                [executable, "server.py", "--no-browser", "--preferred-port", str(port)],
                cwd=self.repo,
                env=environment or dict(os.environ),
                stdin=subprocess.DEVNULL,
                stdout=stdout_stream,
                stderr=stderr_stream,
                close_fds=True,
            )
        self.sentinels.append(process)

        deadline = time.monotonic() + 45.0
        last_error = "connection unavailable"
        while time.monotonic() < deadline:
            returncode = process.poll()
            if returncode is not None:
                self.fail(
                    "console exited before readiness (exit=%d, stderr=%r, stdout=%r)"
                    % (
                        returncode,
                        self._console_output_tail(stderr_path),
                        self._console_output_tail(stdout_path),
                    )
                )
            try:
                state = self._api_json(port, "/api/state", timeout=1.0)
                if state["consolePid"] == process.pid:
                    return process
                last_error = "consolePid did not match fixture process"
            except (OSError, KeyError, ValueError) as exc:
                last_error = type(exc).__name__
            time.sleep(0.1)

        self.fail(
            "console did not become ready within 45s "
            "(lastError=%s, stderr=%r, stdout=%r)"
            % (
                last_error,
                self._console_output_tail(stderr_path),
                self._console_output_tail(stdout_path),
            )
        )

    def _stop_console(self, process):
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10.0)
        if process in self.sentinels:
            self.sentinels.remove(process)

    def _prepare_http_console_app(self, app_id, service_port):
        setup = "\n".join((
            "import os, sys",
            "import server",
            "from localops.command_spec import direct_command_spec",
            "storage = server.prepare_runtime_storage()",
            "assert not storage.get('securityIssues'), storage",
            "cfg = server.Config(server.CONFIG_PATH)",
            "port = int(os.environ['LOCALOPS_FIXTURE_SERVICE_PORT'])",
            "code = \"import http.server; print('HTTP_CONSOLE_READY', flush=True); http.server.ThreadingHTTPServer(('127.0.0.1', %d), http.server.SimpleHTTPRequestHandler).serve_forever()\" % port",
            "app = {**server.Config.APP_DEFAULT, 'id': os.environ['LOCALOPS_FIXTURE_APP_ID'], 'name': 'HTTP console fixture', 'command': 'fixture', 'commandSpec': direct_command_spec(sys.executable, ['-c', code]), 'cwd': os.environ['LOCALOPS_FIXTURE_CWD'], 'port': port, 'kind': 'service'}",
            "cfg.update(lambda data: data['apps'].append(app))",
        ))
        environment = dict(os.environ)
        environment.update({
            "LOCALOPS_FIXTURE_APP_ID": app_id,
            "LOCALOPS_FIXTURE_CWD": self.temp.name,
            "LOCALOPS_FIXTURE_SERVICE_PORT": str(service_port),
        })
        completed = subprocess.run(
            [sys.executable, "-c", setup],
            cwd=self.repo,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_win_life_001_python_http_listener_log_and_job_state(self):
        port = self._free_port()
        code = (
            "import http.server; "
            "print('PYTHON_HTTP_READY', flush=True); "
            f"http.server.ThreadingHTTPServer(('127.0.0.1',{port}),"
            "http.server.SimpleHTTPRequestHandler).serve_forever()"
        )
        identity = self._launch(code)
        self._activate(identity)

        def responds():
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/", timeout=0.5
                ) as response:
                    return response.status == 200
            except OSError:
                return False

        self.assertTrue(self._wait(responds, timeout=20.0))
        inspection = self.platform.inspect_managed(identity)
        self.assertTrue(inspection.verified)
        self.assertIn(identity.root_pid, inspection.members)
        log_path = os.path.join(
            self.platform.runtime_paths().logs_dir, identity.app_id + ".log"
        )
        with open(log_path, encoding="utf-8", errors="replace") as stream:
            self.assertIn("PYTHON_HTTP_READY", stream.read())
        self.assertTrue(self.platform.stop_managed(
            identity, force=True, timeout=2.0
        ).ok)

    def test_win_life_002_node_npm_listener_log_and_state(self):
        npm = shutil.which("npm.cmd")
        self.assertIsNotNone(npm, "Node/npm fixture requires npm.cmd")
        port = self._free_port()
        package = os.path.join(self.temp.name, "package.json")
        script = os.path.join(self.temp.name, "server.js")
        with open(package, "w", encoding="utf-8") as stream:
            json.dump({"scripts": {"start": "node server.js"}}, stream)
        with open(script, "w", encoding="utf-8") as stream:
            stream.write(
                "const http=require('http');"
                f"http.createServer((q,s)=>s.end('node-ok')).listen({port},'127.0.0.1',"
                "()=>console.log('NODE_HTTP_READY'));"
            )
        identity = self._launch_spec(command_spec_for_executable(
            npm, ["start"], platform_name="windows", cwd=self.temp.name
        ))
        self._activate(identity)

        def responds():
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/", timeout=0.5
                ) as response:
                    return response.read() == b"node-ok"
            except OSError:
                return False

        self.assertTrue(self._wait(responds, timeout=20.0))
        inspection = self.platform.inspect_managed(identity)
        self.assertTrue(inspection.verified)
        self.assertTrue(inspection.members)
        log_path = os.path.join(
            self.platform.runtime_paths().logs_dir, identity.app_id + ".log"
        )
        with open(log_path, encoding="utf-8", errors="replace") as stream:
            self.assertIn("NODE_HTTP_READY", stream.read())
        stopped = self.platform.stop_managed(identity, force=True, timeout=2.0)
        self.assertTrue(stopped.ok)
        self.assertTrue(self._release(identity).ok)
        port = self._free_port()
        with open(script, "w", encoding="utf-8") as stream:
            stream.write(
                "const http=require('http');"
                f"http.createServer((q,s)=>s.end('node-ok')).listen({port},'127.0.0.1',"
                "()=>console.log('NODE_HTTP_READY'));"
            )
        restarted = self._launch_spec(command_spec_for_executable(
            npm, ["start"], platform_name="windows", cwd=self.temp.name
        ), app_id=identity.app_id)
        self._activate(restarted)
        self.assertNotEqual(restarted.generation_id, identity.generation_id)
        self.assertTrue(self._wait(responds, timeout=20.0))
        self.assertTrue(self.platform.stop_managed(
            restarted, force=True, timeout=2.0
        ).ok)

    def test_win_life_004_005_console_close_and_reopen_reconnect(self):
        identity = self._launch_from_external_controller()
        # The controller subprocess has exited. A new controller instance has
        # only the persisted public identity and protected runtime records.
        self.platform = WindowsPlatform(self.repo, os.path.join(self.repo, "server.py"))

        inspection = self.platform.inspect_managed(identity)

        self.assertTrue(inspection.verified)
        self.assertEqual(inspection.status, "running")
        self.assertIn(identity.root_pid, inspection.members)
        stopped = self.platform.stop_managed(identity, force=True, timeout=2.0)
        self.assertTrue(stopped.ok, (stopped.code, stopped.error))
        self.assertTrue(self.platform.release_managed(identity).ok)

    def test_win_life_004_005_http_console_process_restart(self):
        app_id = uuid.uuid4().hex[:8]
        service_port = self._free_port()
        console_port = self._console_port()
        self.fixture_app_ids.add(app_id)
        self._prepare_http_console_app(app_id, service_port)
        first_console = self._start_console(console_port)

        started = self._api_json(
            console_port, f"/api/apps/{app_id}/start",
            {"expectedGeneration": None},
        )
        self.assertTrue(started["ok"], started)
        state = self._api_json(console_port, "/api/state")
        row = next(app for app in state["apps"] if app["id"] == app_id)
        identity = WindowsPlatform._identity_from_public(
            row["runtimeIdentity"], app_id
        )
        self.identities.append(identity)
        self.assertEqual(row["lifecycleStatus"], "running")

        def service_responds():
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{service_port}/", timeout=0.5
                ) as response:
                    return response.status == 200
            except OSError:
                return False

        self.assertTrue(self._wait(service_responds, timeout=20.0))
        self._stop_console(first_console)
        self.assertTrue(service_responds(), "managed service died with the console")

        second_console = self._start_console(console_port)
        reopened = self._api_json(console_port, "/api/state")
        reopened_row = next(app for app in reopened["apps"] if app["id"] == app_id)
        self.assertEqual(
            reopened_row["runtimeIdentity"]["generationId"],
            identity.generation_id,
        )
        self.assertEqual(reopened_row["lifecycleStatus"], "running")
        self.assertTrue(reopened_row["controlAvailable"])

        stopped = self._api_json(
            console_port, f"/api/apps/{app_id}/stop",
            {"expectedGeneration": identity.generation_id, "force": True},
        )
        self.assertTrue(stopped["ok"], stopped)
        self.assertTrue(self._wait(lambda: not service_responds(), timeout=10.0))
        final_state = self._api_json(console_port, "/api/state")
        final_row = next(app for app in final_state["apps"] if app["id"] == app_id)
        self.assertEqual(final_row["lifecycleStatus"], "stopped")
        self.assertIsNone(final_row["runtimeIdentity"])
        self._stop_console(second_console)

    def test_win_life_009_suspended_has_no_side_effect_before_resume(self):
        marker = os.path.join(self.temp.name, "resumed.txt")
        identity = self._launch(
            "from pathlib import Path; import time; "
            f"Path({marker!r}).write_text('resumed'); time.sleep(60)"
        )

        self.assertFalse(os.path.exists(marker))
        self._activate(identity)
        self.assertTrue(self._wait(lambda: os.path.isfile(marker)))
        stopped = self.platform.stop_managed(identity, force=True, timeout=2.0)
        self.assertTrue(stopped.ok, (stopped.code, stopped.error))
        self.assertFalse(stopped.still_running)

    def test_win_life_003_background_child_survives_root_exit(self):
        identity = self._launch(
            "import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])"
        )
        self._activate(identity)

        observations = []
        def child_only():
            inspection = WindowsPlatform(self.repo, "server.py").inspect_managed(identity)
            runner_observation = self.platform._observe_process(identity.runner_pid)
            observations.append((
                inspection.verified, inspection.status, inspection.members,
                inspection.code, inspection.issue.message if inspection.issue else None,
                runner_observation, identity.runner_create_time,
            ))
            return (inspection.verified and inspection.status == "running"
                    and inspection.members and identity.root_pid not in inspection.members)

        self.assertTrue(
            self._wait(child_only),
            "background child was not Job-owned: %r" % (observations[-3:],),
        )
        stopped = self.platform.stop_managed(identity, force=True, timeout=2.0)
        self.assertTrue(stopped.ok, (stopped.code, stopped.error))

    def test_win_life_007_008_timeout_then_explicit_owned_job_force(self):
        sentinel = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=win32process.CREATE_NEW_PROCESS_GROUP
            | win32process.CREATE_NO_WINDOW,
        )
        self.sentinels.append(sentinel)
        identity = self._launch(
            "import signal,time; "
            "signal.signal(signal.SIGBREAK, lambda *_: None); time.sleep(60)"
        )
        self._activate(identity)

        graceful = self.platform.stop_managed(identity, force=False, timeout=0.2)
        self.assertFalse(graceful.ok)
        self.assertEqual(graceful.code, "STOP_TIMEOUT")
        self.assertTrue(graceful.still_running)
        self.assertIsNone(sentinel.poll())

        forced = self.platform.stop_managed(identity, force=True, timeout=2.0)
        self.assertTrue(forced.ok, (forced.code, forced.error))
        self.assertFalse(forced.still_running)
        self.assertIsNone(sentinel.poll(), "unrelated fixture sentinel was touched")

    def test_win_life_006_graceful_success_and_generation_release(self):
        identity = self._launch("import time; time.sleep(60)")
        self._activate(identity)

        stopped = self.platform.stop_managed(identity, force=False, timeout=5.0)

        self.assertTrue(stopped.ok, (stopped.code, stopped.error))
        self.assertEqual(stopped.status, "exited")
        self.assertFalse(stopped.still_running)
        runtime_dir = os.path.join(
            self.platform.runtime_paths().runtime_dir,
            identity.app_id,
            identity.generation_id,
        )
        released = self._release(identity)
        self.assertTrue(released.ok, (released.code, released.error))
        self.assertFalse(os.path.exists(runtime_dir))

    def test_win_life_011_runner_crash_kills_only_its_job(self):
        sentinel = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=win32process.CREATE_NEW_PROCESS_GROUP
            | win32process.CREATE_NO_WINDOW,
        )
        self.sentinels.append(sentinel)
        identity = self._launch("import time; time.sleep(60)")
        self._activate(identity)
        runner = win32api.OpenProcess(
            win32con.PROCESS_TERMINATE | win32con.SYNCHRONIZE,
            False,
            identity.runner_pid,
        )
        try:
            self.assertAlmostEqual(
                self.platform._process_create_time(identity.runner_pid),
                identity.runner_create_time,
                delta=0.1,
            )
            win32process.TerminateProcess(runner, 91)
            win32event.WaitForSingleObject(runner, 5000)
        finally:
            runner.Close()

        self.assertTrue(self._wait(lambda: not psutil.pid_exists(identity.root_pid)))
        self.assertIsNone(sentinel.poll(), "unrelated fixture sentinel was touched")
        reconciled = self.platform.inspect_managed(identity)
        self.assertTrue(reconciled.verified)
        self.assertEqual(reconciled.status, "failed")
        self.assertEqual(reconciled.code, "RUNTIME_CONTROL_FAILED")
        self.assertEqual(reconciled.members, ())

    def test_win_life_009_launch_failure_has_no_side_effect_or_runtime_records(self):
        app_id = uuid.uuid4().hex[:8]
        marker = os.path.join(self.temp.name, "must-not-exist.txt")
        generation_id = str(uuid.uuid4())
        self.fixture_app_ids.add(app_id)
        result = self.platform.launch(LaunchRequest(
            app_id=app_id,
            command="fixture",
            cwd=self.temp.name,
            log_path=os.path.join(
                self.platform.runtime_paths().logs_dir, app_id + ".log"
            ),
            command_spec=direct_command_spec(
                os.path.join(self.temp.name, "missing.exe"), [marker]
            ),
            generation_id=generation_id,
        ))

        self.assertFalse(result.ok)
        self.assertFalse(os.path.exists(marker))
        self.assertFalse(os.path.exists(os.path.join(
            self.platform.runtime_paths().runtime_dir, app_id, generation_id
        )))

    def test_win_life_010_runner_identity_mismatch_fails_closed(self):
        identity = self._launch("import time; time.sleep(60)")
        self._activate(identity)
        forged = replace(identity, runner_create_time=identity.runner_create_time + 60)

        stopped = self.platform.stop_managed(forged, force=True, timeout=0.2)

        self.assertFalse(stopped.ok)
        self.assertEqual(stopped.code, "RUNTIME_IDENTITY_UNVERIFIED")
        verified = self.platform.inspect_managed(identity)
        self.assertTrue(verified.verified)
        self.assertTrue(verified.running)
        self.assertTrue(self.platform.stop_managed(
            identity, force=True, timeout=2.0
        ).ok)

    def test_win_life_012_one_hundred_cycles_leave_no_runtime_records(self):
        baseline_handles = psutil.Process().num_handles()
        reusable_app_id = uuid.uuid4().hex[:8]
        for _ in range(100):
            identity = self._launch_spec(direct_command_spec(
                sys.executable, ["-c", "import time; time.sleep(60)"]
            ), app_id=reusable_app_id)
            self._activate(identity)
            stopped = self.platform.stop_managed(
                identity, force=True, timeout=2.0
            )
            self.assertTrue(stopped.ok, (stopped.code, stopped.error))
            self.assertFalse(stopped.still_running)
            terminal = self.platform.inspect_managed(identity)
            self.assertTrue(terminal.verified)
            self.assertEqual(terminal.status, "exited")
            self.assertEqual(terminal.members, ())
            released = self._release(identity)
            self.assertTrue(released.ok, (released.code, released.error))
            self.assertFalse(os.path.exists(os.path.join(
                self.platform.runtime_paths().runtime_dir,
                identity.app_id,
                identity.generation_id,
            )))
        gc.collect()
        self.assertLessEqual(psutil.Process().num_handles(), baseline_handles + 24)


if __name__ == "__main__":
    unittest.main()

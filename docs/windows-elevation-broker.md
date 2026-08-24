# Windows elevation broker

Local Ops uses one fixed elevated broker to launch saved programs. It does not create one scheduled task per executable and does not store arbitrary commands in Task Scheduler.

## Install and unlock

`POST /api/windows/elevation-broker/install` accepts a password of 8 to 1024 characters. The unelevated controller derives a PBKDF2-HMAC-SHA256 verifier, creates a private installation transaction, and invokes the packaged executable with `runas`. The elevated helper validates the transaction path and request digest, copies the complete onedir bundle into a versioned `%ProgramFiles%\LocalOps\Broker\<hash>` directory, protects its ACLs, and registers `\LocalOps-ElevationBroker` with highest run level and no triggers. Existing versioned broker bundles are preserved.

The installation transaction always uses `%LOCALAPPDATA%\LocalOps\runtime\elevation-install`, even when normal application data is redirected with `CONSOLE_DATA_DIR`. UAC launch does not reliably preserve process-local data overrides; keeping this security transaction at one current-user-only path lets the elevated helper validate it before reading while custom business data remains untouched.

The frozen Windows package installs itself directly. A source checkout cannot install or upgrade the broker: it fails before package discovery, path selection or UAC. The HTTP install contract accepts only the password used to derive the verifier and does not accept a package path override. The elevated helper copies the complete current frozen bundle into `%ProgramFiles%`, and the scheduled task never points at user-writable Python source.

An upgrade registers the new exact Program Files action and then stops only the previous fixed broker task instance, waiting for it to leave `Running`. The following unlock starts the newly registered protocol before accepting a password. This prevents an old launch-only process from retaining the fixed Named Pipe after a v2 package has been installed.

After starting the fixed task, the controller retries transient `ERROR_FILE_NOT_FOUND`, pipe-busy, disconnected and semaphore-timeout results until the bounded exchange deadline. Task Scheduler can report `Running` just before the broker creates its Named Pipe; that startup window is not treated as an installation failure.

The separate `tools/install_windows_console_task.ps1` installs the persistent controller as `RunLevel Limited` from the protected bundle. During activation it stops and waits for any previous console task instance to leave `Running`/`Queued` before registering and starting the replacement. The controller's per-data-directory Mutex is explicitly non-inheritable and uses a namespace distinct from the legacy inheritable lock, so surviving business processes cannot block an upgrade. Windowless Docker and fixed Windows CLI calls use `CREATE_NO_WINDOW`; no Guard or Watchdog action is rewritten for this behavior.

`POST /api/windows/elevation-broker/unlock` is browser-session-only and sends the password over a current-user-only Named Pipe. A successful broker token is bound to the actual pipe client PID, that process's creation time, and its owner SID. The token remains only in the active Local Ops platform object and is never written to `config.json`. The HTTP layer separately marks only the HttpOnly browser session that performed the unlock as elevated; CLI bearer requests and other browser sessions cannot reuse it. `POST /api/windows/elevation-broker/lock` clears the broker token and every browser elevation mark; console shutdown attempts the same operation. A dead or replaced Local Ops process invalidates the session at the broker even if an explicit lock could not be delivered.

## Programs

An elevated program uses `kind: "program"`, `elevated: true`, and a direct `commandSpec` containing an absolute `.exe` plus a bounded string argument array. It has no managed Job identity and no restart operation: starting it asks the broker to launch once. Observation and stopping also run inside protocol-v2 broker privilege; an older launch-only broker remains usable only after explicit upgrade and never causes the unelevated controller to guess or perform a protected stop.

The broker observes matching processes without taking ownership. Every readable
process must belong to the configured owner SID; the executable basename must
match and its real path must be the selected EXE or a child of the selected EXE's
directory, which supports launchers that delegate to a `bin` executable. Programs
with arguments additionally require the observed command line to end in the exact
argument list. The API exposes `observedOnly`, `observedPids`,
`observedProcesses`, `programIdentityVerified`, `programStopAvailable`, and
`observedRestricted`. A confirmed stop request contains the complete observed
set and the broker validates every owner SID, executable and creation time before
terminating any member. Missing, mixed, stale, restricted, timed-out or otherwise
unverifiable observations remain read-only and fail closed; no force or restart
operation exists.

When a new program has no explicit glyph or uploaded image, the Windows adapter reads the EXE's associated icon through a fixed system PowerShell/.NET script and stores the resulting PNG as the app icon. The EXE path is passed only through a dedicated environment variable, the target is never executed, and extraction failure falls back to the app initial without blocking creation.

The broker accepts only an absolute `.exe`, at most 128 bounded string arguments, and an absolute working directory. It calls `subprocess.Popen` with `shell=False` and detached process flags. It does not accept scripts, shell text or environment expansion. Stop requests are not PID-only: they contain a bounded exact identity set plus the favorite executable and are rejected before any termination when one identity fails revalidation.

Deleting a program removes only Local Ops configuration. It does not stop the launched process, unregister the broker task, or remove installed broker bundles. Stopping is a separate confirmed action and does not change broker registration.

Protocol v3 advertises `launch`, `observe`, `stop`, and `scheduled`. When a Limited controller cannot connect to the Task Scheduler COM service, the authenticated broker accepts only bounded normalized task paths and fixed `list/query/run/stop/toggle/history` operations. It returns the existing structured rows/results and never accepts shell text or dynamic task definitions. Scheduled-task mutations additionally require the current HttpOnly browser session's elevation mark; CLI bearer access cannot invoke them. Broker status exposes `stopSupported` and `scheduledTaskSupported`. This implementation remains `IMPLEMENTED_UNVERIFIED` until packaged UAC, clean-machine, Defender/SmartScreen, signing, and release-material gates are completed.

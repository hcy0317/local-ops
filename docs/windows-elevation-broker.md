# Windows elevation broker

Local Ops uses one fixed elevated broker to launch saved programs. It does not create one scheduled task per executable and does not store arbitrary commands in Task Scheduler.

## Install and unlock

`POST /api/windows/elevation-broker/install` accepts a password of 8 to 1024 characters. The unelevated controller derives a PBKDF2-HMAC-SHA256 verifier, creates a private installation transaction, and invokes the packaged executable with `runas`. The elevated helper validates the transaction path and request digest, copies the complete onedir bundle into a versioned `%ProgramFiles%\LocalOps\Broker\<hash>` directory, protects its ACLs, and registers `\LocalOps-ElevationBroker` with highest run level and no triggers. Existing versioned broker bundles are preserved.

The frozen Windows package installs itself directly. A source checkout first searches its private data root for the newest valid `packages/<release>/<bundle>/LocalOps.exe`, validates the onedir metadata and Python 3.12 runtime, and uses it without asking the user for a path. `BROKER_PACKAGE_REQUIRED` is only an interactive fallback when no deployed package passes validation. The elevated helper still copies the complete bundle into `%ProgramFiles%` and the scheduled task never points at user-writable Python source.

`POST /api/windows/elevation-broker/unlock` sends the password over a current-user-only Named Pipe. A successful token is bound to the actual pipe client PID, that process's creation time, and its owner SID. The token remains only in the active Local Ops platform object and is never written to `config.json`. `POST /api/windows/elevation-broker/lock` clears it explicitly; console shutdown attempts the same operation. A dead or replaced Local Ops process invalidates the session at the broker even if an explicit lock could not be delivered.

## Programs

An elevated program uses `kind: "program"`, `elevated: true`, and a direct `commandSpec` containing an absolute `.exe` plus a bounded string argument array. It has no managed runtime identity or stop/restart operation: starting it asks the broker to launch once, and the returned PID is informational only.

The state poll observes matching processes without taking ownership. Readable
processes must belong to the current user; the executable basename must match and
its real path must be the selected EXE or a child of the selected EXE's directory,
which supports launchers that delegate to a `bin` executable. Programs with
arguments additionally require the observed command line to end in the exact
encoded argument list. For a protected process whose token, path, and command
line are all hidden by Windows, Local Ops accepts only one same-session, same-name
candidate and only when the saved program has no arguments. The API exposes
`observedOnly`, `observedPids`, and `observedRestricted`; the UI shows `再次启动`
instead of a stop control because observation never grants lifecycle authority.

When a new program has no explicit glyph or uploaded image, the Windows adapter reads the EXE's associated icon through a fixed system PowerShell/.NET script and stores the resulting PNG as the app icon. The EXE path is passed only through a dedicated environment variable, the target is never executed, and extraction failure falls back to the app initial without blocking creation.

The broker accepts only an absolute `.exe`, at most 128 bounded string arguments, and an absolute working directory. It calls `subprocess.Popen` with `shell=False` and detached process flags. It does not accept scripts, shell text, environment expansion, or a PID-based control request.

Deleting a program removes only Local Ops configuration. It does not stop the launched process, unregister the broker task, or remove installed broker bundles.

Capabilities are advertised as `manage_elevation_broker` and `launch_elevated`. This implementation remains `IMPLEMENTED_UNVERIFIED` until packaged UAC, clean-machine, Defender/SmartScreen, signing, and release-material gates are completed.

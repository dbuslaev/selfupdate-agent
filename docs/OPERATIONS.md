# Operations

## Installing

The installer does the three things a running agent can't do for itself: place
both binaries, get an identity, and register with the platform's service manager.

```
installer install \
  -from ./bin \
  -to   ~/.local/bin/selfupdate-agent \
  -manifest https://releases.example.com/stable/manifest.json \
  -enroll   https://fleet.example.com/v1/enroll \
  -code     A1B2-C3D4-E5F6 \
  -report   https://fleet.example.com/v1/events
```

Running it again over an existing install stops the service, replaces the
binaries, and starts it back up — so the same command is a first install or a
repair.

`-system` installs machine-wide and needs admin rights. Without it the agent runs
as the invoking user, which on macOS means only while that user is logged in.

Omitting `-enroll` gives an unenrolled install: it still updates and still takes
part in staged rollouts, but reports nothing back.

### Files it creates

```
<install>/agent               the shim — what the service manager launches
<install>/agent-app           the program
<install>/agent-app.staged    a downloaded update, temporary
<install>/agent-app.prev      the previous program, until the new one commits
<install>/staging.json        describes a staged binary

<data>/state.json             pending version, boot count, failed versions
<data>/events.jsonl           activity log, cleared once delivered
<data>/identity.json          install ID and private key (0600)
```

Data goes to `~/.local/state`, `~/Library/Application Support`, or
`%LOCALAPPDATA%`. Override with `AGENT_DATA_DIR` — required for a system-wide
install, where the service account may have no home directory.

### Uninstalling

```
installer uninstall            # leaves state and identity
installer uninstall -purge     # removes them too
```

`-purge` is opt-in because deleting the identity means the machine can't be
recovered without a fresh enrollment code.

## Service registration

### Linux — systemd

Unit in `~/.config/systemd/user/` or `/etc/systemd/system/`:

```ini
[Service]
ExecStart=/path/to/agent -manifest https://releases.example.com/stable/manifest.json
Environment="AGENT_DATA_DIR=/var/lib/selfupdate-agent"
Restart=always
RestartSec=5s
RestartPreventExitStatus=2
```

`Restart=always`, not `on-failure`: the program exits 0 after staging an update,
so `on-failure` would leave it stopped and the machine dead until a reboot.

`RestartPreventExitStatus=2` honours "below the minimum supported version".
Retrying can't fix that.

```
systemctl --user status selfupdate-agent
journalctl --user -u selfupdate-agent -f
```

### macOS — launchd

A `LaunchAgent` in `~/Library/LaunchAgents/`, or a `LaunchDaemon` in
`/Library/LaunchDaemons/` with `-system`. The agent runs as the user and only
while logged in; the daemon runs as root from boot.

`KeepAlive/SuccessfulExit=false` is the equivalent of `Restart=always`. Without
it a staged update would sit on disk forever.

```
launchctl print gui/$UID/selfupdate-agent
tail -f "~/Library/Application Support/selfupdate-agent/selfupdate-agent.err.log"
```

Those log files are the only unbounded ones here — the internal event log
rotates, launchd's redirects don't. A production install would add rotation.

### Windows

Registered as a **scheduled task**. It starts at boot, restarts on failure, and
runs without a console window, which is everything the agent needs. It doesn't
appear in `services.msc`.

```
schtasks /Query /TN selfupdate-agent /V /FO LIST
schtasks /End   /TN selfupdate-agent
schtasks /Run   /TN selfupdate-agent
```

Registering a true Windows service instead would only change
`internal/service/service_windows.go`.

## Releasing

```
make release VERSION=1.2.3 ROLLOUT=10
```

Cross-compiles six platforms, stamps each with its version and the public release
key, hashes them, signs the manifest, and verifies that signature against the key
clients actually carry — before it reaches anyone.

Then publish `dist/` to the channel. **Artifacts first, manifest second**, or
clients briefly fetch a 404. `updateserver` re-reads the manifest per request, so
publishing needs no restart.

Cache headers matter: artifacts are immutable and get a long TTL, the manifest is
`no-cache` with an ETag. Cache the manifest aggressively at the CDN and the
rollout dial stops working.

### Widening a rollout

Re-sign the same version at a higher percentage. That's the whole mechanism.

```
releasectl sign -key release.key -version 1.2.3 -dir dist -rollout 10
# watch update.committed against update.failed
releasectl sign -key release.key -version 1.2.3 -dir dist -rollout 50
releasectl sign -key release.key -version 1.2.3 -dir dist -rollout 100
```

Machines already updated keep the new version. Raising the number only adds
machines.

`-next-check 300` shortens the poll interval during an active rollout. Raise it
again afterwards.

### Halting one

`-rollout 0`. Nothing pulls back machines that already updated; no further ones
take it.

### Recalling a bad release

```
releasectl sign -key release.key -version 1.2.2 -dir dist -rollout 100 -allow-downgrade
```

Clients refuse to move backwards without that flag, which is what stops a
replayed old manifest reintroducing a fixed bug.

Before doing it, check that 1.2.3 made no change to stored data that 1.2.2 can't
read. **A release must not make changes its predecessor can't tolerate** —
reverting a binary without reverting its data can be worse than the crash.

### A release that can't self-install

Rare. Only for one that changes the shim or the service registration.

```
releasectl sign -key release.key -version 2.0.0 -dir dist -rollout 100 \
  -requires-reinstall -installer-url https://downloads.example.com/agent-2.0.0-installer
```

Clients hold their current version and show:

```
ACTION REQUIRED: version 2.0.0 cannot be installed by the agent.
                 Run a new installer to move past it.
```

Nothing happens automatically. Distribute the installer, track adoption through
events, and pair it with `-min-supported` on a later release so stragglers stop
rather than running indefinitely.

### Retiring old builds

`-min-supported 1.0.0` makes anything below it stop with exit code 2. This is the
backstop that keeps a rolled-back machine from being silently pinned.

It stops machines. Confirm the fleet has moved before setting it.

## Diagnosis

```
agent-app --status
```

```
version:        1.2.3
install id:     d63e407a93dbad2bad96eec5b2bb0611
last committed: 1.2.3
last check:     2026-08-23T09:01:52Z
failed here:    [1.0.2]

recent events:
  2026-08-23T09:01:05Z  update.committed  1.2.3 map[from:1.2.2]
```

### Not updating

`--status` gives the reason. Every skip carries one — a silent skip would be
undebuggable from outside, so the code requires it.

| Symptom | Cause |
|---|---|
| Target version under `failed here` | It was refused or it crash-looped. Never retried on this machine. |
| `last check` is old | Server unreachable. Retries back off up to 32× the interval. |
| Nothing pending, nothing failed | Not in the rollout yet. |
| `ACTION REQUIRED` in status | The release needs a manual install. |
| Exit code 2 in service logs | Below the supported floor; needs reinstalling. |
| "not writable" in the logs | The install folder is owned by something else. |

### Rolled back

Look for `shim.rollback` — `restored` is the version it went back to, `attempts`
is how many starts the new one got.

The failed version is marked locally, so that machine won't retry it. If the same
version is rolling back across many machines, that's the fleet-wide signal: set
`-rollout 0`, then recall with `-allow-downgrade` if some already took it.

### Clearing a failed version

No command, deliberately — the usual answer is to cut a new version rather than
re-offer one that already failed. If you must, edit `poisoned` in `state.json`
with the agent stopped.

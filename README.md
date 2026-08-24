# A program that updates itself

A Go program you install once on Linux, macOS or Windows. It checks for new
versions, installs them, and restarts into them. If a new version turns out to
be broken, it puts the old one back on its own.

Standard library only, no third-party packages.

## Try it

```
./scripts/demo.sh
```

Self-contained: it generates a throwaway signing key, starts a local server, and
keeps everything inside `.demo/`. It does not register anything with launchd or
systemd — a bash loop stands in for the service manager — so nothing is left
behind on your machine. Takes about a minute and shows three things.

1. Version 1.0.0 updates itself to 1.0.1.
2. A bad 1.0.2 is caught and refused before it gets installed.
3. A 1.0.3 that starts but keeps dying is rolled back.

```
make test                    # 98 tests, with Go's race detector
make keys                    # create your real signing key (once, ever)
make release VERSION=1.2.3   # build 6 platforms and sign the release
```

## How it works

**The supervisor** is the operating system's service manager — launchd, systemd,
or Task Scheduler. Not written here. It starts things back up when they exit.

**The shim** is a small program the supervisor launches. It installs any waiting
update, then hands control to the main program.

**The program** is the real software. It checks for updates, verifies them,
downloads them, and leaves them ready for the shim. Then it exits.

```
program: finds a new version, checks it, saves it, exits
   ↓
supervisor: sees the program exited, starts the shim
   ↓
shim: installs the new version, starts the program
   ↓
program: runs, confirms it's working, marks the update as good
```

### Why the shim exists

A program can't safely overwrite its own file while it's running. Windows won't
allow it. Unix allows it only with a specific trick, so you end up with two
different pieces of code doing the same job.

When the shim runs, the main program isn't running, so its file isn't in use.
Installing an update becomes two ordinary renames that behave identically on
every operating system.

The cost: the program has to exit and something has to start it again. Without a
supervisor, an update downloads and never installs.

### What the shim does and doesn't do

It never decides *what* to install. No manifest parsing, no rollout logic, no
release signing key. It installs what the program already downloaded and
verified.

It does hold this machine's own key so it can sign a status report on startup.
That report is its only network call, capped at three seconds so a slow server
can't delay startup. And it makes one decision: that a version has failed often
enough to roll back.

On Unix it doesn't linger — it replaces its own process with the program, same
PID. The supervisor never sees a restart. On Windows there's no equivalent, so it
waits for the program and passes its exit code up.

## Finding updates

The program fetches a **manifest**: a small JSON file listing the current
version, download URLs, and checksums.

It's a static file. It can sit in S3 behind a CDN. There's no API to run, so
updates keep working even when everything else is down.

## Trusting the download

Each release is **signed** with a private key that lives in the build pipeline
and nowhere else. Every copy of the program has the matching public key compiled
into it and checks the signature before installing anything.

The manifest holds a checksum for each download, so verifying the manifest
covers the binaries too.

Someone who takes over the download server can stop updates going out but can't
send their own software. The key they'd need was never on that server.

## Stopping a bad release

**Before installing**, the program runs the downloaded file once and asks for its
version. A binary that can't run at all — wrong processor, missing library,
corrupt download — is caught here, while the working version is untouched.

**After installing**, the new version is on probation. The shim counts its
starts; the program must report that it's working. Three failed starts and the
shim restores the old version and marks the bad one so it's never fetched again.

Counting happens in the shim because the shim always runs. A program that crashes
on startup can't count its own failures.

**Don't get stuck on an old version.** A release can set a minimum supported
version, and clients below it stop rather than carry on. Checked at startup as
well as on the timer, so a laptop that's been off for months finds out
immediately.

This only works if the client can reach the server. A fully offline machine never
finds out. That's a deliberate choice — see
[ARCHITECTURE](docs/ARCHITECTURE.md#the-staleness-floor-and-what-it-cannot-do).

## Gradual rollout

A release can be offered to a percentage of machines, so a bad one breaks ten
percent of the fleet instead of all of it.

Each machine decides for itself whether it's included, by hashing its own install
ID together with the version number. No server involvement, which is what keeps
the manifest a plain static file. The calculation gives the same answer every
time, so raising the percentage only ever adds machines — and it includes the
version number, so the same unlucky machines aren't the canary every release.

To widen a rollout, sign the *same* version again at a higher number and upload
the new manifest. The binaries don't change; only the percentage does.

```
releasectl sign -version 1.2.3 -rollout 10    # watch for a while
releasectl sign -version 1.2.3 -rollout 50
releasectl sign -version 1.2.3 -rollout 100
```

Setting it to zero halts a rollout. Machines that already updated keep the new
version — nothing pulls them back.

## Recalling a bad release

Pulling machines *backwards* is separate, and guarded. An older version in the
manifest is refused by default:

```
releasectl sign -version 1.2.2 -rollout 100 -allow-downgrade
```

The guard exists because a signature proves a manifest is authentic, not that
it's current. Without it, a stale cache or a replayed old manifest could walk the
fleet back onto a version with a known bug. The flag makes it a deliberate act.

Remove it once the recall is done, or every later stale manifest applies too. And
check that the version you're recalling didn't change stored data the older one
can't read — reverting a binary without its data can be worse than the bug.

## Releases needing a manual install

A few releases can't install themselves — mainly ones changing the shim or the
service registration, which the running program doesn't control. Those are marked
in the manifest with a download link, and clients keep running while showing:

```
ACTION REQUIRED: version 2.0.0 cannot be installed by the agent.
                 Run a new installer to move past it.
```

The shim deliberately can't replace itself. It's the bottom of the stack, so if a
replacement were broken there'd be nothing left running to fix it.

## When things go wrong

| Problem | What happens |
|---|---|
| Server unreachable | Retries with growing delays; keeps running the current version |
| Manifest tampered with | Signature check fails, nothing downloads |
| Download corrupted | Checksum fails before the file is ever run |
| New version won't start | Caught before installing |
| New version keeps dying | Old version restored after three tries |
| Downloaded file swapped on disk | Shim re-checks the checksum before installing |
| Crash partway through an update | Finished on the next start |
| Settings file corrupted | Rebuilt; the installed program is the real record |
| Can't write to the install folder | Detected early with a clear message |
| Power cut during a write | Files flushed to disk before anything is renamed |

The rule underneath all of it: **the program file on disk is the only real record
of what's installed.** Everything else can be lost and rebuilt. That's what keeps
the recovery paths short.

## Code layout

```
cmd/shim           installs updates, then starts the program
cmd/app            the program itself
cmd/installer      first-time setup
cmd/releasectl     build-time tool: makes keys, signs releases
cmd/updateserver   serves releases (a real one would be S3 + CDN)

internal/updater   checking, deciding, downloading
internal/manifest  the release file format and its signature
internal/staging   handing an update from the program to the shim
internal/state     what's installed, what failed, what's pending
internal/events    activity log and reporting
internal/identity  this machine's key, used to sign its reports
internal/service   registering with launchd, systemd, Task Scheduler
internal/layout    where every file goes
internal/launch    starting the program (differs on Windows)
internal/fsutil    safe file writing
internal/version   version numbers and comparing them
```

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — why it's built this way
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — manifest and API formats
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — installing, releasing, rolling back
- [QUESTIONS.md](QUESTIONS.md) — questions I'd have asked, and what I assumed

## Tests

`go test -race ./...` runs 98 tests. `-race` catches bugs where two parts of the
program touch the same data at once.

The interesting ones:

- **Rollout maths** (`internal/updater/policy_test.go`) — raising the percentage
  only adds machines, the answer doesn't change between checks, and each release
  picks a different sample.
- **Shim logic** (`cmd/shim/main_test.go`) — installing, counting failures,
  rolling back, refusing a swapped file, coping with a missing backup.
- **Signature checks** (`internal/manifest/manifest_test.go`) — including a
  regression test for a real bug this code had, where Go's JSON formatter
  silently changed the signed bytes and broke every signature.

## What I left out

- **Automatic reinstall.** When a release needs a manual install the program says
  so but doesn't act. That needs admin rights and usually a person.
- **Re-enrollment.** A wiped machine can't get back without an admin issuing a
  new code. Worth designing before it's needed rather than during an incident.
- **Stopping when offline too long.** A product decision more than an engineering
  one, and getting it wrong takes out every machine at once.
- **Smaller downloads.** Full binaries every time, around 8 MB. Sending only the
  differences would help and add a new category of bugs.

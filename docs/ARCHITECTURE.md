# Architecture

Why it's built this way. The README says what it does; this says why, including
the choices that went the other way first.

## The core problem

A running program can't safely replace its own executable.

Unix almost allows it. A rename within one filesystem is atomic, and unlinking a
running binary doesn't disturb it — the kernel keeps the old file alive until the
process exits. So a program can swap itself and keep going.

Windows won't. The loader holds the running image and refuses deletion or
overwrite. It does allow *renaming* it, so an in-process updater has to do two
renames:

```
agent-app.exe   -> agent-app.exe.prev
downloaded.tmp  -> agent-app.exe
```

That works, and it leaves a gap of microseconds where nothing exists at the
target path. A process launching in that gap fails.

So an in-process updater means two implementations, one with a real if small
hole. That's the thing worth designing away.

## The shim

Do the swap when the target isn't running. Something has to be executing at that
moment, and the cheapest option is a small binary that runs at startup and then
gets out of the way.

```
supervisor ──launches──> shim ──installs, then exec──> program
     ▲                                                    │
     └──────────── restarts when it exits ────────────────┘
```

The result: `internal/staging/apply.go` has **no platform-specific code at all**.
Two renames, same everywhere, no gap.

### Why not a separate updater that runs all the time

A permanently running updater service would also solve the swap, and it's worse:

- It needs its own installer and its own update path — the recursion the shim
  avoids by holding no policy.
- It usually needs elevated privileges.
- A persistent privileged process whose job is downloading and running code is a
  high-value target. Chrome's updater has its own CVE history.

The shim runs for milliseconds and, on Unix, stops existing once it has `exec`'d.

### The split is by how often things change

Everything complex and frequently revised — fetching, signature checks, rollout
policy, download, vetting — lives in the program, which ships often. Everything
simple and stable — verify a hash, rename, exec — lives in the shim, which almost
never changes.

That's what turns "who updates the updater" from a recursion into a footnote.

### What the shim actually touches

It reads the staging record and the event log. It reads and writes the state file
for boot counting. It loads this machine's key to sign one startup report, capped
at three seconds.

What it never has: the release signing key, a manifest parser, or any say in what
gets installed.

## The supervisor is a hard dependency

The program exits after staging an update. Something outside the process tree has
to bring it back.

Without one, an update stages and never installs. That's the cost of the design.
An `execve`-based in-process updater is self-sufficient but keeps the Windows gap
and can't recover from a build that won't start.

Two settings in the service definitions matter:

- **`Restart=always`, not `on-failure`.** The program exits 0 after staging an
  update. Under `on-failure` it would stay stopped and the machine would be dead
  until someone rebooted it.
- **`RestartPreventExitStatus=2`.** Exit 2 means the build is below the minimum
  supported version. Retrying can't fix that.

This is also why boot counting moved out of the program. When a program `execve`s
itself, systemd never sees a restart, so its counter and any in-process counter
can't see each other. With the shim there's one restart path and one counter.

## Recovering from a bad release

### Before installing

The candidate is run once with `--self-check` and must print its own version.
This happens while the working binary is still in place, so abandoning costs
nothing.

It catches what a signature can't: bytes that are authentic and still won't run
here. Wrong architecture, missing library, unsigned binary on a machine that
enforces signing, a proxy that truncated the transfer, a pipeline that put the
wrong artifact in the wrong slot.

It also catches them *before* they can crash-loop, because a build that can't
start can never be caught by boot counting — nothing runs to count.

### After installing

The shim increments a counter on each start of a pending version. The program
calls `MarkHealthy()` once it is actually running, which commits the update and
releases the backup. After three boots without it, the shim restores the previous binary and
marks the failed version.

Counting lives in the shim because it's the only thing guaranteed to run every
time. A build that panics during startup never counts itself.

Marking the failure matters as much as the rollback. Without it, the restored
program's next check would see the same release, install it, and crash again.

### Rollback isn't the end state

A rolled-back machine keeps working on the previous version, which is right. One
version behind still does its job; a machine that exited does nothing.

But it mustn't be stuck there forever. `min_supported_version` is the floor:
below it, the program stops and reports. That check runs before every other
decision, because a machine below the floor has to stop even when no update
applies to it.

## The staleness floor, and what it cannot do

`min_supported_version` only works if the machine can reach the server. One that
is offline — or whose route to the server is being blocked — never finds out it
is unsupported, and keeps running.

For most software that's a freshness annoyance. For a security-relevant agent
it's the more interesting failure, because whoever benefits from an old build
running is well placed to stop the client hearing otherwise. Blocking a domain is
easier than defeating a signature.

### What closing it would take

A locally evaluable deadline: a maximum time the client may run without a
*verified* check-in, carried in the signed manifest.

Three details make or break it. Count from the last check that verified, not the
last attempted, or serving garbage resets the clock. Take the deadline from the
signed manifest so it can't be lowered by a hostile server or raised by editing
local state. Degrade in stages — warn, report, then refuse.

### Why it isn't there

It's a dead-man's switch with a severe, correlated failure mode. An expired
certificate, a misconfigured proxy or a botched CDN migration takes out the whole
fleet at once, needing a person at every machine — the exact scenario the rollback
design exists to avoid.

Current behaviour fails open: a client that can't reach the server keeps working
on the last version it verified. Right for a background agent, wrong for a client
gating access to something. That's a product decision, not an engineering one.

The cheaper half is server-side: the API can reject a client reporting an old
version. No client change, and it can't brick anything.

## Trust

### Signing away from the servers is what actually protects the update

Every copy of the program has one public key compiled into it. The manifest is
signed with the matching private key, and the manifest lists a checksum for every
binary, so checking the manifest covers the binaries too.

The private key never goes near the machines that serve files. It lives in the
build pipeline and signs at release time. So even if someone took over the
download server, the CDN and the storage bucket all at once, they could stop
updates going out but couldn't send their own software — the key they'd need was
never there.

This is why TLS and signed URLs aren't enough. A signed URL proves the link came
from your infrastructure; it doesn't prove the bytes are the ones you built. A
compromised API will happily mint valid URLs pointing at attacker binaries, and
every checksum will match because the attacker computed them.

### The machine's own key does a different job

Each machine generates its own keypair when it enrolls. The private half never
leaves it, and the server keeps only public keys — so someone who steals the
fleet database gets nothing they can impersonate a machine with.

This proves a *machine is who it says it is when it reports in*. That's what
makes the reports trustworthy and lets a single machine be revoked. It does
nothing for whether an update is genuine, which runs in the opposite direction
and is what the release signature covers.

Mixing up those two is the easiest mistake to make here.

### Why check-ins are signed when the reply isn't checked

It looks backwards at first: the client signs its report carefully, then ignores
what comes back.

The thing worth protecting is the report, not the reply. If reports were
unsigned, anyone could send one claiming to be any machine. A compromised machine
could be made to look healthy, or a few hundred fake crash reports could halt a
good rollout. Both are cheap attacks against a fleet you can't see directly.

The reply is only an acknowledgement. A forged one wouldn't change anything the
client does, so checking it would add work for nothing.

### Why the machine's key is a file, not in the OS keystore

Start with what the key actually protects. It proves a report came from this
machine. It has nothing to do with whether an update is genuine — that's the
release signature, and it's separate.

So if the key is stolen, an attacker can send fake reports for one machine. Bad,
but it's one machine, and revoking it is a single change on the server.

Using the operating system's keystore instead would mean a separate
implementation for each platform, and on macOS it needs C bindings. Those bindings
would end the single static binary, and with it the ability to build all six
platforms from one machine — which is a lot to give up. Keystores also tend to
prompt for access, which is awkward on a machine with nobody logged in, and that
describes most of a fleet of background agents.

So the key is a plain file readable only by its owner. The risk that remains is
that anyone who can read files as that user can impersonate the machine. If that
ever matters more than it does here, hardware-backed storage is the next step.

## Details where the obvious approach is wrong

Six places where the natural way to build something is subtly broken, and it
isn't obvious until it fails.

**Carry the signed manifest as base64, not as nested JSON.** A signature covers
exact bytes, so the client has to check it against byte-for-byte what was signed.
Putting the manifest inside the outer document as normal JSON looks tidier, but
Go's JSON writer reformats nested content on the way out — adding indentation.
The client then checks the signature against text that differs by a few
whitespace characters, and every signature fails. Base64 hides the manifest from
the formatter, so it arrives exactly as it left.

**Download the new binary into the folder it will end up in.** Installing an
update is a rename. Renaming a file within one disk is instant and all-or-nothing
— it either happened or it didn't. Renaming across two disks isn't a rename at
all; the system quietly copies the file instead, and a copy can be interrupted
halfway, leaving a partial binary in place. System temp folders are often on a
different disk, so downloading there and moving would reintroduce exactly the
problem the design is built to avoid.

**Work out rollout membership from the install ID and the version together.**
Each machine needs to decide for itself whether it's in the 10%, without asking a
server. It hashes those two values into a number from 0 to 99 and compares. Two
things have to be true. The answer must never change, or a machine would drift in
and out of a rollout between checks — and widening a rollout could exclude one
that already updated. And the version has to be part of it, or the same unlucky
machines would be first for every release. Both are tested.

**Put the check interval in the signed manifest.** During a rollout you want
machines checking every few minutes; the rest of the time, rarely. Carrying that
in the manifest means it's controlled centrally with no extra service, and
because the manifest is signed, whatever is serving the files can't tamper with
it. The client caps the value between 30 seconds and a day, so a typo can't turn
the fleet into a denial-of-service attack on your own server.

**Keep the programs and the saved state in separate folders.** Putting state next
to the binary is fine for a demo. On a real machine the install folder often
belongs to an installer and is read-only to the account the agent runs as, while
state has to be writable. One folder can't be both.

**Only ever add to the event log; never overwrite it.** The simple design is one
file holding the report waiting to be sent, replaced each time. It loses data
precisely when it matters: if a second event happens before the first is
delivered, the first is gone. Events pile up fastest during a crash loop, which
is exactly when you need to see them. Adding to the end of a file is safe even if
the machine dies mid-write — you lose the last line, not the file.

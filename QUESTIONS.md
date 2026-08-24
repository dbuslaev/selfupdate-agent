# Questions, and the answers I assumed

The brief says to write questions down, guess the answer, and carry on. These are
the ones that changed the design.

---

**1. Does the program run continuously, or start and finish quickly?**

*Assumed it runs continuously.* Something that stays running for hours can check
for updates on a timer and exit when it finds one. A command that runs for a
fraction of a second would have to update on its next launch instead, which is a
different design. The update check is a single function anyone can call, so a
short-lived tool could run it once at startup and get most of the way there.

**2. Is there a service manager on the machine?**

*Assumed yes, and the installer sets it up.* Everything else rests on this, and
it's the assumption I'd most want confirmed.

With one, the program can exit when it has an update ready, and the swap happens
at the next start when nothing is using the file. That removes all the code that
would otherwise be different on each operating system.

Without one, the program has to replace its own file while running. That works,
but it can't recover from a version that never starts, because nothing is left
running to notice. I built that version first. It's worse.

**3. Does the program have permission to write to its own folder?**

*Assumed yes.* Either a folder the user owns, or a system-wide install where the
account running the agent owns it.

If it were installed somewhere only an administrator can write, and then run as
an ordinary user, no self-updater can work — you'd need a second piece running
with administrator rights to do the file replacement, which is a much bigger
project. That situation is detected before anything is downloaded, and reported
clearly rather than failing halfway through.

**4. Is a few seconds of downtime during a restart acceptable?**

*Assumed yes.* The program exits and the service manager starts it again.

If this were a server handling live connections you'd want to hand those
connections to the new version rather than dropping them, and I didn't build
that. There is a place in the code to finish work in progress before exiting,
which is the smaller version of the same idea.

**5. Do we control how the software is distributed?**

*Assumed yes.* Self-updating is either forbidden or pointless if the software
goes out through an app store or a package manager — those systems expect to own
the files and will fight anything that changes them.

If that turns out to be the case, the answer is to stop self-updating and publish
through that channel instead. The permission check in question 3 is what would
surface it: on a machine where a package manager owns the files, the agent finds
it can't write to them and says so.

**6. Is it one self-contained program file, or a folder of files?**

*Assumed one file.* Replacing a single file can be done in one step that either
happens or doesn't — there's no moment where it's half-replaced. Replacing a
folder can't. You'd have to keep each version in its own folder and switch a
pointer between them, which is a lot more machinery.

Building it as one file with nothing else to install is also what makes it
possible to produce all six platform versions from one machine.

**7. Is download size a concern?**

*Assumed no.* Every update downloads the whole program, about 8 MB. You can send
only the differences between versions instead, which would cut that a lot, but it
adds a whole category of failures where the differences don't apply cleanly. Not
worth it until download size actually costs something.

**8. How quickly does a new release need to reach machines?**

*Assumed minutes to hours, so checking on a timer.* The brief says "periodically
ship new versions", not "immediately", and "seamlessly replaced" describes how
clean the replacement is rather than how fast.

Getting under a minute would mean holding a connection open to every machine —
and you'd still need the timer as a fallback, because connections drop. So it's
extra work on top rather than instead. The middle ground is what's built: the
manifest carries a requested check interval, so you can have machines check more
often during a rollout and less the rest of the time.

**9. Do we need separate release tracks — stable, beta, early access?**

*Assumed one track, but percentage rollout is needed.* Separate tracks are just
separate URLs and need no changes. Rolling out to a percentage of machines does
need support in the manifest, so that's built.

**10. Should machines report back what version they're on?**

*Assumed yes.* Without it you can't answer "how many machines are on 1.4.2",
which is the first question anyone asks during a rollout, and deciding whether to
roll back becomes guesswork. For a company selling identity security, being able
to show which version was running where and when is also something auditors ask
for.

**11. How does the server know which machine it's talking to?**

*Assumed each machine enrolls once with a one-time code, then uses its own key.*
An administrator sends the code out of band, so they know who received it. The
machine creates a pair of keys, sends only the half that can verify signatures,
and gets an ID back.

The alternative is putting one shared password into the software. Then anyone who
pulls it out of a single copy can impersonate every machine, and a break-in on
the server side hands over the whole fleet at once.

**12. Where does the release signing key actually live?**

*Assumed a file here, and a dedicated key service in production.* The code only
calls one small function to sign, so pointing that at a managed key service later
is a contained change. Nothing else is affected, because machines only ever see
the public half.

**13. Who decides to roll back — the machine or a person?**

*Assumed both, for different situations.* The machine handles "this version
doesn't work here", because only it can see that. A person handles "this version
is bad everywhere", by publishing an older one and marking it as an allowed
downgrade.

I considered having a failing machine work backwards through older versions until
one worked, and dropped it. A version that fails on a particular machine usually
fails for a reason the previous few versions share — something about that
machine — so it would download, install and crash several times getting nowhere.
The machine stays simple: go back one, remember what failed, report it. The
server, which can see fifty machines failing the same way, decides what to offer
next.

**14. How does the shim itself get updated?**

*Assumed by reinstalling, not by replacing itself.*

It could replace itself. On Mac and Linux the shim has already stepped aside by
the time the program is running, so nothing is holding its file. On Windows it
could put a replacement in place and swap it at the following start. So this was
never about whether it's possible.

**The reason not to is that nothing sits below the shim to catch it if it
fails.** Everything else here is caught by something outside the part that broke:
a program that keeps crashing is put back by the shim, a program that exits is
restarted by the service manager, a release that can't install itself gets
escalated to a person. But if the shim itself won't run, the service manager just
keeps starting a file that dies instantly. The program never runs, so nothing
even reports the problem. The machine goes silent rather than degraded, and
fixing it needs someone physically there.

Adding a failure counter for the shim doesn't solve it either. Whatever checks
that counter has to run before the shim, so now *that* is the thing at the bottom
with nothing to catch it. This only ends at something the agent doesn't install
and can't break: the service manager, or a person with an installer.

The safeguards that make the program swap safe don't transfer. The pre-install
check works because it runs while the working version is still in place. Failure
counting works because the shim always runs first. A replacement shim can be
checked against its checksum, but that only proves it's the file we downloaded —
not that it runs, which is the failure that matters here precisely because nobody
would be left to notice.

So a release that changes the shim is marked as needing a manual install, with a
download link. Machines keep running their current version and say so. This
should almost never happen.

**15. Should a machine stop if it hasn't reached the server in a long time?**

*Assumed no — keep running.* The minimum supported version retires old builds,
but only for machines that can reach the server. One that's offline never finds
out.

That's a real gap, and for security software it's the interesting one: whoever
benefits from an old version staying in place can block a network address far
more easily than break a signature.

Closing it would mean giving each machine a deadline it can check on its own, set
in the signed manifest. I didn't build it because getting it wrong fails badly
and fails everywhere at once — an expired certificate or a bad server migration
would stop every machine simultaneously, each needing someone to visit it.

Keeping machines running favours availability; stopping them favours certainty
about what's deployed. Which one is right depends on what the software controls,
and that's a business decision rather than a technical one.

There's a cheaper version that covers most of it: the server can refuse to work
with a machine reporting an old version. That needs no change on the machine and
can't take anything out of service. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#the-staleness-floor-and-what-it-cannot-do).

**16. On macOS, is this a plain program or an application bundle?**

*Assumed a plain command-line program.* An application bundle is a folder rather
than a single file, so replacing it can't be done in one step — which is what the
whole swap approach depends on. See question 6.

**17. On Windows, is a scheduled task acceptable, or is a real service required?**

*Assumed a scheduled task is fine.* It starts at boot, restarts on failure, and
runs without a console window, which covers everything the agent needs. The
visible difference is that it doesn't show up in the Services list. If a real
service is required, only one file changes.

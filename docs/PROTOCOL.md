# Protocol

Two contracts, deliberately independent. Updating works with the first alone, so
a fleet API outage can't stop a security release reaching the fleet.

## 1. Release channel

Static files. No authentication, no secrets, no server logic. In production this
is an object store behind a CDN; `cmd/updateserver` implements it so the loop can
run on one machine.

```
GET /manifest.json          the signed manifest
GET /artifacts/{name}       a release binary
```

### Envelope

```json
{
  "manifest":  "eyJ2ZXJzaW9uIjoiMS4yLjMi...",
  "key_id":    "5746f16700f2f0c4",
  "signature": "3v8kQx2..."
}
```

This is the whole file as served. `manifest` holds the actual release
information, base64-encoded; `signature` is Ed25519 over those decoded bytes;
`key_id` is the first 8 bytes of SHA-256 over the public key.

To read it: `jq -r .manifest manifest.json | base64 -d | jq .`

Base64 rather than nested JSON because Go's encoder re-indents embedded raw
messages, which changes the bytes and breaks every signature.

`key_id` lets a client say "signed by a key I don't have" instead of "bad
signature", and it's what key rotation hangs off: ship a build trusting both
keys, wait for the fleet to converge, then sign with the new one.

### Manifest

What the base64 field decodes to.

```json
{
  "version": "1.2.3",
  "released": "2026-08-23T09:00:00Z",
  "rollout": 25,
  "min_supported_version": "0.9.0",
  "allow_downgrade": false,
  "requires_reinstall": false,
  "next_check_seconds": 300,
  "notes": "https://example.com/releases/1.2.3",
  "artifacts": [
    { "os": "darwin", "arch": "arm64",
      "url": "artifacts/agent-app_darwin_arm64",
      "sha256": "b2fc8829bc85e792...", "size": 8042259 }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `version` | yes | MAJOR.MINOR.PATCH, optional `-pre` suffix |
| `released` | yes | publication time, informational |
| `artifacts` | yes | one per platform; a missing platform is reported, not guessed |
| `rollout` | yes | 0–100; machines bucket themselves |
| `min_supported_version` | no | machines below this stop running |
| `allow_downgrade` | no | permits moving backwards; the recall switch |
| `requires_reinstall` | no | the agent can't install this itself; needs `installer_url` |
| `installer_url` | with the above | where to get the installer |
| `next_check_seconds` | no | requested poll interval, clamped to 30s–24h |
| `notes` | no | release notes URL, so a changelog isn't shipped on every check |

`url` may be relative, resolved against the manifest URL, and may not leave its
origin. That does nothing against a forged manifest but limits what a leaked
signing key can reach.

`size` isn't decoration — the download is bounded by it, so a hostile response
can't fill the disk.

### Client behaviour

- Conditional `GET` with `If-None-Match`; the normal case costs a 304.
- The `ETag` is cached only after the body verifies, so a server can't pin a
  client to a manifest it rejected.
- Bodies over 1 MiB are refused before signature checking.
- `User-Agent: selfupdate-agent/{version} ({os}/{arch})` — the access log doubles
  as a crude version census.

### Decision order

First match wins, and every outcome carries a reason.

1. Version unparseable → skip
2. Below `min_supported_version` → **stop the program** (exit 2)
3. Version already failed here → skip
4. Same version → skip
5. Older, without `allow_downgrade` → skip
6. Not in the rollout → skip
7. `requires_reinstall` → report and keep running
8. No artifact for this platform → skip
9. Otherwise → download, check, stage

Staleness is second because a machine below the floor must stop even when no
update applies to it. The reinstall check comes after rollout so a machine the
release doesn't reach is never told to reinstall for nothing.

### Releases needing a reinstall

Some releases change what the running agent doesn't own — the shim, or the
service registration. Those set `requires_reinstall` and an `installer_url`.

A client that reaches one keeps running, logs it once, emits an event, and shows
it in `--status` until a later release supersedes it. Signing refuses
`requires_reinstall` without a URL: a release nobody can install, that doesn't
say where the installer is, strands everyone who reaches it.

## 2. Fleet API

Lives in its own repository. `cmd/updateserver` carries a reference version so
the client half can be exercised — it verifies real signatures and rejects real
replays.

```
POST /v1/enroll     one-time code -> install identity
POST /v1/events     signed telemetry
```

### Enrollment

Runs once, from the installer. An admin issues a code out of band, so the backend
knows who received which.

```json
POST /v1/enroll
{ "code": "A1B2-C3D4-E5F6",
  "public_key": "MCowBQYDK2VwAyEA...",
  "machine": { "hostname": "...", "os": "darwin", "arch": "arm64", "version": "1.2.3" } }

200 { "install_id": "d63e407a93dbad2bad96eec5b2bb0611" }
```

The keypair is generated on the client; only the public half is sent, and the
server stores only public keys.

The returned `install_id` is freshly generated, never derived from the code.
Reusing the code as a long-lived identifier would put an emailed secret into
every request and log line.

Enrollment failure aborts the install. A machine with no identity produces
telemetry nobody can trust, and finding that out months later is worse than
failing while an admin is watching.

Hostname is collected because operators need to recognise machines, and treated
as personal data because in practice it is. No hardware fingerprints — they
change on reimage, they're a privacy liability, and enrollment already gives real
identity.

### Signed requests

| Header | Value |
|---|---|
| `X-Install-Id` | the install ID |
| `X-Timestamp` | Unix seconds |
| `X-Nonce` | 16 random bytes, hex |
| `X-Signature` | Ed25519 over the signing string |

```
METHOD \n PATH \n INSTALL_ID \n TIMESTAMP \n NONCE \n SHA256(body)
```

Each part earns its place, and each has a test that alters it and checks the
signature breaks. Method and path stop a signature being lifted onto another
endpoint. Install ID stops one machine speaking as another. Timestamp bounds how
long a captured request stays useful. Nonce closes replay *inside* that window,
which the timestamp alone can't. Body digest stops the payload being swapped.

Server side: reject outside ±5 minutes, reject a reused nonce, verify against the
stored public key. Five minutes rather than one because a machine with a drifting
clock should file late telemetry, not be locked out — and a rejection returns the
server's time so it can correct.

### Events

```json
POST /v1/events
{ "events": [ { "id": "9f2a...", "time": "...", "kind": "shim.start",
                "source": "shim", "version": "1.2.3", "fields": {...} } ] }

200 { "accepted": 1 }
```

| Kind | Meaning |
|---|---|
| `shim.start` | every start, with pending version and boot count |
| `shim.swap` | a staged binary was installed |
| `shim.rollback` | a pending version was abandoned |
| `update.found` | a newer release applies here |
| `update.staged` | downloaded and verified, waiting for the next start |
| `update.rejected` | the pre-install check refused it |
| `update.failed` | download or install failed |
| `update.committed` | the new version reported healthy |
| `update.requires_reinstall` | a release exists that needs a new installer |
| `agent.stale` | below the supported floor; stopping |
| `agent.panic` | recorded before the process died |
| `agent.shutdown` | clean exit |

`id` is per-event so the server can deduplicate. That matters because the log is
cleared only on a 2xx — if an acknowledgement is lost the client resends, and
idempotent ingestion is what makes that safe.

Events are written locally first and delivered after, so a crash on a
disconnected machine still gets reported once it reconnects.

The client doesn't verify the response. It's an acknowledgement; a forged one
changes nothing.

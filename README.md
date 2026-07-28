# Keyhole

Keyhole is a self-hosted password manager for a household or a small team: one
static Go binary, one SQLite file, and a web app the binary itself serves. Item
bodies, names, and URLs are encrypted in the browser under a key derived from
your master password with Argon2id — 64 MiB, 3 iterations, parallelism 4 — and
that password never leaves the device. **The server never holds a key that opens
anything:** what it stores is a wrapped user key it cannot unwrap and a login
hash, derived by a separate HKDF branch, that decrypts nothing.

---

## Install

The installer creates an unprivileged Debian 12 container on a **Proxmox VE**
host, installs a signed release, and ends by printing a setup URL. It must run
as root on the Proxmox node.

> **Not published yet.** No `v1.0.0` tag exists in this repository, so both
> commands below will 404 today. They are written against the tag
> `scripts/install.sh` already pins, and will work once that tag is pushed.

### Download, inspect, run

```bash
curl -fsSLO https://raw.githubusercontent.com/ssan9876/keyhole/v1.0.0/scripts/install.sh
less install.sh          # read it
bash install.sh
```

### One line

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ssan9876/keyhole/v1.0.0/scripts/install.sh)"
```

Piping a script to a shell is the exact risk a password manager exists to defend
against, which is why the two-step is listed first. `bash install.sh --dry-run`
prints every command the script would run and touches nothing; it needs no
Proxmox host, so you can read the whole plan on your laptop.

### Options

Every prompt has a flag, so the script is usable non-interactively.

| Flag | Default |
|---|---|
| `--ctid N` | next free container id |
| `--hostname NAME` | `keyhole` |
| `--cores N` | `2` |
| `--ram MB` | `1024` |
| `--disk GB` | `8` |
| `--storage NAME` | `local-lvm` |
| `--bridge NAME` | `vmbr0` |
| `--network tunnel\|tls\|proxy` | prompt |
| `--tunnel-token-file PATH` | prompted for in tunnel mode, never echoed |
| `--hostname-external NAME` | required by tunnel and proxy modes |
| `--admin-email ADDR` | prompt |
| `--backup-keep N` | `14` snapshots kept by the nightly backup timer |
| `--dry-run` | print the plan, change nothing |
| `--yes` | skip the confirmation |

### The three network modes

- **tunnel** — binds `127.0.0.1:8477`; Cloudflare terminates TLS. Installs
  `cloudflared` and registers it from a token file that is never passed as an
  argument.
- **tls** — binds `0.0.0.0:8477` and terminates TLS itself with a self-signed
  certificate generated on the spot. Prints the certificate's SHA-256
  fingerprint, so the browser warning can be checked against something.
- **proxy** — binds `127.0.0.1:8477` and terminates no TLS; your reverse proxy
  does.

There is no plain-HTTP mode. `window.crypto.subtle` exists only in a secure
context, so on an `http://` origin that is not localhost every AES-GCM call in
the web app throws. That is not a degraded install — it is a vault that cannot
open a single item.

---

## The signing key

Release assets are checksummed into `SHA256SUMS`, and that file is signed with
minisign. `scripts/install.sh` verifies the signature *before* it trusts the
checksums, and `keyhole update` repeats the same two checks against the same
key, which is compiled into every released binary.

To verify a release by hand, download `keyhole-linux-amd64`, `SHA256SUMS`, and
`SHA256SUMS.minisig` from the release page, then:

```bash
minisign -Vm SHA256SUMS -P 'RWQ...replace-with-the-real-key...'
sha256sum -c SHA256SUMS --ignore-missing
```

### This key is a placeholder

**No keypair exists yet.** `RWQ...replace-with-the-real-key...` is a literal
placeholder, not a truncated real key, and nothing will verify against it.

The repository owner must generate the keypair with `minisign -G` and then put
the halves in four places:

| Half | Goes to |
|---|---|
| secret key (contents of `minisign.key`) | GitHub repository secret `MINISIGN_SECRET_KEY` |
| its passphrase | GitHub repository secret `MINISIGN_PASSWORD` |
| public key (the single base64 line, beginning `RW`) | `MINISIGN_PUBKEY` in `scripts/install.sh` |
| the same public key | the two `minisign -Vm` lines above |

Both repository secrets must exist before the first `v*` tag is pushed:
`.github/workflows/release.yml` checks for them in its first step and fails the
run immediately if either is missing, rather than after building everything.

The release workflow derives the public key from the secret key with
`minisign -R` and prints it to the job summary, so after the first release you
can copy it from there and compare it against what is in this file and in
`scripts/install.sh`. All three must match. Until the placeholder is replaced,
`scripts/install.sh` refuses to install anything: an installer that quietly
skips verification is worse than one that does not run at all.

---

## After installing

The installer ends by running `keyhole admin create`, which prints a one-time
setup link:

```
https://<your host>/enroll/<token>
```

1. **Open it.** The link works once and expires in 72 hours. If you lose it,
   `keyhole admin create --email <address>` reissues one for an account that has
   not been set up yet.
2. **Set a master password.** It is turned into a key in your browser and never
   reaches the server, so nobody — including the person with shell access on the
   container — can recover it for you.
3. **Save the recovery code.** It is 25 characters in Crockford Base32 (the
   alphabet omits I, L, O, and U so nothing can be misread), shown in five
   groups of five, and shown exactly once. Read the section below before you
   decide how much weight to put on it.

The vault locks itself after **15 minutes** idle by default. That is a setting
in the app: 1, 5, 15, 30 or 60 minutes, when the tab closes, or never.

---

## Accepted limitations

These are design decisions with known costs, not oversights. From the design
spec, §3.9:

1. **Public-key substitution.** The server distributes public keys; a
   compromised server could substitute its own to intercept *future* shares.
   Mitigated by a comparable fingerprint shown in the UI. Existing shares are
   unaffected.
2. **Web app code delivery.** The server serves the JavaScript that handles the
   master password, so a compromised server could serve malicious code. Inherent
   to all browser-delivered E2EE. The Milestone 2 extension is not subject to
   this, which is an argument for making it the primary desktop client.
3. **Metadata.** Item counts, blob sizes, modification times, collection names,
   and the membership graph are visible to the server and to Cloudflare. Item
   contents, names, and URLs are not.
4. **Endpoint compromise.** No defence against a keylogger or a compromised
   device.

---

## What the recovery code does, and does not do today

The recovery code protects a second copy of your user key: at enrolment the key
is wrapped a second time under a key derived from the code, and that blob is
stored on the server.

**Redeeming it is not implemented.** There is no endpoint that will hand the
recovery blob to someone who cannot already log in. The only recovery-related
endpoint is `POST /api/account/recovery`, which requires a valid session and a
correct master password, and it *rotates* the code rather than redeeming it. So
today the code is a copy of your key waiting for a future release, not a way
back in.

What that means concretely: **if you forget your master password, an
administrator must reset your account.** That reset deletes every personal item
you own and every folder, revokes all your collection memberships, destroys all
your key material, and returns you to a fresh setup link. Items inside shared
collections survive, because other members still hold the collection key —
nothing else does.

This is also stated on the screen that shows you the code. It is here as well
because someone deciding whether to trust this with their passwords should read
it before installing, not after.

---

## Operating

All commands read `/etc/keyhole/config.yml` unless given `--config PATH`.

```bash
keyhole backup [--out DIR] [--keep N]   # snapshot, then prune old snapshots
keyhole restore <file>                  # replace the database with a snapshot
keyhole update                          # verify, install, roll back on failure
keyhole update --check                  # report what is available, install nothing
```

**`keyhole backup`** writes `keyhole-<UTC timestamp>.db` into
`<data_dir>/backups` (override with `--out`) using SQLite's `VACUUM INTO`, so it
does not need the server stopped. It then prunes to the 14 most recent snapshots
(`--keep N`; `--keep 0` keeps them all).

**The installer schedules it.** `scripts/install.sh` writes
`keyhole-backup.service` — a `oneshot` running `keyhole backup` as the `keyhole`
service user, under the same systemd hardening as the server itself — and
`keyhole-backup.timer`, which it enables. The timer is `OnCalendar=daily`, so it
fires at 00:00 in the container's timezone, plus a `RandomizedDelaySec` of up to
30 minutes so that several containers on one host do not all snapshot at once.
It is `Persistent=true`: a container that was powered off overnight takes its
missed backup on the next boot rather than skipping a day silently.

Retention is the installer's `--backup-keep N`, default 14, written into the
unit's `ExecStart` as `--keep N`. To change it afterwards, edit that line in
`/etc/systemd/system/keyhole-backup.service` and run `systemctl daemon-reload`.
To see when it last ran and when it runs next:

```bash
systemctl list-timers keyhole-backup.timer
journalctl -u keyhole-backup
```

An install done by hand rather than by `scripts/install.sh` has no timer; the
two unit files in that script are the whole of the schedule.

**A snapshot is entirely ciphertext.** Item bodies, names, and URLs are
encrypted under keys the server has never held, so replicating a snapshot
somewhere less trusted than the server itself is a reasonable thing to do.

**`keyhole restore`** refuses to run while the database is open by another
process, because replacing the file underneath a running server produces
something that looks like data loss. Stop the service first:

```bash
systemctl stop keyhole && keyhole restore /var/lib/keyhole/backups/keyhole-20260727T120000Z.db
systemctl start keyhole
```

**`keyhole update`** fetches the latest release from this repository — the URL
is compiled in and cannot be pointed elsewhere — verifies the minisign signature
over `SHA256SUMS` and then the binary's checksum, snapshots the database, stops
the service, swaps the binary, runs migrations under the *new* binary, and
restarts. If `/healthz` does not answer within 30 seconds, the binary and the
database are both rolled back automatically, and the rollback is reported with a
non-zero exit status. It refuses to run on a locally built binary, which has no
release to compare against and no public key embedded.

The installer also writes `/usr/local/bin/update` as a shim for
`keyhole update`.

### Where things live

| Path | What |
|---|---|
| `/etc/keyhole/config.yml` | configuration |
| `/var/lib/keyhole/keyhole.db` | the database — ciphertext, plus metadata |
| `/var/lib/keyhole/server.secret` | server secret, written `0600` on first run |
| `/var/lib/keyhole/backups/` | snapshots |
| `/etc/keyhole/tls.crt`, `tls.key` | TLS material, in `tls` mode only |
| `/etc/systemd/system/keyhole.service` | the server unit |
| `/etc/systemd/system/keyhole-backup.{service,timer}` | the nightly backup |

### Configuration

Flat `key: value` lines and `#` comments. Unknown keys are an error rather than
a silent no-op.

| Key | Default |
|---|---|
| `addr` | `127.0.0.1:8477` |
| `data_dir` | `/var/lib/keyhole` |
| `base_url` | `http://localhost:8477` |
| `log_level` | `info` (`debug`, `info`, `warn`, `error`) |
| `tls_cert`, `tls_key` | unset — both or neither, one without the other is an error |

Logs: `journalctl -u keyhole -f`.

---

## Development

```bash
pnpm install
pnpm -r test        # packages/crypto and apps/web
go test ./...
```

The binary embeds the web app, so **the web app must be built before
`go build`** — otherwise you get a server that installs perfectly and serves a
placeholder page for every route:

```bash
pnpm --filter @keyhole/web build
go build ./cmd/keyhole
```

Vite writes its output straight into `internal/webui/dist`, which is what
`//go:embed` picks up, and it does so with `emptyOutDir: true`. That **deletes
the committed `internal/webui/dist/placeholder.html`** on every build. That is
expected: the file is committed only so `go build ./...` compiles on a fresh
clone, where the embed directory would otherwise be empty and match nothing. Put
it back with

```bash
git checkout internal/webui/dist/placeholder.html
```

`.gitignore` un-excludes that one file from the blanket `dist/` rule — the
directory has to be un-excluded first, because once git excludes a directory it
will not look inside it for a later negation, whatever the order of the rules.

For day-to-day web work, `pnpm --filter @keyhole/web dev` runs Vite on port 5173
and proxies `/api` to `http://127.0.0.1:8477`, so run `go run ./cmd/keyhole
serve --config <path>` alongside it. End-to-end tests
(`pnpm --filter @keyhole/web test:e2e`) build and run the real binary against a
real database.

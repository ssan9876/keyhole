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

> **`v1.0.0` is published.** Both commands below fetch the tag
> `scripts/install.sh` pins, and the installer verifies the binary's minisign
> signature against the key in [The signing key](#the-signing-key) before it
> installs anything.

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
| `--network tunnel\|tunnel-remote\|tls\|proxy` | prompt |
| `--tunnel-token-file PATH` | prompted for in tunnel mode, never echoed |
| `--hostname-external NAME` | required by tunnel, tunnel-remote and proxy modes |
| `--admin-email ADDR` | prompt |
| `--backup-keep N` | `14` snapshots kept by the nightly backup timer |
| `--dry-run` | print the plan, change nothing |
| `--yes` | skip the confirmation |

### The four network modes

- **tunnel** — binds `127.0.0.1:8477`; Cloudflare terminates TLS. Installs
  `cloudflared` and registers a *new* tunnel from a token file that is never
  passed as an argument.
- **tunnel-remote** — for a Cloudflare Tunnel you *already* run on another
  container. Installs no `cloudflared` here: it binds `0.0.0.0:8477` and
  terminates no TLS, so the existing `cloudflared` reaches this vault over the
  LAN. You add one Public Hostname in the Zero Trust dashboard pointing at
  `http://<this container's address>:8477`. Because the port is served in the
  clear on the LAN, any host on that segment can reach the vault directly,
  around Cloudflare — the stored data is ciphertext regardless, but a login
  crosses the LAN in the clear, so firewall `8477` to your `cloudflared` host if
  that matters.
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
minisign -Vm SHA256SUMS -P 'RWQaHZz2jLPpRLK2aEj7/A/Rp0QtvRtJj/H8fjePukf3JMGPiyt91Ts6'
sha256sum -c SHA256SUMS --ignore-missing
```

### Cutting a release

The keypair is in place: the public key above and in `scripts/install.sh` is
real, and the secret half lives only in the repository secrets, never in the
tree. Before pushing a `v*` tag:

- **Both `MINISIGN_SECRET_KEY` and `MINISIGN_PASSWORD` must exist as repository
  secrets.** `.github/workflows/release.yml` checks for them before it builds
  anything and fails the run immediately if either is missing.
- **`scripts/install.sh` must pin the tag being released.** The workflow
  refuses to publish while `VERSION` names a different version, so a `v1.1.0`
  release also means updating `VERSION` in that script, the `curl` URLs in its
  header comment, and the two install commands at the top of this file.

The workflow re-derives the public key from the secret with `minisign -R` and
prints it to the job summary. After a release, compare that value against the
key in this file and in `scripts/install.sh` — all three must match.

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
   groups of five, and shown exactly once. It is the only way back in if you
   forget your master password — the section below is exactly what redeeming
   it does.

The vault locks itself after **15 minutes** idle by default. That is a setting
in the app: 1, 5, 15, 30 or 60 minutes, when the tab closes, or never.

---

## Install to your home screen

Keyhole is an installable web app. Use the browser's *Install* or *Add to Home
Screen* prompt to add it to a phone or desktop home screen, where it opens in
its own window and **loads without a network** — a manifest and a service worker
cache the app shell, so a cold offline launch reaches the unlock screen instead
of a browser error page.

The **vault still needs a connection.** Keyhole deliberately keeps nothing
decryptable — and nothing about your vault at all, including any on-disk cache —
on the device: the service worker never stores vault data, not in IndexedDB and
not in the browser cache. That is the point, not a shortcoming. A memory-only
session is what makes a lost or stolen device yield nothing, so the vault syncs
fresh when you connect and exists only in memory while unlocked. Keyhole installs
and loads offline; it does not read your vault offline.

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

## What the recovery code does

The recovery code protects a second copy of your user key: at enrolment the key
is wrapped a second time under a key derived from the code, and that blob is
stored on the server.

**Redeeming it works.** On the unlock screen, *Forgot your master password?*
asks for your email address and the code, and then for a new master password.
Everything is derived in your browser. The code itself never leaves it: the
server is sent only the authentication half of the key derived from it — which
cannot open the recovery blob — and stores only a hash of that.

Redeeming it:

- **replaces your master password** with the new one you type;
- **issues a new recovery code**, shown once — the old one stops working, so a
  code you suspect someone else has read is worth redeeming for that reason
  alone;
- **signs out every device**, everywhere, including any session the person who
  may have read the old code was holding;
- **leaves your vault exactly as it was.** The same user key is re-wrapped
  under the new password, so no item, folder, or collection membership is
  touched, and nothing has to be re-encrypted.

You have ten minutes between the code being accepted and the new password being
set, and the token that spans that gap can be spent only once.

A refusal is deliberately uninformative. An unknown address, a wrong code, a
disabled account, and an account whose code cannot be redeemed all produce the
same answer, so that this page cannot be used to find out who has an account on
your server. Attempts are rate-limited on the same budget as failed logins,
deliberately — a code and a password are two guesses at one account: the fifth
failure for an address, or from a source address, starts a two-second delay
that doubles with every failure after it, up to five minutes.

**Codes issued by an older Keyhole cannot be redeemed.** Redemption needs a
hash the server did not store before this release (migration `0004`, which
leaves `recovery_auth_hash` NULL for accounts enrolled earlier), and the
endpoints treat a NULL there exactly like an unknown address — so an old code
fails with the same message a wrong one gets. If your account predates this
release, open **Settings → Recovery code → New recovery code**, which asks for
your master password and issues one that can be redeemed. Do it before you need
it.

**If you lose the code as well as the password, an administrator must reset
your account.** That reset deletes every personal item you own and every
folder, revokes all your collection memberships, destroys all your key
material, and returns you to a fresh setup link. Items inside shared
collections survive, because other members still hold the collection key —
nothing else does.

The screen that shows you the code says most of this too. It is here as well
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

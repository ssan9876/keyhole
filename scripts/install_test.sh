#!/usr/bin/env bash
#
# Tests for scripts/install.sh.
#
# The installer cannot be exercised for real anywhere but a Proxmox host, so
# --dry-run is the seam: it prints every command the script would run and
# executes none of them. Everything below is an assertion about that plan.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
check() {
  local name="$1" golden="$2"; shift 2
  if ! diff -u "$golden" <("$@" 2>&1); then
    echo "FAIL: $name"; fail=1
  else
    echo "ok: $name"
  fi
}

check "tunnel mode plan" scripts/testdata/dry-run-tunnel.golden \
  bash scripts/install.sh --dry-run --yes --ctid 200 --network tunnel \
    --hostname-external vault.example.com --admin-email me@example.com \
    --tunnel-token-file /dev/null

check "tls mode plan" scripts/testdata/dry-run-lan.golden \
  bash scripts/install.sh --dry-run --yes --ctid 200 --network tls \
    --admin-email me@example.com

check "tunnel-remote mode plan" scripts/testdata/dry-run-tunnel-remote.golden \
  bash scripts/install.sh --dry-run --yes --ctid 200 --network tunnel-remote \
    --hostname-external vault.example.com --admin-email me@example.com

# The plan must never contain a secret, whatever mode produced it.
#
# The plan is captured into a variable and matched with a bash `case` rather
# than piped into `grep -q`. That is not style. `grep -q` exits the moment it
# matches, the producer on the left of the pipe then dies of EPIPE, and under
# `set -o pipefail` the pipeline reports *that* failure — so the `if` takes its
# else branch and the assertion prints "ok" precisely when the token leaked.
# Written as a pipeline this check cannot fail, in either direction.
token_file="$(mktemp)"
printf 'super-secret-token' > "$token_file"
leak_plan=""
if ! leak_plan="$(bash scripts/install.sh --dry-run --yes --ctid 200 --network tunnel \
                    --hostname-external v.example.com --admin-email me@example.com \
                    --tunnel-token-file "$token_file" 2>&1)"; then
  echo "FAIL: the tunnel dry run did not exit 0"; fail=1
fi
case "$leak_plan" in
  *super-secret-token*)
    echo "FAIL: the dry-run plan leaked the tunnel token"; fail=1 ;;
  *)
    echo "ok: no token in the plan" ;;
esac
rm -f "$token_file"

# tunnel-remote: Keyhole sits behind a Cloudflare Tunnel that is already running
# on another container, so this mode installs no cloudflared of its own. It has
# to bind the LAN rather than loopback — the connector reaches it over the
# bridge, not through 127.0.0.1 — and it must not pull cloudflared in the way
# `tunnel` mode does. Both are asserted here directly, not only through the
# golden, so a careless golden regeneration cannot quietly turn this mode back
# into a second local tunnel or a loopback bind nothing off-box can reach.
remote_plan=""
if ! remote_plan="$(bash scripts/install.sh --dry-run --yes --ctid 200 \
                      --network tunnel-remote --hostname-external vault.example.com \
                      --admin-email me@example.com 2>&1)"; then
  echo "FAIL: the tunnel-remote dry run did not exit 0"; fail=1
fi
case "$remote_plan" in
  *"addr: 0.0.0.0:8477"*)
    echo "ok: tunnel-remote binds the LAN, not loopback" ;;
  *)
    echo "FAIL: tunnel-remote does not bind 0.0.0.0:8477 (an off-box connector cannot reach loopback)"; fail=1 ;;
esac
# The install action is what this mode must not do, not the word: the closing
# help is free to name cloudflared. `tunnel` mode's two telltales are the apt
# install and `cloudflared service install`; neither may appear here.
case "$remote_plan" in
  *"cloudflared service install"* | *"--no-install-recommends cloudflared"*)
    echo "FAIL: tunnel-remote installs cloudflared (it must reuse the existing off-box tunnel)"; fail=1 ;;
  *)
    echo "ok: tunnel-remote installs no cloudflared of its own" ;;
esac
case "$remote_plan" in
  *"Public Hostname"*)
    echo "ok: tunnel-remote tells the operator which Public Hostname to add" ;;
  *)
    echo "FAIL: tunnel-remote's closing instructions never mention adding a Public Hostname"; fail=1 ;;
esac

# keyhole is run inside the container by absolute path, never bare.
#
# `pct exec CT -- keyhole ...` resolves the name through lxc-attach's PATH,
# which does not include /usr/local/bin — so a bare `keyhole` dies on a real
# host with 'No such file or directory - Failed to exec "keyhole"' the instant
# the binary lands there, while every dry-run golden still looks perfect
# (--dry-run execs nothing). The systemd unit and the update shim already use
# the absolute path; the two bootstrap steps must too.
plan_paths="$(bash scripts/install.sh --dry-run --yes --ctid 200 --network tls \
  --admin-email me@example.com 2>&1)"
case "$plan_paths" in
  *"pct exec 200 -- keyhole "*)
    echo "FAIL: migrate/other step runs keyhole by bare name (pct exec PATH omits /usr/local/bin)"; fail=1 ;;
  *"/usr/local/bin/keyhole migrate"*)
    echo "ok: migrate runs keyhole by absolute path" ;;
  *)
    echo "FAIL: no keyhole migrate step found in the plan"; fail=1 ;;
esac
case "$plan_paths" in
  *"runuser -u keyhole -- /usr/local/bin/keyhole admin create"*)
    echo "ok: admin create runs keyhole by absolute path" ;;
  *)
    echo "FAIL: admin create does not run /usr/local/bin/keyhole (bare name fails under pct exec)"; fail=1 ;;
esac
# The update shim lives in /usr/local/bin too, and the closing help tells the
# operator to run it via pct exec — so it has the same bare-name problem.
case "$plan_paths" in
  *"pct exec 200 -- update"*)
    echo "FAIL: the documented update command is a bare name (fails under pct exec PATH)"; fail=1 ;;
  *"pct exec 200 -- /usr/local/bin/update"*)
    echo "ok: the documented update command uses an absolute path" ;;
  *)
    echo "FAIL: the closing help no longer documents the update command"; fail=1 ;;
esac

# ...but that assertion only inspects the plan, and the plan is produced by a
# hand-written printf in push_tunnel_token rather than by the code that moves
# the secret. The two branches are separate code, so the check above is blind to
# the one that matters: rewrite the real branch as
#
#   pct exec "$CTID" -- sh -c "echo $TUNNEL_TOKEN > '${TUNNEL_TOKEN_PATH}'"
#
# and the token is in the container's argv and visible in ps on the host, while
# the dry-run branch still prints "not shown" and every assertion above passes.
#
# So pin the source instead: the host's copy of the token may be expanded in
# exactly two places, and nowhere else. Escaped \$TUNNEL_TOKEN does not count —
# that is the container's own variable inside a quoted command string, read from
# the file rather than carried from here, which is the whole design.
expected_token_expansions="$(cat <<'EXPECTED'
if [ "$DRY_RUN" != "yes" ] && [ -z "$TUNNEL_TOKEN" ]; then
printf '%s' "$TUNNEL_TOKEN" | pct exec "$CTID" -- sh -c "umask 077; cat > '${TUNNEL_TOKEN_PATH}'"
EXPECTED
)"
actual_token_expansions="$(grep -hE '(^|[^\\])\$\{?TUNNEL_TOKEN\}?([^_A-Za-z0-9]|$)' \
  scripts/install.sh | sed 's/^[[:space:]]*//')"
if [ "$expected_token_expansions" = "$actual_token_expansions" ]; then
  echo "ok: the tunnel token is expanded only in the emptiness guard and the printf producer"
else
  echo "FAIL: \$TUNNEL_TOKEN is expanded somewhere it was not before"
  printf '%s\n' "$expected_token_expansions" | sed 's/^/  want: /'
  printf '%s\n' "$actual_token_expansions" | sed 's/^/  got:  /'
  fail=1
fi

# The one that would actually hurt, named separately so the failure says why:
# the token must never be interpolated into a command line, where it lands in
# the process table and in the shell history of whoever typed it. The producer
# above passes because its expansion is on the left of the pipe, not inside the
# pct exec argument list.
if grep -qE 'pct exec.*[^\\]\$\{?TUNNEL_TOKEN\}?([^_A-Za-z0-9]|$)' scripts/install.sh; then
  echo "FAIL: the tunnel token is interpolated into a pct exec command line (visible in ps)"; fail=1
else
  echo "ok: the token never reaches a pct exec argument"
fi

# And the two doors it comes in by: a file, or a prompt that does not echo.
if grep -qE '^[[:space:]]*TUNNEL_TOKEN="\$\(tr -d .* < "\$TUNNEL_TOKEN_FILE"\)"' scripts/install.sh; then
  echo "ok: the token file is read into the variable"
else
  echo "FAIL: the tunnel token file is no longer read the way this test expects"; fail=1
fi
if grep -qE '^[[:space:]]*IFS= read -rs TUNNEL_TOKEN' scripts/install.sh; then
  echo "ok: the prompted token is read with -s, so it is never echoed"
else
  echo "FAIL: the tunnel token prompt no longer reads with -s (it would echo the token)"; fail=1
fi

# An unknown flag must stop, not proceed with a silently ignored option.
#
# Every other flag here is present and valid, so the only thing that can make
# this invocation fail is --nonsense. That matters: the obvious version of this
# assertion, `install.sh --dry-run --yes --nonsense`, passes even against a
# parser that ignores unknown flags — dropping --nonsense also drops nothing
# else, --network is then unset, the script reaches its interactive prompt,
# read hits EOF, and it exits 1. Non-zero for a reason that has nothing to do
# with the flag, which is the exact failure the check exists to catch.
unknown_flag_output="$(bash scripts/install.sh --dry-run --yes --ctid 200 \
  --network tls --admin-email me@example.com --nonsense 2>&1)" && unknown_rc=0 || unknown_rc=$?
if [ "$unknown_rc" -eq 0 ]; then
  echo "FAIL: an unknown flag was accepted"; fail=1
elif ! printf '%s\n' "$unknown_flag_output" | grep -q -- '--nonsense'; then
  echo "FAIL: it stopped, but not because of the unknown flag (no --nonsense in the message)"; fail=1
else
  echo "ok: unknown flag rejected"
fi

# The runtime placeholder-refusal assertion lived here until the real signing
# key was filled in (2026-07-29). It ran install.sh without --dry-run and
# checked that check_signing_key aborts on a placeholder key. With a real key
# there is no refusal left to reach, so it became untestable and was removed;
# check_signing_key itself still guards a fork that forgets the key, and the
# static "not a placeholder" check at the bottom of this file keeps this repo's
# own key from silently reverting.

# Both halves of the supply-chain check must be in the plan, and the signature
# must be checked before the checksums are. sha256sum -c on its own proves only
# that the binary matches a SHA256SUMS file that arrived over the same
# connection as the binary; it is the minisign verification of SHA256SUMS that
# makes the checksum mean anything. Dropping `minisign -V` and keeping
# `sha256sum -c` leaves an installer that looks like it verifies and does not,
# and no other assertion here notices.
plan=""
if ! plan="$(bash scripts/install.sh --dry-run --yes --ctid 200 --network tls \
               --admin-email me@example.com)"; then
  echo "FAIL: the tls dry run did not exit 0"; fail=1
fi
minisign_line="$(printf '%s\n' "$plan" | grep -n -m1 -- 'minisign -Vm' | cut -d: -f1 || true)"
sha256_line="$(printf '%s\n' "$plan" | grep -n -m1 -- 'sha256sum -c' | cut -d: -f1 || true)"
if [ -z "$minisign_line" ]; then
  echo "FAIL: the plan never verifies the signature (no 'minisign -Vm')"; fail=1
else
  echo "ok: the plan verifies the signature"
fi
if [ -z "$sha256_line" ]; then
  echo "FAIL: the plan never checks the checksums (no 'sha256sum -c')"; fail=1
else
  echo "ok: the plan checks the checksums"
fi
if [ -n "$minisign_line" ] && [ -n "$sha256_line" ]; then
  if [ "$minisign_line" -lt "$sha256_line" ]; then
    echo "ok: the signature is verified before the checksums are trusted"
  else
    echo "FAIL: sha256sum -c comes before minisign -Vm in the plan"; fail=1
  fi
fi

# A failed verification must stop the container, not merely exit.
#
# This is a source-level assertion, and deliberately so: it is a proxy for a
# branch no dry run can reach. All three verification-failure sites sit behind
# `if ! in_ct ...`, in_ct goes through run(), and run() returns 0 without
# running anything when DRY_RUN=yes — so the failure branch never executes and
# abort_stopped's output appears in neither golden. Replacing all three calls
# with a plain `die` leaves a running, half-provisioned container after a
# signature verification failure — exactly what the comment above abort_stopped
# forbids — and every other assertion in this file still passes.
#
# Each site is matched by its full call line, so swapping one for `die` while
# keeping the message is caught too.
while IFS='|' read -r what site; do
  if grep -qF -- "$site" scripts/install.sh; then
    echo "ok: a failed ${what} stops the container"
  else
    echo "FAIL: the ${what} failure site no longer calls abort_stopped (looked for: $site)"; fail=1
  fi
done <<'SITES'
download|abort_stopped "downloading ${VERSION} failed"
signature verification|abort_stopped "the minisign signature over SHA256SUMS did not verify against the key in this script"
checksum check|abort_stopped "the downloaded binary does not match its signed checksum"
SITES

# ...and abort_stopped has to actually stop it. A version of that function that
# only printed would satisfy the three assertions above and stop nothing.
#
# Comments are stripped first. The first version of this check looked for the
# string "pct stop" anywhere in the function body and passed against a body
# whose `run pct stop` had been replaced with `run true` — because the words
# "pct stop" survive in the comment and in the failure message. A check a
# comment can satisfy is not a check.
abort_body="$(awk '/^abort_stopped\(\) \{/{f=1} f{print} f && /^\}/{exit}' scripts/install.sh \
  | grep -v '^[[:space:]]*#')"
if printf '%s\n' "$abort_body" | grep -qE 'run pct stop "\$\{?CTID\}?"'; then
  echo "ok: abort_stopped runs pct stop on the container"
else
  echo "FAIL: abort_stopped no longer runs pct stop (its body has no 'run pct stop \"\$CTID\"')"; fail=1
fi

# The nightly backup: §8.3 asks for a timer with configurable retention, and
# `keyhole backup` alone is only half of it. Both goldens cover the default, so
# what is asserted here is the part they cannot see — that --backup-keep is
# threaded through to the unit rather than a constant printed next to a flag
# that goes nowhere.
#
# 5 rather than 14 for exactly that reason: a hard-coded ExecStart still matches
# a plan generated with the default, and this suite would say so.
backup_plan=""
if ! backup_plan="$(bash scripts/install.sh --dry-run --yes --ctid 200 --network tls \
                      --admin-email me@example.com --backup-keep 5 2>&1)"; then
  echo "FAIL: the --backup-keep dry run did not exit 0"; fail=1
fi

# Matched with `case` rather than `grep -q` for the reason spelled out above the
# token-leak check: under `set -o pipefail` a pipeline into `grep -q` reports the
# producer's EPIPE, so the assertion inverts.
case "$backup_plan" in
  *"cat > '/etc/systemd/system/keyhole-backup.service'"*)
    echo "ok: the plan writes keyhole-backup.service" ;;
  *)
    echo "FAIL: the plan never writes /etc/systemd/system/keyhole-backup.service"; fail=1 ;;
esac
case "$backup_plan" in
  *"cat > '/etc/systemd/system/keyhole-backup.timer'"*)
    echo "ok: the plan writes keyhole-backup.timer" ;;
  *)
    echo "FAIL: the plan never writes /etc/systemd/system/keyhole-backup.timer"; fail=1 ;;
esac

# The timer is what has to be enabled, not the oneshot it triggers. Enabling
# keyhole-backup.service instead schedules nothing: it runs once at boot and
# never again, and every other assertion here still passes.
case "$backup_plan" in
  *"RUN: pct exec 200 -- systemctl enable --now keyhole-backup.timer"*)
    echo "ok: the plan enables the timer" ;;
  *)
    echo "FAIL: the plan does not enable keyhole-backup.timer"; fail=1 ;;
esac

case "$backup_plan" in
  *"ExecStart=/usr/local/bin/keyhole backup --config /etc/keyhole/config.yml --keep 5"*)
    echo "ok: --backup-keep reaches the unit's ExecStart" ;;
  *)
    echo "FAIL: --backup-keep 5 did not reach keyhole-backup.service's ExecStart"; fail=1 ;;
esac
# ...and the default it was given instead of must be gone, or "threaded through"
# means an ExecStart with two --keep flags on it.
case "$backup_plan" in
  *"--keep 14"*)
    echo "FAIL: the unit still carries the default --keep 14 after --backup-keep 5"; fail=1 ;;
  *)
    echo "ok: --backup-keep replaces the default rather than adding to it" ;;
esac

# A non-numeric retention would be interpolated straight into ExecStart, where
# systemd loads the unit happily and the job fails every night in the journal.
backup_keep_output="$(bash scripts/install.sh --dry-run --yes --ctid 200 --network tls \
  --admin-email me@example.com --backup-keep nightly 2>&1)" && backup_keep_rc=0 || backup_keep_rc=$?
if [ "$backup_keep_rc" -eq 0 ]; then
  echo "FAIL: a non-numeric --backup-keep was accepted"; fail=1
elif ! printf '%s\n' "$backup_keep_output" | grep -q -- '--backup-keep'; then
  echo "FAIL: it stopped, but not because of --backup-keep (no mention of it in the message)"; fail=1
else
  echo "ok: a non-numeric --backup-keep is rejected"
fi

# The pinned version and key must be real values, not placeholders.
grep -q 'OWNER="ssan9876"' scripts/install.sh || { echo "FAIL: OWNER"; fail=1; }
grep -qE '^VERSION="v[0-9]+\.[0-9]+\.[0-9]+"' scripts/install.sh || { echo "FAIL: VERSION not a pinned tag"; fail=1; }
grep -q 'raw.githubusercontent.com/ssan9876/keyhole/main' scripts/install.sh && { echo "FAIL: a URL points at main"; fail=1; }
# Scoped to the key line itself: the word "replace-with-the-real-key" also
# lives in the file's comment and in is_placeholder_key's pattern, so an
# unscoped grep would flag a real key as a placeholder.
if grep -qE '^readonly MINISIGN_PUBKEY="RW[A-Za-z0-9+/]{54}"$' scripts/install.sh; then
  echo "ok: MINISIGN_PUBKEY is a real minisign public key"
elif grep -qE '^readonly MINISIGN_PUBKEY=".*replace-with-the-real-key' scripts/install.sh; then
  echo "FAIL: MINISIGN_PUBKEY is still the placeholder"; fail=1
else
  echo "FAIL: MINISIGN_PUBKEY is neither the placeholder nor a well-formed key"; fail=1
fi

exit "$fail"

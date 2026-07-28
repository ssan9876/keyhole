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

# An installer that silently skips verification because nobody filled in the
# signing key is the worst outcome this file has, and it is the one thing here
# that a real run must refuse outright rather than warn about.
#
# This is the only assertion in the suite that runs install.sh *without*
# --dry-run, and it is only testable on a machine with no Proxmox on it because
# of the ordering main() already chose: check_signing_key runs before
# require_pve, precisely so the operator hears about a placeholder key wherever
# they are reading the script. Reorder those two and this invocation dies of
# "this must run on a Proxmox VE host" instead — non-zero, but for the wrong
# reason, which is why the message is asserted and not just the exit status.
placeholder_output="$(bash scripts/install.sh --yes --ctid 200 --network tls \
  --admin-email me@example.com 2>&1)" && placeholder_rc=0 || placeholder_rc=$?
if [ "$placeholder_rc" -eq 0 ]; then
  echo "FAIL: the installer ran to completion with a placeholder signing key"; fail=1
elif ! printf '%s\n' "$placeholder_output" | grep -q 'placeholder'; then
  echo "FAIL: it refused, but not because of the placeholder key (no 'placeholder' in the message)"; fail=1
else
  echo "ok: a real run refuses a placeholder signing key"
fi

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

# The pinned version and key must be real values, not placeholders.
grep -q 'OWNER="ssan9876"' scripts/install.sh || { echo "FAIL: OWNER"; fail=1; }
grep -qE '^VERSION="v[0-9]+\.[0-9]+\.[0-9]+"' scripts/install.sh || { echo "FAIL: VERSION not a pinned tag"; fail=1; }
grep -q 'raw.githubusercontent.com/ssan9876/keyhole/main' scripts/install.sh && { echo "FAIL: a URL points at main"; fail=1; }

exit "$fail"

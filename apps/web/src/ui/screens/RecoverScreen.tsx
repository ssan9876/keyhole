import { useState } from "react";
import type { FormEvent } from "react";
import { WrongRecoveryCodeError } from "../../vault/recover.js";
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";
import { describeFailure } from "../errors.js";

export interface RecoverScreenProps {
  /** Prefilled, not substituted for the field: recovery is the one screen most
   *  likely to be reached from a device whose localStorage remembers nothing. */
  rememberedEmail: string | null;
  /** Proves possession of the code and opens the recovery blobs. Rejects with
   *  `WrongRecoveryCodeError` for a refusal and with the vault layer's own
   *  failures for anything else. */
  onRedeemCode(input: { email: string; recoveryCode: string }): Promise<void>;
  /** Rotates both credentials and resolves with the *new* recovery code, which
   *  is shown once and then gone. */
  onSetNewPassword(newMasterPassword: string): Promise<string>;
  onFinish(): void;
  onCancel(): void;
}

/**
 * Copy for a failed redemption, per design spec §9: three outcomes, three
 * sentences.
 *
 * `WrongRecoveryCodeError` is neither an `ApiError` nor a `NetworkError` — the
 * vault layer raises it for the one status (401) that actually means "wrong" —
 * so `describeFailure` alone would drop it to the fallback and every failure on
 * this screen would read the same. That is the whole distinction this screen has
 * to make: a wrong code sends the user hunting for a piece of paper, an
 * unreachable server sends them to check their connection, and a 500 is neither
 * of their faults.
 */
function describeRedemptionFailure(failure: unknown): string {
  if (failure instanceof WrongRecoveryCodeError) return failure.message;
  // ApiError and NetworkError verbatim; anything else falls through to a
  // sentence that blames neither the code nor the connection.
  return describeFailure(failure, "Could not start the recovery");
}

const CODE_PANEL_STYLE = {
  fontFamily: "var(--font-mono)",
  fontSize: "1.125rem",
  padding: "var(--space-4)",
  border: "1px solid var(--rule-strong)",
  margin: "var(--space-6) 0",
} as const;

/**
 * Redeeming a recovery code, in three steps and one screen: email + code, then
 * a new master password, then the new recovery code the rotation issued.
 *
 * Presentational, in the shape the last three screens settled on — every call
 * that touches key material or the network arrives as a prop from
 * `useRecoverScreen`. What it does own is the copy, the acknowledgement gate,
 * and the mismatch check, which has to happen here because it has to happen
 * before the first Argon2id pass.
 */
export function RecoverScreen({
  rememberedEmail,
  onRedeemCode,
  onSetNewPassword,
  onFinish,
  onCancel,
}: RecoverScreenProps) {
  const [email, setEmail] = useState(rememberedEmail ?? "");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [redeemed, setRedeemed] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [newCode, setNewCode] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submitCode(event: FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onRedeemCode({ email, recoveryCode });
      setRedeemed(true);
      // Spent: the server has issued a one-time token and this string opens
      // nothing else. Keeping it in state would leave it on screen behind a
      // browser's back button for no benefit at all.
      setRecoveryCode("");
    } catch (failure) {
      setError(describeRedemptionFailure(failure));
    } finally {
      setBusy(false);
    }
  }

  async function submitNewPassword(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    // Before anything expensive. completeRecovery derives two Argon2id hashes
    // at ~0.5s each by design, and making someone wait out both to be told they
    // mistyped the confirmation is gratuitous — the same reasoning, and the
    // same ordering, as SettingsScreen's master-password form.
    if (newPassword !== confirm) {
      setError("The new password and confirmation do not match");
      return;
    }
    setBusy(true);
    try {
      const issued = await onSetNewPassword(newPassword);
      setNewCode(issued);
      setNewPassword("");
      setConfirm("");
    } catch (failure) {
      setError(describeFailure(failure, "Could not set the new master password"));
    } finally {
      setBusy(false);
    }
  }

  if (newCode !== null) {
    return (
      <main style={{ maxWidth: "28rem", margin: "0 auto", padding: "var(--space-8) var(--space-4)" }}>
        <h1 style={{ fontSize: "1.25rem", fontWeight: 600 }}>Save your new recovery code</h1>
        <p style={{ color: "var(--ink-muted)" }}>
          Your old code no longer works. Save this one somewhere safe and
          offline: it is shown once and cannot be recovered afterwards &mdash;
          not by an administrator, and not by anyone with the database.
        </p>
        <p style={CODE_PANEL_STYLE}>{newCode}</p>
        <label style={{ display: "flex", gap: "var(--space-2)", marginBottom: "var(--space-6)" }}>
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
          />
          I have saved this code somewhere safe
        </label>
        {/* Gated deliberately, exactly as EnrolScreen and SettingsScreen gate
            the same dialog: clicking past it leaves a vault whose only second
            way in was just replaced by something nobody wrote down. */}
        <Button
          type="button"
          disabled={!acknowledged}
          onClick={() => {
            // Cleared here rather than left to a parent unmount. That exact bug
            // — the code surviving in this component's state after the user had
            // moved on, re-renderable — shipped in EnrolScreen once and had to
            // be fixed.
            setNewCode(null);
            setAcknowledged(false);
            onFinish();
          }}
        >
          Continue to my vault
        </Button>
      </main>
    );
  }

  if (redeemed) {
    return (
      <main style={{ maxWidth: "22rem", margin: "0 auto", padding: "var(--space-8) var(--space-4)" }}>
        <h1 style={{ fontSize: "1.25rem", fontWeight: 600, marginBottom: "var(--space-4)" }}>
          Set a new master password
        </h1>
        <p style={{ color: "var(--ink-muted)", marginBottom: "var(--space-4)" }}>
          Choose it as carefully as the first one. It is turned into a key in
          this browser and never reaches the server, so nobody can recover it
          for you.
        </p>
        <form onSubmit={(e) => void submitNewPassword(e)}>
          <Field
            label="New master password"
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
          />
          <Field
            label="Confirm new master password"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
          />
          {error !== null && (
            <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
              {error}
            </p>
          )}
          <Button type="submit" disabled={busy}>
            {busy ? "Setting…" : "Set new master password"}
          </Button>
        </form>
      </main>
    );
  }

  return (
    <main style={{ maxWidth: "22rem", margin: "0 auto", padding: "var(--space-8) var(--space-4)" }}>
      <h1 style={{ fontSize: "1.25rem", fontWeight: 600, marginBottom: "var(--space-4)" }}>
        Recover your vault
      </h1>
      {/* Both consequences stated before the form, not after it: neither is
          guessable from a page that only asks for a code, and both are
          irreversible. The vault contents are untouched because the key inside
          the recovery blob is the same userKey — only its wrapping changes. */}
      <p style={{ color: "var(--ink-muted)", marginBottom: "var(--space-4)" }}>
        Redeeming your recovery code replaces your master password with a new
        one and signs out every other device. Everything in your vault stays
        exactly where it is &mdash; nothing is re-encrypted and nothing is lost.
      </p>
      <p style={{ color: "var(--ink-muted)", marginBottom: "var(--space-4)" }}>
        A wrong code, an address with no account here, and an account with no
        usable recovery code are all answered identically, on purpose: this page
        cannot be used to find out who has an account on this server. So a
        refusal below cannot tell you which of those it was.
      </p>
      <form onSubmit={(e) => void submitCode(e)}>
        <Field
          label="Email"
          type="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <Field
          label="Recovery code"
          type="text"
          autoComplete="off"
          spellCheck={false}
          value={recoveryCode}
          onChange={(e) => setRecoveryCode(e.target.value)}
          required
        />
        {error !== null && (
          <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
            {error}
          </p>
        )}
        <div style={{ display: "flex", gap: "var(--space-2)" }}>
          {/* Disabled while working, same as UnlockScreen: this endpoint shares
              its rate-limit budget with login (a code and a password are two
              guesses at one account), so an impatient double-click spends two
              of five free attempts. */}
          <Button type="submit" disabled={busy}>
            {busy ? "Checking…" : "Continue"}
          </Button>
          <Button type="button" variant="quiet" onClick={onCancel}>
            Back to unlocking
          </Button>
        </div>
      </form>
    </main>
  );
}

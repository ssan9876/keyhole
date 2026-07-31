import { useState } from "react";
import type { FormEvent } from "react";
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";
import { Keyhole } from "../components/icons.js";

interface EnrolScreenProps {
  inviteToken: string;
  onEnrol(input: {
    inviteToken: string;
    email: string;
    masterPassword: string;
  }): Promise<{ recoveryCode: string }>;
  onFinish(): void;
}

export function EnrolScreen({ inviteToken, onEnrol, onFinish }: EnrolScreenProps) {
  const [email, setEmail] = useState("");
  const [masterPassword, setMasterPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (masterPassword !== confirm) {
      // A typo here is unrecoverable: the vault would be encrypted under a
      // password nobody knows, and the server cannot help, by design.
      setError("The passwords do not match");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const outcome = await onEnrol({ inviteToken, email, masterPassword });
      setRecoveryCode(outcome.recoveryCode);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not set up the account");
    } finally {
      setBusy(false);
    }
  }

  if (recoveryCode !== null) {
    return (
      <main className="kh-auth kh-auth-wide">
        <p className="kh-auth-mark">
          <Keyhole size={14} /> Keyhole
        </p>
        <h1 className="kh-auth-title">Save your recovery code</h1>
        <p className="kh-muted">
          Save this somewhere safe and offline. It is shown once and cannot be
          recovered afterwards &mdash; not by an administrator, and not by
          anyone with the database.
        </p>
        <p className="kh-muted">
          If you forget your master password, this code is what gets you back
          in: redeeming it sets a new password, signs out every other device,
          and leaves every item in your vault exactly as it is. Without it, an
          administrator can only reset the account, which deletes your personal
          items and folders and drops you from every collection you are in.
        </p>
        {/* The one piece of text on any screen that has to be copied by hand:
            monospace, tabular, and given the room to be read a character at a
            time. */}
        <p className="kh-code kh-code-hero">{recoveryCode}</p>
        <label className="kh-check">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
          />
          I have saved this code somewhere safe
        </label>
        {/* Gated deliberately. Letting someone click past this hands them a
            vault with no second way in, silently. */}
        <Button
          type="button"
          block
          disabled={!acknowledged}
          onClick={() => {
            // Clear it here, not just rely on the parent unmounting this
            // screen: the code must not still be sitting in this component's
            // state (and so re-renderable) after the user has moved on.
            setRecoveryCode(null);
            onFinish();
          }}
        >
          Continue to my vault
        </Button>
      </main>
    );
  }

  return (
    <main className="kh-auth">
      <p className="kh-auth-mark">
        <Keyhole size={14} /> Keyhole
      </p>
      <h1 className="kh-auth-title">Set your master password</h1>
      <p className="kh-auth-lede">
        This password encrypts your vault. Nobody can reset it for you, so pick
        something long and memorable.
      </p>
      <form onSubmit={submit}>
        <Field
          label="Email"
          type="email"
          autoComplete="username"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <Field
          label="Master password"
          type="password"
          autoComplete="new-password"
          value={masterPassword}
          onChange={(e) => setMasterPassword(e.target.value)}
          required
        />
        <Field
          label="Confirm master password"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
        />
        {error !== null && (
          <p role="alert" className="kh-alert">
            {error}
          </p>
        )}
        <Button type="submit" block disabled={busy}>
          {busy ? "Setting up…" : "Set master password"}
        </Button>
      </form>
    </main>
  );
}

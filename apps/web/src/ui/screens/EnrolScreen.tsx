import { useState } from "react";
import type { FormEvent } from "react";
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";

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
      <main style={{ maxWidth: "28rem", margin: "0 auto", padding: "var(--space-8) var(--space-4)" }}>
        <h1 style={{ fontSize: "1.25rem", fontWeight: 600 }}>Save your recovery code</h1>
        <p style={{ color: "var(--ink-muted)" }}>
          Save this somewhere safe and offline. It is shown once and cannot be
          recovered afterwards &mdash; not by an administrator, and not by
          anyone with the database.
        </p>
        <p style={{ color: "var(--ink-muted)" }}>
          Note: redeeming this code is not built yet. Today it protects a copy
          of your key for a future release; it will not currently get you back
          into a vault whose master password you have forgotten.
        </p>
        <p
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "1.125rem",
            padding: "var(--space-4)",
            border: "1px solid var(--rule-strong)",
            margin: "var(--space-6) 0",
          }}
        >
          {recoveryCode}
        </p>
        <label style={{ display: "flex", gap: "var(--space-2)", marginBottom: "var(--space-6)" }}>
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
    <main style={{ maxWidth: "22rem", margin: "0 auto", padding: "var(--space-8) var(--space-4)" }}>
      <h1 style={{ fontSize: "1.25rem", fontWeight: 600, marginBottom: "var(--space-6)" }}>
        Set your master password
      </h1>
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
          <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
            {error}
          </p>
        )}
        <Button type="submit" disabled={busy}>
          {busy ? "Setting up…" : "Set master password"}
        </Button>
      </form>
    </main>
  );
}

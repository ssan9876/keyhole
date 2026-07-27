import { useState } from "react";
import type { FormEvent } from "react";
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";

interface UnlockScreenProps {
  rememberedEmail: string | null;
  onUnlock(input: { email: string; masterPassword: string }): Promise<void>;
}

export function UnlockScreen({ rememberedEmail, onUnlock }: UnlockScreenProps) {
  const [email, setEmail] = useState(rememberedEmail ?? "");
  const [masterPassword, setMasterPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onUnlock({ email, masterPassword });
    } catch (failure) {
      // The message is produced by the vault layer, which already distinguishes
      // a wrong password from an unreachable server. This only renders it.
      setError(failure instanceof Error ? failure.message : "Could not unlock");
    } finally {
      setBusy(false);
      setMasterPassword("");
    }
  }

  return (
    <main style={{ maxWidth: "22rem", margin: "0 auto", padding: "var(--space-8) var(--space-4)" }}>
      <h1 style={{ fontSize: "1.25rem", fontWeight: 600, marginBottom: "var(--space-6)" }}>
        Unlock your vault
      </h1>
      <form onSubmit={submit}>
        {rememberedEmail === null ? (
          <Field
            label="Email"
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        ) : (
          <p style={{ color: "var(--ink-muted)", marginBottom: "var(--space-4)" }}>
            {rememberedEmail}
          </p>
        )}
        <Field
          label="Master password"
          type="password"
          autoComplete="current-password"
          value={masterPassword}
          onChange={(e) => setMasterPassword(e.target.value)}
          required
        />
        {error !== null && (
          <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
            {error}
          </p>
        )}
        {/* Disabled while working: Argon2id takes about a second, and an
            impatient double-click would otherwise spend two of the five free
            login attempts before the limiter starts adding delay. */}
        <Button type="submit" disabled={busy}>
          {busy ? "Unlocking…" : "Unlock"}
        </Button>
      </form>
    </main>
  );
}

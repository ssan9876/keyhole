import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { NetworkError } from "../../vault/api.js";
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";

interface UnlockScreenProps {
  rememberedEmail: string | null;
  onUnlock(input: { email: string; masterPassword: string }): Promise<void>;
  /** Leaves for the recovery screen. Reached from here because this is where
   *  someone discovers they have forgotten the password, and a recovery code
   *  they cannot find their way to redeem is not a way back in. */
  onForgotPassword(): void;
}

/** Shown when the browser reports no connection, or when an unlock attempt
 *  could not reach the server while offline. Deliberately worded to be
 *  actionable ("reconnect") and distinct from a wrong-password or a
 *  server-fault message — design spec §9 requires these to read differently,
 *  and this is the offline case the shell-only PWA design exists to serve. */
export const OFFLINE_MESSAGE = "You're offline. Connect to load your vault.";

/**
 * The message the unlock form shows for a failed attempt.
 *
 * A NetworkError is the vault layer's "the request never reached the server"
 * (src/vault/api.ts) — distinct in type from an ApiError, which is a server that
 * answered. That is exactly the offline/unreachable case, so it gets the offline
 * wording: actionable, and not confusable with a wrong password (a different
 * error type) or a generic server fault (an ApiError, rendered verbatim below).
 * It is keyed on the error type, not on navigator.onLine, because a request that
 * could not leave the device is the ground truth here — navigator.onLine can
 * report a connection that does not actually reach the server.
 */
export function unlockErrorMessage(failure: unknown): string {
  if (failure instanceof NetworkError) {
    return OFFLINE_MESSAGE;
  }
  if (failure instanceof Error) return failure.message;
  return "Could not unlock";
}

export function UnlockScreen({ rememberedEmail, onUnlock, onForgotPassword }: UnlockScreenProps) {
  const [email, setEmail] = useState(rememberedEmail ?? "");
  const [masterPassword, setMasterPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Tracked live so a banner can appear and clear as connectivity changes,
  // rather than being frozen at the value navigator.onLine had on first render.
  const [online, setOnline] = useState(() => navigator.onLine);

  useEffect(() => {
    const update = (): void => setOnline(navigator.onLine);
    window.addEventListener("online", update);
    window.addEventListener("offline", update);
    return () => {
      window.removeEventListener("online", update);
      window.removeEventListener("offline", update);
    };
  }, []);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onUnlock({ email, masterPassword });
    } catch (failure) {
      // The vault layer already distinguishes a wrong password from an
      // unreachable server; unlockErrorMessage adds the one distinction it
      // cannot make on its own — offline vs. a server that is merely down.
      setError(unlockErrorMessage(failure));
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
        {error !== null ? (
          <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
            {error}
          </p>
        ) : (
          !online && (
            // Before any attempt: say the connection is needed rather than let
            // the user spend an Argon2id pass on a request that cannot leave the
            // device. Suppressed once there is an error to show, so the two
            // never stack. role="status", not "alert" — it is standing context,
            // not the result of an action.
            <p role="status" style={{ color: "var(--ink-muted)", marginBottom: "var(--space-4)" }}>
              {OFFLINE_MESSAGE}
            </p>
          )
        )}
        {/* Disabled while working: Argon2id takes about a second, and an
            impatient double-click would otherwise spend two of the five free
            login attempts before the limiter starts adding delay. */}
        <Button type="submit" disabled={busy}>
          {busy ? "Unlocking…" : "Unlock"}
        </Button>
      </form>
      {/* Outside the form: it is a way out of this screen, not a second way to
          submit it, and a <button> inside a form without type="button" would
          submit on Enter. */}
      <p style={{ marginTop: "var(--space-6)" }}>
        <Button type="button" variant="quiet" onClick={onForgotPassword}>
          Forgot your master password?
        </Button>
      </p>
    </main>
  );
}

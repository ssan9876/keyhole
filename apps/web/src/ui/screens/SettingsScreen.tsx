import { useId, useState } from "react";
import type { FormEvent } from "react";
import type { DeviceSession } from "../../vault/account.js";
import type { AutoLockSetting } from "../../vault/autolock.js";
import { Button } from "../components/Button.js";
import { Confirm } from "../components/Confirm.js";
import { Field } from "../components/Field.js";
import { describeFailure } from "../errors.js";

export interface SettingsScreenProps {
  autoLock: AutoLockSetting;
  onAutoLockChange(setting: AutoLockSetting): void;
  onChangePassword(input: { currentPassword: string; newPassword: string }): Promise<void>;
  sessions: DeviceSession[];
  onRevokeSession(sessionId: string): Promise<void>;
  /** The current device's own session was just revoked -- the vault can no
   *  longer talk to the server as this user, so it must lock rather than sit
   *  there looking usable. */
  onLock(): void;
  onRegenerateRecoveryCode(currentPassword: string): Promise<string>;
}

const AUTO_LOCK_OPTIONS: { value: AutoLockSetting; label: string }[] = [
  { value: 1, label: "1 minute" },
  { value: 5, label: "5 minutes" },
  { value: 15, label: "15 minutes" },
  { value: 30, label: "30 minutes" },
  { value: 60, label: "60 minutes" },
  { value: "on-close", label: "When this tab closes" },
  { value: "never", label: "Never" },
];

function parseAutoLockValue(raw: string): AutoLockSetting {
  return raw === "on-close" || raw === "never" ? raw : (Number(raw) as AutoLockSetting);
}

function AutoLockSection({
  autoLock,
  onAutoLockChange,
}: Pick<SettingsScreenProps, "autoLock" | "onAutoLockChange">) {
  const selectId = useId();
  return (
    <section style={{ marginBottom: "var(--space-6)" }}>
      <h2 style={{ fontSize: "1rem", fontWeight: 600 }}>Auto-lock</h2>
      <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-2)" }}>
        <label htmlFor={selectId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
          Auto-lock
        </label>
        <select
          id={selectId}
          value={String(autoLock)}
          onChange={(e) => onAutoLockChange(parseAutoLockValue(e.target.value))}
        >
          {AUTO_LOCK_OPTIONS.map((option) => (
            <option key={String(option.value)} value={String(option.value)}>
              {option.label}
            </option>
          ))}
        </select>
      </div>
      {/* Design spec §3.8 requires "never" to carry a warning, not just be an
          option sitting quietly next to the timed ones. */}
      {autoLock === "never" && (
        <p style={{ color: "var(--danger)" }}>
          Never locks automatically: the vault stays unlocked until you close this tab or browser.
        </p>
      )}
    </section>
  );
}

function MasterPasswordSection({ onChangePassword }: Pick<SettingsScreenProps, "onChangePassword">) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setSuccess(false);
    setError(null);
    // Checked before onChangePassword is ever called: it derives two Argon2id
    // hashes (~0.5s each by design), and making someone wait out both just to
    // learn they mistyped the confirmation is gratuitous.
    if (newPassword !== confirmPassword) {
      setError("The new password and confirmation do not match");
      return;
    }
    setBusy(true);
    try {
      await onChangePassword({ currentPassword, newPassword });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setSuccess(true);
    } catch (failure) {
      setError(describeFailure(failure, "Could not change the master password"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section style={{ marginBottom: "var(--space-6)" }}>
      <h2 style={{ fontSize: "1rem", fontWeight: 600 }}>Master password</h2>
      <form onSubmit={(e) => void submit(e)}>
        <Field
          label="Current master password"
          type="password"
          autoComplete="current-password"
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
          required
        />
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
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
        />
        {error !== null && (
          <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
            {error}
          </p>
        )}
        {success && (
          // The server (store.RotatePassword) revokes every other session but
          // keeps this one -- a user who is not told that will see nothing
          // wrong here and assume the rest of their devices broke on their
          // own.
          <p style={{ color: "var(--ink-muted)", marginBottom: "var(--space-4)" }}>
            Master password changed. Your other devices have been signed out.
          </p>
        )}
        <Button type="submit" disabled={busy}>
          {busy ? "Changing…" : "Change master password"}
        </Button>
      </form>
    </section>
  );
}

function SessionsSection({
  sessions,
  onRevokeSession,
  onLock,
}: Pick<SettingsScreenProps, "sessions" | "onRevokeSession" | "onLock">) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Only the current session's revoke goes through a confirmation dialog:
  // revoking another device is a one-click "I don't recognise that, kill it
  // now" action that costs nothing (the device just signs back in), while
  // revoking this one locks the vault immediately and costs a full
  // master-password re-entry and Argon2id derivation for a misclick.
  const [confirming, setConfirming] = useState<DeviceSession | null>(null);

  async function handleRevoke(target: DeviceSession): Promise<void> {
    setBusyId(target.id);
    setError(null);
    try {
      await onRevokeSession(target.id);
      // Only the current session's revocation locks the vault: revoking any
      // other device's session is just bookkeeping from here, since this
      // device's own access token is still good.
      if (target.current) onLock();
    } catch (failure) {
      setError(describeFailure(failure, "Could not sign out that device"));
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section style={{ marginBottom: "var(--space-6)" }}>
      <h2 style={{ fontSize: "1rem", fontWeight: 600 }}>Active sessions</h2>
      {sessions.length === 0 ? (
        <p style={{ color: "var(--ink-muted)" }}>No other sessions.</p>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
          {sessions.map((deviceSession) => (
            <li
              key={deviceSession.id}
              style={{
                borderTop: "1px solid var(--rule)",
                padding: "var(--space-2) 0",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "var(--space-2)",
              }}
            >
              <div>
                <span style={{ display: "block" }}>
                  {deviceSession.deviceLabel}
                  {deviceSession.current ? " (this device)" : ""}
                </span>
                <span style={{ color: "var(--ink-muted)", fontSize: "0.75rem" }}>
                  Last seen {deviceSession.lastSeenAt}
                </span>
              </div>
              <Button
                type="button"
                variant={deviceSession.current ? "danger" : "quiet"}
                disabled={busyId === deviceSession.id}
                onClick={() => {
                  if (deviceSession.current) {
                    setConfirming(deviceSession);
                  } else {
                    void handleRevoke(deviceSession);
                  }
                }}
              >
                {deviceSession.current ? "Sign out this device" : "Revoke session"}
              </Button>
            </li>
          ))}
        </ul>
      )}
      {error !== null && (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {error}
        </p>
      )}
      {confirming !== null && (
        <Confirm
          title="Sign out this device?"
          body="This signs out this device and locks the vault. You will need your master password to get back in."
          confirmLabel="Sign out this device"
          onCancel={() => setConfirming(null)}
          onConfirm={() => {
            const target = confirming;
            setConfirming(null);
            void handleRevoke(target);
          }}
        />
      )}
    </section>
  );
}

function RecoverySection({
  onRegenerateRecoveryCode,
}: Pick<SettingsScreenProps, "onRegenerateRecoveryCode">) {
  const [open, setOpen] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [code, setCode] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const next = await onRegenerateRecoveryCode(currentPassword);
      setCode(next);
      setOpen(false);
      setCurrentPassword("");
    } catch (failure) {
      setError(describeFailure(failure, "Could not generate a new recovery code"));
    } finally {
      setBusy(false);
    }
  }

  if (code !== null) {
    return (
      <section style={{ marginBottom: "var(--space-6)" }}>
        <h2 style={{ fontSize: "1rem", fontWeight: 600 }}>Recovery code</h2>
        <p style={{ color: "var(--ink-muted)" }}>
          Save this somewhere safe and offline. It is shown once and cannot be recovered afterwards
          &mdash; not by an administrator, and not by anyone with the database.
        </p>
        <p
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "1.125rem",
            padding: "var(--space-4)",
            border: "1px solid var(--rule-strong)",
            margin: "var(--space-4) 0",
          }}
        >
          {code}
        </p>
        <label style={{ display: "flex", gap: "var(--space-2)", marginBottom: "var(--space-4)" }}>
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
          />
          I have saved this code somewhere safe
        </label>
        {/* Gated deliberately, same as EnrolScreen's identical dialog: letting
            someone click past this replaces their only other way in with
            nothing, silently. */}
        <Button
          type="button"
          disabled={!acknowledged}
          onClick={() => {
            // Cleared here, not left for a parent unmount to take care of --
            // that exact bug (the code surviving in state after the user
            // moved on) was found and fixed in EnrolScreen.
            setCode(null);
            setAcknowledged(false);
          }}
        >
          Done
        </Button>
      </section>
    );
  }

  return (
    <section style={{ marginBottom: "var(--space-6)" }}>
      <h2 style={{ fontSize: "1rem", fontWeight: 600 }}>Recovery code</h2>
      <p style={{ color: "var(--ink-muted)" }}>Generating a new code invalidates the old one.</p>
      {!open ? (
        <Button type="button" variant="quiet" onClick={() => setOpen(true)}>
          New recovery code
        </Button>
      ) : (
        <form onSubmit={(e) => void submit(e)}>
          <Field
            label="Master password"
            type="password"
            autoComplete="current-password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
          />
          {error !== null && (
            <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
              {error}
            </p>
          )}
          <div style={{ display: "flex", gap: "var(--space-2)" }}>
            <Button type="submit" disabled={busy}>
              {busy ? "Generating…" : "Generate new code"}
            </Button>
            <Button
              type="button"
              variant="quiet"
              onClick={() => {
                setOpen(false);
                setCurrentPassword("");
                setError(null);
              }}
            >
              Cancel
            </Button>
          </div>
        </form>
      )}
    </section>
  );
}

export function SettingsScreen({
  autoLock,
  onAutoLockChange,
  onChangePassword,
  sessions,
  onRevokeSession,
  onLock,
  onRegenerateRecoveryCode,
}: SettingsScreenProps) {
  return (
    <div>
      <AutoLockSection autoLock={autoLock} onAutoLockChange={onAutoLockChange} />
      <MasterPasswordSection onChangePassword={onChangePassword} />
      <SessionsSection sessions={sessions} onRevokeSession={onRevokeSession} onLock={onLock} />
      <RecoverySection onRegenerateRecoveryCode={onRegenerateRecoveryCode} />
    </div>
  );
}

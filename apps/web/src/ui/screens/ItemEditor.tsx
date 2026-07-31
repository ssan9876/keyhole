import { useState } from "react";
import type { FormEvent } from "react";
// Brief defect fix: routed through vault/types.js rather than
// "@keyhole/crypto" directly — eslint.config.js's no-restricted-imports bans
// that import anywhere under src/ui/**, including type-only imports, as the
// mechanised form of design spec 6.3's "crypto stays out of the UI" gate.
import type { ItemPlaintext, LoginItem } from "../../vault/types.js";
import { generatePassword } from "../../vault/generator.js";
import { Button } from "../components/Button.js";
import { Field } from "../components/Field.js";

interface ItemEditorProps {
  initial: ItemPlaintext;
  /** The server's winning copy after a 409, once VaultScreen has decrypted
   *  it. Rendered alongside the conflict message so the user sees both
   *  versions -- their own edit still sitting in this form, and what is
   *  actually on the server -- rather than just being told a collision
   *  happened. */
  conflict?: ItemPlaintext | null;
  onSave(next: ItemPlaintext): Promise<void>;
  onCancel(): void;
}

function isLogin(item: ItemPlaintext): item is LoginItem {
  return item.type === "login";
}

export function ItemEditor({ initial, conflict = null, onSave, onCancel }: ItemEditorProps) {
  const [name, setName] = useState(initial.name);
  const [notes, setNotes] = useState(initial.notes);
  const [username, setUsername] = useState(isLogin(initial) ? initial.username : "");
  const [password, setPassword] = useState(isLogin(initial) ? initial.password : "");
  const [revealed, setRevealed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const next: ItemPlaintext = isLogin(initial)
      ? { ...initial, name, notes, username, password }
      : { ...initial, name, notes };
    try {
      await onSave(next);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not save");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} required />
      {isLogin(initial) && (
        <>
          <Field
            label="Username"
            autoComplete="off"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          {/* The field and the two controls that act on it are one block: the
              old layout let a 16px gap and a margin split them apart. */}
          <div className="kh-field kh-field-tight">
            <Field
              label="Password"
              // Masked by default: an editor left open on a desk is the
              // ordinary case, not the exception.
              type={revealed ? "text" : "password"}
              autoComplete="off"
              className="kh-mono-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <div className="kh-actions">
              <Button
                type="button"
                variant="quiet"
                size="sm"
                aria-pressed={revealed}
                onClick={() => setRevealed(!revealed)}
              >
                {revealed ? "Hide" : "Reveal"}
              </Button>
              <Button
                type="button"
                variant="quiet"
                size="sm"
                onClick={() => setPassword(generatePassword())}
              >
                Generate
              </Button>
            </div>
          </div>
        </>
      )}
      <Field label="Notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
      {error !== null && (
        <p role="alert" className="kh-alert">
          {error}
        </p>
      )}
      {conflict !== null && (
        <p className="kh-note">
          The version currently on the server is named &ldquo;{conflict.name}
          &rdquo;. Save again to apply your edit on top of it.
        </p>
      )}
      <div className="kh-actions">
        <Button type="submit" disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </Button>
        <Button type="button" variant="quiet" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

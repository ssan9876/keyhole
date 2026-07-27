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
  onSave(next: ItemPlaintext): Promise<void>;
  onCancel(): void;
}

function isLogin(item: ItemPlaintext): item is LoginItem {
  return item.type === "login";
}

export function ItemEditor({ initial, onSave, onCancel }: ItemEditorProps) {
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
    <form onSubmit={submit} style={{ padding: "var(--space-4)" }}>
      <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} required />
      {isLogin(initial) && (
        <>
          <Field
            label="Username"
            autoComplete="off"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <Field
            label="Password"
            // Masked by default: an editor left open on a desk is the ordinary
            // case, not the exception.
            type={revealed ? "text" : "password"}
            autoComplete="off"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <div style={{ display: "flex", gap: "var(--space-2)", marginBottom: "var(--space-4)" }}>
            <Button type="button" variant="quiet" onClick={() => setRevealed(!revealed)}>
              {revealed ? "Hide" : "Reveal"}
            </Button>
            <Button type="button" variant="quiet" onClick={() => setPassword(generatePassword())}>
              Generate
            </Button>
          </div>
        </>
      )}
      <Field label="Notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
      {error !== null && (
        <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
          {error}
        </p>
      )}
      <div style={{ display: "flex", gap: "var(--space-2)" }}>
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

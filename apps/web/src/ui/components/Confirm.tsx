import { useEffect, useId, useRef, useState } from "react";
import type { KeyboardEvent, ReactNode } from "react";
import { Button } from "./Button.js";

export interface ConfirmProps {
  title: string;
  body: ReactNode;
  confirmLabel: string;
  /** When set, the confirm button stays disabled until the user types this
   *  exactly. Used for admin reset, which destroys a vault. */
  requireTyped?: string;
  onConfirm(): void;
  onCancel(): void;
}

const FOCUSABLE_SELECTOR =
  'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

/**
 * A focus-trapped confirmation dialog, per design spec 6.4.
 *
 * `role="alertdialog"` plus `aria-modal` mark it as a dialog that interrupts
 * the current task and must be dismissed before anything else can be done.
 * Focus moves onto it the moment it mounts, Tab/Shift+Tab cannot leave it
 * while it is open, Escape cancels, and focus returns to whatever triggered
 * it once it closes -- a caller who opened this from a "Remove" button lands
 * back on that same button, not lost at the top of the page.
 */
export function Confirm({
  title,
  body,
  confirmLabel,
  requireTyped,
  onConfirm,
  onCancel,
}: ConfirmProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);
  const [typed, setTyped] = useState("");
  const titleId = useId();
  const typedFieldId = useId();

  useEffect(() => {
    previouslyFocused.current = document.activeElement as HTMLElement | null;
    dialogRef.current?.focus();
    return () => {
      previouslyFocused.current?.focus();
    };
  }, []);

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>): void {
    if (event.key === "Escape") {
      event.preventDefault();
      onCancel();
      return;
    }
    if (event.key !== "Tab") return;

    const focusable = dialogRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR);
    if (focusable === undefined || focusable.length === 0) {
      event.preventDefault();
      return;
    }
    const list = Array.from(focusable);
    const first = list[0] as HTMLElement;
    const last = list[list.length - 1] as HTMLElement;

    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  const confirmDisabled = requireTyped !== undefined && typed !== requireTyped;

  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby={titleId}
      ref={dialogRef}
      tabIndex={-1}
      onKeyDown={handleKeyDown}
      style={{
        position: "fixed",
        inset: 0,
        display: "grid",
        placeItems: "center",
        background: "rgba(20, 20, 15, 0.4)",
        zIndex: 1,
      }}
    >
      <div
        style={{
          background: "var(--ground)",
          color: "var(--ink)",
          border: "1px solid var(--rule-strong)",
          padding: "var(--space-4)",
          maxWidth: "24rem",
          width: "calc(100% - 2rem)",
        }}
      >
        <h2 id={titleId} style={{ fontSize: "1rem", fontWeight: 600, marginTop: 0 }}>
          {title}
        </h2>
        <div style={{ color: "var(--ink-muted)", marginBottom: "var(--space-4)" }}>{body}</div>
        {requireTyped !== undefined && (
          <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-4)" }}>
            <label htmlFor={typedFieldId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
              Type &ldquo;{requireTyped}&rdquo; to confirm
            </label>
            <input
              id={typedFieldId}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              style={{
                font: "inherit",
                padding: "var(--space-2)",
                border: "1px solid var(--rule)",
                background: "transparent",
                color: "var(--ink)",
              }}
            />
          </div>
        )}
        <div style={{ display: "flex", gap: "var(--space-2)" }}>
          <Button type="button" variant="danger" disabled={confirmDisabled} onClick={onConfirm}>
            {confirmLabel}
          </Button>
          <Button type="button" variant="quiet" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </div>
    </div>
  );
}

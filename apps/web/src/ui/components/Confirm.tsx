import { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
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

  // Portalled to <body>, not rendered where it was written. A modal has to
  // cover the whole page, and z-index cannot promise that from inside an
  // arbitrary ancestor: the folder rail is `position: sticky`, which creates a
  // stacking context, so a scrim rendered within it was confined to the rail's
  // layer and the sticky page header painted straight over it. Escaping to the
  // document root makes the scrim's z-index mean what it says, whichever screen
  // opens the dialog. Focus management above is unaffected -- it works on refs,
  // not on tree position -- and the dialog is still queryable from `screen` in
  // tests, which search all of document.body.
  return createPortal(
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby={titleId}
      ref={dialogRef}
      tabIndex={-1}
      onKeyDown={handleKeyDown}
      className="kh-scrim"
    >
      <div className="kh-dialog">
        <h2 id={titleId} className="kh-dialog-title">
          {title}
        </h2>
        <div className="kh-dialog-body">{body}</div>
        {requireTyped !== undefined && (
          <div className="kh-field">
            <label htmlFor={typedFieldId} className="kh-label">
              Type &ldquo;{requireTyped}&rdquo; to confirm
            </label>
            <input id={typedFieldId} value={typed} onChange={(e) => setTyped(e.target.value)} />
          </div>
        )}
        <div className="kh-actions">
          <Button type="button" variant="danger" disabled={confirmDisabled} onClick={onConfirm}>
            {confirmLabel}
          </Button>
          <Button type="button" variant="quiet" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </div>
    </div>,
    document.body,
  );
}

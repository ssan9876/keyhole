import { useId } from "react";
import type { InputHTMLAttributes, ReactNode } from "react";

interface FieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "id"> {
  label: string;
  /** Standing guidance, kept below the input rather than hidden in a
   *  placeholder that disappears the moment someone starts typing. Bound with
   *  aria-describedby so it is announced, not just seen. */
  hint?: ReactNode;
}

/**
 * A labelled input. The label is bound by id rather than wrapping, so screen
 * readers and Testing Library's getByLabelText agree on what this control is —
 * design spec 6.4 lists labelled form controls as a requirement, not a polish
 * pass.
 *
 * The input itself is styled by the `input` element rule in tokens.css, which
 * is what gives every hand-rolled input elsewhere in the app the same height,
 * hover, and focus ring without each screen restating them.
 */
export function Field({ label, hint, className, ...rest }: FieldProps) {
  const id = useId();
  const hintId = useId();
  return (
    <div className={className === undefined ? "kh-field" : `kh-field ${className}`}>
      <label htmlFor={id} className="kh-label">
        {label}
      </label>
      <input {...rest} id={id} aria-describedby={hint === undefined ? undefined : hintId} />
      {hint !== undefined && (
        <p id={hintId} className="kh-hint">
          {hint}
        </p>
      )}
    </div>
  );
}

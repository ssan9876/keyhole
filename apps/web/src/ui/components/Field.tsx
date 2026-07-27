import { useId } from "react";
import type { InputHTMLAttributes } from "react";

interface FieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "id"> {
  label: string;
}

/**
 * A labelled input. The label is bound by id rather than wrapping, so screen
 * readers and Testing Library's getByLabelText agree on what this control is —
 * design spec 6.4 lists labelled form controls as a requirement, not a polish
 * pass.
 */
export function Field({ label, ...rest }: FieldProps) {
  const id = useId();
  return (
    <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-4)" }}>
      <label htmlFor={id} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
        {label}
      </label>
      <input
        {...rest}
        id={id}
        style={{
          font: "inherit",
          padding: "var(--space-2)",
          border: "1px solid var(--rule)",
          background: "transparent",
          color: "var(--ink)",
        }}
      />
    </div>
  );
}

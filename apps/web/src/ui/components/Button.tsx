import type { ButtonHTMLAttributes, ReactNode } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  children: ReactNode;
  variant?: "primary" | "quiet" | "danger";
}

export function Button({ children, variant = "primary", ...rest }: ButtonProps) {
  return (
    <button
      {...rest}
      data-variant={variant}
      style={{
        font: "inherit",
        padding: "var(--space-2) var(--space-4)",
        border: `1px solid ${variant === "quiet" ? "var(--rule)" : "var(--rule-strong)"}`,
        background: "transparent",
        color: variant === "danger" ? "var(--danger)" : "var(--ink)",
        cursor: rest.disabled === true ? "default" : "pointer",
        opacity: rest.disabled === true ? 0.55 : 1,
      }}
    >
      {children}
    </button>
  );
}

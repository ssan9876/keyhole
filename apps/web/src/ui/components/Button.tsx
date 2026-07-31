import type { ButtonHTMLAttributes, ReactNode } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  children: ReactNode;
  variant?: "primary" | "quiet" | "danger";
  /** `sm` for controls that sit inside a row (Rename, Delete on a folder line)
   *  rather than ending a form. Still 36px tall, and the row around it carries
   *  the rest of the touch target. */
  size?: "md" | "sm";
  block?: boolean;
}

/**
 * The one button.
 *
 * Variant and size are data attributes rather than inline styles so hover,
 * active, and disabled states live in tokens.css — an inline style object
 * cannot express any of them, which is why every control in this app used to
 * look identical whether you were pointing at it or not. `primary` is the only
 * variant that fills, so a screen with two of them is visibly wrong.
 */
export function Button({
  children,
  variant = "primary",
  size = "md",
  block = false,
  className,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      data-variant={variant}
      data-size={size}
      data-block={block ? "true" : undefined}
      className={className === undefined ? "kh-btn" : `kh-btn ${className}`}
    >
      {children}
    </button>
  );
}

/**
 * The icon set: hand-drawn SVG, one family, one stroke weight.
 *
 * Deliberately tiny and local rather than a dependency — Mono uses icons as
 * punctuation (a chevron that says "this row opens", a keyhole that says "this
 * is the app"), never as labels, so the set does not grow. Every glyph shares a
 * 24-unit box, 1.5 stroke, round caps, and `currentColor`, which is what keeps
 * them looking like one family and makes them theme automatically.
 *
 * All of them are `aria-hidden`: each sits beside text that already says the
 * same thing, so announcing them would only repeat it.
 */

const base = {
  width: 16,
  height: 16,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true,
  focusable: false,
} as const;

/** Points at the row it ends: this opens something. */
export function Chevron({ className }: { className?: string }) {
  return (
    <svg {...base} className={className ?? "kh-row-chevron"}>
      <path d="M9 6l6 6-6 6" />
    </svg>
  );
}

/**
 * The wordmark's glyph.
 *
 * Filled, not stroked — the outlined version of this shape is a circle above a
 * stem, which at 16px is indistinguishable from a figure 8. A silhouette reads
 * as a keyhole at any size, which is the one thing this mark has to do.
 */
export function Keyhole({ size = 16 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden
      focusable={false}
    >
      <path d="M12 2.5a5.5 5.5 0 00-3.1 10.04L6.8 20.4A1.2 1.2 0 008 21.9h8a1.2 1.2 0 001.2-1.5l-2.1-7.86A5.5 5.5 0 0012 2.5zm0 3a2.5 2.5 0 110 5 2.5 2.5 0 010-5z" />
    </svg>
  );
}

export function Lock({ size = 16 }: { size?: number }) {
  return (
    <svg {...base} width={size} height={size}>
      <rect x="4.5" y="10.5" width="15" height="9.5" rx="2" />
      <path d="M8 10.5V7.5a4 4 0 018 0v3" />
    </svg>
  );
}

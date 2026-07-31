/**
 * Idle auto-lock, DOM half.
 *
 * The setting itself lives in `preferences.ts` because the browser extension
 * shares it. This module does not, and must not, move with it: it listens to
 * pointer, key, focus, and visibility events, none of which exist in a service
 * worker. The extension drives the same setting from `chrome.alarms` instead.
 */

export type AutoLockSetting = 1 | 5 | 15 | 30 | 60 | "on-close" | "never";

const ACTIVITY_EVENTS = ["pointerdown", "keydown", "focus"] as const;

export function startAutoLock(input: {
  setting: AutoLockSetting;
  onLock: () => void;
  now?: () => number;
}): () => void {
  if (input.setting === "never") return () => undefined;

  const now = input.now ?? (() => Date.now());
  const onHidden = (): void => {
    if (document.visibilityState === "hidden") input.onLock();
  };

  if (input.setting === "on-close") {
    document.addEventListener("visibilitychange", onHidden);
    return () => document.removeEventListener("visibilitychange", onHidden);
  }

  const idleMs = input.setting * 60_000;
  let lastActivity = now();
  let timer: ReturnType<typeof setTimeout> | null = null;

  const fire = (): void => {
    timer = null;
    input.onLock();
  };

  const restart = (): void => {
    lastActivity = now();
    if (timer !== null) clearTimeout(timer);
    timer = setTimeout(fire, idleMs);
  };

  // A setTimeout does not run while the machine is asleep, and browsers
  // throttle timers in background tabs — so the timer alone would leave a
  // vault unlocked across a closed lid, the exact case this feature exists
  // for. Every wake re-checks the wall clock.
  const checkElapsed = (): void => {
    if (now() - lastActivity >= idleMs) {
      if (timer !== null) clearTimeout(timer);
      fire();
      return;
    }
    restart();
  };

  for (const event of ACTIVITY_EVENTS) window.addEventListener(event, restart);
  document.addEventListener("visibilitychange", checkElapsed);
  restart();

  return () => {
    if (timer !== null) clearTimeout(timer);
    for (const event of ACTIVITY_EVENTS) window.removeEventListener(event, restart);
    document.removeEventListener("visibilitychange", checkElapsed);
  };
}

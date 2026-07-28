/**
 * Idle auto-lock. Design spec §3.8.
 *
 * The setting is a preference, not a secret, so it may be persisted — this and
 * `keyhole.email` are the only two values this application writes to storage.
 */

export type AutoLockSetting = 1 | 5 | 15 | 30 | 60 | "on-close" | "never";

export const AUTO_LOCK_STORAGE_KEY = "keyhole.autolock";
export const DEFAULT_AUTO_LOCK: AutoLockSetting = 15;

const SETTINGS: readonly AutoLockSetting[] = [1, 5, 15, 30, 60, "on-close", "never"];

export function readAutoLock(): AutoLockSetting {
  const raw = localStorage.getItem(AUTO_LOCK_STORAGE_KEY);
  if (raw === null) return DEFAULT_AUTO_LOCK;
  const parsed: AutoLockSetting = /^\d+$/.test(raw) ? (Number(raw) as AutoLockSetting) : (raw as AutoLockSetting);
  // An unrecognized value falls back rather than passing through. A stored "0"
  // would otherwise mean a zero-length timeout or an unbounded one depending
  // on how it is read, and either is a worse answer than the default.
  return SETTINGS.includes(parsed) ? parsed : DEFAULT_AUTO_LOCK;
}

export function writeAutoLock(setting: AutoLockSetting): void {
  localStorage.setItem(AUTO_LOCK_STORAGE_KEY, String(setting));
}

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

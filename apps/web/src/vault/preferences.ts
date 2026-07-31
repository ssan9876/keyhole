import type { AutoLockSetting } from "./autolock.js";

/**
 * The whole of this application's persistence, behind three methods.
 *
 * It exists so that `session` and the auto-lock setting stop naming
 * `localStorage`, which a service worker does not have — that is what lets
 * this layer be shared with the browser extension.
 *
 * Deliberately synchronous. `chrome.storage.local` is async, so the extension
 * hydrates it into memory once at context startup and writes through; the
 * alternative was an async interface, which would force `App.tsx`'s
 * `useState(readAutoLock)` and every caller like it into an effect for no gain.
 *
 * It carries two keys and must never carry a third that is secret. The
 * prohibition on persisting key material is unchanged by this indirection.
 */
export interface PreferenceStore {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

/**
 * An email address is not a secret to the server — it is the account identity,
 * already known to anyone holding the device. Persisting it buys a
 * password-only unlock screen. Persisting the refresh token would buy nothing
 * beyond that, because the wrapped keys come back only from
 * POST /api/auth/login and never from refresh, while handing a device thief
 * working API access.
 */
export const EMAIL_STORAGE_KEY = "keyhole.email";
export const AUTO_LOCK_STORAGE_KEY = "keyhole.autolock";

export const DEFAULT_AUTO_LOCK: AutoLockSetting = 15;

const SETTINGS: readonly AutoLockSetting[] = [1, 5, 15, 30, 60, "on-close", "never"];

export interface Preferences {
  rememberEmail(email: string): void;
  rememberedEmail(): string | null;
  forgetEmail(): void;
  readAutoLock(): AutoLockSetting;
  writeAutoLock(setting: AutoLockSetting): void;
}

export function createPreferences(store: PreferenceStore): Preferences {
  return {
    rememberEmail(email) {
      store.set(EMAIL_STORAGE_KEY, email);
    },
    rememberedEmail() {
      return store.get(EMAIL_STORAGE_KEY);
    },
    forgetEmail() {
      store.remove(EMAIL_STORAGE_KEY);
    },
    readAutoLock() {
      const raw = store.get(AUTO_LOCK_STORAGE_KEY);
      if (raw === null) return DEFAULT_AUTO_LOCK;
      const parsed: AutoLockSetting = /^\d+$/.test(raw)
        ? (Number(raw) as AutoLockSetting)
        : (raw as AutoLockSetting);
      // An unrecognised value falls back rather than passing through.
      return SETTINGS.includes(parsed) ? parsed : DEFAULT_AUTO_LOCK;
    },
    writeAutoLock(setting) {
      store.set(AUTO_LOCK_STORAGE_KEY, String(setting));
    },
  };
}

import type { PreferenceStore } from "../vault/preferences.js";

/**
 * The web app's binding of PreferenceStore to the browser.
 *
 * It lives outside `vault/` on purpose: `localStorage` is a DOM global, and
 * keeping it out of the shared layer is what allows that layer to run in a
 * service worker unchanged.
 */
export function localStoragePreferences(): PreferenceStore {
  return {
    get: (key) => localStorage.getItem(key),
    set: (key, value) => localStorage.setItem(key, value),
    remove: (key) => localStorage.removeItem(key),
  };
}

import { useCallback, useEffect, useMemo, useState } from "react";
import { createApiClient } from "../vault/api.js";
import { createSession, rememberedEmail } from "../vault/session.js";
import { createVaultStore } from "../vault/store.js";
import { enroll } from "../vault/enroll.js";
import { unlock } from "../vault/unlock.js";
import { readAutoLock, startAutoLock } from "../vault/autolock.js";
import { EnrolScreen } from "./screens/EnrolScreen.js";
import { UnlockScreen } from "./screens/UnlockScreen.js";
import { VaultScreen } from "./screens/VaultScreen.js";
import { useSession } from "./useVault.js";

/**
 * Reads the one URL this application cares about.
 *
 * Deferring a router does not mean ignoring the address bar: the invite token is
 * the only way the enrolment screen knows which invite it is completing. This is
 * a single string match — no history integration, no route table.
 */
export function inviteTokenFromPath(pathname: string): string | null {
  const parts = pathname.split("/").filter((part) => part.length > 0);
  if (parts.length !== 2 || parts[0] !== "enroll") return null;
  const token = parts[1] as string;
  return token.length > 0 ? decodeURIComponent(token) : null;
}

const DEVICE_LABEL = "Web";

export function App() {
  const session = useMemo(() => createSession(), []);
  const store = useMemo(() => createVaultStore(), []);
  const [refreshFailed, setRefreshFailed] = useState(false);

  const api = useMemo(
    () =>
      createApiClient({
        getAccessToken: () => session.getAccessToken(),
        // Exactly one refresh attempt, then lock. The refresh token is
        // single-use server-side, so a loop would burn the session.
        onUnauthorized: async () => {
          const refreshToken = session.getRefreshToken();
          if (refreshToken === null) return false;
          try {
            const response = await fetch("/api/auth/refresh", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ refreshToken }),
            });
            if (!response.ok) throw new Error("refresh failed");
            const tokens = (await response.json()) as {
              accessToken: string;
              refreshToken: string;
            };
            session.replaceTokens(tokens);
            return true;
          } catch {
            setRefreshFailed(true);
            store.clear();
            session.lock();
            return false;
          }
        },
      }),
    [session, store],
  );

  const { isUnlocked } = useSession(session);
  const inviteToken = useMemo(() => inviteTokenFromPath(window.location.pathname), []);
  const [enrolled, setEnrolled] = useState(false);
  const [autoLock, setAutoLock] = useState(readAutoLock);

  // Started only while unlocked -- there is nothing to lock otherwise -- and
  // torn down and restarted whenever `autoLock` changes, so a setting picked
  // in SettingsScreen takes effect immediately rather than at the next
  // reload. `autoLock` must stay in this dependency array for exactly that
  // reason: drop it and the timer keeps running under whatever setting was
  // in effect when the session unlocked.
  useEffect(() => {
    if (!isUnlocked) return undefined;
    return startAutoLock({
      setting: autoLock,
      onLock: () => {
        store.clear();
        session.lock();
      },
    });
  }, [autoLock, isUnlocked, session, store]);

  const handleUnlock = useCallback(
    async (input: { email: string; masterPassword: string }) => {
      setRefreshFailed(false);
      await unlock({ api, session }, { ...input, deviceLabel: DEVICE_LABEL });
      await store.load({ api, session });
    },
    [api, session, store],
  );

  const handleEnrol = useCallback(
    async (input: { inviteToken: string; email: string; masterPassword: string }) => {
      const outcome = await enroll({ api, session }, { ...input, deviceLabel: DEVICE_LABEL });
      // enroll() already resolved, which means POST /api/enroll/:token
      // returned 200 and outcome.recoveryCode must reach the caller no matter
      // what happens below. Only sync if login actually opened the session —
      // store.load needs session.getKeys(), which throws while locked — and
      // swallow a failed sync rather than let it reject this promise: the
      // user must land on the recovery-code screen with a recoverable error,
      // never back on a form with the code destroyed. VaultScreen already
      // renders store's own "error" status once the user gets there.
      if (outcome.loggedIn) {
        await store.load({ api, session }).catch(() => undefined);
      }
      return outcome;
    },
    [api, session, store],
  );

  // WebCrypto's SubtleCrypto is only exposed in a secure context. On a plain
  // http:// origin that is not localhost it is simply absent, and every
  // AES-GCM call throws "Cannot read properties of undefined" -- which reads
  // like a bug in Keyhole rather than a deployment that cannot work. This
  // guard runs before every other branch below: none of EnrolScreen,
  // UnlockScreen, or VaultScreen is safe to reach without crypto.subtle,
  // since the first two derive keys on submit and the third only exists
  // once a session already has them. It comes after the hooks above rather
  // than before them so App still calls the same hooks on every render --
  // isSecureContext and crypto.subtle cannot change during a mount, so this
  // costs nothing and keeps the component's hook calls unconditional.
  if (!window.isSecureContext || globalThis.crypto?.subtle === undefined) {
    return (
      <main role="alert">
        <h1>This page needs a secure connection</h1>
        <p>
          Keyhole does all of its encryption in your browser, and browsers only
          provide the encryption API over HTTPS. Reach this server over{" "}
          <code>https://</code> and try again.
        </p>
      </main>
    );
  }

  if (inviteToken !== null && !enrolled) {
    return (
      <EnrolScreen
        inviteToken={inviteToken}
        onEnrol={handleEnrol}
        onFinish={() => {
          // Clear the one-time invite path from the address bar. Without
          // this, inviteToken above is re-derived from window.location on
          // every mount, so a reload after enrolling — which wipes the
          // memory-only session and React state by design — would land back
          // on the enrolment screen instead of the unlock screen, even
          // though the invite was already consumed and the account exists.
          window.history.replaceState(null, "", "/");
          setEnrolled(true);
        }}
      />
    );
  }

  if (!isUnlocked) {
    return (
      <>
        {refreshFailed && (
          <p role="status" style={{ textAlign: "center", color: "var(--ink-muted)" }}>
            Your session expired. Unlock to continue.
          </p>
        )}
        <UnlockScreen rememberedEmail={rememberedEmail()} onUnlock={handleUnlock} />
      </>
    );
  }

  return (
    <VaultScreen
      api={api}
      session={session}
      store={store}
      autoLock={autoLock}
      onAutoLockChange={setAutoLock}
    />
  );
}

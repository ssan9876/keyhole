import { useCallback, useEffect, useRef } from "react";
import type { ApiClient } from "../vault/api.js";
import type { Session } from "../vault/session.js";
import type { VaultStore } from "../vault/store.js";
import {
  completeRecovery,
  recoverAccount,
  type RecoveryOutcome,
  type RecoverySession,
} from "../vault/recover.js";
import { unlock } from "../vault/unlock.js";
import type { RecoverScreenProps } from "./screens/RecoverScreen.js";

/**
 * The recovery controller: the two vault-layer calls, the keys between them,
 * and the sign-in that follows.
 *
 * Same split as useCollectionsPanel/useSettingsPanel/useAdminPanel — the screen
 * stays presentational and this holds every reference that matters. There is
 * one such reference here and it is the important one: `RecoverySession`
 * carries a live userKey and privateKey, and because ESLint forbids
 * `src/ui/**` from importing `@keyhole/crypto` at all, `destroy()` is the only
 * way anything above the vault layer can clear them. Every path out of this
 * hook — finished, cancelled, unmounted — goes through it.
 *
 * Returns exactly the props `RecoverScreen` needs, so a caller renders it as
 * `<RecoverScreen {...useRecoverScreen({ ... })} />`.
 */
export function useRecoverScreen({
  api,
  session,
  store,
  deviceLabel,
  rememberedEmail,
  onExit,
}: {
  api: ApiClient;
  session: Session;
  store: VaultStore;
  deviceLabel: string;
  rememberedEmail: string | null;
  /** Leave the recovery screen. The caller decides what replaces it — the
   *  vault when the sign-in below succeeded, the unlock screen otherwise. */
  onExit(): void;
}): RecoverScreenProps {
  const recovery = useRef<RecoverySession | null>(null);

  const discard = useCallback((): void => {
    recovery.current?.destroy();
    recovery.current = null;
  }, []);

  // An unmount that is not a reload — an error boundary, a route change, a
  // parent deciding to render something else — would otherwise leave a userKey
  // and a privateKey live in the heap with nothing left pointing at them.
  useEffect(() => discard, [discard]);

  const onRedeemCode = useCallback(
    async (input: { email: string; recoveryCode: string }): Promise<void> => {
      // A second attempt after a refusal (a mistyped address, a mistyped code)
      // must not strand the first attempt's keys.
      discard();
      recovery.current = await recoverAccount({ api }, input);
    },
    [api, discard],
  );

  const onSetNewPassword = useCallback(
    async (newMasterPassword: string): Promise<RecoveryOutcome> => {
      const pending = recovery.current;
      if (pending === null) {
        // Unreachable from RecoverScreen, which renders the password step only
        // after onRedeemCode resolves. Loud rather than silent: a caller that
        // got here would otherwise believe a rotation had happened.
        throw new Error("There is no recovery in progress");
      }

      // Deliberately outside a try/finally: a throw here leaves the recovery
      // session intact so the user can press the button again. That is now
      // narrowed to the cases where retrying can actually work — completeRecovery
      // throws only when the server *refused* (a 4xx) or when nothing was sent
      // at all, and turns "we never heard back" into a resolved outcome with
      // confirmed:false instead. It used to throw on those too, and the retry
      // that followed sent a token the server had already spent and came back
      // 401, confirming a failure that had in fact succeeded.
      const outcome = await completeRecovery({ api }, pending, newMasterPassword);

      const { email } = pending;
      // Spent, whether or not the answer arrived: the token is one-time and the
      // screen is on its way to showing the new code either way. Retrying is
      // not on offer from here, so nothing is served by keeping the keys live.
      discard();

      try {
        // /api/auth/recover/complete answers 204 and revokes every session, so
        // there is nothing in that response to open a vault with. This is a
        // full prelogin/login round trip and another Argon2id pass, which is
        // the price of not sending someone who has just set a password back to
        // a form asking for it.
        await unlock({ api, session }, { email, masterPassword: newMasterPassword, deviceLabel });
        await store.load({ api, session });
      } catch {
        // Swallowed on purpose, exactly as App.tsx's handleEnrol swallows a
        // failed post-enrolment sync: the new recovery code is shown once and
        // is unrecoverable afterwards by anyone, so it must reach the user even
        // if this device cannot sign in. They land on the unlock screen after
        // acknowledging it, which is a recoverable place to be.
        //
        // Attempted even when outcome.confirmed is false, because it is the
        // cheapest available answer to "did the rotation land?": if it did, this
        // succeeds and the user is simply in their vault.
      }

      return outcome;
    },
    [api, deviceLabel, discard, session, store],
  );

  // Finishing and abandoning are the same operation from here: drop anything
  // still held and hand control back. Only the caller's own state decides which
  // screen comes next.
  const leave = useCallback((): void => {
    discard();
    onExit();
  }, [discard, onExit]);

  return {
    rememberedEmail,
    onRedeemCode,
    onSetNewPassword,
    onFinish: leave,
    onCancel: leave,
  };
}

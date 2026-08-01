import { useSyncExternalStore } from "react";
import type { Session, SessionUser, VaultState, VaultStore } from "@keyhole/vault";

/**
 * The bridge between the framework-free core and React.
 *
 * useSyncExternalStore rather than a context holding the values: the store owns
 * its state, React only observes it, and no key material is ever placed in the
 * component tree.
 */
export function useSession(session: Session): {
  isUnlocked: boolean;
  user: SessionUser | null;
} {
  // The snapshot is a boolean, deliberately. getSnapshot must return a
  // referentially stable value between changes — returning a fresh object here
  // would give React a new identity on every call and loop forever.
  const isUnlocked = useSyncExternalStore(
    (listener) => session.subscribe(listener),
    () => session.isUnlocked,
  );
  return { isUnlocked, user: isUnlocked ? session.user : null };
}

export function useVaultState(store: VaultStore): VaultState {
  return useSyncExternalStore(
    (listener) => store.subscribe(listener),
    () => store.getState(),
  );
}

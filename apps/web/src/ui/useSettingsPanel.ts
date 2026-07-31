import { useCallback, useEffect, useState } from "react";
import type { ApiClient } from "../vault/api.js";
import type { Session } from "../vault/session.js";
import type { VaultStore } from "../vault/store.js";
import {
  changeMasterPassword,
  listSessions,
  regenerateRecoveryCode,
  revokeSession,
  type DeviceSession,
} from "../vault/account.js";
import type { AutoLockSetting } from "../vault/autolock.js";
import type { SettingsScreenProps } from "./screens/SettingsScreen.js";

/**
 * The settings-management controller: state and handlers for the Settings
 * tab, kept out of VaultScreen for the same reason Task 10 pulled
 * useCollectionsPanel out of it -- VaultScreen already carries item CRUD and
 * the tab strip, and a screen with a real second responsibility inline
 * becomes untestable without mounting the whole thing.
 *
 * Returns exactly the props `SettingsScreen` needs, so a caller renders it as
 * `<SettingsScreen {...useSettingsPanel({ api, session, store, active,
 * autoLock, onAutoLockChange })} />` with nothing else to wire up.
 */
export function useSettingsPanel({
  api,
  session,
  store,
  active,
  autoLock,
  onAutoLockChange,
  writeAutoLock,
}: {
  api: ApiClient;
  session: Session;
  store: VaultStore;
  /** Whether the Settings tab is the one currently showing. Gates the lazy
   *  sessions load below, same pattern as useCollectionsPanel's directory
   *  load. */
  active: boolean;
  autoLock: AutoLockSetting;
  /** App.tsx's raw setter. This hook is the one that also persists the
   *  choice -- see handleAutoLockChange below -- so App.tsx itself never
   *  needs to import writeAutoLock. */
  onAutoLockChange(setting: AutoLockSetting): void;
  /** Injected rather than imported, so this hook does not reach a module
   *  singleton -- the same reason unlock() and enroll() take rememberEmail as
   *  a dependency instead of importing it. */
  writeAutoLock(setting: AutoLockSetting): void;
}): SettingsScreenProps {
  const [sessions, setSessions] = useState<DeviceSession[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (!active || loaded) return;
    let cancelled = false;
    void listSessions({ api, session })
      .then((list) => {
        if (!cancelled) {
          setSessions(list);
          setLoaded(true);
        }
      })
      .catch(() => {
        // Best-effort, matching useCollectionsPanel's directory load: a
        // failed sessions fetch must not blank out the rest of the settings
        // screen, which has nothing to do with this request.
      });
    return () => {
      cancelled = true;
    };
  }, [active, loaded, api, session]);

  const handleAutoLockChange = useCallback(
    (setting: AutoLockSetting) => {
      // Persisted immediately, not just held in React state: a reload before
      // the next explicit save must not revert the choice.
      writeAutoLock(setting);
      onAutoLockChange(setting);
    },
    [onAutoLockChange, writeAutoLock],
  );

  const handleChangePassword = useCallback(
    async (input: { currentPassword: string; newPassword: string }): Promise<void> => {
      const email = session.user?.email ?? "";
      await changeMasterPassword({ api, session }, { email, ...input });
    },
    [api, session],
  );

  const handleRegenerateRecoveryCode = useCallback(
    async (currentPassword: string): Promise<string> => {
      const email = session.user?.email ?? "";
      return regenerateRecoveryCode({ api, session }, { email, currentPassword });
    },
    [api, session],
  );

  const handleRevokeSession = useCallback(
    async (sessionId: string): Promise<void> => {
      await revokeSession({ api, session }, sessionId);
      // Not a resync -- a revoked entry is simply gone, no other session's
      // fields could have changed as a side effect of this call.
      setSessions((prev) => prev.filter((s) => s.id !== sessionId));
    },
    [api, session],
  );

  const handleLock = useCallback((): void => {
    store.clear();
    session.lock();
  }, [session, store]);

  return {
    autoLock,
    onAutoLockChange: handleAutoLockChange,
    onChangePassword: handleChangePassword,
    sessions,
    onRevokeSession: handleRevokeSession,
    onLock: handleLock,
    onRegenerateRecoveryCode: handleRegenerateRecoveryCode,
  };
}

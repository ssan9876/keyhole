import { useCallback, useEffect, useState } from "react";
import type { ApiClient } from "../vault/api.js";
import {
  createUser,
  deleteUser,
  listUsers,
  loadAudit,
  loadCollectionOverview,
  reissueInvite,
  resetUser,
  setUserStatus,
  type AdminUser,
  type AuditEntry,
  type CollectionOverview,
  type Invite,
} from "../vault/admin.js";
import type { PendingGrant } from "../vault/collections.js";
import type { AdminScreenProps } from "./screens/AdminScreen.js";

/** Matches the server's own page size default closely enough for a human
 *  scrolling a table -- there is no protocol reason for this exact number,
 *  just "a screenful or two, not everything at once". */
const AUDIT_PAGE_SIZE = 50;

/**
 * The admin-console controller: state and handlers for the Admin tab, kept
 * out of VaultScreen for the same reason useCollectionsPanel and
 * useSettingsPanel are -- a screen with a real second responsibility inline
 * becomes untestable without mounting the whole thing, and two prior reviews
 * in this plan already pushed wiring out of VaultScreen once each.
 *
 * Unlike those two, this hook takes no `session`: every function in
 * vault/admin.js depends on nothing but `{ api }` (see admin.ts's own
 * comment -- an admin holds no ability to read another user's vault, which
 * is enforced cryptographically, not by anything this hook could check). Do
 * not add a session parameter here "for consistency" with the other two
 * panels; there is nothing here for it to do.
 *
 * Returns exactly the props `AdminScreen` needs, so a caller renders it as
 * `<AdminScreen {...useAdminPanel({ api, active })} />` with nothing else to
 * wire up.
 */
export function useAdminPanel({
  api,
  active,
}: {
  api: ApiClient;
  /** Whether the Admin tab is the one currently showing (and the caller
   *  session is really an admin's -- VaultScreen folds that check in here
   *  too, not just into whether the tab button is drawn). Gates the lazy
   *  users/collections/audit load below, same pattern as
   *  useCollectionsPanel's directory load. */
  active: boolean;
}): AdminScreenProps {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [collections, setCollections] = useState<CollectionOverview[]>([]);
  const [pendingGrants, setPendingGrants] = useState<PendingGrant[]>([]);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (!active || loaded) return;
    let cancelled = false;
    void (async () => {
      try {
        const [userList, overview, audit] = await Promise.all([
          listUsers({ api }),
          loadCollectionOverview({ api }),
          loadAudit({ api }, { limit: AUDIT_PAGE_SIZE }),
        ]);
        if (!cancelled) {
          setUsers(userList);
          setCollections(overview.collections);
          setPendingGrants(overview.pendingGrants);
          setAuditEntries(audit);
          setLoaded(true);
        }
      } catch {
        // Best-effort, matching useCollectionsPanel/useSettingsPanel: a
        // failed initial load must not crash the tab. There is no retry
        // button yet -- the sections just stay empty -- but failing open
        // with nothing shown beats a half-populated screen with no
        // indication some of it never arrived.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [active, loaded, api]);

  const handleCreateUser = useCallback(
    async (input: {
      email: string;
      name: string;
      role: "admin" | "user";
    }): Promise<{ user: AdminUser } & Invite> => {
      const result = await createUser({ api }, input);
      setUsers((prev) => [...prev, result.user]);
      return result;
    },
    [api],
  );

  const handleReissueInvite = useCallback(
    async (userId: string): Promise<Invite> => reissueInvite({ api }, userId),
    [api],
  );

  const handleSetStatus = useCallback(
    async (input: { userId: string; status: "active" | "disabled" }): Promise<void> => {
      const updated = await setUserStatus({ api }, input);
      setUsers((prev) => prev.map((user) => (user.id === updated.id ? updated : user)));
    },
    [api],
  );

  const handleReset = useCallback(
    async (input: { userId: string; confirmEmail: string }): Promise<Invite & { message: string }> => {
      const result = await resetUser({ api }, input);
      // The reset has already happened by the time `result` exists: the
      // account's key material and every personal item are destroyed, and
      // `result` is the only place the fresh invite will ever appear
      // (internal/httpapi/admin.go:205-210 -- resetUser returns no user at
      // all, so a refetch is the only way `users` picks up the account's new
      // pending state). If that refetch blips, the reset itself must not be
      // reported as failed and the one-time invite must not be lost with it
      // -- so nothing after `result` is captured may reject this promise.
      await listUsers({ api }).then(setUsers).catch(() => undefined);
      return result;
    },
    [api],
  );

  const handleDelete = useCallback(
    async (userId: string): Promise<void> => {
      await deleteUser({ api }, userId);
      setUsers((prev) => prev.filter((user) => user.id !== userId));
    },
    [api],
  );

  const handleLoadAudit = useCallback(
    async (input: { before?: string }): Promise<void> => {
      const older = await loadAudit({ api }, { ...input, limit: AUDIT_PAGE_SIZE });
      setAuditEntries((prev) => [...prev, ...older]);
    },
    [api],
  );

  return {
    users,
    collections,
    pendingGrants,
    auditEntries,
    onCreateUser: handleCreateUser,
    onReissueInvite: handleReissueInvite,
    onSetStatus: handleSetStatus,
    onReset: handleReset,
    onDelete: handleDelete,
    onLoadAudit: handleLoadAudit,
  };
}

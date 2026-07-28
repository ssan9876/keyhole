import { describe, expect, it } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import type { ApiClient } from "../vault/api.js";
import { fakeApi } from "../vault/test-helpers.js";
import { useAdminPanel } from "./useAdminPanel.js";

function baseUser(over: Record<string, unknown> = {}) {
  return {
    id: "u1",
    email: "bee@example.com",
    name: "Bee",
    role: "user",
    status: "active",
    hasPendingInvite: false,
    createdAt: "2026-06-01T00:00:00Z",
    ...over,
  };
}

describe("useAdminPanel", () => {
  it("does not fetch anything while the Admin tab is inactive", () => {
    // Mirrors useCollectionsPanel's directory load and useSettingsPanel's
    // sessions load: an admin who never opens this tab must not pay for
    // three admin-only requests they will never see the result of.
    let calls = 0;
    const api: ApiClient = fakeApi({
      get: async (path) => {
        calls += 1;
        throw new Error(`unexpected GET ${path}`);
      },
    });

    renderHook(() => useAdminPanel({ api, active: false }));

    expect(calls).toBe(0);
  });

  it("loads users, the collection overview, and the first audit page once the tab becomes active", async () => {
    const api: ApiClient = fakeApi({
      get: async (path) => {
        if (path === "/api/admin/users") return { users: [baseUser()] };
        if (path === "/api/admin/collections") {
          return {
            collections: [
              { id: "c1", name: "Household", createdBy: "u1", createdAt: "2026-06-01T00:00:00Z", memberCount: 1 },
            ],
            pendingGrants: [],
          };
        }
        if (path === "/api/admin/audit?limit=50") {
          return {
            entries: [
              { id: "a1", actorUserId: "u1", action: "user.create", target: "user:u1", metadata: "", createdAt: "2026-07-01T00:00:00Z" },
            ],
          };
        }
        throw new Error(`unexpected GET ${path}`);
      },
    });

    const { result } = renderHook(() => useAdminPanel({ api, active: true }));

    await waitFor(() => expect(result.current.users).toHaveLength(1));
    expect(result.current.users[0]?.email).toBe("bee@example.com");
    expect(result.current.collections).toEqual([
      { id: "c1", name: "Household", createdBy: "u1", createdAt: "2026-06-01T00:00:00Z", memberCount: 1 },
    ]);
    expect(result.current.auditEntries).toHaveLength(1);
  });

  it("appends a newly created user to the list rather than requiring a refetch", async () => {
    const api: ApiClient = fakeApi({
      get: async (path) => {
        if (path === "/api/admin/users") return { users: [] };
        if (path === "/api/admin/collections") return { collections: [], pendingGrants: [] };
        if (path === "/api/admin/audit?limit=50") return { entries: [] };
        throw new Error(`unexpected GET ${path}`);
      },
      post: async (path, body) => {
        if (path === "/api/admin/users") {
          expect(body).toEqual({ email: "cee@example.com", name: "Cee", role: "user" });
          return {
            user: baseUser({ id: "u2", email: "cee@example.com", name: "Cee", hasPendingInvite: true }),
            inviteUrl: "https://vault.example/enroll/tok-2",
            expiresIn: "72h0m0s",
          };
        }
        throw new Error(`unexpected POST ${path}`);
      },
    });

    const { result } = renderHook(() => useAdminPanel({ api, active: true }));
    await waitFor(() => expect(result.current.users).toEqual([]));

    await act(async () => {
      await result.current.onCreateUser({ email: "cee@example.com", name: "Cee", role: "user" });
    });

    expect(result.current.users).toHaveLength(1);
    expect(result.current.users[0]?.email).toBe("cee@example.com");
  });

  it("removes a deleted user from the list without waiting for a refetch", async () => {
    const api: ApiClient = fakeApi({
      get: async (path) => {
        if (path === "/api/admin/users") return { users: [baseUser({ id: "u1" }), baseUser({ id: "u2", email: "cee@example.com" })] };
        if (path === "/api/admin/collections") return { collections: [], pendingGrants: [] };
        if (path === "/api/admin/audit?limit=50") return { entries: [] };
        throw new Error(`unexpected GET ${path}`);
      },
      del: async (path) => {
        expect(path).toBe("/api/admin/users/u1");
        return null;
      },
    });

    const { result } = renderHook(() => useAdminPanel({ api, active: true }));
    await waitFor(() => expect(result.current.users).toHaveLength(2));

    await act(async () => {
      await result.current.onDelete("u1");
    });

    expect(result.current.users.map((u) => u.id)).toEqual(["u2"]);
  });

  it("refetches the user list after a reset, since the reset response carries no updated user", async () => {
    // internal/httpapi/admin.go's reset handler (:200-210) returns only a
    // fresh invite and a message -- no user object -- so this is the only way
    // the hook can pick up the account's new pending state.
    let userListCalls = 0;
    const api: ApiClient = fakeApi({
      get: async (path) => {
        if (path === "/api/admin/users") {
          userListCalls += 1;
          const status = userListCalls === 1 ? "active" : "pending";
          return { users: [baseUser({ status, hasPendingInvite: userListCalls > 1 })] };
        }
        if (path === "/api/admin/collections") return { collections: [], pendingGrants: [] };
        if (path === "/api/admin/audit?limit=50") return { entries: [] };
        throw new Error(`unexpected GET ${path}`);
      },
      post: async (path, body) => {
        if (path === "/api/admin/users/u1/reset") {
          expect(body).toEqual({ confirmEmail: "bee@example.com" });
          return {
            inviteUrl: "https://vault.example/enroll/tok-reset",
            expiresIn: "72h0m0s",
            message: "Key material and personal items destroyed.",
          };
        }
        throw new Error(`unexpected POST ${path}`);
      },
    });

    const { result } = renderHook(() => useAdminPanel({ api, active: true }));
    await waitFor(() => expect(result.current.users[0]?.status).toBe("active"));

    await act(async () => {
      await result.current.onReset({ userId: "u1", confirmEmail: "bee@example.com" });
    });

    expect(userListCalls).toBe(2);
    expect(result.current.users[0]?.status).toBe("pending");
  });

  it("still returns the fresh invite when the follow-up user-list refetch fails", async () => {
    // The reset itself already destroyed the account's key material and
    // personal items by the time this refetch runs -- if the refetch
    // (transiently) fails, the invite must not be lost with it: it exists
    // exactly once, in this response, and cannot be reissued from a failed
    // promise. A reload to recover would also lock the vault.
    const api: ApiClient = fakeApi({
      get: async (path) => {
        if (path === "/api/admin/users") throw new Error("network blip");
        if (path === "/api/admin/collections") return { collections: [], pendingGrants: [] };
        if (path === "/api/admin/audit?limit=50") return { entries: [] };
        throw new Error(`unexpected GET ${path}`);
      },
      post: async (path, body) => {
        if (path === "/api/admin/users/u1/reset") {
          expect(body).toEqual({ confirmEmail: "bee@example.com" });
          return {
            inviteUrl: "https://vault.example/enroll/tok-reset",
            expiresIn: "72h0m0s",
            message: "Key material and personal items destroyed.",
          };
        }
        throw new Error(`unexpected POST ${path}`);
      },
    });

    const { result } = renderHook(() => useAdminPanel({ api, active: true }));

    let outcome: { inviteUrl: string } | undefined;
    await act(async () => {
      outcome = await result.current.onReset({ userId: "u1", confirmEmail: "bee@example.com" });
    });

    expect(outcome?.inviteUrl).toBe("https://vault.example/enroll/tok-reset");
  });

  it("preserves hasPendingInvite when a status change comes back without it", async () => {
    // internal/httpapi/admin.go:164 builds the PATCH response from a bare
    // store.UserSummary{User: user}, leaving HasPendingInvite at its zero
    // value regardless of the account's real state. A whole-object merge of
    // that response over the row by id would erase "Reissue invite" for a
    // pending user the moment an admin toggles their status.
    const api: ApiClient = fakeApi({
      get: async (path) => {
        if (path === "/api/admin/users") {
          return { users: [baseUser({ status: "active", hasPendingInvite: true })] };
        }
        if (path === "/api/admin/collections") return { collections: [], pendingGrants: [] };
        if (path === "/api/admin/audit?limit=50") return { entries: [] };
        throw new Error(`unexpected GET ${path}`);
      },
      patch: async (path, body) => {
        expect(path).toBe("/api/admin/users/u1");
        expect(body).toEqual({ status: "disabled" });
        // The server's real shape: hasPendingInvite always false here, even
        // though the account genuinely still has a pending invite.
        return baseUser({ status: "disabled", hasPendingInvite: false });
      },
    });

    const { result } = renderHook(() => useAdminPanel({ api, active: true }));
    await waitFor(() => expect(result.current.users).toHaveLength(1));

    await act(async () => {
      await result.current.onSetStatus({ userId: "u1", status: "disabled" });
    });

    expect(result.current.users[0]?.status).toBe("disabled");
    expect(result.current.users[0]?.hasPendingInvite).toBe(true);
  });

  it("passes `before` through to loadAudit and appends the older page after the newer one", async () => {
    const api: ApiClient = fakeApi({
      get: async (path) => {
        if (path === "/api/admin/users") return { users: [] };
        if (path === "/api/admin/collections") return { collections: [], pendingGrants: [] };
        if (path === "/api/admin/audit?limit=50") {
          return { entries: [{ id: "a2", actorUserId: "u1", action: "user.login", target: "user:u1", metadata: "", createdAt: "2026-07-10T00:00:00Z" }] };
        }
        if (path === "/api/admin/audit?limit=50&before=2026-07-10T00%3A00%3A00Z") {
          return { entries: [{ id: "a1", actorUserId: "u1", action: "user.create", target: "user:u1", metadata: "", createdAt: "2026-07-01T00:00:00Z" }] };
        }
        throw new Error(`unexpected GET ${path}`);
      },
    });

    const { result } = renderHook(() => useAdminPanel({ api, active: true }));
    await waitFor(() => expect(result.current.auditEntries).toHaveLength(1));

    await act(async () => {
      await result.current.onLoadAudit({ before: "2026-07-10T00:00:00Z" });
    });

    expect(result.current.auditEntries.map((e) => e.id)).toEqual(["a2", "a1"]);
  });
});

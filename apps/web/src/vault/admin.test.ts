import { describe, expect, it } from "vitest";
import { ApiError } from "./api.js";
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
} from "./admin.js";
import { fakeApi } from "./test-helpers.js";

function adminUser(over: Partial<AdminUser> = {}): AdminUser {
  return {
    id: "u1",
    email: "a@example.com",
    name: "A",
    role: "user",
    status: "active",
    hasPendingInvite: false,
    createdAt: "2026-07-27T00:00:00Z",
    ...over,
  };
}

describe("listUsers", () => {
  it("unwraps the users array from the list response", async () => {
    const api = fakeApi({
      get: async (path) => {
        expect(path).toBe("/api/admin/users");
        return { users: [adminUser({ id: "u1" }), adminUser({ id: "u2" })] };
      },
    });

    await expect(listUsers({ api })).resolves.toEqual([
      adminUser({ id: "u1" }),
      adminUser({ id: "u2" }),
    ]);
  });
});

describe("createUser", () => {
  it("returns the one-time invite url from the create response", async () => {
    // Nothing else ever produces it: internal/httpapi/admin.go:103-105 states
    // the raw token cannot be recovered from the database afterwards.
    const api = fakeApi({
      post: async (path) => {
        expect(path).toBe("/api/admin/users");
        return {
          user: adminUser({ hasPendingInvite: true }),
          inviteUrl: "https://vault.example/enroll/tok-abc123",
          expiresIn: "72h0m0s",
        };
      },
    });

    const result = await createUser({ api }, { email: "b@example.com", name: "B", role: "user" });

    expect(result.inviteUrl).toBe("https://vault.example/enroll/tok-abc123");
    expect(result.expiresIn).toBe("72h0m0s");
    expect(result.user).toEqual(adminUser({ hasPendingInvite: true }));
  });

  it("defaults a new user's role to user rather than admin", async () => {
    // Defaulting the other way would silently make every invited person an
    // administrator (internal/httpapi/admin.go:72-74 does the same default
    // server-side, but the client must not rely on that alone).
    let sentRole: unknown;
    const api = fakeApi({
      post: async (_path, body) => {
        sentRole = (body as { role?: unknown } | undefined)?.role;
        return { user: adminUser(), inviteUrl: "u", expiresIn: "1h" };
      },
    });

    await createUser({ api }, { email: "b@example.com", name: "B" });

    expect(sentRole).toBe("user");
  });

  it("sends an explicitly chosen admin role rather than overriding it", async () => {
    let sentRole: unknown;
    const api = fakeApi({
      post: async (_path, body) => {
        sentRole = (body as { role?: unknown } | undefined)?.role;
        return { user: adminUser({ role: "admin" }), inviteUrl: "u", expiresIn: "1h" };
      },
    });

    await createUser({ api }, { email: "b@example.com", name: "B", role: "admin" });

    expect(sentRole).toBe("admin");
  });
});

describe("reissueInvite", () => {
  it("posts to the per-user invite endpoint and returns the new invite", async () => {
    const api = fakeApi({
      post: async (path) => {
        expect(path).toBe("/api/admin/users/u1/invite");
        return { inviteUrl: "https://vault.example/enroll/tok-2", expiresIn: "72h0m0s" };
      },
    });

    await expect(reissueInvite({ api }, "u1")).resolves.toEqual({
      inviteUrl: "https://vault.example/enroll/tok-2",
      expiresIn: "72h0m0s",
    });
  });
});

describe("setUserStatus", () => {
  it("PATCHes the user's status and returns the updated user", async () => {
    const api = fakeApi({
      patch: async (path, body) => {
        expect(path).toBe("/api/admin/users/u1");
        expect(body).toEqual({ status: "disabled" });
        return adminUser({ status: "disabled" });
      },
    });

    await expect(setUserStatus({ api }, { userId: "u1", status: "disabled" })).resolves.toEqual(
      adminUser({ status: "disabled" }),
    );
  });
});

describe("resetUser", () => {
  it("sends confirmEmail on reset, so the server's own check can run", async () => {
    // The dialog's typed confirmation is re-checked server-side because an
    // irreversible action that destroys a vault must not hinge on a client
    // check (internal/httpapi/admin.go:191-198).
    let sent: Record<string, unknown> | undefined;
    const api = fakeApi({
      post: async (path, body) => {
        if (path === "/api/admin/users/u1/reset") sent = body as Record<string, unknown>;
        return { inviteUrl: "u", expiresIn: "1h", message: "done" };
      },
    });

    await resetUser({ api }, { userId: "u1", confirmEmail: "bee@example.com" });

    expect(sent?.["confirmEmail"]).toBe("bee@example.com");
  });

  it("returns the invite and the destructive-action message together", async () => {
    const api = fakeApi({
      post: async () => ({
        inviteUrl: "https://vault.example/enroll/tok-3",
        expiresIn: "72h0m0s",
        message: "Key material and personal items destroyed.",
      }),
    });

    await expect(
      resetUser({ api }, { userId: "u1", confirmEmail: "bee@example.com" }),
    ).resolves.toEqual({
      inviteUrl: "https://vault.example/enroll/tok-3",
      expiresIn: "72h0m0s",
      message: "Key material and personal items destroyed.",
    });
  });
});

describe("deleteUser", () => {
  it("DELETEs the per-user endpoint", async () => {
    const api = fakeApi({
      del: async (path) => {
        expect(path).toBe("/api/admin/users/u1");
        return null;
      },
    });

    await expect(deleteUser({ api }, "u1")).resolves.toBeUndefined();
  });

  it("surfaces the server's explanation when deleting a referenced user conflicts", async () => {
    // 409 conflict with "this account created a collection or granted a
    // membership..." (internal/httpapi/admin.go:222-229). A generic "could
    // not delete" leaves the operator with no next step.
    const api = fakeApi({
      del: async () => {
        throw new ApiError(
          "conflict",
          409,
          "this account created a collection or granted a membership. " +
            "Delete or reassign those collections first, or disable the account instead.",
          {},
        );
      },
    });

    await expect(deleteUser({ api }, "u2")).rejects.toThrow(/created a collection/);
  });
});

describe("loadAudit", () => {
  it("passes limit and before through to the audit query string", async () => {
    let path = "";
    const api = fakeApi({
      get: async (p) => {
        path = p;
        return { entries: [] };
      },
    });

    await loadAudit({ api }, { limit: 50, before: "2026-07-01T00:00:00Z" });

    expect(path).toBe("/api/admin/audit?limit=50&before=2026-07-01T00%3A00%3A00Z");
  });

  it("requests the audit log with no query string when given no arguments", async () => {
    let path = "";
    const api = fakeApi({
      get: async (p) => {
        path = p;
        return { entries: [] };
      },
    });

    await loadAudit({ api });

    expect(path).toBe("/api/admin/audit");
  });

  it("unwraps the entries array from the response envelope", async () => {
    const entry = {
      id: "a1",
      actorUserId: "u1",
      action: "user.create",
      target: "user:u2",
      metadata: "",
      createdAt: "2026-07-27T00:00:00Z",
    };
    const api = fakeApi({
      get: async () => ({ entries: [entry] }),
    });

    await expect(loadAudit({ api })).resolves.toEqual([entry]);
  });
});

describe("loadCollectionOverview", () => {
  it("requests the admin collections endpoint and returns collections with pending grants", async () => {
    const collections = [
      { id: "c1", name: "Household", createdBy: "u1", createdAt: "2026-07-27T00:00:00Z", memberCount: 2 },
    ];
    const pendingGrants = [
      {
        collectionId: "c1",
        collectionName: "Household",
        userId: "u2",
        role: "member",
        requestedBy: "u1",
        createdAt: "2026-07-27T00:00:00Z",
      },
    ];
    const api = fakeApi({
      get: async (path) => {
        expect(path).toBe("/api/admin/collections");
        return { collections, pendingGrants };
      },
    });

    await expect(loadCollectionOverview({ api })).resolves.toEqual({ collections, pendingGrants });
  });
});

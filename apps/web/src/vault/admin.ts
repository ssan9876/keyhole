/**
 * Typed client for user administration and the audit log.
 *
 * Eight thin wrappers over `internal/httpapi/admin.go`, which is the contract:
 * every field name, status code, and error message here mirrors that file.
 *
 * `deps` is `{ api: ApiClient }` and nothing else. An admin holds no ability to
 * read another user's vault — that is enforced cryptographically, by
 * `adminUserJSON` having no field for key material, not by a permission check
 * here. This module must never become the place that changes: it must not add
 * fields the server does not send, and must not widen a type to swallow one
 * that arrives unexpectedly.
 */
import type { ApiClient } from "./api.js";
import type { PendingGrant } from "./collections.js";

type Deps = { api: ApiClient };

/** Mirrors adminUserJSON (internal/httpapi/admin.go:20-28) field for field. */
export interface AdminUser {
  id: string;
  email: string;
  name: string;
  role: string;
  status: string;
  hasPendingInvite: boolean;
  createdAt: string;
}

/**
 * The raw invite token exists exactly once, in the response that carries this
 * shape, and cannot be recovered from the database afterwards — by an admin
 * or by anyone who steals it. Nothing else ever produces it.
 */
export interface Invite {
  inviteUrl: string;
  expiresIn: string;
}

export interface AuditEntry {
  id: string;
  actorUserId: string;
  action: string;
  target: string;
  metadata: string;
  createdAt: string;
}

export interface CollectionOverview {
  id: string;
  name: string;
  createdBy: string;
  createdAt: string;
  memberCount: number;
}

export async function listUsers(deps: Deps): Promise<AdminUser[]> {
  const response = await deps.api.get<{ users: AdminUser[] }>("/api/admin/users");
  return response.users;
}

export async function createUser(
  deps: Deps,
  input: { email: string; name: string; role?: "admin" | "user" },
): Promise<{ user: AdminUser } & Invite> {
  return deps.api.post<{ user: AdminUser } & Invite>("/api/admin/users", {
    email: input.email,
    name: input.name,
    // Mirrors the server's own default (internal/httpapi/admin.go:72-74): an
    // empty role becomes "user" there too. Defaulting the other way here
    // would silently make every invited person an administrator.
    role: input.role ?? "user",
  });
}

export async function reissueInvite(deps: Deps, userId: string): Promise<Invite> {
  return deps.api.post<Invite>(`/api/admin/users/${userId}/invite`);
}

export async function setUserStatus(
  deps: Deps,
  input: { userId: string; status: "active" | "disabled" },
): Promise<AdminUser> {
  return deps.api.patch<AdminUser>(`/api/admin/users/${input.userId}`, {
    status: input.status,
  });
}

/**
 * Destroys an account's key material and personal items and issues a fresh
 * invite so the user can enrol again from scratch.
 *
 * `confirmEmail` is sent verbatim so the server's own check can run
 * (internal/httpapi/admin.go:194): an irreversible action that destroys a
 * vault must not hinge on a client-side check alone, and the server rejects
 * a mismatch with 400 regardless of what this function does.
 */
export async function resetUser(
  deps: Deps,
  input: { userId: string; confirmEmail: string },
): Promise<Invite & { message: string }> {
  return deps.api.post<Invite & { message: string }>(`/api/admin/users/${input.userId}/reset`, {
    confirmEmail: input.confirmEmail,
  });
}

/**
 * Deletes an account outright.
 *
 * `ApiError` is left to propagate rather than translated: a 409 `conflict`
 * here carries the server's own explanation of what to do next (delete or
 * reassign the collection, or disable the account instead), and a generic
 * "could not delete" would throw that away.
 */
export async function deleteUser(deps: Deps, userId: string): Promise<void> {
  await deps.api.del(`/api/admin/users/${userId}`);
}

export async function loadAudit(
  deps: Deps,
  input?: { limit?: number; before?: string },
): Promise<AuditEntry[]> {
  const params = new URLSearchParams();
  if (input?.limit !== undefined) params.set("limit", String(input.limit));
  if (input?.before !== undefined) params.set("before", input.before);
  const query = params.toString();
  const response = await deps.api.get<{ entries: AuditEntry[] }>(
    `/api/admin/audit${query ? `?${query}` : ""}`,
  );
  return response.entries;
}

/**
 * The membership-graph view: every collection and every grant still waiting
 * for a manager to fulfil it. Carries no sealed keys — an admin who is not a
 * member holds none, and the server has none to give.
 */
export async function loadCollectionOverview(
  deps: Deps,
): Promise<{ collections: CollectionOverview[]; pendingGrants: PendingGrant[] }> {
  return deps.api.get<{ collections: CollectionOverview[]; pendingGrants: PendingGrant[] }>(
    "/api/admin/collections",
  );
}

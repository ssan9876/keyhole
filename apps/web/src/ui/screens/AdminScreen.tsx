import { useId, useState } from "react";
import type { FormEvent } from "react";
import { ApiError, NetworkError } from "../../vault/api.js";
import type { AdminUser, AuditEntry, CollectionOverview, Invite } from "../../vault/admin.js";
import type { PendingGrant } from "../../vault/collections.js";
import { Button } from "../components/Button.js";
import { Confirm } from "../components/Confirm.js";
import { Field } from "../components/Field.js";

export interface AdminScreenProps {
  users: AdminUser[];
  collections: CollectionOverview[];
  pendingGrants: PendingGrant[];
  /** Newest first. "Load older" (below) pages backwards from the oldest entry
   *  currently here. */
  auditEntries: AuditEntry[];
  onCreateUser(input: {
    email: string;
    name: string;
    role: "admin" | "user";
  }): Promise<{ user: AdminUser } & Invite>;
  onReissueInvite(userId: string): Promise<Invite>;
  onSetStatus(input: { userId: string; status: "active" | "disabled" }): Promise<void>;
  /** Mirrors vault/admin.js's resetUser signature exactly, `before` and all --
   *  this screen has nothing to add to it. */
  onReset(input: { userId: string; confirmEmail: string }): Promise<Invite & { message: string }>;
  onDelete(userId: string): Promise<void>;
  onLoadAudit(input: { before?: string }): Promise<void>;
}

/**
 * Mirrors SettingsScreen's describeFailure verbatim: ApiError.message is
 * already the server's own human-readable explanation
 * (internal/httpapi/errors.go) -- codes are for branching, never for display
 * -- so both branches show it verbatim. NetworkError gets copy of its own
 * because nothing reached the server to explain itself. This is the function
 * that makes "a 409 on delete shows the server's own message" true: it never
 * substitutes a generic string for a message an ApiError actually carried.
 */
function describeFailure(failure: unknown, fallback: string): string {
  if (failure instanceof NetworkError) return failure.message;
  if (failure instanceof ApiError) return failure.message;
  return fallback;
}

type RevealedInvite = { email: string; invite: Invite; message?: string };

/**
 * The raw invite token exists exactly once, in the response this reads from
 * (internal/httpapi/admin.go:103-105 for create, :136-139 for reissue,
 * :205-210 for reset) -- it cannot be recovered from the database afterwards,
 * by an admin or by anyone who steals it. It is rendered in a read-only,
 * selectable field so it can always be copied by hand: the Copy button below
 * is a convenience layered on top, never the only way to get it, because
 * `navigator.clipboard` is undefined in insecure contexts and in jsdom, and a
 * copy button that silently does nothing would be worse than no button at
 * all.
 */
function InviteReveal({ reveal, onDismiss }: { reveal: RevealedInvite; onDismiss(): void }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "unavailable">("idle");
  const fieldId = useId();

  async function handleCopy(): Promise<void> {
    if (typeof navigator === "undefined" || navigator.clipboard === undefined) {
      setCopyState("unavailable");
      return;
    }
    try {
      await navigator.clipboard.writeText(reveal.invite.inviteUrl);
      setCopyState("copied");
    } catch {
      setCopyState("unavailable");
    }
  }

  return (
    <div
      role="group"
      aria-label="One-time invite link"
      style={{
        border: "1px solid var(--rule-strong)",
        padding: "var(--space-4)",
        marginBottom: "var(--space-6)",
      }}
    >
      <p style={{ marginTop: 0 }}>
        Hand this over out of band. It cannot be shown again &mdash; reissue a new one if it is
        lost.
      </p>
      {reveal.message !== undefined && (
        <p style={{ color: "var(--ink-muted)" }}>{reveal.message}</p>
      )}
      <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-2)" }}>
        <label htmlFor={fieldId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
          Invite link for {reveal.email}
        </label>
        <input
          id={fieldId}
          readOnly
          value={reveal.invite.inviteUrl}
          onFocus={(e) => e.currentTarget.select()}
          style={{
            font: "inherit",
            fontFamily: "var(--font-mono)",
            padding: "var(--space-2)",
            border: "1px solid var(--rule)",
            background: "transparent",
            color: "var(--ink)",
            width: "100%",
          }}
        />
      </div>
      <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
        <Button type="button" variant="quiet" onClick={() => void handleCopy()}>
          Copy link
        </Button>
        <Button type="button" variant="quiet" onClick={onDismiss}>
          Done
        </Button>
        {copyState === "copied" && <span style={{ color: "var(--ink-muted)" }}>Copied.</span>}
        {copyState === "unavailable" && (
          <span style={{ color: "var(--ink-muted)" }}>
            Copy isn&rsquo;t available here &mdash; select the text above and copy it by hand.
          </span>
        )}
      </div>
    </div>
  );
}

function CreateUserForm({
  onCreateUser,
  onCreated,
}: {
  onCreateUser: AdminScreenProps["onCreateUser"];
  onCreated(reveal: RevealedInvite): void;
}) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<"admin" | "user">("user");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const roleId = useId();

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await onCreateUser({ email, name, role });
      onCreated({
        email: result.user.email,
        invite: { inviteUrl: result.inviteUrl, expiresIn: result.expiresIn },
      });
      setEmail("");
      setName("");
      setRole("user");
    } catch (failure) {
      setError(describeFailure(failure, "Could not create that user"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} style={{ marginBottom: "var(--space-4)" }}>
      <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} required />
      <Field
        label="Email"
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        required
      />
      <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-4)" }}>
        <label htmlFor={roleId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
          Role
        </label>
        <select
          id={roleId}
          value={role}
          onChange={(e) => setRole(e.target.value === "admin" ? "admin" : "user")}
        >
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      {error !== null && (
        <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
          {error}
        </p>
      )}
      <Button type="submit" disabled={busy}>
        {busy ? "Creating…" : "Create user"}
      </Button>
    </form>
  );
}

function UserRow({
  user,
  onReissueInvite,
  onSetStatus,
  onRequestReset,
  onRequestDelete,
  onInviteRevealed,
}: {
  user: AdminUser;
  onReissueInvite: AdminScreenProps["onReissueInvite"];
  onSetStatus: AdminScreenProps["onSetStatus"];
  onRequestReset(): void;
  onRequestDelete(): void;
  onInviteRevealed(reveal: RevealedInvite): void;
}) {
  const [reissueBusy, setReissueBusy] = useState(false);
  const [reissueError, setReissueError] = useState<string | null>(null);
  const [statusBusy, setStatusBusy] = useState(false);
  const [statusError, setStatusError] = useState<string | null>(null);

  async function handleReissue(): Promise<void> {
    setReissueBusy(true);
    setReissueError(null);
    try {
      const invite = await onReissueInvite(user.id);
      onInviteRevealed({ email: user.email, invite });
    } catch (failure) {
      setReissueError(describeFailure(failure, "Could not reissue an invite"));
    } finally {
      setReissueBusy(false);
    }
  }

  async function handleToggleStatus(): Promise<void> {
    setStatusBusy(true);
    setStatusError(null);
    try {
      await onSetStatus({
        userId: user.id,
        status: user.status === "active" ? "disabled" : "active",
      });
    } catch (failure) {
      setStatusError(describeFailure(failure, "Could not change that account's status"));
    } finally {
      setStatusBusy(false);
    }
  }

  return (
    <tr style={{ borderTop: "1px solid var(--rule)" }}>
      <td style={{ padding: "var(--space-2) var(--space-2) var(--space-2) 0" }}>{user.name}</td>
      <td>{user.email}</td>
      <td>{user.role}</td>
      <td>{user.status}</td>
      <td>
        <div style={{ display: "flex", gap: "var(--space-2)", flexWrap: "wrap" }}>
          {user.hasPendingInvite && (
            <Button
              type="button"
              variant="quiet"
              disabled={reissueBusy}
              onClick={() => void handleReissue()}
            >
              Reissue invite
            </Button>
          )}
          <Button
            type="button"
            variant="quiet"
            disabled={statusBusy}
            onClick={() => void handleToggleStatus()}
          >
            {user.status === "active" ? "Disable" : "Activate"}
          </Button>
          <Button type="button" variant="quiet" onClick={onRequestReset}>
            Reset
          </Button>
          <Button type="button" variant="danger" onClick={onRequestDelete}>
            Delete
          </Button>
        </div>
        {reissueError !== null && (
          <p role="alert" style={{ color: "var(--danger)" }}>
            {reissueError}
          </p>
        )}
        {statusError !== null && (
          <p role="alert" style={{ color: "var(--danger)" }}>
            {statusError}
          </p>
        )}
      </td>
    </tr>
  );
}

function UsersSection({
  users,
  onCreateUser,
  onReissueInvite,
  onSetStatus,
  onReset,
  onDelete,
  onInviteRevealed,
}: {
  users: AdminUser[];
  onCreateUser: AdminScreenProps["onCreateUser"];
  onReissueInvite: AdminScreenProps["onReissueInvite"];
  onSetStatus: AdminScreenProps["onSetStatus"];
  onReset: AdminScreenProps["onReset"];
  onDelete: AdminScreenProps["onDelete"];
  onInviteRevealed(reveal: RevealedInvite): void;
}) {
  const [creating, setCreating] = useState(false);
  // Confirm dialogs and their errors live here, one level above the row that
  // triggers them, for the same reason CollectionsScreen's remove-member
  // dialog does: onConfirm closes the dialog immediately, so an error from
  // the request it kicked off has nowhere to land inside the (now unmounted)
  // dialog -- it has to surface on the section itself.
  const [resetTarget, setResetTarget] = useState<AdminUser | null>(null);
  const [resetError, setResetError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<AdminUser | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  return (
    <section style={{ marginBottom: "var(--space-6)" }}>
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          marginBottom: "var(--space-4)",
        }}
      >
        <h2 style={{ fontSize: "1rem", fontWeight: 600, margin: 0 }}>Users</h2>
        <Button type="button" variant="quiet" onClick={() => setCreating((open) => !open)}>
          Add user
        </Button>
      </header>

      {creating && (
        <CreateUserForm
          onCreateUser={onCreateUser}
          onCreated={(reveal) => {
            onInviteRevealed(reveal);
            setCreating(false);
          }}
        />
      )}

      {users.length === 0 ? (
        <p style={{ color: "var(--ink-muted)" }}>No users yet.</p>
      ) : (
        <table aria-label="Users" style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={{ textAlign: "left" }}>Name</th>
              <th style={{ textAlign: "left" }}>Email</th>
              <th style={{ textAlign: "left" }}>Role</th>
              <th style={{ textAlign: "left" }}>Status</th>
              <th style={{ textAlign: "left" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <UserRow
                key={user.id}
                user={user}
                onReissueInvite={onReissueInvite}
                onSetStatus={onSetStatus}
                onRequestReset={() => {
                  setResetTarget(user);
                  setResetError(null);
                }}
                onRequestDelete={() => {
                  setDeleteTarget(user);
                  setDeleteError(null);
                }}
                onInviteRevealed={onInviteRevealed}
              />
            ))}
          </tbody>
        </table>
      )}

      {resetTarget !== null && (
        <Confirm
          title={`Reset ${resetTarget.name}'s account?`}
          body={
            <>
              <p style={{ marginTop: 0 }}>
                This permanently destroys this account&rsquo;s key material, every personal item,
                and every collection membership it holds.
              </p>
              <p style={{ marginBottom: 0 }}>
                After the account enrols again, collection access must be re-granted from
                scratch.
              </p>
            </>
          }
          confirmLabel="Reset this account"
          requireTyped={resetTarget.email}
          onCancel={() => setResetTarget(null)}
          onConfirm={() => {
            const target = resetTarget;
            setResetTarget(null);
            void (async () => {
              try {
                const result = await onReset({ userId: target.id, confirmEmail: target.email });
                onInviteRevealed({
                  email: target.email,
                  invite: { inviteUrl: result.inviteUrl, expiresIn: result.expiresIn },
                  message: result.message,
                });
              } catch (failure) {
                setResetError(describeFailure(failure, "Could not reset that account"));
              }
            })();
          }}
        />
      )}
      {resetError !== null && (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {resetError}
        </p>
      )}

      {deleteTarget !== null && (
        <Confirm
          title={`Delete ${deleteTarget.name}?`}
          body="This permanently deletes the account. This cannot be undone."
          confirmLabel="Delete account"
          onCancel={() => setDeleteTarget(null)}
          onConfirm={() => {
            const target = deleteTarget;
            setDeleteTarget(null);
            void (async () => {
              try {
                await onDelete(target.id);
              } catch (failure) {
                // The server's own message (409: "this account created a
                // collection or granted a membership...") names the obstacle
                // and the next step. describeFailure passes it through
                // verbatim -- a generic "could not delete" here would throw
                // that away.
                setDeleteError(describeFailure(failure, "Could not delete this account"));
              }
            })();
          }}
        />
      )}
      {deleteError !== null && (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {deleteError}
        </p>
      )}
    </section>
  );
}

function CollectionsOverviewSection({
  collections,
  pendingGrants,
}: {
  collections: CollectionOverview[];
  pendingGrants: PendingGrant[];
}) {
  return (
    <section style={{ marginBottom: "var(--space-6)" }}>
      <h2 style={{ fontSize: "1rem", fontWeight: 600 }}>Collections overview</h2>
      {collections.length === 0 ? (
        <p style={{ color: "var(--ink-muted)" }}>No collections yet.</p>
      ) : (
        <table
          aria-label="Collections overview"
          style={{ width: "100%", borderCollapse: "collapse" }}
        >
          <thead>
            <tr>
              <th style={{ textAlign: "left" }}>Name</th>
              <th style={{ textAlign: "left" }}>Created by</th>
              <th style={{ textAlign: "left" }}>Created</th>
              <th style={{ textAlign: "left" }}>Members</th>
            </tr>
          </thead>
          <tbody>
            {collections.map((collection) => (
              <tr key={collection.id} style={{ borderTop: "1px solid var(--rule)" }}>
                <td>{collection.name}</td>
                <td>{collection.createdBy}</td>
                <td>{collection.createdAt}</td>
                <td>{collection.memberCount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {pendingGrants.length > 0 && (
        <p style={{ color: "var(--ink-muted)" }}>
          {pendingGrants.length} pending grant{pendingGrants.length === 1 ? "" : "s"} awaiting
          fulfilment.
        </p>
      )}
    </section>
  );
}

function AuditLogSection({
  auditEntries,
  onLoadAudit,
}: {
  auditEntries: AuditEntry[];
  onLoadAudit: AdminScreenProps["onLoadAudit"];
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleLoadOlder(): Promise<void> {
    // Newest first, so the oldest loaded entry is the last one in the array
    // -- that is the boundary the server needs to page backwards from.
    const oldest = auditEntries[auditEntries.length - 1];
    if (oldest === undefined) return;
    setBusy(true);
    setError(null);
    try {
      await onLoadAudit({ before: oldest.createdAt });
    } catch (failure) {
      setError(describeFailure(failure, "Could not load older entries"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2 style={{ fontSize: "1rem", fontWeight: 600 }}>Audit log</h2>
      {auditEntries.length === 0 ? (
        <p style={{ color: "var(--ink-muted)" }}>No audit entries yet.</p>
      ) : (
        <table aria-label="Audit log" style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={{ textAlign: "left" }}>Actor</th>
              <th style={{ textAlign: "left" }}>Action</th>
              <th style={{ textAlign: "left" }}>Target</th>
              <th style={{ textAlign: "left" }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {auditEntries.map((entry) => (
              <tr key={entry.id} style={{ borderTop: "1px solid var(--rule)" }}>
                <td>{entry.actorUserId}</td>
                <td>{entry.action}</td>
                <td>{entry.target}</td>
                <td>{entry.createdAt}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <Button
        type="button"
        variant="quiet"
        disabled={busy || auditEntries.length === 0}
        onClick={() => void handleLoadOlder()}
      >
        {busy ? "Loading…" : "Load older"}
      </Button>
      {error !== null && (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {error}
        </p>
      )}
    </section>
  );
}

export function AdminScreen({
  users,
  collections,
  pendingGrants,
  auditEntries,
  onCreateUser,
  onReissueInvite,
  onSetStatus,
  onReset,
  onDelete,
  onLoadAudit,
}: AdminScreenProps) {
  const [reveal, setReveal] = useState<RevealedInvite | null>(null);

  return (
    <div>
      {reveal !== null && <InviteReveal reveal={reveal} onDismiss={() => setReveal(null)} />}

      <UsersSection
        users={users}
        onCreateUser={onCreateUser}
        onReissueInvite={onReissueInvite}
        onSetStatus={onSetStatus}
        onReset={onReset}
        onDelete={onDelete}
        onInviteRevealed={setReveal}
      />

      <CollectionsOverviewSection collections={collections} pendingGrants={pendingGrants} />

      <AuditLogSection auditEntries={auditEntries} onLoadAudit={onLoadAudit} />
    </div>
  );
}

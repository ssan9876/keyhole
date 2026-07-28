import { useId, useState } from "react";
import type { CollectionSummary, Member, PendingGrant } from "../../vault/collections.js";
import type { DirectoryEntry } from "../../vault/directory.js";
import { Button } from "../components/Button.js";
import { Confirm } from "../components/Confirm.js";
import { Field } from "../components/Field.js";

export interface CollectionsScreenProps {
  /** session.user.role. Gates the Create collection button, which mirrors a
   *  server rule (POST /api/collections is requireAdmin) -- hiding it here is
   *  a UI courtesy, not the security boundary; the server enforces that. */
  role: string;
  collections: CollectionSummary[];
  pendingGrants: PendingGrant[];
  directory: DirectoryEntry[];
  /** Members of `selectedCollectionId`, loaded by the caller. */
  members: Member[];
  selectedCollectionId: string | null;
  onSelectCollection(collectionId: string | null): void;
  onCreateCollection(name: string): Promise<void>;
  onFulfil(grant: PendingGrant, recipient: DirectoryEntry): Promise<void>;
  onAddMember(input: {
    collectionId: string;
    recipient: DirectoryEntry;
    role: "manager" | "member";
  }): Promise<"granted" | "pending">;
  onRemoveMember(input: { collectionId: string; userId: string }): Promise<void>;
}

function PendingGrantRow({
  grant,
  directory,
  onFulfil,
}: {
  grant: PendingGrant;
  directory: DirectoryEntry[];
  onFulfil: CollectionsScreenProps["onFulfil"];
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The recipient this grant is *for*, not merely "someone in the
  // directory": sealing to the wrong person is silent, so the id must match
  // exactly.
  const recipient = directory.find((entry) => entry.id === grant.userId) ?? null;

  return (
    <li style={{ borderTop: "1px solid var(--rule)", padding: "var(--space-2) 0" }}>
      <div>
        {grant.collectionName} &middot; {recipient?.name ?? grant.userId}
      </div>
      {recipient !== null ? (
        <>
          {/* Design spec 3.9.1's mitigation for a substituted public key is two
              people comparing this aloud -- it must be visible here, before the
              seal happens, not only in a confirmation after the fact. */}
          <div
            style={{
              color: "var(--ink-muted)",
              fontSize: "0.875rem",
              fontFamily: "var(--font-mono)",
            }}
          >
            {recipient.fingerprint}
          </div>
          <Button
            type="button"
            variant="quiet"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setError(null);
              try {
                await onFulfil(grant, recipient);
              } catch (failure) {
                setError(failure instanceof Error ? failure.message : "Could not grant access");
              } finally {
                setBusy(false);
              }
            }}
          >
            Grant access
          </Button>
        </>
      ) : (
        <p style={{ color: "var(--ink-muted)" }}>
          This person is no longer in the directory, so this device cannot seal a key to them.
        </p>
      )}
      {error !== null && (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {error}
        </p>
      )}
    </li>
  );
}

function MembersPanel({
  collection,
  members,
  directory,
  onAddMember,
  onRemoveMember,
}: {
  collection: CollectionSummary;
  members: Member[];
  directory: DirectoryEntry[];
  onAddMember: CollectionsScreenProps["onAddMember"];
  onRemoveMember: CollectionsScreenProps["onRemoveMember"];
}) {
  const [removing, setRemoving] = useState<Member | null>(null);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [recipientId, setRecipientId] = useState("");
  const [newRole, setNewRole] = useState<"member" | "manager">("member");
  const [addBusy, setAddBusy] = useState(false);
  const [addNotice, setAddNotice] = useState<string | null>(null);
  const [addError, setAddError] = useState<string | null>(null);
  const recipientSelectId = useId();
  const roleSelectId = useId();

  // A UI courtesy, matching the server's own requireManager check
  // (internal/httpapi/collections.go) on add/remove -- not a substitute for
  // it, since the request would still fail server-side for a non-manager.
  const isManager = collection.role === "manager";
  const chosenRecipient = directory.find((entry) => entry.id === recipientId) ?? null;

  return (
    <div style={{ marginTop: "var(--space-3)", paddingLeft: "var(--space-4)" }}>
      <h3 style={{ fontSize: "0.875rem", margin: 0 }}>Members</h3>
      {members.length === 0 ? (
        <p style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>No members loaded.</p>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
          {members.map((member) => {
            const entry = directory.find((d) => d.id === member.userId);
            return (
              <li
                key={member.userId}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "var(--space-1) 0",
                }}
              >
                <div>
                  <span style={{ display: "block" }}>
                    {member.name} &middot; {member.role}
                  </span>
                  {entry !== undefined && (
                    <span
                      style={{
                        color: "var(--ink-muted)",
                        fontSize: "0.75rem",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      {entry.fingerprint}
                    </span>
                  )}
                </div>
                {isManager && (
                  <Button
                    type="button"
                    variant="quiet"
                    onClick={() => {
                      setRemoving(member);
                      setRemoveError(null);
                    }}
                  >
                    Remove
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
      )}

      {removing !== null && (
        <Confirm
          title={`Remove ${removing.name}?`}
          body="Removing a member does not rotate the collection key. Someone who kept a copy can still read what they already had. If this removal is adversarial, change the shared passwords too."
          confirmLabel="Remove member"
          onCancel={() => setRemoving(null)}
          onConfirm={() => {
            const target = removing;
            setRemoving(null);
            setRemoveError(null);
            // The dialog closes immediately either way -- if the request
            // then fails (stale session, a server-side requireManager
            // mismatch, a dropped connection), the manager still needs to
            // know the removal did not happen. This is the one action in
            // this screen whose entire justification is "if this removal is
            // adversarial, change the shared passwords too": failing silent
            // here is the wrong outcome.
            void (async () => {
              try {
                await onRemoveMember({ collectionId: collection.id, userId: target.userId });
              } catch (failure) {
                setRemoveError(
                  failure instanceof Error ? failure.message : "Could not remove that member",
                );
              }
            })();
          }}
        />
      )}
      {removeError !== null && (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {removeError}
        </p>
      )}

      {isManager && (
        <div style={{ marginTop: "var(--space-3)" }}>
          <Button type="button" variant="quiet" onClick={() => setAddOpen((open) => !open)}>
            Add member
          </Button>
          {addOpen && (
            <div style={{ marginTop: "var(--space-2)" }}>
              <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-2)" }}>
                <label
                  htmlFor={recipientSelectId}
                  style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}
                >
                  New member
                </label>
                <select
                  id={recipientSelectId}
                  value={recipientId}
                  onChange={(e) => {
                    setRecipientId(e.target.value);
                    setAddNotice(null);
                  }}
                >
                  <option value="">Choose someone&hellip;</option>
                  {directory.map((entry) => (
                    <option key={entry.id} value={entry.id}>
                      {entry.name} &lt;{entry.email}&gt;
                    </option>
                  ))}
                </select>
                {chosenRecipient !== null && (
                  <p
                    style={{
                      color: "var(--ink-muted)",
                      fontSize: "0.75rem",
                      fontFamily: "var(--font-mono)",
                      margin: 0,
                    }}
                  >
                    {chosenRecipient.fingerprint}
                  </p>
                )}
              </div>
              <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-2)" }}>
                <label htmlFor={roleSelectId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
                  Role
                </label>
                <select
                  id={roleSelectId}
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value === "manager" ? "manager" : "member")}
                >
                  <option value="member">Member</option>
                  <option value="manager">Manager</option>
                </select>
              </div>
              <Button
                type="button"
                disabled={addBusy || chosenRecipient === null}
                onClick={async () => {
                  if (chosenRecipient === null) return;
                  setAddBusy(true);
                  setAddError(null);
                  setAddNotice(null);
                  try {
                    const outcome = await onAddMember({
                      collectionId: collection.id,
                      recipient: chosenRecipient,
                      role: newRole,
                    });
                    if (outcome === "pending") {
                      // addMember returned "pending": this device does not
                      // hold the collection key, so nothing was granted --
                      // only requested. Reporting it as done would tell this
                      // admin the user has access when they do not.
                      setAddNotice(
                        "This was only recorded as a request: a member of this collection " +
                          "must grant access before it takes effect.",
                      );
                    } else {
                      setRecipientId("");
                    }
                  } catch (failure) {
                    setAddError(failure instanceof Error ? failure.message : "Could not add that member");
                  } finally {
                    setAddBusy(false);
                  }
                }}
              >
                Add
              </Button>
              {addNotice !== null && <p style={{ color: "var(--ink-muted)" }}>{addNotice}</p>}
              {addError !== null && (
                <p role="alert" style={{ color: "var(--danger)" }}>
                  {addError}
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CollectionRow({
  collection,
  isSelected,
  members,
  directory,
  onSelect,
  onAddMember,
  onRemoveMember,
}: {
  collection: CollectionSummary;
  isSelected: boolean;
  members: Member[];
  directory: DirectoryEntry[];
  onSelect(): void;
  onAddMember: CollectionsScreenProps["onAddMember"];
  onRemoveMember: CollectionsScreenProps["onRemoveMember"];
}) {
  return (
    <li style={{ borderTop: "1px solid var(--rule)", padding: "var(--space-3) 0" }}>
      <button
        type="button"
        onClick={onSelect}
        aria-expanded={isSelected}
        style={{
          font: "inherit",
          background: "transparent",
          border: "none",
          color: "var(--ink)",
          cursor: "pointer",
          textAlign: "left",
          padding: 0,
          width: "100%",
        }}
      >
        <span style={{ display: "block" }}>{collection.name}</span>
        <span style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>{collection.role}</span>
      </button>
      {!collection.usable && (
        // Never hidden: a user staring at items they cannot read with nothing
        // anywhere explaining why is the worse outcome.
        <p style={{ color: "var(--danger)" }}>
          Shared with you, but this device can't open it. Ask a member to grant access again.
        </p>
      )}
      {isSelected && (
        <MembersPanel
          collection={collection}
          members={members}
          directory={directory}
          onAddMember={onAddMember}
          onRemoveMember={onRemoveMember}
        />
      )}
    </li>
  );
}

export function CollectionsScreen({
  role,
  collections,
  pendingGrants,
  directory,
  members,
  selectedCollectionId,
  onSelectCollection,
  onCreateCollection,
  onFulfil,
  onAddMember,
  onRemoveMember,
}: CollectionsScreenProps) {
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  return (
    <section>
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          marginBottom: "var(--space-4)",
        }}
      >
        <h2 style={{ fontSize: "1rem", fontWeight: 600, margin: 0 }}>Collections</h2>
        {role === "admin" && (
          <Button type="button" variant="quiet" onClick={() => setCreating((open) => !open)}>
            Create collection
          </Button>
        )}
      </header>

      {creating && (
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setCreateBusy(true);
            setCreateError(null);
            try {
              await onCreateCollection(newName);
              setNewName("");
              setCreating(false);
            } catch (failure) {
              setCreateError(
                failure instanceof Error ? failure.message : "Could not create that collection",
              );
            } finally {
              setCreateBusy(false);
            }
          }}
          style={{ marginBottom: "var(--space-4)" }}
        >
          <Field label="Name" value={newName} onChange={(e) => setNewName(e.target.value)} required />
          {createError !== null && (
            <p role="alert" style={{ color: "var(--danger)" }}>
              {createError}
            </p>
          )}
          <Button type="submit" disabled={createBusy}>
            {createBusy ? "Creating…" : "Save collection"}
          </Button>
        </form>
      )}

      {pendingGrants.length > 0 && (
        <section style={{ marginBottom: "var(--space-6)" }}>
          <h3 style={{ fontSize: "0.875rem" }}>Pending grants</h3>
          <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
            {pendingGrants.map((grant) => (
              <PendingGrantRow
                key={`${grant.collectionId}:${grant.userId}`}
                grant={grant}
                directory={directory}
                onFulfil={onFulfil}
              />
            ))}
          </ul>
        </section>
      )}

      {collections.length === 0 ? (
        <p style={{ color: "var(--ink-muted)" }}>No collections yet.</p>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
          {collections.map((collection) => (
            <CollectionRow
              key={collection.id}
              collection={collection}
              isSelected={collection.id === selectedCollectionId}
              members={collection.id === selectedCollectionId ? members : []}
              directory={directory}
              onSelect={() =>
                onSelectCollection(collection.id === selectedCollectionId ? null : collection.id)
              }
              onAddMember={onAddMember}
              onRemoveMember={onRemoveMember}
            />
          ))}
        </ul>
      )}
    </section>
  );
}

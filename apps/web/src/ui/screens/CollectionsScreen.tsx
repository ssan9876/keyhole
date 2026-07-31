import { useId, useState } from "react";
import type { CollectionSummary, Member, PendingGrant } from "../../vault/collections.js";
import type { DirectoryEntry } from "../../vault/directory.js";
import { Button } from "../components/Button.js";
import { Confirm } from "../components/Confirm.js";
import { Field } from "../components/Field.js";
import { describeFailure } from "../errors.js";

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
    <li className="kh-row-item">
      <div>
        {grant.collectionName} &middot; {recipient?.name ?? grant.userId}
      </div>
      {recipient !== null ? (
        <>
          {/* Design spec 3.9.1's mitigation for a substituted public key is two
              people comparing this aloud -- it must be visible here, before the
              seal happens, not only in a confirmation after the fact. */}
          <div className="kh-meta kh-mono"
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
                setError(describeFailure(failure, "Could not grant access"));
              } finally {
                setBusy(false);
              }
            }}
          >
            Grant access
          </Button>
        </>
      ) : (
        <p className="kh-muted">
          This person is no longer in the directory, so this device cannot seal a key to them.
        </p>
      )}
      {error !== null && (
        <p role="alert" className="kh-alert">
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
    <div className="kh-bullets kh-mt-sm">
      <h3 className="kh-text-sm kh-m-0">Members</h3>
      {members.length === 0 ? (
        <p className="kh-meta">No members loaded.</p>
      ) : (
        <ul className="kh-plain-list">
          {members.map((member) => {
            const entry = directory.find((d) => d.id === member.userId);
            return (
              <li
                key={member.userId} className="kh-split"
              >
                <div>
                  <span className="kh-block">
                    {member.name} &middot; {member.role}
                  </span>
                  {entry !== undefined && (
                    <span className="kh-meta-xs kh-mono"
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
                setRemoveError(describeFailure(failure, "Could not remove that member"));
              }
            })();
          }}
        />
      )}
      {removeError !== null && (
        <p role="alert" className="kh-alert">
          {removeError}
        </p>
      )}

      {isManager && (
        <div className="kh-mt-sm">
          <Button type="button" variant="quiet" onClick={() => setAddOpen((open) => !open)}>
            Add member
          </Button>
          {addOpen && (
            <div className="kh-mt-xs">
              <div className="kh-field kh-field-sm">
                <label
                  htmlFor={recipientSelectId} className="kh-label"
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
                  <p className="kh-meta-xs kh-mono kh-m-0"
                  >
                    {chosenRecipient.fingerprint}
                  </p>
                )}
              </div>
              <div className="kh-field kh-field-sm">
                <label htmlFor={roleSelectId} className="kh-label">
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
                    setAddError(describeFailure(failure, "Could not add that member"));
                  } finally {
                    setAddBusy(false);
                  }
                }}
              >
                Add
              </Button>
              {addNotice !== null && <p className="kh-muted">{addNotice}</p>}
              {addError !== null && (
                <p role="alert" className="kh-alert">
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
    <li className="kh-row-item">
      <button
        type="button"
        onClick={onSelect}
        aria-expanded={isSelected} className="kh-row"
      >
        <span className="kh-block">{collection.name}</span>
        <span className="kh-meta">{collection.role}</span>
      </button>
      {!collection.usable && (
        // Never hidden: a user staring at items they cannot read with nothing
        // anywhere explaining why is the worse outcome.
        <p className="kh-alert">
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
      <header className="kh-split kh-mb">
        <h2 className="kh-subhead kh-m-0">Collections</h2>
        {role === "admin" && (
          // aria-expanded, because this button does not navigate anywhere: it
          // discloses the form below it, and a screen reader should say so.
          <Button
            type="button"
            variant="quiet"
            aria-expanded={creating}
            onClick={() => setCreating((open) => !open)}
          >
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
              setCreateError(describeFailure(failure, "Could not create that collection"));
            } finally {
              setCreateBusy(false);
            }
          }} className="kh-mb"
        >
          <Field label="Name" value={newName} onChange={(e) => setNewName(e.target.value)} required />
          {createError !== null && (
            <p role="alert" className="kh-alert">
              {createError}
            </p>
          )}
          <Button type="submit" disabled={createBusy}>
            {createBusy ? "Creating…" : "Save collection"}
          </Button>
        </form>
      )}

      {pendingGrants.length > 0 && (
        <section className="kh-mb-lg">
          <h3 className="kh-text-sm">Pending grants</h3>
          <ul className="kh-plain-list">
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
        <p className="kh-empty">
          <span className="kh-empty-title">No collections yet.</span>
          A collection is a set of items shared with other people. Anything not in
          one stays personal to you.
        </p>
      ) : (
        <ul className="kh-plain-list">
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

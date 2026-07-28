import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { CollectionSummary, PendingGrant } from "../../vault/collections.js";
import type { DirectoryEntry } from "../../vault/directory.js";
import { CollectionsScreen, type CollectionsScreenProps } from "./CollectionsScreen.js";

const DEFAULT_COLLECTIONS: CollectionSummary[] = [
  { id: "c1", name: "Household", role: "manager", usable: true },
];

/**
 * Builds full, valid props for CollectionsScreen, with `overrides` replacing
 * whole top-level keys. The brief's Step 1 sketch calls a `props(...)` helper
 * that does not exist yet -- this is the real thing: CollectionsScreen is
 * presentational (holds no api/session), so every render needs a complete,
 * self-consistent set of data and callbacks, and the defaults here are chosen
 * to line up with each other (selectedCollectionId "c1" matches the default
 * collection's own id, the default pending-grant fixtures below reuse "c1"
 * too) so a test overriding one slice doesn't have to restate the rest.
 */
function props(overrides: Partial<CollectionsScreenProps> = {}): CollectionsScreenProps {
  return {
    role: "admin",
    collections: DEFAULT_COLLECTIONS,
    pendingGrants: [],
    directory: [],
    members: [],
    selectedCollectionId: "c1",
    onSelectCollection: vi.fn(),
    onCreateCollection: vi.fn().mockResolvedValue(undefined),
    onFulfil: vi.fn().mockResolvedValue(undefined),
    onAddMember: vi.fn().mockResolvedValue("granted"),
    onRemoveMember: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

describe("CollectionsScreen", () => {
  it("lists a collection with the caller's role", async () => {
    render(
      <CollectionsScreen
        {...props({
          collections: [{ id: "c1", name: "Household", role: "manager", usable: true }],
        })}
      />,
    );
    expect(await screen.findByText("Household")).toBeInTheDocument();
    expect(screen.getByText(/manager/i)).toBeInTheDocument();
  });

  it("says a collection is unopenable on this device rather than hiding it", async () => {
    render(
      <CollectionsScreen
        {...props({
          collections: [{ id: "c1", name: "Household", role: "member", usable: false }],
        })}
      />,
    );
    expect(await screen.findByText("Household")).toBeInTheDocument();
    // The exact copy from design spec 5.1, not a paraphrase: it states a real
    // limitation (this device cannot open the collection) that the product
    // does not otherwise disclose.
    expect(
      screen.getByText(
        "Shared with you, but this device can't open it. Ask a member to grant access again.",
      ),
    ).toBeInTheDocument();
  });

  it("offers to fulfil a pending grant and passes the matching directory entry", async () => {
    const onFulfil = vi.fn().mockResolvedValue(undefined);
    render(
      <CollectionsScreen
        {...props({
          pendingGrants: [
            {
              collectionId: "c1",
              collectionName: "Household",
              userId: "u2",
              role: "member",
              requestedBy: "u1",
              createdAt: "2026-07-27T00:00:00Z",
            },
          ],
          // Two entries, deliberately: a directory of one cannot distinguish
          // "the recipient this grant is for" from "whichever entry happened
          // to be first" -- Mutation C (Step 7) needs this to be detectable.
          directory: [
            {
              id: "u9",
              name: "Ari",
              email: "ari@example.com",
              publicKey: "AA==",
              fingerprint: "QRST-UVWX-YZAB-CDEF",
            },
            {
              id: "u2",
              name: "Bee",
              email: "bee@example.com",
              publicKey: "BB==",
              fingerprint: "ABCD-EFGH-JKMN-PQRS",
            },
          ],
          onFulfil,
        })}
      />,
    );

    await userEvent.click(await screen.findByRole("button", { name: /grant access/i }));

    // The recipient, not just the grant: sealing to the wrong person is silent.
    expect(onFulfil).toHaveBeenCalledWith(
      expect.objectContaining({ userId: "u2" }),
      expect.objectContaining({ id: "u2" }),
    );
  });

  it("shows the recipient's fingerprint before sealing a key to them", async () => {
    // Spec 3.9.1's mitigation only exists if it is on screen at the moment
    // the decision is made -- this renders the pending-grant row on its own
    // and asserts the fingerprint is present without ever clicking "Grant
    // access", so a regression that only shows it after the fact would fail
    // this test even though it might still pass a looser "appears somewhere"
    // check.
    const directory: DirectoryEntry[] = [
      {
        id: "u9",
        name: "Ari",
        email: "ari@example.com",
        publicKey: "AA==",
        fingerprint: "QRST-UVWX-YZAB-CDEF",
      },
      {
        id: "u2",
        name: "Bee",
        email: "bee@example.com",
        publicKey: "BB==",
        fingerprint: "ABCD-EFGH-JKMN-PQRS",
      },
    ];
    const grant: PendingGrant = {
      collectionId: "c1",
      collectionName: "Household",
      userId: "u2",
      role: "member",
      requestedBy: "u1",
      createdAt: "2026-07-27T00:00:00Z",
    };
    render(<CollectionsScreen {...props({ pendingGrants: [grant], directory })} />);

    expect(await screen.findByText("ABCD-EFGH-JKMN-PQRS")).toBeInTheDocument();
  });

  it("warns that removing a member is not retroactive, before removing them", async () => {
    const onRemoveMember = vi.fn();
    render(
      <CollectionsScreen
        {...props({
          members: [
            { userId: "u2", name: "Bee", email: "bee@example.com", role: "member", grantedAt: "2026-07-01T00:00:00Z" },
          ],
          onRemoveMember,
        })}
      />,
    );
    await userEvent.click(await screen.findByRole("button", { name: /remove/i }));

    // The exact copy from design spec 5.1, stating the real limitation.
    expect(
      screen.getByText(
        "Removing a member does not rotate the collection key. Someone who kept a copy " +
          "can still read what they already had. If this removal is adversarial, change " +
          "the shared passwords too.",
      ),
    ).toBeInTheDocument();
    expect(onRemoveMember).not.toHaveBeenCalled(); // still behind the confirmation
  });

  it("tells an admin that adding a member they cannot seal to is only a request", async () => {
    // addMember returned "pending": this admin does not hold the collection
    // key, so nothing was actually granted.
    const onAddMember = vi.fn().mockResolvedValue("pending");
    render(
      <CollectionsScreen
        {...props({
          directory: [
            {
              id: "u5",
              name: "Cee",
              email: "cee@example.com",
              publicKey: "CC==",
              fingerprint: "WXYZ-ABCD-EFGH-JKMN",
            },
          ],
          onAddMember,
        })}
      />,
    );

    await userEvent.click(screen.getByRole("button", { name: /^add member$/i }));
    await userEvent.selectOptions(screen.getByLabelText(/^new member$/i), "u5");
    await userEvent.click(screen.getByRole("button", { name: /^add$/i }));

    expect(onAddMember).toHaveBeenCalledWith({
      collectionId: "c1",
      recipient: expect.objectContaining({ id: "u5" }),
      role: "member",
    });
    expect(await screen.findByText(/a member of this collection must grant/i)).toBeInTheDocument();
  });

  it("does not offer Create collection to a non-admin", () => {
    render(<CollectionsScreen {...props({ role: "user" })} />);
    expect(screen.queryByRole("button", { name: /create collection/i })).not.toBeInTheDocument();
  });
});

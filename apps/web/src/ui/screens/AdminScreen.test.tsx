import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ApiError } from "../../vault/api.js";
import type { AdminUser, AuditEntry, CollectionOverview } from "../../vault/admin.js";
import type { PendingGrant } from "../../vault/collections.js";
import { AdminScreen, type AdminScreenProps } from "./AdminScreen.js";

const DEFAULT_USERS: AdminUser[] = [
  {
    id: "u1",
    email: "bee@example.com",
    name: "Bee",
    role: "user",
    status: "active",
    hasPendingInvite: false,
    createdAt: "2026-06-01T00:00:00Z",
  },
];

const DEFAULT_COLLECTIONS: CollectionOverview[] = [
  { id: "c1", name: "Household", createdBy: "u1", createdAt: "2026-06-01T00:00:00Z", memberCount: 2 },
];

const DEFAULT_PENDING_GRANTS: PendingGrant[] = [];

// Newest first, matching what the server sends (internal/httpapi/admin.go's
// AuditPage) -- the oldest entry ("user.reset") is deliberately last, since
// that ordering is what "Load older" depends on to find its `before`
// boundary.
const DEFAULT_AUDIT: AuditEntry[] = [
  {
    id: "a3",
    actorUserId: "u1",
    action: "user.create",
    target: "user:u4",
    metadata: "",
    createdAt: "2026-07-20T00:00:00Z",
  },
  {
    id: "a2",
    actorUserId: "u1",
    action: "user.login",
    target: "user:u1",
    metadata: "",
    createdAt: "2026-07-10T00:00:00Z",
  },
  {
    id: "a1",
    actorUserId: "u1",
    action: "user.reset",
    target: "user:u5",
    metadata: "",
    createdAt: "2026-07-01T00:00:00Z",
  },
];

/**
 * Builds full, valid props for AdminScreen, with `overrides` replacing whole
 * top-level keys. AdminScreen is presentational -- like CollectionsScreen and
 * SettingsScreen, it holds no `api`/`session` -- so every render needs a
 * complete, self-consistent set of data and callbacks. Most row-action tests
 * below deliberately keep the single-user default rather than adding a
 * second user: CollectionsScreen.test.tsx hit this same ambiguity twice
 * (button text like "Reset" or "Delete" is not unique once a second row
 * exists), and the fix there was fixture size, not a fussier query.
 */
function props(overrides: Partial<AdminScreenProps> = {}): AdminScreenProps {
  return {
    users: DEFAULT_USERS,
    collections: DEFAULT_COLLECTIONS,
    pendingGrants: DEFAULT_PENDING_GRANTS,
    auditEntries: DEFAULT_AUDIT,
    onCreateUser: vi.fn().mockResolvedValue({
      user: {
        id: "u9",
        email: "cee@example.com",
        name: "Cee",
        role: "user",
        status: "pending",
        hasPendingInvite: true,
        createdAt: "2026-07-27T00:00:00Z",
      },
      inviteUrl: "https://vault.example/enroll/tok-cee9",
      expiresIn: "72h0m0s",
    }),
    onReissueInvite: vi
      .fn()
      .mockResolvedValue({ inviteUrl: "https://vault.example/enroll/tok-again", expiresIn: "72h0m0s" }),
    onSetStatus: vi.fn().mockResolvedValue(undefined),
    onReset: vi.fn().mockResolvedValue({
      inviteUrl: "https://vault.example/enroll/tok-reset1",
      expiresIn: "72h0m0s",
      message:
        "Key material and personal items destroyed. Collection access must be re-granted after the user enrolls again.",
    }),
    onDelete: vi.fn().mockResolvedValue(undefined),
    onLoadAudit: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

async function openCreateForm(): Promise<void> {
  await userEvent.click(screen.getByRole("button", { name: "Add user" }));
}

describe("AdminScreen", () => {
  it("creates a user, shows the invite link once, and states it cannot be shown again", async () => {
    const onCreateUser = props().onCreateUser;
    render(<AdminScreen {...props({ onCreateUser })} />);

    await openCreateForm();
    // Exact strings: "Name" and "Email" each label exactly one control in
    // this render (the create-user form). A looser /name/i or /email/i would
    // still be unambiguous here, but the reset dialog opened by a later test
    // adds a third labelled control -- "Type "bee@example.com" to confirm" --
    // whose text has nothing in common with either, so there is no shared
    // regex that would quietly start matching two things if this screen
    // grows another field later. Exact strings make that non-issue explicit
    // rather than accidental.
    await userEvent.type(screen.getByLabelText("Name"), "Cee");
    await userEvent.type(screen.getByLabelText("Email"), "cee@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Create user" }));

    expect(
      await screen.findByDisplayValue("https://vault.example/enroll/tok-cee9"),
    ).toBeInTheDocument();
    expect(screen.getByText(/cannot be shown again/i)).toBeInTheDocument();
    expect(onCreateUser).toHaveBeenCalledWith({
      email: "cee@example.com",
      name: "Cee",
      role: "user",
    });
  });

  it("shows a manual-copy fallback instead of doing nothing when the clipboard API is unavailable", async () => {
    // jsdom implements no Clipboard API by default, and `navigator.clipboard`
    // is undefined in any insecure (non-https) context too -- this is the
    // realistic case the requirement exists for, not a contrived one. A copy
    // button that silently no-ops here would look identical to one that
    // worked.
    render(<AdminScreen {...props()} />);
    await openCreateForm();
    await userEvent.type(screen.getByLabelText("Name"), "Cee");
    await userEvent.type(screen.getByLabelText("Email"), "cee@example.com");
    await userEvent.click(screen.getByRole("button", { name: "Create user" }));
    await screen.findByDisplayValue("https://vault.example/enroll/tok-cee9");

    await userEvent.click(screen.getByRole("button", { name: "Copy link" }));

    expect(await screen.findByText(/copy isn.t available here/i)).toBeInTheDocument();
    // The field itself is unaffected -- still there, still holding the link,
    // regardless of whether the copy attempt worked.
    expect(screen.getByDisplayValue("https://vault.example/enroll/tok-cee9")).toBeInTheDocument();
  });

  it("keeps the reset confirm button disabled until the account's email is typed exactly", async () => {
    render(<AdminScreen {...props()} />);
    await userEvent.click(screen.getByRole("button", { name: "Reset" }));

    const confirmButton = screen.getByRole("button", { name: "Reset this account" });
    expect(confirmButton).toBeDisabled();

    // The label text is Confirm's own -- `Type "<email>" to confirm`, with
    // Confirm's curly quotes (&ldquo;/&rdquo;), not a straight-quote
    // paraphrase -- so this query only ever matches the one field the dialog
    // actually renders.
    const typedField = screen.getByLabelText("Type “bee@example.com” to confirm");
    await userEvent.type(typedField, "bee@example.co");
    expect(confirmButton).toBeDisabled();

    await userEvent.type(typedField, "m");
    expect(confirmButton).toBeEnabled();
  });

  it("states what a reset destroys and that access must be re-granted, before the confirm click", async () => {
    render(<AdminScreen {...props()} />);
    await userEvent.click(screen.getByRole("button", { name: "Reset" }));

    expect(screen.getByText(/key material/i)).toBeInTheDocument();
    expect(screen.getByText(/personal item/i)).toBeInTheDocument();
    expect(screen.getByText(/collection membership/i)).toBeInTheDocument();
    expect(screen.getByText(/re-granted/i)).toBeInTheDocument();
  });

  it("reveals the reset account's fresh invite once the typed confirmation is submitted", async () => {
    const onReset = props().onReset;
    render(<AdminScreen {...props({ onReset })} />);
    await userEvent.click(screen.getByRole("button", { name: "Reset" }));
    await userEvent.type(
      screen.getByLabelText("Type “bee@example.com” to confirm"),
      "bee@example.com",
    );
    await userEvent.click(screen.getByRole("button", { name: "Reset this account" }));

    expect(onReset).toHaveBeenCalledWith({ userId: "u1", confirmEmail: "bee@example.com" });
    expect(
      await screen.findByDisplayValue("https://vault.example/enroll/tok-reset1"),
    ).toBeInTheDocument();
    expect(screen.getByText(/cannot be shown again/i)).toBeInTheDocument();
  });

  it("shows the server's own explanation, not a generic message, when a delete conflicts", async () => {
    const onDelete = vi
      .fn()
      .mockRejectedValue(
        new ApiError(
          "conflict",
          409,
          "this account created a collection or granted a membership. Delete or reassign those " +
            "collections first, or disable the account instead.",
          null,
        ),
      );
    render(<AdminScreen {...props({ onDelete })} />);

    await userEvent.click(screen.getByRole("button", { name: "Delete" }));
    await userEvent.click(screen.getByRole("button", { name: "Delete account" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/reassign those collections/i);
    expect(alert).not.toHaveTextContent(/^could not delete this account$/i);
  });

  it("passes the oldest loaded audit entry's createdAt as `before` when loading older entries", async () => {
    const onLoadAudit = props().onLoadAudit;
    render(<AdminScreen {...props({ onLoadAudit })} />);

    await userEvent.click(screen.getByRole("button", { name: "Load older" }));

    expect(onLoadAudit).toHaveBeenCalledWith(
      expect.objectContaining({ before: "2026-07-01T00:00:00Z" }),
    );
  });

  it("renders the audit log as a table with actor, action, target, and time, newest first", () => {
    render(<AdminScreen {...props()} />);

    const table = screen.getByRole("table", { name: "Audit log" });
    const rows = within(table).getAllByRole("row");
    // One header row plus one per entry -- proves nothing was dropped or
    // duplicated, not just that "a table exists somewhere".
    expect(rows).toHaveLength(DEFAULT_AUDIT.length + 1);
    // The newest entry (by fixture order) must be the first data row and the
    // oldest the last -- this is what "newest first" means operationally,
    // not just that all three rows are present in some order.
    expect(within(rows[1]!).getByText("user.create")).toBeInTheDocument();
    expect(within(rows[rows.length - 1]!).getByText("user.reset")).toBeInTheDocument();
  });

  it("renders no key material for any listed user", () => {
    // The admin list endpoint carries none by construction
    // (internal/httpapi/admin.go:20-28's adminUserJSON has no field for it) --
    // this asserts the screen does not invent a place to put some. Lowercased
    // and stripped of underscores before searching, copied from
    // internal/httpapi/helpers_test.go: a needle list that only spells one
    // casing (camelCase or snake_case) missed every key it existed to catch
    // when a mutated handler once returned the raw record in PascalCase.
    const { container } = render(<AdminScreen {...props()} />);
    const html = container.innerHTML.toLowerCase().replace(/_/g, "");
    for (const needle of [
      "protecteduserkey",
      "encryptedprivatekey",
      "authhash",
      "kdfsalt",
      "recoverysalt",
    ]) {
      expect(html).not.toContain(needle);
    }
  });

  it("does not offer to reissue an invite for an account that has none pending", () => {
    render(
      <AdminScreen
        {...props({
          users: [{ ...DEFAULT_USERS[0]!, hasPendingInvite: false }],
        })}
      />,
    );
    expect(screen.queryByRole("button", { name: "Reissue invite" })).not.toBeInTheDocument();
  });
});

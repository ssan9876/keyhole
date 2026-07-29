import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MANUAL_FORMATS, type CsvColumnMapping } from "../../vault/import/map.js";
import { ImportScreen, type ImportScreenProps, type PreviewResult } from "./ImportScreen.js";

/**
 * The four-step import screen, presentational: every call that touches the file,
 * the vault or the network arrives as a prop, so these tests drive it with
 * fabricated handlers and assert on what it renders. The properties under test
 * are the ones the brief gives teeth: the counts reconcile, the per-row errors
 * are shown with their row and message, the duplicate report and the unchecked
 * rows are rendered, the completion count is the *landed* one, and the last
 * thing on the completion screen is the instruction to delete the export file.
 */

function blankMapping(): CsvColumnMapping {
  return {
    name: null,
    username: null,
    password: null,
    url: null,
    notes: null,
    folder: null,
    folderSeparator: "/",
    totp: null,
    custom: [],
  };
}

function props(overrides: Partial<ImportScreenProps> = {}): ImportScreenProps {
  return {
    formats: MANUAL_FORMATS,
    collections: [],
    onInspect: vi.fn().mockResolvedValue({
      filename: "vault.json",
      format: "bitwarden-json",
      vendors: ["bitwarden"],
      header: [],
      suggestedMapping: blankMapping(),
    }),
    onPreview: vi.fn().mockResolvedValue({ rows: [], errors: [], duplicates: { groups: [], unchecked: [] } }),
    onImport: vi.fn().mockResolvedValue({ uploaded: 0, total: 0, inDoubt: 0, error: null }),
    ...overrides,
  };
}

/** Drives upload → map by selecting a file and clicking Continue. */
async function toMap(user: ReturnType<typeof userEvent.setup>): Promise<void> {
  await user.upload(screen.getByLabelText("Choose an export file"), new File(["{}"], "vault.json"));
  await user.click(screen.getByRole("button", { name: "Continue" }));
  await screen.findByLabelText("Export format");
}

/** Drives upload → map → preview. */
async function toPreview(user: ReturnType<typeof userEvent.setup>): Promise<void> {
  await toMap(user);
  await user.click(screen.getByRole("button", { name: "Preview the import" }));
  await screen.findByText(/read from your file/i);
}

describe("ImportScreen, the upload step", () => {
  it("keeps Continue disabled until a file is chosen", () => {
    render(<ImportScreen {...props()} />);
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
  });
});

describe("ImportScreen, the map step", () => {
  it("pre-selects the detected format", async () => {
    const user = userEvent.setup();
    render(<ImportScreen {...props()} />);
    await toMap(user);
    expect(screen.getByLabelText("Export format")).toHaveValue("bitwarden-json");
  });

  it("shows a column mapper whose labels do not collide, for an unrecognised CSV", async () => {
    // The label trap: a substring query for /password/ matches both "Password
    // column" and "One-time-password column", and /name/ matches both "Name
    // column" and "Username column". Exact labels are the only safe query, and
    // this test pins that each is present and distinct.
    const onInspect = vi.fn().mockResolvedValue({
      filename: "unknown.csv",
      format: "generic-csv",
      vendors: [],
      header: ["login", "secret", "memo"],
      suggestedMapping: { ...blankMapping(), username: "login", password: "secret", notes: "memo" },
    });
    const user = userEvent.setup();
    render(<ImportScreen {...props({ onInspect })} />);
    await toMap(user);

    expect(screen.getByLabelText("Password column", { exact: true })).toHaveValue("secret");
    expect(screen.getByLabelText("One-time-password column", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("Username column", { exact: true })).toHaveValue("login");
    expect(screen.getByLabelText("Name column", { exact: true })).toHaveValue("");
  });

  it("warns before Keeper's header-less CSV, whose columns only the preview can check", async () => {
    const user = userEvent.setup();
    render(<ImportScreen {...props()} />);
    await toMap(user);
    await user.selectOptions(screen.getByLabelText("Export format"), "keeper-csv");
    expect(screen.getByText(/no header row/i)).toBeInTheDocument();
  });
});

/** A preview with three parsed rows, one duplicate against the vault, one
 *  unchecked row, and one unreadable row. */
function previewFixture(): PreviewResult {
  return {
    rows: [
      { index: 0, sourceRow: 2, type: "login", name: "Alpha", username: "a@x.com", passwordPreview: "aaa", urls: ["https://x.com"], carriedCount: 0 },
      { index: 1, sourceRow: 3, type: "login", name: "Beta", username: "b@y.com", passwordPreview: "bbb", urls: ["https://y.com"], carriedCount: 1 },
      { index: 2, sourceRow: 4, type: "note", name: "Gamma", username: "", passwordPreview: "", urls: [], carriedCount: 0 },
    ],
    errors: [
      { row: 5, message: "This row is a Bitwarden card, which Keyhole cannot import yet, so it was not imported" },
    ],
    duplicates: {
      groups: [
        {
          key: { host: "x.com", username: "a@x.com" },
          rows: [0],
          existing: [{ id: "e1", name: "Old Alpha", username: "a@x.com", urls: ["https://x.com"] }],
        },
      ],
      unchecked: [2],
    },
  };
}

describe("ImportScreen, the preview step", () => {
  it("shows counts that reconcile: to-import plus skipped plus unreadable equals rows read", async () => {
    const onPreview = vi.fn().mockResolvedValue(previewFixture());
    const user = userEvent.setup();
    render(<ImportScreen {...props({ onPreview })} />);
    await toPreview(user);

    // Three rows parsed + one unreadable = four read. The duplicate defaults to
    // skip (it is already in the vault), so 2 import + 1 skip + 1 unreadable = 4.
    expect(screen.getByText(/4 rows read from your file/i)).toBeInTheDocument();
    expect(screen.getByText(/2 will be imported/i)).toBeInTheDocument();
    expect(screen.getByText(/1 skipped as duplicates/i)).toBeInTheDocument();
    expect(screen.getByText(/1 could not be read/i)).toBeInTheDocument();
  });

  it("lists each unreadable row with its number and the format's own message", async () => {
    const onPreview = vi.fn().mockResolvedValue(previewFixture());
    const user = userEvent.setup();
    render(<ImportScreen {...props({ onPreview })} />);
    await toPreview(user);

    // "Imported 400 of 414" is only trustworthy if the user can see which rows
    // and why.
    expect(screen.getByText(/row 5:/i)).toBeInTheDocument();
    expect(screen.getByText(/is a Bitwarden card, which Keyhole cannot import/i)).toBeInTheDocument();
  });

  it("renders the duplicate report and the unchecked rows, defaulting a vault clash to skip", async () => {
    const onPreview = vi.fn().mockResolvedValue(previewFixture());
    const user = userEvent.setup();
    render(<ImportScreen {...props({ onPreview })} />);
    await toPreview(user);

    // The duplicate group is shown and pre-selected to skip because it is
    // already in the vault; the user can flip it.
    expect(screen.getByText(/possible duplicates/i)).toBeInTheDocument();
    expect(screen.getByRole("checkbox")).toBeChecked();
    // The unchecked row is reported as unchecked, not as clean.
    expect(screen.getByText(/1 row has no web address/i)).toBeInTheDocument();
  });

  it("shows the start of each login's password, so a shifted column is visible", async () => {
    // Keeper's header-less CSV has no other check: a URL mapped into the
    // password column would read here as its first characters, which is the
    // whole point of showing them.
    const shifted: PreviewResult = {
      rows: [
        { index: 0, sourceRow: 1, type: "login", name: "Shifted", username: "https://example.com", passwordPreview: "htt", urls: [], carriedCount: 0 },
      ],
      errors: [],
      duplicates: { groups: [], unchecked: [] },
    };
    const user = userEvent.setup();
    render(<ImportScreen {...props({ onPreview: vi.fn().mockResolvedValue(shifted) })} />);
    await toPreview(user);

    // The password column shows "htt" — a URL shifted into it, plainly wrong.
    const row = screen.getByText("Shifted").closest("tr");
    expect(row).not.toBeNull();
    expect(within(row as HTMLElement).getByText("htt")).toBeInTheDocument();
  });
});

describe("ImportScreen, the completion step", () => {
  async function toDone(
    user: ReturnType<typeof userEvent.setup>,
    outcome: { uploaded: number; total: number; inDoubt: number; error: Error | null },
  ): Promise<void> {
    const onPreview = vi.fn().mockResolvedValue({
      rows: [
        { index: 0, sourceRow: 1, type: "login", name: "Alpha", username: "a@x.com", passwordPreview: "aaa", urls: ["https://x.com"], carriedCount: 0 },
        { index: 1, sourceRow: 2, type: "login", name: "Beta", username: "b@y.com", passwordPreview: "bbb", urls: ["https://y.com"], carriedCount: 0 },
        { index: 2, sourceRow: 3, type: "login", name: "Gamma", username: "c@z.com", passwordPreview: "ccc", urls: ["https://z.com"], carriedCount: 0 },
      ],
      errors: [],
      duplicates: { groups: [], unchecked: [] },
    } satisfies PreviewResult);
    const onImport = vi.fn().mockResolvedValue(outcome);

    render(<ImportScreen {...props({ onPreview, onImport })} />);
    await toPreview(user);
    await user.click(screen.getByRole("button", { name: "Import 3 items" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Import 3 items" }));
    await screen.findByRole("heading", { name: /imported/i });
  }

  it("reports the landed count on a partial failure, never the count attempted", async () => {
    // The failure mode with no undo: a partial upload that reported the attempt
    // would tell the user 3 items are in their vault when 2 are, and send them
    // into a re-import that duplicates the 2 that did land. upload.ts returns
    // the true count; this screen must show it.
    const user = userEvent.setup();
    await toDone(user, { uploaded: 2, total: 3, inDoubt: 1, error: new Error("connection lost") });

    expect(screen.getByRole("heading", { name: /imported 2 items into personal/i })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /imported 3 items/i })).not.toBeInTheDocument();
    // The partial failure and the in-doubt items are both spelled out.
    expect(screen.getByText(/did not upload/i)).toBeInTheDocument();
    expect(screen.getByText(/in doubt/i)).toBeInTheDocument();
  });

  it("ends with the instruction to delete the export file, as the last thing on the screen", async () => {
    const user = userEvent.setup();
    await toDone(user, { uploaded: 3, total: 3, inDoubt: 0, error: null });

    const summary = screen.getByRole("heading", { name: /imported 3 items into personal/i });
    const deleteInstruction = screen.getByText(/now delete the export file/i);
    expect(deleteInstruction).toBeInTheDocument();
    // Not a footnote, and not buried above the summary: it follows everything
    // else on the screen (spec §7 — the export file is the likeliest real-world
    // compromise of the whole system).
    expect(
      summary.compareDocumentPosition(deleteInstruction) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    // And it follows the only action on the screen too, so it is genuinely the
    // last thing the user reads rather than something the eye slides past.
    const buttons = screen.getAllByRole("button");
    const lastButton = buttons[buttons.length - 1] as HTMLElement;
    expect(
      lastButton.compareDocumentPosition(deleteInstruction) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });
});

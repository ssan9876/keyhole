import { useId, useMemo, useRef, useState } from "react";
import type { ImportVendor } from "../../vault/import/detect.js";
import type { DuplicateGroup, DuplicateReport } from "../../vault/import/dedupe.js";
import type {
  CsvColumnMapping,
  ManualFormat,
  ManualFormatChoice,
} from "../../vault/import/map.js";
import type { ImportRowError } from "../../vault/import/types.js";
import type { UploadOutcome } from "../../vault/import/upload.js";
import { Button } from "../components/Button.js";
import { Confirm } from "../components/Confirm.js";
import { describeFailure } from "../errors.js";

/**
 * The four-step import screen: upload → map → preview → done.
 *
 * Presentational, in the shape the last four screens settled on — every call
 * that touches the file, the vault, or the network arrives as a prop from
 * `useImportPanel`, which is also where the bytes-vs-text seam lives. What this
 * owns is the copy, the step it is on, the format the user picked, the column
 * mapping they are editing, and which duplicate groups they chose to skip.
 *
 * The one thing this screen must get right that a form does not usually have to:
 * **its numbers have to add up, and its last word has to be the instruction to
 * delete the export file.** An import is the largest volume of other people's
 * plaintext this app ever handles; a total that does not reconcile hides a
 * dropped password, and an unencrypted export left in Downloads is the most
 * likely real-world compromise of the whole system (spec §7).
 */

export interface InspectResult {
  filename: string;
  /** Detection's answer, pre-selecting the picker. `generic-csv` when nothing
   *  was recognised, which is where the column mapper comes in. */
  format: ManualFormat;
  /** Every product the file could have come from; empty when unrecognised. */
  vendors: readonly ImportVendor[];
  /** The CSV header in the file's own spelling, for the generic column mapper.
   *  Empty for a JSON or `.1pux` file. */
  header: readonly string[];
  suggestedMapping: CsvColumnMapping;
}

/** One parsed item as the preview renders it — never the whole password. */
export interface PreviewRow {
  /** Index into the parsed items array, so a skip decision names a row the
   *  importer can then exclude. */
  index: number;
  sourceRow: number;
  type: "login" | "note";
  name: string;
  username: string;
  /** The first few characters of the password only — enough to catch a shifted
   *  column, not the secret itself. */
  passwordPreview: string;
  urls: readonly string[];
  /** How many things will be folded into the note rather than a field of their
   *  own (folder, TOTP, custom fields, exporter metadata). */
  carriedCount: number;
}

export interface PreviewResult {
  rows: PreviewRow[];
  errors: ImportRowError[];
  duplicates: DuplicateReport;
}

export interface PreviewRequest {
  file: File;
  format: ManualFormat;
  /** Only read for `generic-csv`; ignored by every other format. */
  mapping: CsvColumnMapping | null;
}

export interface ImportRequest extends PreviewRequest {
  /** Item indices the user chose to skip as duplicates. */
  skipRows: readonly number[];
  /** The collection to import into, or null for personal items. */
  collectionId: string | null;
  onProgress?(progress: { uploaded: number; total: number }): void;
}

export interface ImportScreenProps {
  /** The formats the user can name by hand, including Keeper's header-less CSV. */
  formats: readonly ManualFormatChoice[];
  /** Collections this device can import into. Empty when there are none, in
   *  which case there is no target picker and everything is personal. */
  collections: { id: string; name: string }[];
  onInspect(file: File): Promise<InspectResult>;
  onPreview(input: PreviewRequest): Promise<PreviewResult>;
  onImport(input: ImportRequest): Promise<UploadOutcome>;
}

/** The generic-CSV column mapping form's fields, each a select over the header. */
const MAPPING_FIELDS: {
  key: "name" | "username" | "password" | "url" | "notes" | "folder" | "totp";
  label: string;
}[] = [
  { key: "name", label: "Name column" },
  { key: "username", label: "Username column" },
  { key: "password", label: "Password column" },
  { key: "url", label: "Web address column" },
  { key: "notes", label: "Notes column" },
  { key: "folder", label: "Folder column" },
  { key: "totp", label: "One-time-password column" },
];

type Step = "upload" | "map" | "preview" | "done";

/** What the completion screen needs beyond the raw upload outcome. */
interface Completed {
  outcome: UploadOutcome;
  /** Rows skipped as duplicates, so the completion count reconciles. */
  skipped: number;
  /** Rows that never parsed, shown so "imported N" from a larger file is
   *  something the user can check rather than take on trust. */
  errors: ImportRowError[];
  /** Where the items went, for the completion sentence. */
  targetName: string;
}

export function ImportScreen({ formats, collections, onInspect, onPreview, onImport }: ImportScreenProps) {
  const [step, setStep] = useState<Step>("upload");
  const [file, setFile] = useState<File | null>(null);
  const [inspect, setInspect] = useState<InspectResult | null>(null);
  const [format, setFormat] = useState<ManualFormat>("generic-csv");
  const [mapping, setMapping] = useState<CsvColumnMapping | null>(null);
  const [collectionId, setCollectionId] = useState<string | null>(null);
  const [preview, setPreview] = useState<PreviewResult | null>(null);
  const [skipGroups, setSkipGroups] = useState<Record<number, boolean>>({});
  const [confirming, setConfirming] = useState(false);
  const [progress, setProgress] = useState<{ uploaded: number; total: number } | null>(null);
  const [completed, setCompleted] = useState<Completed | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fileInputId = useId();
  const formatSelectId = useId();
  const targetSelectId = useId();
  const separatorId = useId();
  // Only relevant while resetting between imports.
  const fileInputRef = useRef<HTMLInputElement>(null);

  const chosenFormat = useMemo(
    () => formats.find((choice) => choice.id === format) ?? null,
    [formats, format],
  );

  function reset(): void {
    setStep("upload");
    setFile(null);
    setInspect(null);
    setFormat("generic-csv");
    setMapping(null);
    setCollectionId(null);
    setPreview(null);
    setSkipGroups({});
    setConfirming(false);
    setProgress(null);
    setCompleted(null);
    setError(null);
    if (fileInputRef.current !== null) fileInputRef.current.value = "";
  }

  async function inspectFile(): Promise<void> {
    if (file === null) return;
    setBusy(true);
    setError(null);
    try {
      const result = await onInspect(file);
      setInspect(result);
      setFormat(result.format);
      setMapping(result.suggestedMapping);
      setStep("map");
    } catch (failure) {
      setError(describeFailure(failure, "Could not read that file"));
    } finally {
      setBusy(false);
    }
  }

  async function runPreview(): Promise<void> {
    if (file === null) return;
    setBusy(true);
    setError(null);
    try {
      const result = await onPreview({ file, format, mapping: format === "generic-csv" ? mapping : null });
      setPreview(result);
      // Default: skip a group already in the vault (re-import), keep a group
      // that only clashes within the file (two accounts on one host the user
      // presumably wants both of). Either way the user is asked, and can flip
      // any of them.
      const defaults: Record<number, boolean> = {};
      result.duplicates.groups.forEach((group, index) => {
        defaults[index] = group.existing.length > 0;
      });
      setSkipGroups(defaults);
      setStep("preview");
    } catch (failure) {
      setError(describeFailure(failure, "Could not read that file"));
    } finally {
      setBusy(false);
    }
  }

  const skipRows = useMemo(() => {
    if (preview === null) return [] as number[];
    const rows: number[] = [];
    preview.duplicates.groups.forEach((group, index) => {
      if (skipGroups[index]) rows.push(...group.rows);
    });
    return rows;
  }, [preview, skipGroups]);

  const counts = useMemo(() => {
    if (preview === null) return { total: 0, toImport: 0, skipped: 0, errors: 0 };
    const skipped = skipRows.length;
    return {
      total: preview.rows.length + preview.errors.length,
      toImport: preview.rows.length - skipped,
      skipped,
      errors: preview.errors.length,
    };
  }, [preview, skipRows]);

  async function runImport(): Promise<void> {
    if (file === null || preview === null) return;
    setConfirming(false);
    setBusy(true);
    setError(null);
    setProgress({ uploaded: 0, total: counts.toImport });
    try {
      const outcome = await onImport({
        file,
        format,
        mapping: format === "generic-csv" ? mapping : null,
        skipRows,
        collectionId,
        onProgress: setProgress,
      });
      const target = collections.find((c) => c.id === collectionId);
      setCompleted({
        outcome,
        skipped: counts.skipped,
        errors: preview.errors,
        targetName: target?.name ?? "Personal",
      });
      setStep("done");
    } catch (failure) {
      // uploadItems never throws, so reaching here means the map step or the
      // read did. The parsed plaintext is still in hand; the user can retry.
      setError(describeFailure(failure, "The import could not be completed"));
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }

  return (
    <div>
      <h2 style={{ fontSize: "1rem", fontWeight: 600 }}>Import a password export</h2>

      {error !== null && (
        <p role="alert" style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>
          {error}
        </p>
      )}

      {step === "upload" && (
        <section>
          <p style={{ color: "var(--ink-muted)" }}>
            Export your vault from your current password manager, then choose that file here. It is
            read and encrypted entirely in this browser; nothing in it is sent anywhere until you
            have reviewed exactly what will be imported.
          </p>
          <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-4)" }}>
            <label htmlFor={fileInputId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
              Choose an export file
            </label>
            <input
              id={fileInputId}
              ref={fileInputRef}
              type="file"
              onChange={(e) => {
                setFile(e.target.files?.[0] ?? null);
                setError(null);
              }}
            />
          </div>
          <Button type="button" disabled={file === null || busy} onClick={() => void inspectFile()}>
            {busy ? "Reading…" : "Continue"}
          </Button>
        </section>
      )}

      {step === "map" && inspect !== null && (
        <section>
          <p style={{ color: "var(--ink-muted)" }}>
            {inspect.vendors.length > 0
              ? `This looks like a ${vendorList(inspect.vendors)} export. Change it if that is wrong.`
              : "We could not recognise this file, so tell us the format, or map the columns yourself below."}
          </p>

          <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-4)" }}>
            <label htmlFor={formatSelectId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
              Export format
            </label>
            <select
              id={formatSelectId}
              value={format}
              onChange={(e) => setFormat(e.target.value as ManualFormat)}
            >
              {formats.map((choice) => (
                <option key={choice.id} value={choice.id}>
                  {choice.label}
                </option>
              ))}
            </select>
          </div>

          {chosenFormat?.caution !== undefined && (
            // Keeper's header-less CSV is the one format whose columns cannot be
            // checked against anything but the preview, so its own warning has
            // to be read before the user gets there.
            <p style={{ color: "var(--danger)", marginBottom: "var(--space-4)" }}>{chosenFormat.caution}</p>
          )}

          {format === "generic-csv" && mapping !== null && (
            <ColumnMapping
              header={inspect.header}
              mapping={mapping}
              onChange={setMapping}
              separatorId={separatorId}
            />
          )}

          {collections.length > 0 && (
            <div style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-4)" }}>
              <label htmlFor={targetSelectId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
                Import into
              </label>
              <select
                id={targetSelectId}
                value={collectionId ?? ""}
                onChange={(e) => setCollectionId(e.target.value === "" ? null : e.target.value)}
              >
                <option value="">Personal</option>
                {collections.map((collection) => (
                  <option key={collection.id} value={collection.id}>
                    {collection.name}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div style={{ display: "flex", gap: "var(--space-2)" }}>
            <Button type="button" disabled={busy} onClick={() => void runPreview()}>
              {busy ? "Reading…" : "Preview the import"}
            </Button>
            <Button type="button" variant="quiet" onClick={reset}>
              Start over
            </Button>
          </div>
        </section>
      )}

      {step === "preview" && preview !== null && (
        <section>
          <PreviewSummary counts={counts} />

          {preview.rows.length > 0 && <PreviewTable rows={preview.rows} />}

          {preview.duplicates.groups.length > 0 && (
            <DuplicatesSection
              groups={preview.duplicates.groups}
              skipGroups={skipGroups}
              onToggle={(index, skip) => setSkipGroups((prev) => ({ ...prev, [index]: skip }))}
            />
          )}

          {preview.duplicates.unchecked.length > 0 && (
            // Rendered on purpose: a row with no web address was not compared to
            // anything, which is a different answer from "checked and clean" and
            // the user is owed the distinction.
            <p style={{ color: "var(--ink-muted)", marginTop: "var(--space-4)" }}>
              {preview.duplicates.unchecked.length}{" "}
              {preview.duplicates.unchecked.length === 1 ? "row has" : "rows have"} no web address,
              so {preview.duplicates.unchecked.length === 1 ? "it was" : "they were"} not checked for
              duplicates.
            </p>
          )}

          {preview.errors.length > 0 && <ErrorList title="These rows could not be read" errors={preview.errors} />}

          {progress !== null && (
            <p role="status" style={{ color: "var(--ink-muted)", marginTop: "var(--space-4)" }}>
              Uploading… {progress.uploaded} of {progress.total} saved so far.
            </p>
          )}

          <div style={{ display: "flex", gap: "var(--space-2)", marginTop: "var(--space-4)" }}>
            <Button type="button" disabled={busy || counts.toImport === 0} onClick={() => setConfirming(true)}>
              {counts.toImport === 1 ? "Import 1 item" : `Import ${counts.toImport} items`}
            </Button>
            <Button type="button" variant="quiet" disabled={busy} onClick={() => setStep("map")}>
              Back
            </Button>
          </div>

          {confirming && (
            <Confirm
              title="Import these items?"
              body={
                <>
                  This will add {counts.toImport} {counts.toImport === 1 ? "item" : "items"} to your
                  vault
                  {completedTarget(collections, collectionId)}.{" "}
                  {counts.skipped > 0 && `${counts.skipped} skipped as duplicates. `}
                  {counts.errors > 0 && `${counts.errors} could not be read. `}
                </>
              }
              confirmLabel={counts.toImport === 1 ? "Import 1 item" : `Import ${counts.toImport} items`}
              onCancel={() => setConfirming(false)}
              onConfirm={() => void runImport()}
            />
          )}
        </section>
      )}

      {step === "done" && completed !== null && (
        <CompletionScreen completed={completed} onImportAnother={reset} />
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*                              The generic mapper                            */
/* -------------------------------------------------------------------------- */

function ColumnMapping({
  header,
  mapping,
  onChange,
  separatorId,
}: {
  header: readonly string[];
  mapping: CsvColumnMapping;
  onChange(next: CsvColumnMapping): void;
  separatorId: string;
}) {
  const ids = useId();
  return (
    <fieldset style={{ border: "1px solid var(--rule)", padding: "var(--space-4)", marginBottom: "var(--space-4)" }}>
      <legend style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>Which column holds what</legend>
      {MAPPING_FIELDS.map((field) => {
        const id = `${ids}-${field.key}`;
        return (
          <div key={field.key} style={{ display: "grid", gap: "var(--space-1)", marginBottom: "var(--space-2)" }}>
            <label htmlFor={id} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
              {field.label}
            </label>
            <select
              id={id}
              value={mapping[field.key] ?? ""}
              onChange={(e) => onChange({ ...mapping, [field.key]: e.target.value === "" ? null : e.target.value })}
            >
              <option value="">(none)</option>
              {header.map((column) => (
                <option key={column} value={column}>
                  {column}
                </option>
              ))}
            </select>
          </div>
        );
      })}
      <div style={{ display: "grid", gap: "var(--space-1)" }}>
        <label htmlFor={separatorId} style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
          Folder separator
        </label>
        <input
          id={separatorId}
          type="text"
          value={mapping.folderSeparator}
          onChange={(e) => onChange({ ...mapping, folderSeparator: e.target.value })}
          style={{ font: "inherit", padding: "var(--space-2)", border: "1px solid var(--rule)", background: "transparent", color: "var(--ink)" }}
        />
      </div>
    </fieldset>
  );
}

/* -------------------------------------------------------------------------- */
/*                                 The preview                                */
/* -------------------------------------------------------------------------- */

function PreviewSummary({ counts }: { counts: { total: number; toImport: number; skipped: number; errors: number } }) {
  // The numbers have to reconcile: to-import + skipped + could-not-be-read
  // equals the rows read from the file. Shown broken out rather than as a
  // single "imported N", so a number that does not add up says which part is
  // which instead of hiding a dropped row inside a total.
  return (
    <div style={{ marginBottom: "var(--space-4)" }}>
      <p style={{ margin: 0 }}>
        {counts.total} {counts.total === 1 ? "row" : "rows"} read from your file.
      </p>
      <ul style={{ margin: "var(--space-2) 0 0", paddingLeft: "var(--space-4)" }}>
        <li>{counts.toImport} will be imported</li>
        <li>{counts.skipped} skipped as duplicates</li>
        <li>{counts.errors} could not be read</li>
      </ul>
    </div>
  );
}

function PreviewTable({ rows }: { rows: readonly PreviewRow[] }) {
  return (
    <div style={{ overflowX: "auto", marginBottom: "var(--space-4)" }}>
      <table style={{ borderCollapse: "collapse", width: "100%", fontSize: "0.875rem" }}>
        <thead>
          <tr>
            {["Row", "Name", "Username", "Password", "Kind"].map((heading) => (
              <th
                key={heading}
                style={{ textAlign: "left", borderBottom: "1px solid var(--rule-strong)", padding: "var(--space-1) var(--space-2)" }}
              >
                {heading}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.index} style={{ borderBottom: "1px solid var(--rule)" }}>
              <td style={{ padding: "var(--space-1) var(--space-2)", color: "var(--ink-muted)" }}>{row.sourceRow}</td>
              <td style={{ padding: "var(--space-1) var(--space-2)" }}>{row.name || <em style={{ color: "var(--ink-muted)" }}>(no name)</em>}</td>
              <td style={{ padding: "var(--space-1) var(--space-2)" }}>{row.username}</td>
              <td style={{ padding: "var(--space-1) var(--space-2)", fontFamily: "var(--font-mono)" }}>
                {/* The start of the password only. A URL shifted into this
                    column reads as "ht…", which is the whole point of showing
                    it — Keeper's header-less CSV has no other check. */}
                {row.type === "note" ? <span style={{ color: "var(--ink-muted)" }}>—</span> : row.passwordPreview}
              </td>
              <td style={{ padding: "var(--space-1) var(--space-2)", color: "var(--ink-muted)" }}>
                {row.type === "note" ? "Note" : "Login"}
                {row.carriedCount > 0 ? ` (+${row.carriedCount} in notes)` : ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DuplicatesSection({
  groups,
  skipGroups,
  onToggle,
}: {
  groups: readonly DuplicateGroup[];
  skipGroups: Record<number, boolean>;
  onToggle(index: number, skip: boolean): void;
}) {
  return (
    <section style={{ marginTop: "var(--space-4)" }}>
      <h3 style={{ fontSize: "0.9375rem", fontWeight: 600 }}>
        Possible duplicates ({groups.length})
      </h3>
      <p style={{ color: "var(--ink-muted)", fontSize: "0.875rem" }}>
        Same website and username as something you already have, or as another row in this file.
        Choose whether to skip each one; nothing is merged for you.
      </p>
      <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
        {groups.map((group, index) => (
          <li key={`${group.key.host}\n${group.key.username}`} style={{ borderTop: "1px solid var(--rule)", padding: "var(--space-2) 0" }}>
            <label style={{ display: "flex", gap: "var(--space-2)", alignItems: "baseline" }}>
              <input
                type="checkbox"
                checked={skipGroups[index] ?? false}
                onChange={(e) => onToggle(index, e.target.checked)}
              />
              <span>
                <span style={{ display: "block" }}>
                  {group.key.host}
                  {group.key.username !== "" ? ` · ${group.key.username}` : ""}
                </span>
                <span style={{ color: "var(--ink-muted)", fontSize: "0.8125rem" }}>
                  {group.existing.length > 0
                    ? `Already in your vault${group.rows.length > 1 ? `, and ${group.rows.length} rows in this file` : ""}`
                    : `Appears on ${group.rows.length} rows in this file`}
                  {" — "}
                  {(skipGroups[index] ?? false) ? "skip" : "import anyway"}
                </span>
              </span>
            </label>
          </li>
        ))}
      </ul>
    </section>
  );
}

function ErrorList({ title, errors }: { title: string; errors: readonly ImportRowError[] }) {
  return (
    <section style={{ marginTop: "var(--space-4)" }}>
      <h3 style={{ fontSize: "0.9375rem", fontWeight: 600 }}>
        {title} ({errors.length})
      </h3>
      <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
        {errors.map((rowError) => (
          <li
            key={`${rowError.row}:${rowError.message}`}
            style={{ borderTop: "1px solid var(--rule)", padding: "var(--space-2) 0", fontSize: "0.875rem" }}
          >
            {/* Row number plus the format's own message: a user who imports 400
                of 414 can see which 14 and why, rather than trusting a bare
                "imported 400". */}
            <span style={{ color: "var(--ink-muted)" }}>Row {rowError.row}:</span> {rowError.message}
          </li>
        ))}
      </ul>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/*                              The completion                                */
/* -------------------------------------------------------------------------- */

function CompletionScreen({ completed, onImportAnother }: { completed: Completed; onImportAnother(): void }) {
  const { outcome, skipped, errors, targetName } = completed;
  // The landed count, straight from what the server confirmed — never the
  // number of items attempted. A partial failure that reported the attempt
  // would tell the user 400 items are in their vault when 200 are, and send
  // them into a re-import that duplicates the 200 that did land.
  const landed = outcome.uploaded;
  const attempted = outcome.total;
  const notLanded = attempted - landed;

  return (
    <section>
      <h3 style={{ fontSize: "1rem", fontWeight: 600 }}>
        Imported {landed} {landed === 1 ? "item" : "items"} into {targetName}.
      </h3>

      {/* The full accounting, so "imported N" is a number the user can check. */}
      <ul style={{ margin: "var(--space-2) 0", paddingLeft: "var(--space-4)", color: "var(--ink-muted)" }}>
        {skipped > 0 && <li>{skipped} skipped as duplicates</li>}
        {errors.length > 0 && <li>{errors.length} could not be read (listed below)</li>}
      </ul>

      {outcome.error !== null && notLanded > 0 && (
        <p role="alert" style={{ color: "var(--danger)" }}>
          {notLanded} {notLanded === 1 ? "item" : "items"} did not upload, so {landed} of{" "}
          {attempted} landed. You can import the file again — the {landed} already saved will show as
          duplicates you can skip.
        </p>
      )}

      {outcome.inDoubt > 0 && (
        // Genuinely unknown, not merely failed: a lost connection or a 5xx can
        // arrive after the write committed, so these items may or may not be in
        // the vault. Saying which is the only honest answer.
        <p role="status" style={{ color: "var(--ink-muted)" }}>
          {outcome.inDoubt} of those {outcome.inDoubt === 1 ? "item is" : "items are"} in doubt: the
          server did not confirm them, so they may or may not have been saved. Check for them before
          importing again.
        </p>
      )}

      {errors.length > 0 && <ErrorList title="Rows that could not be read" errors={errors} />}

      {/* The next action sits above the delete instruction on purpose, so that
          instruction is the last thing on the screen rather than something the
          eye slides past on its way to a button. */}
      <div style={{ marginTop: "var(--space-4)" }}>
        <Button type="button" variant="quiet" onClick={onImportAnother}>
          Import another file
        </Button>
      </div>

      {/* The last thing on the screen, and deliberately so. Spec §7: an
          unencrypted CSV of every password sitting in Downloads is the most
          likely real-world compromise of this system. This is not a footnote. */}
      <div
        style={{
          marginTop: "var(--space-6)",
          padding: "var(--space-4)",
          border: "1px solid var(--rule-strong)",
        }}
      >
        <h3 style={{ fontSize: "1rem", fontWeight: 600, marginTop: 0, color: "var(--danger)" }}>
          Now delete the export file
        </h3>
        <p style={{ margin: 0 }}>
          It is an unencrypted copy of every password you just imported. A file like that left in
          your Downloads folder is the most likely way this vault is ever compromised — delete it,
          and empty your trash.
        </p>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/*                                  Helpers                                   */
/* -------------------------------------------------------------------------- */

const VENDOR_NAMES: Record<ImportVendor, string> = {
  bitwarden: "Bitwarden",
  lastpass: "LastPass",
  onepassword: "1Password",
  chrome: "Chrome",
  edge: "Edge",
  brave: "Brave",
  firefox: "Firefox",
  safari: "Safari",
  keepass: "KeePass",
  keepassxc: "KeePassXC",
  nordpass: "NordPass",
  dashlane: "Dashlane",
  protonpass: "Proton Pass",
  keeper: "Keeper",
};

function vendorList(vendors: readonly ImportVendor[]): string {
  const names = vendors.map((vendor) => VENDOR_NAMES[vendor]);
  if (names.length <= 1) return names[0] ?? "";
  return `${names.slice(0, -1).join(", ")} or ${names[names.length - 1]}`;
}

function completedTarget(collections: { id: string; name: string }[], collectionId: string | null): string {
  if (collectionId === null) return "";
  const name = collections.find((c) => c.id === collectionId)?.name;
  return name === undefined ? "" : ` in ${name}`;
}

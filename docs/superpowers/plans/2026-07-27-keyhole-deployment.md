# Keyhole Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the repository into something installable — one binary that serves its own web app over TLS, a one-command Proxmox installer that verifies what it downloads, and `update` / `backup` / `restore` that cannot leave the operator with a broken vault and no way back.

**Architecture:** The built web app is embedded in the Go binary with `embed.FS` and served from the same origin as `/api`, which is what the CSP and the session cookies already assume. Releases are built by GitHub Actions as static `CGO_ENABLED=0` binaries, published with a SHA-256 checksum and a minisign signature; both the installer and `keyhole update` verify both before anything is written to disk. `keyhole update` snapshots the database first and rolls back binary *and* database automatically if the new version does not come up healthy.

**Tech Stack:** Go 1.25 stdlib + `aead.dev/minisign`, `modernc.org/sqlite` (pure Go, so cross-compiling to arm64 needs no C toolchain), GitHub Actions, bash, systemd, Proxmox VE `pct`, optional `cloudflared`.

## Global Constraints

- **`OWNER` is `ssan9876` and the repository is `keyhole`.** The release URL is `https://github.com/ssan9876/keyhole/releases/download/<TAG>/...`. Not a placeholder — write it out.
- **The installer pins a release tag, never `main`,** and embeds the minisign public key in the script text so the key is reviewable in the same download the user inspects.
- **Verify before write.** Checksum and signature are both checked before any downloaded byte reaches an executable path. A verification failure aborts and leaves the previous state untouched.
- **The server must never be left down by an update.** Every failure path restarts something that works.
- **`crypto.subtle` requires a secure context.** The web app cannot function over plain HTTP on a non-loopback origin — `globalThis.crypto.subtle` is `undefined` there, so every AES-GCM call in `packages/crypto/src/symmetric.ts` throws. Any install path that would produce that is a broken install, and Task 2 makes it impossible to configure one silently.
- **Secrets never appear in logs or command lines.** A Cloudflare tunnel token is read from a prompt or a file, never passed as a visible argument that lands in shell history or `ps`.
- Go: `go build ./... && go vet ./... && gofmt -l . && go test ./...` all clean. New shell scripts pass `shellcheck` and `bash -n`.
- Every task ends with a mutation check: break the production code, watch the named test fail, revert, and paste the failure output into the report.
- Commit after each task.

## Verification commands

```bash
go test ./... && go vet ./... && gofmt -l .
cd apps/web && pnpm build && pnpm test
shellcheck scripts/install.sh
```

---

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `internal/webui/webui.go` | Embeds `dist/` and serves it with SPA fallback and correct caching |
| `internal/webui/dist/placeholder.html` | Committed stand-in so `go build` works on a fresh clone |
| `internal/release/release.go` | Fetch the latest release, verify checksum + signature |
| `internal/release/install.go` | Atomic binary swap, keep-previous, rollback |
| `internal/backup/backup.go` | `VACUUM INTO` snapshots, retention, restore |
| `cmd/keyhole/update.go`, `backup.go`, `restore.go` | The three new subcommands |
| `scripts/install.sh` | Proxmox LXC creation and provisioning |
| `.github/workflows/ci.yml` | Tests on every push |
| `.github/workflows/release.yml` | Tagged release: build, checksum, sign, publish |
| `README.md` | Install, accepted limitations, operating notes |

**Modified:**

| Path | Change |
|---|---|
| `internal/config/config.go` | `tls_cert`, `tls_key`, `service_name`, `update_repo` |
| `internal/httpapi/server.go` | `/api/` keeps the JSON 404; `/` serves the web app |
| `internal/httpapi/middleware.go` | Cache headers that let hashed assets be cached |
| `cmd/keyhole/serve.go` | Serve HTTPS when a certificate is configured |
| `cmd/keyhole/main.go` | New subcommands in the usage text |
| `apps/web/vite.config.ts` | Build into `internal/webui/dist` |
| `apps/web/src/ui/App.tsx` | Refuse to run in an insecure context, and say why |
| `.gitignore` | Ignore the built `dist` except the placeholder |

---

## Task 1: Serve the web app from the binary

Today `keyhole serve` answers `/` with `{"error":{"code":"not_found"}}`. Every page of the web app 404s, including `/enroll/<token>` — which is the *first* URL any new user opens. Vite's dev server has been hiding this for two plans.

**Files:**
- Create: `internal/webui/webui.go`, `internal/webui/webui_test.go`, `internal/webui/dist/placeholder.html`
- Modify: `internal/httpapi/server.go`, `internal/httpapi/middleware.go`, `apps/web/vite.config.ts`, `.gitignore`

**Interfaces:**
- Produces: `webui.Handler() (http.Handler, error)` and `webui.Built() bool`.

- [ ] **Step 1: Write the failing test**

Create `internal/webui/webui_test.go`:

```go
package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestHandlerServesTheIndexAtRoot(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	rec := get(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct == "" {
		t.Error("no Content-Type on the index")
	}
}

// The invite link is the first URL a new user ever opens, and it is a client
// route with no file behind it. Without the fallback it 404s and the account
// can never be set up.
func TestHandlerServesTheIndexForAClientRoute(t *testing.T) {
	h, _ := Handler()
	rec := get(t, h, "/enroll/tok_abc123")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /enroll/tok_abc123 = %d, want 200", rec.Code)
	}
	root := get(t, h, "/")
	if rec.Body.String() != root.Body.String() {
		t.Error("client route did not return the same document as /")
	}
}

// A missing asset must NOT fall back to the index: a bundle referencing a file
// that no longer exists would receive HTML with a 200 and fail with an opaque
// syntax error instead of a 404 anyone can diagnose.
func TestHandlerReturnsNotFoundForAMissingAsset(t *testing.T) {
	h, _ := Handler()
	if rec := get(t, h, "/assets/does-not-exist.js"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /assets/does-not-exist.js = %d, want 404", rec.Code)
	}
}

func TestHashedAssetsAreCacheableAndTheIndexIsNot(t *testing.T) {
	h, _ := Handler()

	index := get(t, h, "/")
	if cc := index.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("index Cache-Control = %q, want no-store", cc)
	}

	// The index names the hashed bundles, so caching it would pin a browser to
	// an old build forever. The bundles themselves carry a content hash in the
	// name, so they can be cached for a year.
	asset := get(t, h, "/assets/"+someAssetName(t))
	if cc := asset.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("asset Cache-Control = %q, want a year and immutable", cc)
	}
}

func TestBuiltReportsWhetherARealIndexIsEmbedded(t *testing.T) {
	// Guards the failure mode where a release ships the placeholder because
	// `pnpm build` never ran. Built() is what release.yml asserts against.
	if !Built() {
		t.Skip("dist holds only the placeholder; run `pnpm --filter @keyhole/web build`")
	}
}
```

`someAssetName` is a helper that reads the embedded `dist/assets` directory and returns the first entry, skipping the whole test with a clear message when the app has not been built. Do not hard-code a hashed filename — it changes on every build.

- [ ] **Step 2: Run to verify it fails**

```bash
go test ./internal/webui/
```

Expected: build failure, no such package.

- [ ] **Step 3: Create the placeholder and the ignore rules**

`internal/webui/dist/placeholder.html`:

```html
<!doctype html>
<title>Keyhole — web app not built</title>
<p>This binary was built without the web app. Run
<code>pnpm --filter @keyhole/web build</code> and rebuild.</p>
```

Append to `.gitignore`:

```
# The built web app is embedded at build time. The placeholder is committed so
# `go build ./...` works on a fresh clone, where dist/ would otherwise be empty
# and the //go:embed pattern would match nothing and fail to compile.
/internal/webui/dist/*
!/internal/webui/dist/placeholder.html
```

- [ ] **Step 4: Implement the handler**

Create `internal/webui/webui.go`:

```go
// Package webui embeds the built web application and serves it beside the API.
//
// Same origin, deliberately: the CSP in internal/httpapi/middleware.go is
// "default-src 'self'" with no external hosts, and serving the app from
// anywhere else would require loosening it.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// all: is required — without it the pattern skips files beginning with "_" or
// ".", and Vite emits neither today but a plugin could tomorrow.
//
//go:embed all:dist
var embedded embed.FS

const indexPath = "index.html"

func dist() (fs.FS, error) { return fs.Sub(embedded, "dist") }

// Built reports whether a real build is embedded rather than the placeholder.
// The release workflow asserts on this so a binary that would serve the
// placeholder never reaches a release page.
func Built() bool {
	files, err := dist()
	if err != nil {
		return false
	}
	_, err = fs.Stat(files, indexPath)
	return err == nil
}

// Handler serves the embedded application.
//
// Two rules, and the difference between them matters:
//
//   - A path under /assets/ is a real file or it is a 404. Falling back to the
//     index there would answer a request for a missing bundle with HTML and a
//     200, which the browser reports as a syntax error in an unrelated file.
//   - Any other unmatched GET returns the index, because the client owns its
//     routes. /enroll/<token> is the first URL a new user opens and there is no
//     file behind it.
func Handler() (http.Handler, error) {
	files, err := dist()
	if err != nil {
		return nil, err
	}
	server := http.FileServer(http.FS(files))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = indexPath
		}

		if _, statErr := fs.Stat(files, name); statErr != nil {
			if strings.HasPrefix(r.URL.Path, "/assets/") {
				http.NotFound(w, r)
				return
			}
			name = indexPath
			r = r.Clone(r.Context())
			r.URL.Path = "/" + indexPath
		}

		// Overwrites the blanket no-store from securityHeaders, which runs
		// before this handler and has not flushed yet. Vite puts a content hash
		// in every asset filename, so those are immutable; the index names them
		// and must never be cached, or a browser pins itself to an old build.
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		server.ServeHTTP(w, r)
	}), nil
}
```

If `Built()` is false, `Handler` still works — it serves `placeholder.html` for `/` via a small branch, so an operator who built wrong gets an explanation rather than a 404. Add that branch and a test for it.

- [ ] **Step 5: Route it**

In `internal/httpapi/server.go`, replace the catch-all. The API's JSON 404 must survive for API paths, or a mistyped endpoint would return an HTML page to a JSON client:

```go
	// /api/ before /: ServeMux picks the longer pattern, so an unknown API
	// path keeps the JSON envelope every client parses, while everything else
	// falls through to the web app.
	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, http.StatusNotFound, CodeNotFound, "no such endpoint")
	})

	if s.web != nil {
		s.mux.Handle("/", s.web)
	} else {
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			WriteError(w, http.StatusNotFound, CodeNotFound, "no such endpoint")
		})
	}
```

Add a `web http.Handler` field to `Server` and a `WithWebUI(http.Handler)` option, defaulting to nil so every existing test keeps its JSON 404. `cmd/keyhole/serve.go` passes `webui.Handler()`.

Add to `internal/httpapi/server_test.go`:

```go
func TestUnknownAPIPathStillReturnsTheJSONEnvelope(t *testing.T)
func TestUnknownNonAPIPathReachesTheWebHandlerWhenOneIsConfigured(t *testing.T)
```

- [ ] **Step 6: Point Vite at it**

`apps/web/vite.config.ts`:

```ts
export default defineConfig({
  plugins: [react()],
  build: {
    // Straight into the Go embed directory: a copy step is one more thing to
    // forget, and forgetting it ships a binary serving the placeholder.
    outDir: "../../internal/webui/dist",
    emptyOutDir: true,
  },
  server: { /* unchanged */ },
});
```

`emptyOutDir: true` deletes `placeholder.html` on every build. That is fine and expected — it is committed, so `git checkout internal/webui/dist/placeholder.html` restores it, and Task 5's release workflow does not need it. Add a line saying so in the README's development section.

- [ ] **Step 7: Run everything**

```bash
cd apps/web && pnpm build && cd ../..
go test ./... && go vet ./... && gofmt -l .
```

Then start it for real and check the route that has never worked:

```bash
go run ./cmd/keyhole serve --config /tmp/keyhole/config.yml
curl -si http://127.0.0.1:8477/enroll/tok_abc | head -1     # want 200
curl -si http://127.0.0.1:8477/api/nope | head -1           # want 404 + JSON
```

- [ ] **Step 8: Mutation check**

Mutation A — remove the `/assets/` branch so every miss falls back to the index. `TestHandlerReturnsNotFoundForAMissingAsset` must fail.

Mutation B — drop the `/api/` catch-all registration. `TestUnknownAPIPathStillReturnsTheJSONEnvelope` must fail with an HTML body.

Mutation C — set `Cache-Control: no-store` unconditionally. The cache test must fail. Revert all three.

- [ ] **Step 9: Commit**

```bash
git add internal/webui .gitignore internal/httpapi apps/web/vite.config.ts
git commit -m "feat(server): serve the embedded web app, with SPA fallback and asset caching"
```

---

## Task 2: TLS, and refusing to run without it

`packages/crypto/src/symmetric.ts` calls `globalThis.crypto.subtle` for every AES-GCM operation, and **`crypto.subtle` is undefined outside a secure context**. Served over plain HTTP on a LAN address, Keyhole is not a degraded password manager — it is one that cannot open a single item, failing with an opaque `Cannot read properties of undefined`.

So the server has to be able to terminate TLS itself, and the client has to say plainly what is wrong when it cannot.

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`, `cmd/keyhole/serve.go`
- Modify: `apps/web/src/ui/App.tsx`, `apps/web/src/ui/App.test.tsx`
- Create: `cmd/keyhole/serve_test.go`

**Interfaces:**
- Produces: `Config.TLSCert`, `Config.TLSKey`, `Config.TLSEnabled() bool`.

- [ ] **Step 1: Write the failing tests**

`internal/config/config_test.go`:

```go
func TestLoadReadsTLSPaths(t *testing.T)
func TestTLSEnabledRequiresBothCertAndKey(t *testing.T) {
	// One without the other is a misconfiguration, not a half-enabled state:
	// silently serving plain HTTP because the key path had a typo produces an
	// install where nothing can be decrypted and nothing says why.
}
func TestLoadRejectsACertWithoutAKey(t *testing.T) {
	// ...want an error mentioning both keys
}
```

`cmd/keyhole/serve_test.go`: generate a self-signed certificate into a temp dir with `crypto/x509`, start the server on `127.0.0.1:0`, and assert `GET https://.../healthz` returns 200 over TLS with a client trusting that certificate. Then assert a plain `http://` request to the same port fails.

`apps/web/src/ui/App.test.tsx`:

```tsx
it("explains that an insecure origin cannot work, instead of showing the unlock form", () => {
  // jsdom: delete the subtle property and set isSecureContext false
  vi.stubGlobal("isSecureContext", false);
  render(<App />);
  expect(screen.getByRole("alert")).toHaveTextContent(/https/i);
  expect(screen.queryByLabelText("Master password")).not.toBeInTheDocument();
});

it("shows the unlock form on a secure origin", () => { /* the control case */ });
```

- [ ] **Step 2–4: Implement**

`config.go` gains:

```go
	// TLSCert and TLSKey terminate TLS in this process. Set by the installer on
	// a LAN-only install, where the alternative is a plain-HTTP origin — and a
	// plain-HTTP origin has no window.crypto.subtle, so the web app cannot
	// derive a key, unwrap a key, or open a single item.
	TLSCert string
	TLSKey  string
```

with `tls_cert` / `tls_key` keys, and a validation error naming both when exactly one is set.

`serve.go`:

```go
	if cfg.TLSEnabled() {
		logger.Info("listening", "addr", cfg.Addr, "tls", true, "base_url", cfg.BaseURL)
		err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		logger.Info("listening", "addr", cfg.Addr, "tls", false, "base_url", cfg.BaseURL)
		err = srv.ListenAndServe()
	}
```

plus a startup warning when TLS is off *and* `Addr` is not loopback:

```go
	// Not fatal: a reverse proxy in front of a loopback bind is a correct
	// deployment, and so is a tunnel. Binding a routable address in the clear
	// is not, and the operator should hear about it at the moment they do it
	// rather than from a user who cannot unlock.
	logger.Warn("serving without TLS on a non-loopback address; " +
		"the web app needs a secure context and will not be able to decrypt anything")
```

`App.tsx` gains a boot guard before any other branch:

```tsx
  // WebCrypto's SubtleCrypto is only exposed in a secure context. On a plain
  // http:// origin that is not localhost it is simply absent, and every
  // AES-GCM call throws "Cannot read properties of undefined" — which reads
  // like a bug in Keyhole rather than a deployment that cannot work.
  if (!window.isSecureContext || globalThis.crypto?.subtle === undefined) {
    return (
      <main role="alert" /* ... */>
        <h1>This page needs a secure connection</h1>
        <p>
          Keyhole does all of its encryption in your browser, and browsers only
          provide the encryption API over HTTPS. Reach this server over
          <code>https://</code> and try again.
        </p>
      </main>
    );
  }
```

- [ ] **Step 5: Mutation check**

Mutation A — make `TLSEnabled()` return `c.TLSCert != ""`. `TestTLSEnabledRequiresBothCertAndKey` must fail.

Mutation B — change the guard to `!window.isSecureContext` only. Write the covering case first: a jsdom environment with `isSecureContext` true but `crypto.subtle` deleted, which is what an old browser looks like. Revert.

- [ ] **Step 6: Commit**

```bash
git add internal/config cmd/keyhole apps/web/src/ui
git commit -m "feat: terminate TLS in-process, and refuse to pretend an insecure origin can work"
```
---

## Task 3: `keyhole backup` and `keyhole restore`

`VACUUM INTO` produces a consistent snapshot from a live database without stopping the server. The snapshot is entirely ciphertext, so it can be replicated somewhere not fully trusted without exposing a password — which is the point of saying so in the README.

**Files:**
- Create: `internal/backup/backup.go`, `internal/backup/backup_test.go`
- Create: `cmd/keyhole/backup.go`, `cmd/keyhole/restore.go`
- Modify: `cmd/keyhole/main.go`

**Interfaces:**
- Produces:
  ```go
  func Snapshot(ctx context.Context, db *sql.DB, dir string, at time.Time) (string, error)
  func Prune(dir string, keep int) ([]string, error)
  func Restore(snapshotPath, dbPath string) error
  ```

**Naming.** `keyhole-20260727T143000Z.db`, UTC, second precision, so lexical order is chronological — which is what makes `Prune` a sort and a slice rather than a date parser.

- [ ] **Step 1: Write the failing tests**

`internal/backup/backup_test.go`:

```go
func TestSnapshotProducesAReadableDatabaseWithTheSameRows(t *testing.T) {
	// Open a real store, migrate, insert a known row, snapshot, then open the
	// snapshot and read the row back. "A file appeared" is not evidence: a
	// zero-byte file appears too.
}

func TestSnapshotRefusesToOverwriteAnExistingFile(t *testing.T) {
	// Two backups in the same second must not silently leave one snapshot.
}

func TestPruneKeepsTheNewestAndDeletesTheRest(t *testing.T) {
	// Names sort chronologically by construction; assert on which files remain.
}

func TestPruneIgnoresFilesItDidNotWrite(t *testing.T) {
	// An operator's own notes.txt in the backup directory must survive. This is
	// a delete loop pointed at a user-specified directory; the filter is the
	// only thing between it and their files.
}

func TestPruneWithKeepZeroDeletesNothing(t *testing.T) {
	// A missing --keep must not be read as "keep none".
}

func TestRestoreReplacesTheDatabaseAndItOpens(t *testing.T)

func TestRestoreRefusesAFileThatIsNotASQLiteDatabase(t *testing.T) {
	// ...and leaves the original database untouched. Verified by reading a row
	// from it afterwards, not by checking the error alone.
}

func TestRestoreKeepsTheReplacedDatabaseBesideIt(t *testing.T) {
	// keyhole.db.replaced-<stamp>: restoring the wrong snapshot is a mistake
	// an operator makes at 2am, and it must not be the last copy.
}
```

- [ ] **Step 2: Run to verify failure**

```bash
go test ./internal/backup/
```

- [ ] **Step 3: Implement**

`internal/backup/backup.go`:

```go
// Package backup snapshots and restores the Keyhole database.
//
// Every snapshot is ciphertext: item bodies, names, and URLs are encrypted
// under keys the server has never held. That is what makes off-box replication
// to somewhere less trusted a reasonable thing to do, and it is worth saying
// out loud because it is unusual.
package backup

const snapshotPrefix = "keyhole-"
const snapshotSuffix = ".db"

// Snapshot writes a consistent copy without stopping the server. VACUUM INTO
// takes its own read transaction, so a write landing mid-copy cannot produce a
// torn file.
func Snapshot(ctx context.Context, db *sql.DB, dir string, at time.Time) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	name := snapshotPrefix + at.UTC().Format("20060102T150405Z") + snapshotSuffix
	path := filepath.Join(dir, name)

	// VACUUM INTO fails on an existing target, but checking first turns a
	// driver-specific error into one that names the file.
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("snapshot %s already exists", path)
	}

	// Quoting: the path is interpolated because VACUUM INTO takes no
	// parameters. Doubling any single quote is what keeps a directory name
	// with an apostrophe from ending the string literal.
	quoted := "'" + strings.ReplaceAll(path, "'", "''") + "'"
	if _, err := db.ExecContext(ctx, "VACUUM INTO "+quoted); err != nil {
		return "", fmt.Errorf("vacuum into %s: %w", path, err)
	}
	return path, nil
}
```

`Prune` lists the directory, keeps only entries matching the prefix **and** suffix, sorts descending, and removes everything past `keep`. `keep <= 0` returns immediately having deleted nothing.

`Restore`:

1. Open the snapshot read-only and run `PRAGMA integrity_check` — a truncated download must be caught before it becomes the live database.
2. Confirm it has a `schema_migrations` table, so restoring some unrelated SQLite file fails loudly.
3. Rename the existing database to `keyhole.db.replaced-<stamp>` rather than deleting it.
4. Copy the snapshot into place with `0o600`, then `fsync` the file and the directory.
5. Remove any stale `-wal` and `-shm` beside the old database; leaving them applies a journal belonging to a database that no longer exists.

`cmd/keyhole/backup.go`: `keyhole backup [--config PATH] [--out DIR] [--keep N]`, defaulting `--out` to `<data_dir>/backups` and `--keep` to 14. Prints the path and, when it pruned, what it removed. `cmd/keyhole/restore.go`: `keyhole restore <file> [--config PATH]`, refusing to run if the database is currently locked by another process (attempt `PRAGMA locking_mode=EXCLUSIVE` plus a write), with an error telling the operator to stop the service first.

- [ ] **Step 4: Run and check by hand**

```bash
go test ./internal/backup/
go run ./cmd/keyhole backup --config /tmp/keyhole/config.yml
```

- [ ] **Step 5: Mutation check**

Mutation A — in `Prune`, drop the prefix filter so every file in the directory is a candidate. `TestPruneIgnoresFilesItDidNotWrite` must fail. This is the one that matters: the mutation is a plausible simplification and its blast radius is an operator's data.

Mutation B — in `Restore`, skip the integrity check. `TestRestoreRefusesAFileThatIsNotASQLiteDatabase` must fail.

Mutation C — in `Prune`, treat `keep == 0` as "keep none". Its test must fail. Revert.

- [ ] **Step 6: Commit**

```bash
git add internal/backup cmd/keyhole
git commit -m "feat(cli): keyhole backup and restore, with retention and a kept-aside original"
```

---

## Task 4: `keyhole update`, with automatic rollback

Design spec §10 names the acceptance test: *rollback verified by pointing the updater at a deliberately broken binary and asserting the service returns healthy*. That is the test this task is built around, so everything that touches the outside world sits behind an interface.

**Files:**
- Create: `internal/release/release.go`, `internal/release/release_test.go`
- Create: `internal/release/install.go`, `internal/release/install_test.go`
- Create: `cmd/keyhole/update.go`
- Modify: `cmd/keyhole/main.go`, `go.mod` (add `aead.dev/minisign`)

**Interfaces:**
- Produces:
  ```go
  type Release struct { Version, Notes string; Assets map[string]string }
  type Source interface { Latest(ctx context.Context) (Release, error); Download(ctx context.Context, url string) ([]byte, error) }
  type Service interface { Stop(ctx context.Context) error; Start(ctx context.Context) error }
  type Health interface { Wait(ctx context.Context, timeout time.Duration) error }

  func Verify(binary []byte, sha256Line string, signature []byte, publicKey string) error
  func Update(ctx context.Context, deps Deps, opts Options) (Outcome, error)
  ```

**The sequence, and why each step is where it is:**

1. Fetch the latest release; compare with the compiled-in `Version`. `--check` stops here and prints.
2. Download binary, `SHA256SUMS`, and `.minisig`.
3. **Verify both, before writing anything.** The signature is over `SHA256SUMS`, not over the binary — so one signature covers every architecture, and the checksum line binds this file to it. Verify the signature first, then the checksum: checking the checksum against an unsigned list proves nothing.
4. Snapshot the database. Migrations run in step 6 and are not reversible.
5. Stop the service. Rename the running binary to `keyhole.prev`. Write the new one to a temp file in the same directory, `chmod 0755`, `fsync`, `rename` into place — same-directory rename is what makes the swap atomic.
6. Run `keyhole migrate` with the new binary. Start the service.
7. Poll `/healthz` for up to 30 seconds.
8. On any failure from step 5 onward: stop, move `keyhole.prev` back, restore the snapshot, start, and **report that a rollback happened** — a silent rollback leaves an operator believing they upgraded.

- [ ] **Step 1: Write the failing tests**

`internal/release/release_test.go`:

```go
func TestVerifyAcceptsAGenuineSignatureAndChecksum(t *testing.T) {
	// Generate a real minisign keypair in the test with aead.dev/minisign,
	// sign a real SHA256SUMS, and verify. A hand-written fixture cannot prove
	// the verifier accepts what the release workflow actually produces.
}

func TestVerifyRejectsATamperedBinary(t *testing.T) {
	// Flip one byte of the binary. The signature over SHA256SUMS is still
	// valid, which is exactly the attack the checksum step exists to catch.
}

func TestVerifyRejectsATamperedChecksumFile(t *testing.T) {
	// Rewrite SHA256SUMS to match the tampered binary. Now the checksum
	// matches and the signature does not, which is the other half.
}

func TestVerifyRejectsASignatureFromADifferentKey(t *testing.T)

func TestVerifyRejectsAChecksumFileWithNoLineForThisFile(t *testing.T) {
	// A signed SHA256SUMS from a different release names other files. Falling
	// through to "no line, nothing to compare, fine" would accept anything.
}
```

`internal/release/install_test.go`:

```go
func TestUpdateInstallsTheNewBinaryAndStartsTheService(t *testing.T)

func TestUpdateRollsBackBinaryAndDatabaseWhenHealthNeverComesUp(t *testing.T) {
	// Spec §10's named test. A fake Health that always fails, and afterwards:
	//   - the binary on disk is byte-identical to the original
	//   - the database contains the row written before the update
	//   - the fake Service was started again
	//   - the Outcome says RolledBack, with the reason
}

func TestUpdateDoesNotStopTheServiceWhenVerificationFails(t *testing.T) {
	// The service must never go down for a download that was never going to be
	// installed.
}

func TestUpdateWithCheckOnlyDownloadsNothingAndChangesNothing(t *testing.T)

func TestUpdateReportsAlreadyCurrentWithoutTouchingTheService(t *testing.T)

func TestRollbackItselfFailingIsReportedRatherThanSwallowed(t *testing.T) {
	// The worst case — new binary bad AND the previous one unreadable — must
	// produce an error naming both, not a generic failure. An operator in that
	// state needs to know to restore from a snapshot by hand.
}
```

- [ ] **Step 2: Run to verify failure**

```bash
go test ./internal/release/
```

- [ ] **Step 3: Implement**

Add the dependency:

```bash
go get aead.dev/minisign@latest
```

`Verify`:

```go
// Verify checks a downloaded binary against a signed checksum list.
//
// The signature covers SHA256SUMS rather than the binary, which is what lets
// one signature cover every architecture in a release. That only holds if both
// halves are checked: the signature proves the list is ours, and the list's
// line for this file proves the bytes are the ones we published. Either alone
// is worthless — a valid signature over a list that does not mention this file
// says nothing about it.
func Verify(binary []byte, checksums string, signature []byte, publicKey string, filename string) error {
	var key minisign.PublicKey
	if err := key.UnmarshalText([]byte(publicKey)); err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	if !minisign.Verify(key, []byte(checksums), signature) {
		return errors.New("the release signature is not valid for these checksums")
	}

	want, ok := checksumFor(checksums, filename)
	if !ok {
		return fmt.Errorf("the signed checksum list has no entry for %s", filename)
	}
	got := hex.EncodeToString(sha256.New().Sum(nil)) // replaced by a real sum below
	sum := sha256.Sum256(binary)
	got = hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("checksum mismatch for %s", filename)
	}
	return nil
}
```

(Write that cleanly — the placeholder line above is there to make the point that the sum is computed from `binary`, not from anything the server sent.)

`checksumFor` parses the standard `sha256sum` format: `<64 hex>  <name>`, two spaces, one entry per line. Match on the basename, ignore unknown lines, and return false when the name is absent.

`Update` takes everything external as an interface:

```go
type Deps struct {
	Source  Source
	Service Service
	Health  Health
	// Paths of the running binary, the previous-binary slot, and the database.
	BinaryPath, PreviousPath, DBPath, BackupDir string
	Migrate func(ctx context.Context) error
	Logf    func(format string, args ...any)
}
```

so the rollback test drives it with fakes and no systemd, no network, and no real binary.

`cmd/keyhole/update.go` wires the real implementations: a `githubSource` over `https://api.github.com/repos/ssan9876/keyhole/releases/latest`, a `systemctlService`, and an `httpHealth` polling `/healthz` on `cfg.Addr` (over TLS when configured, skipping verification for a self-signed local certificate — it is a loopback liveness check, not an authentication decision, and that reasoning belongs in a comment beside it).

`Version` is a package-level `var Version = "dev"` in `main`, set at build time by `-ldflags`. `keyhole update` on a `dev` build refuses with "this build was not produced by a release; update is for released binaries."

Also install the `/usr/local/bin/update` shim (spec §8.2) — a two-line script calling `keyhole update "$@"` — from `install.sh` in Task 6, not from here.

- [ ] **Step 4: Run the tests**

```bash
go test ./internal/release/ -v -run Rollback
go test ./... && go vet ./...
```

- [ ] **Step 5: Mutation check**

Mutation A — in `Verify`, return nil when `checksumFor` reports the file is absent. `TestVerifyRejectsAChecksumFileWithNoLineForThisFile` must fail.

Mutation B — in `Verify`, check the checksum but skip `minisign.Verify`. `TestVerifyRejectsATamperedChecksumFile` must fail.

Mutation C — in `Update`, skip restoring the database during rollback (restore only the binary). `TestUpdateRollsBackBinaryAndDatabaseWhenHealthNeverComesUp` must fail on the row assertion. If it does not, the test is not reading a row that the failed migration would have changed — fix the test, because that is the half of rollback nobody notices is missing.

Mutation D — move the service stop before verification. `TestUpdateDoesNotStopTheServiceWhenVerificationFails` must fail. Revert all four.

- [ ] **Step 6: Commit**

```bash
git add internal/release cmd/keyhole go.mod go.sum
git commit -m "feat(cli): keyhole update with signature verification and automatic rollback"
```

---

## Task 5: CI and signed releases

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`

**Repository secrets the operator must create before the first tag** — document these in the README, because a release that fails at the signing step after building everything is a bad first experience:

| Secret | What it is |
|---|---|
| `MINISIGN_SECRET_KEY` | The contents of `minisign.key`, produced by `minisign -G` |
| `MINISIGN_PASSWORD` | The passphrase protecting it |

The **public** key goes into `scripts/install.sh` and the README, in plain sight.

- [ ] **Step 1: CI workflow**

`.github/workflows/ci.yml`, on push and pull request:

```yaml
name: CI
on: [push, pull_request]
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.25" }
      - run: go vet ./...
      - name: gofmt
        # gofmt -l prints offending files and exits 0, so the exit code is
        # useless as a gate; the output is the signal.
        run: test -z "$(gofmt -l .)"
      - run: go test -race ./...
  web:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with: { node-version: "22", cache: pnpm }
      - run: pnpm install --frozen-lockfile
      - run: pnpm -r typecheck
      - run: pnpm --filter @keyhole/web lint
      - run: pnpm -r test
  shell:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: shellcheck scripts/install.sh
      - run: bash -n scripts/install.sh
```

The e2e suite builds a Go binary and drives a browser; add it as a fourth job with `pnpm exec playwright install --with-deps chromium`, and let it be the slow one rather than folding it into `web`.

- [ ] **Step 2: Release workflow**

`.github/workflows/release.yml`, on `push: tags: ["v*"]`:

```yaml
      - name: Build the web app first
        run: |
          pnpm install --frozen-lockfile
          pnpm --filter @keyhole/web build

      - name: Refuse to release a binary with no web app
        # Task 1's Built() exists for this. A release that ships the
        # placeholder installs cleanly and then serves nothing.
        run: test -f internal/webui/dist/index.html

      - name: Build static binaries
        env:
          CGO_ENABLED: "0"
        run: |
          TAG="${GITHUB_REF_NAME}"
          for arch in amd64 arm64; do
            GOOS=linux GOARCH="$arch" go build \
              -trimpath \
              -ldflags "-s -w -X main.Version=${TAG}" \
              -o "dist/keyhole-linux-${arch}" ./cmd/keyhole
          done
```

`modernc.org/sqlite` is pure Go, so `CGO_ENABLED=0` cross-compiles to arm64 with no toolchain — that is why it was chosen, and the workflow should say so in a comment.

Then:

```yaml
      - name: Checksums
        run: cd dist && sha256sum keyhole-linux-* > SHA256SUMS

      - name: Sign the checksums
        env:
          MINISIGN_SECRET_KEY: ${{ secrets.MINISIGN_SECRET_KEY }}
          MINISIGN_PASSWORD: ${{ secrets.MINISIGN_PASSWORD }}
        run: |
          sudo apt-get update && sudo apt-get install -y minisign
          printf '%s' "$MINISIGN_SECRET_KEY" > /tmp/minisign.key
          # -S signs; the password arrives on stdin so it never appears in a
          # command line or in the workflow log.
          printf '%s\n' "$MINISIGN_PASSWORD" | \
            minisign -S -s /tmp/minisign.key -m dist/SHA256SUMS
          shred -u /tmp/minisign.key

      - name: Publish
        env: { GH_TOKEN: "${{ github.token }}" }
        run: |
          gh release create "$GITHUB_REF_NAME" \
            dist/keyhole-linux-amd64 dist/keyhole-linux-arm64 \
            dist/SHA256SUMS dist/SHA256SUMS.minisig \
            --generate-notes
```

- [ ] **Step 3: Verify the round trip before trusting it**

This workflow is not unit-testable, so verify it once, deliberately, on a throwaway tag:

```bash
git tag v0.0.1-rc1 && git push origin v0.0.1-rc1
# then, locally, against the published assets:
curl -fsSLO https://github.com/ssan9876/keyhole/releases/download/v0.0.1-rc1/SHA256SUMS
curl -fsSLO https://github.com/ssan9876/keyhole/releases/download/v0.0.1-rc1/SHA256SUMS.minisig
curl -fsSLO https://github.com/ssan9876/keyhole/releases/download/v0.0.1-rc1/keyhole-linux-amd64
minisign -Vm SHA256SUMS -P "<the public key>"
sha256sum -c SHA256SUMS --ignore-missing
go test ./internal/release/ -run TestVerifyAcceptsAGenuineSignature   # same code path
```

Then delete the tag and its release. **Do not skip this.** Every part of Task 4's verification is tested against a keypair the tests generate; this is the only check that the workflow produces the format that code reads.

- [ ] **Step 4: Commit**

```bash
git add .github
git commit -m "ci: test on every push, and publish signed static binaries on a tag"
```
---

## Task 6: `scripts/install.sh`

One command on the Proxmox host shell that ends with a working vault and a setup URL. Piping a script to a shell is the exact risk this product exists to defend against, so the script pins a tag, verifies what it downloads against a key printed in its own text, and prints its whole plan before touching anything.

**Files:**
- Create: `scripts/install.sh`
- Create: `scripts/testdata/dry-run-tunnel.golden`, `scripts/testdata/dry-run-lan.golden`
- Create: `scripts/install_test.sh` (or a Go test that shells out — pick one and say which)

**The command the README leads with:**

```bash
curl -fsSLO https://raw.githubusercontent.com/ssan9876/keyhole/v1.0.0/scripts/install.sh
less install.sh          # read it
bash install.sh
```

with the one-liner offered second, as the convenience option:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ssan9876/keyhole/v1.0.0/scripts/install.sh)"
```

**Flags — every prompt has one, so the script is usable non-interactively:**

```
--ctid N              container id (default: next free)
--hostname NAME       default: keyhole
--cores N             default: 2
--ram MB              default: 1024
--disk GB             default: 8
--storage NAME        default: local-lvm
--bridge NAME         default: vmbr0
--network tunnel|tls|proxy   how the vault is reached (default: prompt)
--tunnel-token-file PATH     read the Cloudflare token from a file
--hostname-external NAME     the public hostname, for base_url
--admin-email ADDR    the first administrator
--dry-run             print every command that would run, change nothing
--yes                 skip the confirmation
```

**The three network modes, and why the third exists:**

| Mode | Binds | TLS | `base_url` |
|---|---|---|---|
| `tunnel` | `127.0.0.1:8477` | Cloudflare terminates it | `https://<hostname-external>` |
| `tls` | `0.0.0.0:8477` | self-signed, generated here | `https://<container IP>:8477` |
| `proxy` | `127.0.0.1:8477` | yours | whatever you tell it |

There is no plain-HTTP-on-a-LAN-address mode. `crypto.subtle` does not exist outside a secure context, so that install would produce a vault nobody can unlock (Task 2). `tls` mode prints the certificate's SHA-256 fingerprint so the browser warning can be checked against something rather than clicked through blindly.

**Secret handling.** The Cloudflare token is read with `read -rs` or from `--tunnel-token-file`, written to a root-owned `0600` file, and passed to `cloudflared service install` from that file. Never as an argument — arguments are visible in `ps` and land in shell history.

- [ ] **Step 1: Write the failing test**

`--dry-run` is what makes this testable. It prints, in order, every command the script would execute, and exits 0 without running any of them — including without touching `pct`, so it runs anywhere.

`scripts/install_test.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
check() {
  local name="$1" golden="$2"; shift 2
  if ! diff -u "$golden" <("$@" 2>&1); then
    echo "FAIL: $name"; fail=1
  else
    echo "ok: $name"
  fi
}

check "tunnel mode plan" scripts/testdata/dry-run-tunnel.golden \
  bash scripts/install.sh --dry-run --yes --ctid 200 --network tunnel \
    --hostname-external vault.example.com --admin-email me@example.com \
    --tunnel-token-file /dev/null

check "tls mode plan" scripts/testdata/dry-run-lan.golden \
  bash scripts/install.sh --dry-run --yes --ctid 200 --network tls \
    --admin-email me@example.com

# The plan must never contain a secret, whatever mode produced it.
printf 'super-secret-token' > /tmp/kh-token
if bash scripts/install.sh --dry-run --yes --ctid 200 --network tunnel \
     --hostname-external v.example.com --admin-email me@example.com \
     --tunnel-token-file /tmp/kh-token | grep -q 'super-secret-token'; then
  echo "FAIL: the dry-run plan leaked the tunnel token"; fail=1
else
  echo "ok: no token in the plan"
fi
rm -f /tmp/kh-token

# An unknown flag must stop, not proceed with a silently ignored option.
if bash scripts/install.sh --dry-run --yes --nonsense >/dev/null 2>&1; then
  echo "FAIL: an unknown flag was accepted"; fail=1
else
  echo "ok: unknown flag rejected"
fi

# The pinned version and key must be real values, not placeholders.
grep -q 'OWNER="ssan9876"' scripts/install.sh || { echo "FAIL: OWNER"; fail=1; }
grep -qE '^VERSION="v[0-9]+\.[0-9]+\.[0-9]+"' scripts/install.sh || { echo "FAIL: VERSION not a pinned tag"; fail=1; }
grep -q 'raw.githubusercontent.com/ssan9876/keyhole/main' scripts/install.sh && { echo "FAIL: a URL points at main"; fail=1; }

exit "$fail"
```

Add it to `.github/workflows/ci.yml`'s `shell` job.

- [ ] **Step 2: Run to verify it fails**

```bash
bash scripts/install_test.sh
```

Expected: the script does not exist.

- [ ] **Step 3: Write the script**

`scripts/install.sh`. The skeleton — fill in every function completely:

```bash
#!/usr/bin/env bash
#
# Keyhole installer for Proxmox VE.
#
# Creates an unprivileged Debian 12 container, installs a signed release, and
# leaves you with a URL to set up the first administrator.
#
# Piping a script to a shell is precisely the risk a password manager exists to
# defend against, so: this file pins a release tag rather than main; it verifies
# the binary against a signature made by the key printed below, which you can
# compare against the one in the repository README; and it prints everything it
# is going to do before it does any of it.
set -euo pipefail

readonly OWNER="ssan9876"
readonly REPO="keyhole"
readonly VERSION="v1.0.0"

# The release signing key. Compare it against the README before trusting this
# script — if they differ, stop.
readonly MINISIGN_PUBKEY="RWQ...replace-with-the-real-key..."

readonly TEMPLATE_STORAGE="local"
readonly SERVICE_USER="keyhole"
readonly DATA_DIR="/var/lib/keyhole"
readonly CONFIG_DIR="/etc/keyhole"
readonly PORT="8477"

CTID=""; HOSTNAME_CT="keyhole"; CORES="2"; RAM="1024"; DISK="8"
STORAGE="local-lvm"; BRIDGE="vmbr0"; NETWORK=""; TUNNEL_TOKEN_FILE=""
HOSTNAME_EXTERNAL=""; ADMIN_EMAIL=""; DRY_RUN="no"; ASSUME_YES="no"

die() { printf 'keyhole: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

# Every side effect goes through run(), which is what makes --dry-run a real plan
# rather than an approximation that drifts from what the script does.
run() {
  if [ "$DRY_RUN" = "yes" ]; then
    printf 'RUN: %s\n' "$*"
    return 0
  fi
  "$@"
}

# For commands that must run inside the container.
in_ct() { run pct exec "$CTID" -- "$@"; }

usage() { cat <<'EOF'
... every flag from the table above, with its default ...
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --ctid) CTID="$2"; shift 2 ;;
      # ... one arm per flag ...
      --dry-run) DRY_RUN="yes"; shift ;;
      --yes) ASSUME_YES="yes"; shift ;;
      -h|--help) usage; exit 0 ;;
      # An unknown flag stops. Ignoring it would silently drop an option the
      # operator believes they set — --network among them.
      *) die "unknown option: $1" ;;
    esac
  done
}

require_pve() {
  [ "$DRY_RUN" = "yes" ] && return 0
  command -v pveversion >/dev/null 2>&1 || die "this must run on a Proxmox VE host"
  [ "$(id -u)" -eq 0 ] || die "this must run as root"
}

print_plan() {
  cat <<EOF

Keyhole ${VERSION} will be installed as follows.

  Container    ${CTID} (${HOSTNAME_CT}), unprivileged Debian 12
  Resources    ${CORES} cores, ${RAM} MB RAM, ${DISK} GB on ${STORAGE}, bridge ${BRIDGE}
  Reached by   ${NETWORK}
  Binary       https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/keyhole-linux-\${arch}
               verified against SHA256SUMS and its minisign signature
  Data         ${DATA_DIR} (SQLite; entirely ciphertext)
  Config       ${CONFIG_DIR}/config.yml
  Service      systemd unit "keyhole", running as ${SERVICE_USER}
  Admin        ${ADMIN_EMAIL}

Nothing has been changed yet.
EOF
  [ "$ASSUME_YES" = "yes" ] && return 0
  printf '\nProceed? [y/N] '
  read -r answer
  case "$answer" in y|Y|yes) ;; *) die "aborted" ;; esac
}
```

The remaining functions, each of which must be written out in full:

- **`resolve_ctid`** — `pvesh get /cluster/nextid` when `--ctid` was not given.
- **`ensure_template`** — `pveam update`, then pick the newest `debian-12-standard` from `pveam available --section system` and `pveam download` it if absent. Do not hard-code a template filename; the point release changes.
- **`create_container`** — `pct create` with `--unprivileged 1 --features nesting=0 --onboot 1`, DHCP on the chosen bridge, then `pct start` and a wait loop until `pct exec ... true` succeeds.
- **`provision_base`** — `apt-get update`, install `ca-certificates curl minisign` (and `openssl` in `tls` mode).
- **`install_binary`** — detect the architecture with `dpkg --print-architecture`; download the matching binary, `SHA256SUMS`, and `SHA256SUMS.minisig` into `/tmp` inside the container; `minisign -Vm SHA256SUMS -P "$MINISIGN_PUBKEY"`; `sha256sum -c SHA256SUMS --ignore-missing`; only then install to `/usr/local/bin/keyhole` with mode `0755`. Also write the `/usr/local/bin/update` shim (spec §8.2). **Verification failure must abort with the container left stopped**, not half-provisioned and running.
- **`create_service_user`** — `useradd --system --home ${DATA_DIR} --shell /usr/sbin/nologin`, `install -d -o keyhole -g keyhole -m 0700 ${DATA_DIR}`.
- **`configure_network`** — the three-way branch. `tls` mode runs `openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=${ip}" -addext "subjectAltName=IP:${ip}"`, installs the pair `0640 root:keyhole`, and captures the fingerprint from `openssl x509 -noout -fingerprint -sha256` for the closing message. `tunnel` mode installs `cloudflared` from Cloudflare's apt repository and registers the service from the token file. `proxy` mode writes no TLS keys and prints the two lines a reverse proxy needs.
- **`write_config`** — the four-to-six line `config.yml`, `0640 root:keyhole`.
- **`write_unit`** — the systemd unit below.
- **`bootstrap_admin`** — `keyhole migrate`, `systemctl enable --now keyhole`, wait for `/healthz`, then `runuser -u keyhole -- keyhole admin create --email "$ADMIN_EMAIL"` and capture the setup URL.
- **`print_next_steps`** — the setup URL, the certificate fingerprint in `tls` mode, where the data lives, and the two commands worth knowing: `keyhole backup` and `update`.

The systemd unit:

```ini
[Unit]
Description=Keyhole password manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=keyhole
Group=keyhole
ExecStart=/usr/local/bin/keyhole serve --config /etc/keyhole/config.yml
Restart=on-failure
RestartSec=2

# The process needs one writable directory and nothing else. Everything below
# is what keeps a compromise of the HTTP handler from becoming a compromise of
# the container.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
ReadWritePaths=/var/lib/keyhole

[Install]
WantedBy=multi-user.target
```

`MemoryDenyWriteExecute=yes` is safe here — the binary is `CGO_ENABLED=0` static Go with no JIT and no plugins. Note that in a comment, because it is the setting most likely to be removed by someone who assumes it broke something.

- [ ] **Step 4: Generate the golden files, then read them**

```bash
bash scripts/install.sh --dry-run --yes --ctid 200 --network tunnel \
  --hostname-external vault.example.com --admin-email me@example.com \
  --tunnel-token-file /dev/null > scripts/testdata/dry-run-tunnel.golden
```

Read the golden file line by line before committing it. A golden file recorded from a wrong implementation locks the wrong behaviour in and makes the test agree with the bug forever.

- [ ] **Step 5: Run the tests**

```bash
shellcheck scripts/install.sh && bash -n scripts/install.sh && bash scripts/install_test.sh
```

- [ ] **Step 6: Mutation check**

Mutation A — change the unknown-flag arm to `*) shift ;;`. "unknown flag rejected" must fail. This mutation is the realistic one: an ignored `--network` silently gives the operator a mode they did not ask for.

Mutation B — in `install_binary`, drop the `minisign -V` line and keep `sha256sum -c`. No unit test covers this, which is the finding: **add** a check to `install_test.sh` asserting that both `minisign -Vm` and `sha256sum -c` appear in the dry-run plan, in that order, then confirm the mutation fails it.

Mutation C — pass the token as an argument instead of via the file. "no token in the plan" must fail. Revert all three.

- [ ] **Step 7: Commit**

```bash
git add scripts .github/workflows/ci.yml
git commit -m "feat: proxmox installer that verifies its download and prints its plan first"
```

---

## Task 7: README

The place design spec §3.9 says the accepted limitations must live — "documented in the README, not just here."

**Files:**
- Create: `README.md`

**Sections, in this order:**

1. **What it is**, in three sentences, including the one that matters: the server never holds a key that opens anything.
2. **Install** — download-inspect-run first, the one-liner second, with the pinned tag visible in both.
3. **The signing key**, printed in full, with `minisign -Vm SHA256SUMS -P '<key>'` shown so a reader can verify a release by hand.
4. **After installing** — open the setup URL, set a master password, save the recovery code.
5. **Accepted limitations**, all four from spec §3.9, in the spec's own words: public-key substitution and the fingerprint mitigation; web-app code delivery; metadata visible to the server and to Cloudflare; endpoint compromise.
6. **What the recovery code does and does not do today.** It protects a copy of your key; **redeeming it is not implemented yet**, so a forgotten master password currently means an admin reset, which destroys personal items and collection memberships. Say this here as well as on the enrolment screen — someone deciding whether to trust this with their passwords deserves to read it before installing, not after.
7. **Operating** — `keyhole backup`, `keyhole restore`, `keyhole update`, `update --check`, where the data lives, and that snapshots are entirely ciphertext and safe to replicate off-box.
8. **Development** — `pnpm install`, `pnpm -r test`, `pnpm --filter @keyhole/web build` before `go build` (and that the build replaces the committed `internal/webui/dist/placeholder.html`, which `git checkout` restores).

- [ ] **Step 1: Write it, then check the claims**

Every factual claim in the README must be checked against the code, not against this plan. In particular: the Argon2id parameters (`packages/crypto/src/kdf.ts:20`), the recovery code's length and alphabet (`recovery.ts:14`), the default auto-lock (Plan 4 Task 8), the ports, and the paths.

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: README with install instructions and the accepted limitations"
```

---

## Task 8: Install it for real

Nothing above proves the thing installs. This task is manual and deliberate; record the result in the task report with actual output.

- [ ] **Step 1: Tag a release candidate and let CI publish it**

- [ ] **Step 2: Install into a fresh container**

On the Proxmox host:

```bash
curl -fsSLO https://raw.githubusercontent.com/ssan9876/keyhole/<TAG>/scripts/install.sh
bash install.sh --network tls --admin-email you@example.com
```

Record: whether verification ran and passed, the certificate fingerprint, the setup URL.

- [ ] **Step 3: Walk the whole flow in a browser**

Open the setup URL over HTTPS, accept the certificate after checking the fingerprint against what the installer printed, set a master password, save the recovery code, add an item, lock, unlock, read it back. Then reload `/enroll/<token>` and confirm it does **not** show enrolment again — Plan 3 shipped that bug and the SPA fallback added in Task 1 is a new chance to reintroduce it.

- [ ] **Step 4: Prove the rollback, on the real machine**

Spec §10's acceptance test, end to end rather than against fakes:

```bash
# Break the binary the updater will install:
printf 'not a binary' > /tmp/broken
# Point keyhole update at it (add a hidden --binary-file flag for exactly this,
# or stage a local release fixture), then:
keyhole update
systemctl is-active keyhole      # want: active
curl -sk https://127.0.0.1:8477/healthz   # want: {"status":"ok",...}
keyhole --version                # want: the OLD version
```

If the service is not healthy afterwards, this task is not complete — the update path is the one place a bug takes someone's vault offline while they are not looking.

- [ ] **Step 5: Backup, restore, and update forward**

```bash
keyhole backup
systemctl stop keyhole && keyhole restore /var/lib/keyhole/backups/keyhole-*.db && systemctl start keyhole
update --check
update
```

Confirm the item added in step 3 is still readable after each.

- [ ] **Step 6: Write it all down**

Fold anything surprising into the README, and record the full transcript in the task report.

---

## Self-review

**Spec coverage.** §8.1 install → Task 6. §8.2 update, with the `update` shim and `--check` and automatic rollback → Tasks 4, 6, 8. §8.3 backup and restore → Task 3; **the nightly systemd timer is part of Task 6's provisioning** (`keyhole-backup.service` + `keyhole-backup.timer`, `OnCalendar=daily`, `--keep 14`) — do not let it fall between the two tasks. §10's CI, update rollback, and static binaries → Tasks 4, 5, 8. §3.9's limitations in the README → Task 7. §6.5's PWA is **not** covered — see below.

**Deliberately not covered.**
- **PWA and offline reads** (§6.5). A manifest and a service worker caching ciphertext is a genuine feature with its own failure modes — a stale service worker serving an old bundle is a support problem that outlives the release that caused it. It belongs with, or just after, the import plan, on top of a deployment that already serves the app correctly.
- **Recovery-code redemption.** Still open; Task 7 documents it in the README, where someone can read it before trusting the product.
- **Multi-host, clustering, or non-Proxmox installers.** Out of scope by the spec.

**Ordering.** Task 1 must land before Task 6, because the installer's success criterion is a browser reaching the app. Task 5 must land before Task 8, because there is nothing to install without a release. Tasks 2, 3, and 4 are independent of each other.

**Type consistency check.** `release.Deps` is constructed only in `cmd/keyhole/update.go` and consumed only by `release.Update`. `backup.Snapshot` returns the path that `backup.Restore` accepts and that `release.Update` stores for its rollback — one string, one meaning. `Config.TLSEnabled()` is read by `cmd/keyhole/serve.go` and by `update.go`'s health checker, and nowhere else.

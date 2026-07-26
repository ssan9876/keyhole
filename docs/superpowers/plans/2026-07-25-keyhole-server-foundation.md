# Keyhole Server Foundation Implementation Plan (Plan 2a)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Go server's foundation — schema, admin bootstrap, HTTP skeleton, enrollment, login, and sessions — ending with a binary you can create an admin on, enroll through, and log into.

**Architecture:** A single static Go binary over SQLite. The server stores opaque ciphertext and performs no vault crypto; its only cryptographic work is Argon2id over the client-supplied auth hash and random token generation. Migrations are embedded with `embed.FS`, so the production artifact is one file plus a database.

**Tech Stack:** Go 1.23+, `modernc.org/sqlite` (pure Go — cgo would forfeit the static binary), `golang.org/x/crypto/argon2`, stdlib `net/http` routing (Go 1.22+ method-and-wildcard patterns cover every route in §4.3), stdlib `log/slog`.

**Spec:** `docs/superpowers/specs/2026-07-25-keyhole-design.md` §4 and §5.

**Scope boundary:** This plan covers `serve`, `admin`, and `migrate`. Items, folders, sync, collections, account, admin HTTP endpoints, and the audit log are Plan 2b. `backup`, `restore`, and `update` are Plan 4.

## Global Constraints

- **Go 1.25.0 or newer.** `go.mod` declares `go 1.25.0` — not a preference: `modernc.org/sqlite` v1.54.0 declares that floor in its own `go.mod`, verified with `go list -m -f '{{.GoVersion}}' modernc.org/sqlite`.
- **SQLite driver is `modernc.org/sqlite`, registered as `"sqlite"`.** Never `mattn/go-sqlite3` — it needs cgo, which costs the static binary that the entire deploy story depends on.
- **The server performs no vault crypto.** It never derives, unwraps, or inspects a vault key. Its only crypto is `argon2.IDKey` over the auth hash, `crypto/rand`, `crypto/sha256`, `crypto/hmac`, and `crypto/subtle`.
- **Argon2id over the auth hash, server side:** `time=3`, `memory=65536` (KiB), `threads=4`, `keyLen=32`. These are the server's own parameters and are unrelated to the client's per-user KDF params, which the server only stores and echoes.
- **All opaque blobs are stored exactly as received** — `protected_user_key`, `recovery_protected_user_key`, `encrypted_private_key`, `public_key`, `kdf_salt`, `recovery_salt`, `kdf_params`, `recovery_kdf_params`. The server never parses their contents.
- **Session tokens are 32 random bytes**, base64url-encoded without padding for transport, stored only as a lowercase hex SHA-256 digest. Access token 30 minutes with sliding expiry; refresh token 30 days.
- **IDs are 32 lowercase hex characters** from 16 `crypto/rand` bytes.
- **Timestamps are RFC3339 in UTC**, stored as TEXT.
- **Error envelope, exactly:** `{"error":{"code":"...","message":"..."}}`. Codes are stable identifiers from a fixed set, never free text.
- **`CF-Connecting-IP` is trusted only when the connection's remote address is loopback.** Trusting it unconditionally makes rate limiting bypassable by anyone who can set a header.
- **Unknown email and wrong auth hash produce identical response bodies, identical status codes, and comparable timing.**
- **Constant-time comparison** (`crypto/subtle.ConstantTimeCompare`) for every token and hash check.
- **There is no registration endpoint.** Accounts come into existence only via `keyhole admin create` or an admin-issued invite.
- **Logs never contain** ciphertext, tokens, auth hashes, or email addresses above `slog.LevelDebug`.
- **Package is `internal/httpapi`, not `internal/http`.** Spec §4.1 writes `internal/http/`, but a package named `http` shadows the stdlib import at every call site. This is a deliberate, documented deviation.

---

### Task 1: Module scaffold, config, store, and migrations

**Files:**
- Create: `go.mod`
- Create: `cmd/keyhole/main.go`
- Create: `cmd/keyhole/migrate.go`
- Create: `internal/config/config.go`
- Create: `internal/store/store.go`
- Create: `internal/store/migrations.go`
- Create: `internal/store/migrations/0001_init.sql`
- Test: `internal/store/store_test.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `config.Config` struct with fields `Addr string`, `DataDir string`, `BaseURL string`, `LogLevel string`
  - `config.Load(path string) (Config, error)`
  - `config.Default() Config`
  - `store.Store` struct wrapping `*sql.DB`
  - `store.Open(dbPath string) (*Store, error)`
  - `(*Store).Close() error`
  - `(*Store).DB() *sql.DB`
  - `(*Store).Migrate(ctx context.Context) error`
  - `(*Store).SchemaVersion(ctx context.Context) (int, error)`

- [ ] **Step 1: Initialize the module and pull dependencies**

Run from `D:\password-manager`:

```bash
go mod init github.com/ssan9876/keyhole
```

Then add the two dependencies:

```bash
go get modernc.org/sqlite@latest
go get golang.org/x/crypto/argon2@latest
```

Expected: `go.mod` and `go.sum` created, `go.mod` declares `go 1.23` or newer.

Note the Go module lives at the repo root alongside the pnpm workspace. `packages/` and `apps/` contain no Go files, so `go build ./...` will not see them.

- [ ] **Step 2: Write the failing config test**

`internal/config/config_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultHasUsableValues(t *testing.T) {
	c := Default()
	if c.Addr == "" {
		t.Error("Default().Addr must not be empty")
	}
	if c.DataDir == "" {
		t.Error("Default().DataDir must not be empty")
	}
	if c.LogLevel != "info" {
		t.Errorf("Default().LogLevel = %q, want %q", c.LogLevel, "info")
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "absent.yml"))
	if err != nil {
		t.Fatalf("Load on a missing file should fall back to defaults, got error: %v", err)
	}
	if c.Addr != Default().Addr {
		t.Errorf("Addr = %q, want the default %q", c.Addr, Default().Addr)
	}
}

func TestLoadOverridesOnlyWhatIsSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	body := "addr: 127.0.0.1:9999\nlog_level: debug\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Addr != "127.0.0.1:9999" {
		t.Errorf("Addr = %q, want %q", c.Addr, "127.0.0.1:9999")
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", c.LogLevel, "debug")
	}
	// DataDir was absent from the file and must keep its default.
	if c.DataDir != Default().DataDir {
		t.Errorf("DataDir = %q, want the default %q", c.DataDir, Default().DataDir)
	}
}

func TestLoadRejectsUnparsableLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("this line has no colon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load should reject a line that is not key: value")
	}
}

func TestDBPathSitsUnderDataDir(t *testing.T) {
	c := Default()
	c.DataDir = filepath.Join("var", "lib", "keyhole")
	want := filepath.Join("var", "lib", "keyhole", "keyhole.db")
	if got := c.DBPath(); got != want {
		t.Errorf("DBPath() = %q, want %q", got, want)
	}
}
```

- [ ] **Step 3: Run the config test to verify it fails**

Run: `go test ./internal/config/`
Expected: FAIL — `undefined: Default`, `undefined: Load`.

- [ ] **Step 4: Implement config**

`internal/config/config.go`:

```go
// Package config loads the server's on-disk configuration.
//
// The format is a deliberately tiny subset of YAML — flat "key: value" lines
// and "#" comments. A real YAML parser would be a dependency we do not need for
// four settings, and the installer writes this file, so the surface is ours.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	// Addr is the local address the HTTP server binds. The tunnel connects to
	// it, so it should stay on loopback in production.
	Addr string
	// DataDir holds the SQLite database and the server secret.
	DataDir string
	// BaseURL is the externally reachable origin, used to build setup and
	// invite links. No trailing slash.
	BaseURL string
	// LogLevel is one of debug, info, warn, error.
	LogLevel string
}

func Default() Config {
	return Config{
		Addr:     "127.0.0.1:8477",
		DataDir:  "/var/lib/keyhole",
		BaseURL:  "http://localhost:8477",
		LogLevel: "info",
	}
}

// DBPath is where the SQLite database lives for this configuration.
func (c Config) DBPath() string {
	return filepath.Join(c.DataDir, "keyhole.db")
}

// SecretPath is where the server secret lives. Written 0600 on first run.
func (c Config) SecretPath() string {
	return filepath.Join(c.DataDir, "server.secret")
}

// Load reads path over the defaults. A missing file is not an error: a fresh
// install with no config should start with sane values rather than refuse.
func Load(path string) (Config, error) {
	c := Default()

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			return c, fmt.Errorf("config line %d: expected \"key: value\", got %q", lineNo, line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "addr":
			c.Addr = value
		case "data_dir":
			c.DataDir = value
		case "base_url":
			c.BaseURL = strings.TrimRight(value, "/")
		case "log_level":
			c.LogLevel = value
		default:
			return c, fmt.Errorf("config line %d: unknown key %q", lineNo, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return c, fmt.Errorf("read config: %w", err)
	}
	return c, nil
}
```

- [ ] **Step 5: Run the config test to verify it passes**

Run: `go test ./internal/config/`
Expected: PASS — `ok  github.com/ssan9876/keyhole/internal/config`.

- [ ] **Step 6: Write the failing store test**

`internal/store/store_test.go`:

```go
package store

import (
	"context"
	"path/filepath"
	"testing"
)

// openTemp gives each test its own migrated database on disk. A file rather
// than :memory: because the production path is a file and WAL behaviour
// differs between the two.
func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func TestMigrateCreatesEveryTable(t *testing.T) {
	s := openTemp(t)

	want := []string{
		"users", "invites", "sessions", "items", "folders",
		"collections", "collection_memberships", "pending_grants",
		"audit_log", "server_settings", "schema_migrations",
	}
	for _, table := range want {
		var name string
		err := s.DB().QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q missing after migrate: %v", table, err)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	before, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	after, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if before != after {
		t.Errorf("schema version moved on a no-op migrate: %d -> %d", before, after)
	}
	if after < 1 {
		t.Errorf("schema version = %d, want at least 1", after)
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	s := openTemp(t)

	// A session for a user that does not exist must be rejected. SQLite
	// silently ignores foreign keys unless the pragma is on per connection,
	// which is exactly the kind of thing that only shows up in production.
	_, err := s.DB().Exec(
		`INSERT INTO sessions (id, user_id, token_hash, refresh_hash, device_label, created_at, last_seen_at, expires_at)
		 VALUES ('a','nonexistent','h','r','dev','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z')`,
	)
	if err == nil {
		t.Error("insert with a dangling user_id succeeded; foreign keys are not enforced")
	}
}

func TestEmailIsUniqueCaseInsensitively(t *testing.T) {
	s := openTemp(t)

	insert := `INSERT INTO users (id, email, name, role, status, created_at, updated_at, revision)
	           VALUES (?, ?, 'Test', 'user', 'pending', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0)`

	if _, err := s.DB().Exec(insert, "id1", "person@example.com"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	// Emails are normalized to lowercase before storage, but the constraint
	// must hold regardless so a bug upstream cannot create two accounts that
	// a user would consider the same address.
	if _, err := s.DB().Exec(insert, "id2", "Person@Example.com"); err == nil {
		t.Error("a second user with the same email in different case was accepted")
	}
}

func TestWALIsEnabled(t *testing.T) {
	s := openTemp(t)

	var mode string
	if err := s.DB().QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want %q", mode, "wal")
	}
}

func TestSchemaVersionOnAnUnmigratedDatabase(t *testing.T) {
	// Deliberately not openTemp: that helper migrates first, which is exactly
	// the ordering that hides this bug. `keyhole migrate` reads the version
	// before creating the tracking table on every first-ever run, so without
	// the sqlite_master pre-check this path fails on every new install.
	s, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	version, err := s.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion on a fresh database returned an error: %v", err)
	}
	if version != 0 {
		t.Errorf("SchemaVersion = %d on a fresh database, want 0", version)
	}
}

func TestOpenCreatesTheParentDirectory(t *testing.T) {
	nested := filepath.Join(t.TempDir(), "does", "not", "exist", "keyhole.db")

	s, err := Open(nested)
	if err != nil {
		t.Fatalf("Open should create the parent directory, got: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := os.Stat(nested); err != nil {
		t.Errorf("database file was not created: %v", err)
	}
}
```

Add `"os"` to this test file's imports alongside `"context"`, `"path/filepath"`, and `"testing"`.

- [ ] **Step 7: Run the store test to verify it fails**

Run: `go test ./internal/store/`
Expected: FAIL — `undefined: Open`.

- [ ] **Step 8: Write the schema migration**

`internal/store/migrations/0001_init.sql`:

```sql
-- Keyhole initial schema. See spec section 4.2.
--
-- Every column holding client-produced key material stores an opaque string
-- exactly as received. The server never parses these.

CREATE TABLE users (
    id                          TEXT PRIMARY KEY,
    email                       TEXT NOT NULL,
    name                        TEXT NOT NULL,
    role                        TEXT NOT NULL CHECK (role IN ('admin','user')),
    status                      TEXT NOT NULL CHECK (status IN ('pending','active','disabled')),

    -- Populated at enrollment. NULL while the account is pending.
    kdf_salt                    TEXT,
    kdf_params                  TEXT,
    auth_hash                   TEXT,
    protected_user_key          TEXT,
    recovery_protected_user_key TEXT,
    recovery_salt               TEXT,
    recovery_kdf_params         TEXT,
    public_key                  TEXT,
    encrypted_private_key       TEXT,

    revision                    INTEGER NOT NULL DEFAULT 0,
    created_at                  TEXT NOT NULL,
    updated_at                  TEXT NOT NULL
);

-- Case-insensitive uniqueness: a user considers Person@example.com and
-- person@example.com the same address, so the database must too.
CREATE UNIQUE INDEX users_email_unique ON users (lower(email));

CREATE TABLE invites (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT
);

CREATE INDEX invites_user ON invites (user_id);

CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    refresh_hash TEXT NOT NULL UNIQUE,
    device_label TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    revoked_at   TEXT
);

CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE collections (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);

CREATE TABLE collection_memberships (
    collection_id         TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sealed_collection_key TEXT NOT NULL,
    role                  TEXT NOT NULL CHECK (role IN ('member','manager')),
    granted_by            TEXT NOT NULL REFERENCES users(id),
    granted_at            TEXT NOT NULL,
    PRIMARY KEY (collection_id, user_id)
);

CREATE INDEX collection_memberships_user ON collection_memberships (user_id);

CREATE TABLE pending_grants (
    collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requested_by  TEXT NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL,
    PRIMARY KEY (collection_id, user_id)
);

CREATE TABLE folders (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_name TEXT NOT NULL,
    revision       INTEGER NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    deleted_at     TEXT
);

CREATE INDEX folders_user ON folders (user_id);

-- No `type` column: it lives inside the encrypted body so the server cannot
-- tell a login from a note, or count how many of each a user holds.
CREATE TABLE items (
    id               TEXT PRIMARY KEY,
    owner_user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    collection_id    TEXT REFERENCES collections(id) ON DELETE CASCADE,
    folder_id        TEXT REFERENCES folders(id) ON DELETE SET NULL,
    ciphertext       TEXT NOT NULL,
    wrapped_item_key TEXT NOT NULL,
    revision         INTEGER NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    deleted_at       TEXT
);

CREATE INDEX items_owner_revision ON items (owner_user_id, revision);
CREATE INDEX items_collection ON items (collection_id);

CREATE TABLE audit_log (
    id             TEXT PRIMARY KEY,
    actor_user_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
    action         TEXT NOT NULL,
    target         TEXT NOT NULL,
    metadata       TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL
);

CREATE INDEX audit_log_created ON audit_log (created_at);

CREATE TABLE server_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

- [ ] **Step 9: Implement the migration runner**

`internal/store/migrations.go`:

```go
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads the embedded migrations, ordered by their numeric
// prefix. A filename that does not start with digits is a build-time mistake,
// so it is an error rather than something to skip quietly.
func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	migrations := make([]migration, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		prefix, _, found := strings.Cut(name, "_")
		if !found {
			return nil, fmt.Errorf("migration %q: expected a NNNN_name.sql filename", name)
		}
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("migration %q: %q is not a version number", name, prefix)
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", name, err)
		}
		migrations = append(migrations, migration{version: version, name: name, sql: string(body)})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})
	return migrations, nil
}

// Migrate applies every migration newer than the recorded schema version. Each
// runs in its own transaction, so a failure leaves the database at the last
// version that fully applied rather than half-way through one.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	current, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, m migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", m.version, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("apply migration %s: %w", m.name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, datetime('now'))`,
		m.version, m.name); err != nil {
		return fmt.Errorf("record migration %s: %w", m.name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", m.name, err)
	}
	return nil
}

// SchemaVersion is the highest applied migration version, or 0 on a fresh
// database.
//
// The existence check comes first because `keyhole migrate` reads the version
// BEFORE Migrate has created the tracking table — which is every first-ever run
// on a new install. Querying schema_migrations directly fails there with
// "no such table". Only that specific absence yields 0; every real SQL error
// still propagates.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var exists int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
	).Scan(&exists); err != nil {
		return 0, fmt.Errorf("check schema_migrations table: %w", err)
	}
	if exists == 0 {
		return 0, nil
	}

	var version sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	if !version.Valid {
		return 0, nil
	}
	return int(version.Int64), nil
}
```

- [ ] **Step 10: Implement the store**

`internal/store/store.go`:

```go
// Package store owns SQLite access and the embedded schema migrations.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"
)

type Store struct {
	db *sql.DB
}

// Open connects to the SQLite database at dbPath, creating it if absent.
//
// The pragmas are not optional decoration:
//   - foreign_keys is OFF by default in SQLite and is per-connection, so
//     without it every REFERENCES clause in the schema is documentation.
//   - WAL lets reads proceed during a write, which matters because sync reads
//     are the common case.
//   - busy_timeout turns "database is locked" from an error into a wait.
func Open(dbPath string) (*Store, error) {
	// 0700, not 0755: this directory holds every user's wrapped key material.
	// Creating it here means a fresh install gets a working database rather
	// than SQLite's opaque "unable to open database file".
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create database directory %s: %w", dir, err)
	}

	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	// SQLite tolerates one writer. Capping the pool avoids a thundering herd
	// of writers all waiting on busy_timeout.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for packages that build their own queries.
func (s *Store) DB() *sql.DB { return s.db }
```

- [ ] **Step 11: Run the store test to verify it passes**

Run: `go test ./internal/store/`
Expected: PASS — all five tests green.

- [ ] **Step 12: Implement the command entry point and migrate subcommand**

`cmd/keyhole/main.go`:

```go
// Command keyhole is the Keyhole server and its administrative CLI.
package main

import (
	"fmt"
	"os"
)

const usage = `keyhole — self-hosted end-to-end-encrypted password manager

Usage:
  keyhole serve     [--config PATH]   Run the HTTP server
  keyhole migrate   [--config PATH]   Apply pending database migrations
  keyhole admin     <subcommand>      Administrative commands

Run "keyhole admin" for administrative subcommands.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "migrate":
		err = runMigrate(os.Args[2:])
	case "admin":
		err = runAdmin(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "keyhole: %v\n", err)
		os.Exit(1)
	}
}
```

`cmd/keyhole/migrate.go`:

```go
package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/store"
)

const defaultConfigPath = "/etc/keyhole/config.yml"

func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.yml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	before, err := st.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	after, err := st.SchemaVersion(ctx)
	if err != nil {
		return err
	}

	if before == after {
		fmt.Printf("Schema already at version %d; nothing to do.\n", after)
	} else {
		fmt.Printf("Migrated schema %d -> %d.\n", before, after)
	}
	return nil
}
```

Add a temporary stub so the package compiles before Tasks 2 and 3 land. Create `cmd/keyhole/stubs.go`:

```go
package main

import "errors"

// Replaced by the real implementations in Tasks 2 and 3. Present only so the
// command package builds while the plan is executed task by task.
func runServe(args []string) error { return errors.New("serve: not implemented until Task 3") }
func runAdmin(args []string) error { return errors.New("admin: not implemented until Task 2") }
```

- [ ] **Step 13: Verify the binary builds and migrate runs end to end**

Run:

```bash
go build ./... && go vet ./...
```

Expected: no output, exit 0.

Then exercise `migrate` against a scratch directory. Create `/tmp/kh-test/config.yml` (or the Windows equivalent under the scratch dir) containing `data_dir: <that directory>`, then:

```bash
go run ./cmd/keyhole migrate --config <that directory>/config.yml
```

Expected: `Migrated schema 0 -> 1.` Running it a second time prints `Schema already at version 1; nothing to do.`

- [ ] **Step 14: Commit**

```bash
git add go.mod go.sum cmd/keyhole internal/config internal/store
git commit -m "feat(server): scaffold module, config, store, and embedded migrations"
```

---

### Task 2: IDs, users and invites store, and `keyhole admin create`

**Files:**
- Create: `internal/store/ids.go`
- Create: `internal/store/users.go`
- Create: `internal/store/invites.go`
- Create: `cmd/keyhole/admin.go`
- Modify: `cmd/keyhole/stubs.go` (remove `runAdmin`)
- Test: `internal/store/ids_test.go`
- Test: `internal/store/users_test.go`
- Test: `internal/store/invites_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.Open`, `(*Store).Migrate`, `(*Store).DB` (Task 1); `config.Load`, `config.Config` (Task 1).
- Produces:
  - `store.NewID() (string, error)` — 32 lowercase hex characters
  - `store.NormalizeEmail(email string) string` — trimmed, lowercased
  - `store.HashToken(token string) string` — lowercase hex SHA-256
  - `store.ErrNotFound` — sentinel error
  - `store.ErrEmailTaken` — sentinel error
  - `store.User` struct: `ID, Email, Name, Role, Status string`; `KDFSalt, KDFParams, AuthHash, ProtectedUserKey, RecoveryProtectedUserKey, RecoverySalt, RecoveryKDFParams, PublicKey, EncryptedPrivateKey sql.NullString`; `Revision int64`; `CreatedAt, UpdatedAt time.Time`
  - `(*Store).CreatePendingUser(ctx context.Context, email, name, role string) (User, error)`
  - `(*Store).UserByID(ctx context.Context, id string) (User, error)`
  - `(*Store).UserByEmail(ctx context.Context, email string) (User, error)`
  - `(*Store).CountUsers(ctx context.Context) (int, error)`
  - `store.Invite` struct: `ID, UserID string`; `CreatedAt, ExpiresAt time.Time`; `UsedAt sql.NullTime`
  - `(*Store).CreateInvite(ctx context.Context, userID string, ttl time.Duration) (invite Invite, token string, err error)`
  - `(*Store).InviteByToken(ctx context.Context, token string) (Invite, error)` — returns `ErrNotFound` for unknown, used, or expired
  - `(*Store).MarkInviteUsed(ctx context.Context, inviteID string) error`

- [ ] **Step 1: Write the failing ID and helper tests**

`internal/store/ids_test.go`:

```go
package store

import (
	"regexp"
	"testing"
)

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestNewIDShape(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if !hex32.MatchString(id) {
		t.Errorf("NewID() = %q, want 32 lowercase hex characters", id)
	}
}

func TestNewIDDoesNotRepeat(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if seen[id] {
			t.Fatalf("NewID returned a duplicate: %q", id)
		}
		seen[id] = true
	}
}

func TestNormalizeEmail(t *testing.T) {
	cases := map[string]string{
		"  Person@Example.COM ": "person@example.com",
		"person@example.com":    "person@example.com",
		"\tA@B.c\n":             "a@b.c",
	}
	for input, want := range cases {
		if got := NormalizeEmail(input); got != want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestHashTokenIsStableAndHex(t *testing.T) {
	first := HashToken("some-token")
	second := HashToken("some-token")
	if first != second {
		t.Error("HashToken is not deterministic")
	}
	if len(first) != 64 {
		t.Errorf("HashToken length = %d, want 64", len(first))
	}
	if first == HashToken("some-other-token") {
		t.Error("HashToken collided on different inputs")
	}
	// The stored form must never be the token itself.
	if first == "some-token" {
		t.Error("HashToken returned its input")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/store/ -run 'TestNewID|TestNormalizeEmail|TestHashToken'`
Expected: FAIL — `undefined: NewID`.

- [ ] **Step 3: Implement the helpers**

`internal/store/ids.go`:

```go
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrNotFound means the row does not exist, or exists in a state the caller
// should treat as absent (a used or expired invite, for instance).
var ErrNotFound = errors.New("not found")

// ErrEmailTaken means an account already exists for that address.
var ErrEmailTaken = errors.New("email already registered")

const idBytes = 16

// NewID returns a 32-character lowercase hex identifier from 16 random bytes.
func NewID() (string, error) {
	buf := make([]byte, idBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// NormalizeEmail is the single definition of "the same address". Used both
// before storage and before lookup, so the two can never disagree.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// HashToken is the at-rest form of session and invite tokens. A database dump
// must not yield anything a caller could present as a credential.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run to verify the helper tests pass**

Run: `go test ./internal/store/ -run 'TestNewID|TestNormalizeEmail|TestHashToken'`
Expected: PASS — 4 tests.

- [ ] **Step 5: Write the failing users test**

`internal/store/users_test.go`:

```go
package store

import (
	"context"
	"errors"
	"testing"
)

func TestCreatePendingUser(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	u, err := s.CreatePendingUser(ctx, "  Person@Example.com ", "Person", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}

	if u.Email != "person@example.com" {
		t.Errorf("Email = %q, want it normalized to %q", u.Email, "person@example.com")
	}
	if u.Status != "pending" {
		t.Errorf("Status = %q, want %q", u.Status, "pending")
	}
	if !hex32.MatchString(u.ID) {
		t.Errorf("ID = %q, want 32 hex characters", u.ID)
	}
	// A pending account holds no key material at all.
	if u.AuthHash.Valid || u.ProtectedUserKey.Valid || u.PublicKey.Valid {
		t.Error("a pending user must have no key material set")
	}
}

func TestCreatePendingUserRejectsDuplicateEmail(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	if _, err := s.CreatePendingUser(ctx, "person@example.com", "Person", "user"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.CreatePendingUser(ctx, "PERSON@example.com", "Someone Else", "user")
	if !errors.Is(err, ErrEmailTaken) {
		t.Errorf("second create error = %v, want ErrEmailTaken", err)
	}
}

func TestCreatePendingUserRejectsBadRole(t *testing.T) {
	s := openTemp(t)
	if _, err := s.CreatePendingUser(context.Background(), "x@example.com", "X", "superuser"); err == nil {
		t.Error("an unknown role was accepted")
	}
}

func TestUserByEmailNormalizesLookup(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	created, err := s.CreatePendingUser(ctx, "person@example.com", "Person", "admin")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}

	found, err := s.UserByEmail(ctx, "  PERSON@EXAMPLE.COM  ")
	if err != nil {
		t.Fatalf("UserByEmail: %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("UserByEmail returned %q, want %q", found.ID, created.ID)
	}
	if found.Role != "admin" {
		t.Errorf("Role = %q, want %q", found.Role, "admin")
	}
}

func TestUserLookupsReportNotFound(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	if _, err := s.UserByEmail(ctx, "nobody@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserByEmail error = %v, want ErrNotFound", err)
	}
	if _, err := s.UserByID(ctx, "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrNotFound) {
		t.Errorf("UserByID error = %v, want ErrNotFound", err)
	}
}

func TestCountUsers(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	if n, err := s.CountUsers(ctx); err != nil || n != 0 {
		t.Fatalf("CountUsers on empty database = %d, %v; want 0, nil", n, err)
	}
	if _, err := s.CreatePendingUser(ctx, "a@example.com", "A", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePendingUser(ctx, "b@example.com", "B", "user"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CountUsers(ctx); err != nil || n != 2 {
		t.Errorf("CountUsers = %d, %v; want 2, nil", n, err)
	}
}
```

- [ ] **Step 6: Run to verify it fails**

Run: `go test ./internal/store/ -run TestCreatePendingUser`
Expected: FAIL — `undefined: (*Store).CreatePendingUser`.

- [ ] **Step 7: Implement the users store**

`internal/store/users.go`:

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// User mirrors the users table. Every key-material field is nullable because
// an account exists in a pending state before its owner has set a master
// password, and the server never fabricates key material.
type User struct {
	ID     string
	Email  string
	Name   string
	Role   string
	Status string

	KDFSalt                  sql.NullString
	KDFParams                sql.NullString
	AuthHash                 sql.NullString
	ProtectedUserKey         sql.NullString
	RecoveryProtectedUserKey sql.NullString
	RecoverySalt             sql.NullString
	RecoveryKDFParams        sql.NullString
	PublicKey                sql.NullString
	EncryptedPrivateKey      sql.NullString

	Revision  int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

const userColumns = `id, email, name, role, status,
	kdf_salt, kdf_params, auth_hash, protected_user_key,
	recovery_protected_user_key, recovery_salt, recovery_kdf_params,
	public_key, encrypted_private_key,
	revision, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var createdAt, updatedAt string
	err := row.Scan(
		&u.ID, &u.Email, &u.Name, &u.Role, &u.Status,
		&u.KDFSalt, &u.KDFParams, &u.AuthHash, &u.ProtectedUserKey,
		&u.RecoveryProtectedUserKey, &u.RecoverySalt, &u.RecoveryKDFParams,
		&u.PublicKey, &u.EncryptedPrivateKey,
		&u.Revision, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("scan user: %w", err)
	}
	if u.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return User{}, fmt.Errorf("parse created_at: %w", err)
	}
	if u.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
		return User{}, fmt.Errorf("parse updated_at: %w", err)
	}
	return u, nil
}

// CreatePendingUser creates an account with no key material. The account
// becomes usable only when its owner completes an invite and uploads their
// own wrapped blobs — the server can never populate them.
func (s *Store) CreatePendingUser(ctx context.Context, email, name, role string) (User, error) {
	if role != "admin" && role != "user" {
		return User{}, fmt.Errorf("invalid role %q: want admin or user", role)
	}
	normalized := NormalizeEmail(email)
	if normalized == "" || !strings.Contains(normalized, "@") {
		return User{}, fmt.Errorf("invalid email %q", email)
	}
	if strings.TrimSpace(name) == "" {
		return User{}, errors.New("name must not be empty")
	}

	id, err := NewID()
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, role, status, revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, 'pending', 0, ?, ?)`,
		id, normalized, strings.TrimSpace(name), role, now, now)
	if err != nil {
		// modernc's driver reports constraint violations in the message; the
		// unique index on lower(email) is the only one this insert can trip.
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	return s.UserByID(ctx, id)
}

func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

// UserByEmail normalizes before looking up, so callers cannot accidentally
// miss an account by case or surrounding whitespace.
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = ?`, NormalizeEmail(email)))
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}
```

- [ ] **Step 8: Run to verify the users tests pass**

Run: `go test ./internal/store/`
Expected: PASS — all store tests including the six new ones.

- [ ] **Step 9: Write the failing invites test**

`internal/store/invites_test.go`:

```go
package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func makeUser(t *testing.T, s *Store, email string) User {
	t.Helper()
	u, err := s.CreatePendingUser(context.Background(), email, "Test", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	return u
}

func TestCreateInviteReturnsATokenStoredOnlyAsAHash(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := makeUser(t, s, "person@example.com")

	invite, token, err := s.CreateInvite(ctx, u.ID, 48*time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if token == "" {
		t.Fatal("CreateInvite returned an empty token")
	}
	if invite.UserID != u.ID {
		t.Errorf("UserID = %q, want %q", invite.UserID, u.ID)
	}

	// The raw token must not be recoverable from the database.
	var stored string
	if err := s.DB().QueryRow(`SELECT token_hash FROM invites WHERE id = ?`, invite.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token {
		t.Error("the invite token was stored in the clear")
	}
	if stored != HashToken(token) {
		t.Error("stored value is not the SHA-256 of the token")
	}
}

func TestInviteByTokenRoundTrips(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := makeUser(t, s, "person@example.com")

	created, token, err := s.CreateInvite(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	found, err := s.InviteByToken(ctx, token)
	if err != nil {
		t.Fatalf("InviteByToken: %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("InviteByToken returned %q, want %q", found.ID, created.ID)
	}
}

func TestInviteByTokenRejectsUnknownToken(t *testing.T) {
	s := openTemp(t)
	if _, err := s.InviteByToken(context.Background(), "not-a-real-token"); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestInviteByTokenRejectsUsedInvite(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := makeUser(t, s, "person@example.com")

	invite, token, err := s.CreateInvite(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkInviteUsed(ctx, invite.ID); err != nil {
		t.Fatalf("MarkInviteUsed: %v", err)
	}
	// A one-time link must be exactly one time: a leaked URL in a chat log
	// cannot be replayed to seize an account that was already set up.
	if _, err := s.InviteByToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Errorf("used invite error = %v, want ErrNotFound", err)
	}
}

func TestInviteByTokenRejectsExpiredInvite(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := makeUser(t, s, "person@example.com")

	_, token, err := s.CreateInvite(ctx, u.ID, -time.Minute) // already expired
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InviteByToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired invite error = %v, want ErrNotFound", err)
	}
}

func TestMarkInviteUsedIsNotRepeatable(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := makeUser(t, s, "person@example.com")

	invite, _, err := s.CreateInvite(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkInviteUsed(ctx, invite.ID); err != nil {
		t.Fatalf("first MarkInviteUsed: %v", err)
	}
	if err := s.MarkInviteUsed(ctx, invite.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second MarkInviteUsed error = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 10: Run to verify it fails**

Run: `go test ./internal/store/ -run TestInvite`
Expected: FAIL — `undefined: (*Store).CreateInvite`.

- [ ] **Step 11: Implement the invites store**

`internal/store/invites.go`:

```go
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

type Invite struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    sql.NullTime
}

const inviteTokenBytes = 32

// CreateInvite mints a one-time token and stores only its hash. The raw token
// is returned once, to be handed to the invitee out of band; it cannot be
// recovered afterwards, by an admin or by anyone with the database.
func (s *Store) CreateInvite(ctx context.Context, userID string, ttl time.Duration) (Invite, string, error) {
	raw := make([]byte, inviteTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return Invite{}, "", fmt.Errorf("generate invite token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	id, err := NewID()
	if err != nil {
		return Invite{}, "", err
	}

	now := time.Now().UTC()
	expires := now.Add(ttl)

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO invites (id, user_id, token_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, userID, HashToken(token),
		now.Format(time.RFC3339), expires.Format(time.RFC3339))
	if err != nil {
		return Invite{}, "", fmt.Errorf("insert invite: %w", err)
	}

	return Invite{ID: id, UserID: userID, CreatedAt: now, ExpiresAt: expires}, token, nil
}

// InviteByToken returns the invite only if it is unused and unexpired. Used
// and expired invites report ErrNotFound rather than a distinct error, so a
// caller cannot learn from the response whether a token was ever valid.
func (s *Store) InviteByToken(ctx context.Context, token string) (Invite, error) {
	var inv Invite
	var createdAt, expiresAt string

	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, created_at, expires_at
		 FROM invites
		 WHERE token_hash = ? AND used_at IS NULL`,
		HashToken(token),
	).Scan(&inv.ID, &inv.UserID, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, ErrNotFound
	}
	if err != nil {
		return Invite{}, fmt.Errorf("select invite: %w", err)
	}

	if inv.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return Invite{}, fmt.Errorf("parse created_at: %w", err)
	}
	if inv.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt); err != nil {
		return Invite{}, fmt.Errorf("parse expires_at: %w", err)
	}
	if time.Now().UTC().After(inv.ExpiresAt) {
		return Invite{}, ErrNotFound
	}
	return inv, nil
}

// MarkInviteUsed consumes the invite. The WHERE clause carries the
// used_at IS NULL condition so two concurrent enrollments cannot both succeed:
// the second affects zero rows and gets ErrNotFound.
func (s *Store) MarkInviteUsed(ctx context.Context, inviteID string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339), inviteID)
	if err != nil {
		return fmt.Errorf("mark invite used: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}
```

- [ ] **Step 12: Run to verify the invite tests pass**

Run: `go test ./internal/store/`
Expected: PASS — every store test green.

- [ ] **Step 13: Implement `keyhole admin create`**

Replace `cmd/keyhole/stubs.go` so it contains only `runServe`:

```go
package main

import "errors"

// Replaced by the real implementation in Task 3. Present only so the command
// package builds while the plan is executed task by task.
func runServe(args []string) error { return errors.New("serve: not implemented until Task 3") }
```

`cmd/keyhole/admin.go`:

```go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/store"
)

const adminUsage = `keyhole admin — administrative commands

Usage:
  keyhole admin create --email ADDRESS [--name NAME] [--config PATH]
        Create an administrator account and print a one-time setup link.
`

// inviteTTL is how long a setup or invite link stays valid. Long enough to
// hand over in person or by message; short enough that a stale link in a chat
// log stops being useful.
const inviteTTL = 72 * time.Hour

func runAdmin(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, adminUsage)
		os.Exit(2)
	}
	switch args[0] {
	case "create":
		return runAdminCreate(args[1:])
	case "-h", "--help", "help":
		fmt.Print(adminUsage)
		return nil
	default:
		return fmt.Errorf("unknown admin subcommand %q", args[0])
	}
}

func runAdminCreate(args []string) error {
	fs := flag.NewFlagSet("admin create", flag.ExitOnError)
	email := fs.String("email", "", "email address of the administrator (required)")
	name := fs.String("name", "", "display name (defaults to the email address)")
	configPath := fs.String("config", defaultConfigPath, "path to config.yml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("--email is required")
	}
	if *name == "" {
		*name = *email
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	user, err := st.CreatePendingUser(ctx, *email, *name, "admin")
	if errors.Is(err, store.ErrEmailTaken) {
		return fmt.Errorf("an account already exists for %s", *email)
	}
	if err != nil {
		return err
	}

	_, token, err := st.CreateInvite(ctx, user.ID, inviteTTL)
	if err != nil {
		return err
	}

	fmt.Printf(`
Administrator account created for %s.

Open this link to set your master password:

    %s/enroll/%s

The link works once and expires in %s. Your master password is set in the
browser and never reaches the server, so nobody — including this command —
can recover it for you. Save the recovery code the setup screen gives you.

`, user.Email, cfg.BaseURL, token, inviteTTL)

	return nil
}
```

- [ ] **Step 14: Verify the command end to end**

Run `go build ./... && go vet ./...` — expect no output.

Then, against the scratch config from Task 1:

```bash
go run ./cmd/keyhole admin create --email you@example.com --config <scratch>/config.yml
```

Expected: the setup link prints with a base64url token. Running the same command a second time prints `keyhole: an account already exists for you@example.com` and exits non-zero.

- [ ] **Step 15: Commit**

```bash
git add internal/store cmd/keyhole
git commit -m "feat(server): add users and invites store with admin create command"
```

---

### Task 3: HTTP skeleton — error envelope, middleware, router, health, serve

**Files:**
- Create: `internal/httpapi/errors.go`
- Create: `internal/httpapi/middleware.go`
- Create: `internal/httpapi/server.go`
- Create: `internal/secret/secret.go`
- Create: `cmd/keyhole/serve.go`
- Delete: `cmd/keyhole/stubs.go`
- Test: `internal/httpapi/errors_test.go`
- Test: `internal/httpapi/middleware_test.go`
- Test: `internal/httpapi/server_test.go`
- Test: `internal/secret/secret_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.Open`, `(*Store).Migrate` (Task 1); `config.Config`, `config.Load` (Task 1).
- Produces:
  - `httpapi.ErrorCode` (string type) with constants `CodeBadRequest`, `CodeUnauthorized`, `CodeForbidden`, `CodeNotFound`, `CodeConflict`, `CodeRateLimited`, `CodeInternal`
  - `httpapi.WriteError(w http.ResponseWriter, status int, code ErrorCode, message string)`
  - `httpapi.WriteJSON(w http.ResponseWriter, status int, payload any)`
  - `httpapi.DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool` — writes the error and returns false on failure
  - `httpapi.ClientIP(r *http.Request) string`
  - `httpapi.RequestIDFrom(ctx context.Context) string`
  - `httpapi.Server` struct and `httpapi.New(cfg config.Config, st *store.Store, secret []byte, logger *slog.Logger) *Server`
  - `(*Server).Handler() http.Handler`
  - `secret.LoadOrCreate(path string) ([]byte, error)` — 32 bytes, file mode `0600`

- [ ] **Step 1: Write the failing secret test**

`internal/secret/secret_test.go`:

```go
package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrCreateGenerates32Bytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.secret")

	s, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if len(s) != 32 {
		t.Errorf("secret length = %d, want 32", len(s))
	}
}

func TestLoadOrCreateIsStableAcrossCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.secret")

	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	// A regenerated secret would invalidate every decoy salt the server has
	// ever issued, making prelogin responses inconsistent across restarts.
	if !bytes.Equal(first, second) {
		t.Error("the secret changed on the second load")
	}
}

func TestLoadOrCreateWritesRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file modes are not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "server.secret")
	if _, err := LoadOrCreate(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 600", mode)
	}
}

func TestLoadOrCreateRejectsATruncatedSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.secret")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Silently regenerating would be worse than failing: it would change the
	// decoy salts with no operator visible signal.
	if _, err := LoadOrCreate(path); err == nil {
		t.Error("a truncated secret file was accepted")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/secret/`
Expected: FAIL — `undefined: LoadOrCreate`.

- [ ] **Step 3: Implement the secret**

`internal/secret/secret.go`:

```go
// Package secret manages the server's long-lived secret key.
//
// It is used only for keyed hashing that must stay stable across restarts —
// today, the decoy KDF salts that make prelogin useless for account
// enumeration. It is never a vault key: no amount of access to it lets anyone
// decrypt anything a user stored.
package secret

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

const secretBytes = 32

// LoadOrCreate reads the secret at path, generating one on first run.
//
// A short or unreadable file is an error rather than a prompt to regenerate:
// a new secret changes every decoy salt the server issues, and doing that
// silently would turn a corrupted file into a subtle behaviour change nobody
// notices.
func LoadOrCreate(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) != secretBytes {
			return nil, fmt.Errorf("server secret at %s is %d bytes, want %d; refusing to regenerate", path, len(data), secretBytes)
		}
		return data, nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("read server secret: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create secret directory: %w", err)
	}

	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate server secret: %w", err)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return nil, fmt.Errorf("write server secret: %w", err)
	}
	return buf, nil
}
```

- [ ] **Step 4: Run to verify the secret tests pass**

Run: `go test ./internal/secret/`
Expected: PASS — 4 tests (3 on Windows, one skipped).

- [ ] **Step 5: Write the failing error-envelope test**

`internal/httpapi/errors_test.go`:

```go
package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusNotFound, CodeNotFound, "no such item")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body.Error.Code != "not_found" {
		t.Errorf("code = %q, want %q", body.Error.Code, "not_found")
	}
	if body.Error.Message != "no such item" {
		t.Errorf("message = %q, want %q", body.Error.Message, "no such item")
	}
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, map[string]string{"id": "abc"})

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"id":"abc"}` {
		t.Errorf("body = %q, want %q", got, `{"id":"abc"}`)
	}
}

func TestDecodeJSONAcceptsValidBody(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"x"}`))

	var dst struct {
		Name string `json:"name"`
	}
	if ok := DecodeJSON(rec, req, &dst); !ok {
		t.Fatalf("DecodeJSON returned false; body was %q", rec.Body.String())
	}
	if dst.Name != "x" {
		t.Errorf("Name = %q, want %q", dst.Name, "x")
	}
}

func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"x","surprise":1}`))

	var dst struct {
		Name string `json:"name"`
	}
	// Unknown fields are rejected so a client sending a misspelled key gets
	// told, rather than having it silently ignored — which for a field like
	// recoveryKdfParams would mean a vault that cannot be recovered.
	if ok := DecodeJSON(rec, req, &dst); ok {
		t.Error("DecodeJSON accepted an unknown field")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDecodeJSONRejectsMalformedAndOversizedBodies(t *testing.T) {
	for name, body := range map[string]string{
		"malformed": `{"name":`,
		"oversized": `{"name":"` + strings.Repeat("a", 2<<20) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			var dst struct {
				Name string `json:"name"`
			}
			if ok := DecodeJSON(rec, req, &dst); ok {
				t.Error("DecodeJSON accepted a body it should have rejected")
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}
```

- [ ] **Step 6: Run to verify it fails**

Run: `go test ./internal/httpapi/`
Expected: FAIL — `undefined: WriteError`.

- [ ] **Step 7: Implement the error envelope**

`internal/httpapi/errors.go`:

```go
// Package httpapi is the HTTP surface: routing, middleware, and handlers.
//
// Named httpapi rather than http, deliberately: a package named http shadows
// the standard library import at every call site inside it.
package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// ErrorCode is a stable identifier a client can branch on. Messages are for
// humans and may change; codes may not.
type ErrorCode string

const (
	CodeBadRequest   ErrorCode = "bad_request"
	CodeUnauthorized ErrorCode = "unauthorized"
	CodeForbidden    ErrorCode = "forbidden"
	CodeNotFound     ErrorCode = "not_found"
	CodeConflict     ErrorCode = "conflict"
	CodeRateLimited  ErrorCode = "rate_limited"
	CodeInternal     ErrorCode = "internal"
)

// maxRequestBody caps decoded request bodies at 1 MiB. Vault items are small;
// anything larger is a mistake or an attempt to exhaust memory.
const maxRequestBody = 1 << 20

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func WriteError(w http.ResponseWriter, status int, code ErrorCode, message string) {
	WriteJSON(w, status, errorEnvelope{Error: errorBody{Code: code, Message: message}})
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		// The status line is already sent, so this can only be logged.
		slog.Error("encode response", "error", err)
	}
}

// DecodeJSON reads a JSON body into dst. It writes the error response itself
// and returns false when it fails, so handlers read as:
//
//	if !DecodeJSON(w, r, &req) { return }
//
// Unknown fields are rejected. Silently dropping a misspelled key is how a
// client ships without recoveryKdfParams and nobody notices until a user tries
// to recover a vault.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		var maxBytes *http.MaxBytesError
		switch {
		case errors.As(err, &maxBytes):
			WriteError(w, http.StatusBadRequest, CodeBadRequest, "request body is too large")
		case strings.Contains(err.Error(), "unknown field"):
			WriteError(w, http.StatusBadRequest, CodeBadRequest, "request contains an unrecognized field")
		default:
			WriteError(w, http.StatusBadRequest, CodeBadRequest, "request body is not valid JSON")
		}
		return false
	}

	// A second value in the stream means the client sent something we would
	// only partly honour.
	if decoder.More() {
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "request body must contain a single JSON object")
		return false
	}
	return true
}
```

- [ ] **Step 8: Run to verify the error tests pass**

Run: `go test ./internal/httpapi/`
Expected: PASS — 6 tests.

- [ ] **Step 9: Write the failing middleware test**

`internal/httpapi/middleware_test.go`:

```go
package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPIgnoresCFHeaderFromNonLoopback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("CF-Connecting-IP", "198.51.100.1")

	// Trusting this header from an arbitrary peer would let anyone forge their
	// own source address and walk straight past the rate limiter.
	if got := ClientIP(req); got != "203.0.113.9" {
		t.Errorf("ClientIP = %q, want the real peer %q", got, "203.0.113.9")
	}
}

func TestClientIPHonoursCFHeaderFromLoopback(t *testing.T) {
	for _, remote := range []string{"127.0.0.1:41000", "[::1]:41000"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		req.Header.Set("CF-Connecting-IP", "198.51.100.1")

		if got := ClientIP(req); got != "198.51.100.1" {
			t.Errorf("ClientIP with remote %s = %q, want %q", remote, got, "198.51.100.1")
		}
	}
}

func TestClientIPFallsBackToPeerWhenHeaderAbsent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:41000"

	if got := ClientIP(req); got != "127.0.0.1" {
		t.Errorf("ClientIP = %q, want %q", got, "127.0.0.1")
	}
}

func TestClientIPRejectsAMalformedCFHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:41000"
	req.Header.Set("CF-Connecting-IP", "not-an-ip")

	if got := ClientIP(req); got != "127.0.0.1" {
		t.Errorf("ClientIP = %q, want the peer %q when the header is not an IP", got, "127.0.0.1")
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy is not set")
	}
}

func TestRequestIDIsGeneratedAndReturned(t *testing.T) {
	var seen string
	handler := requestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if seen == "" {
		t.Error("no request ID was placed in the context")
	}
	if got := rec.Header().Get("X-Request-Id"); got != seen {
		t.Errorf("X-Request-Id header = %q, want the context value %q", got, seen)
	}
}

func TestRequestIDIsNotTakenFromTheClient(t *testing.T) {
	var seen string
	handler := requestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "attacker-supplied-value")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Echoing a client-chosen ID lets a caller forge or collide log entries.
	if seen == "attacker-supplied-value" {
		t.Error("the client-supplied request ID was adopted")
	}
}
```

- [ ] **Step 10: Run to verify it fails**

Run: `go test ./internal/httpapi/ -run 'TestClientIP|TestSecurityHeaders|TestRequestID'`
Expected: FAIL — `undefined: ClientIP`.

- [ ] **Step 11: Implement the middleware**

`internal/httpapi/middleware.go`:

```go
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"time"
)

type contextKey string

const requestIDKey contextKey = "request-id"

// RequestIDFrom returns the per-request identifier, or "" outside a request.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

func newRequestID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(buf)
}

// requestID assigns every request a fresh identifier and echoes it. The
// client's own X-Request-Id is deliberately ignored: adopting it would let a
// caller forge or collide entries in our logs.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// No inline script, no external anything. The web app is served from
		// this same origin and is built without inline handlers.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ClientIP is the address to attribute a request to.
//
// Cloudflare terminates TLS and forwards the real address in CF-Connecting-IP,
// but that header is trusted ONLY when the immediate peer is loopback — which,
// with the tunnel running beside the server, is the only path it can legitimately
// arrive by. Trusting it unconditionally would let anyone who can reach the
// server set their own apparent address and bypass rate limiting entirely.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	peer := net.ParseIP(host)
	if peer == nil || !peer.IsLoopback() {
		return host
	}

	forwarded := r.Header.Get("CF-Connecting-IP")
	if forwarded == "" {
		return host
	}
	if net.ParseIP(forwarded) == nil {
		return host
	}
	return forwarded
}

// statusRecorder captures the status code for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// accessLog records one line per request. It deliberately logs the path but
// never the query string, body, or headers: those carry tokens and email
// addresses, which must not reach an info-level log.
func accessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			logger.Info("request",
				"id", RequestIDFrom(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// recoverPanic turns a handler panic into a 500 rather than a dropped
// connection, and logs it with the request ID so it can be traced.
func recoverPanic(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.Error("panic",
						"id", RequestIDFrom(r.Context()),
						"path", r.URL.Path,
						"value", recovered,
					)
					WriteError(w, http.StatusInternalServerError, CodeInternal, "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
```

- [ ] **Step 12: Run to verify the middleware tests pass**

Run: `go test ./internal/httpapi/`
Expected: PASS — 13 tests.

- [ ] **Step 13: Write the failing server test**

`internal/httpapi/server_test.go`:

```go
package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/store"
)

// newTestServer builds a server over a fresh migrated database.
func newTestServer(t *testing.T) *Server {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	cfg := config.Default()
	cfg.BaseURL = "http://test.local"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	return New(cfg, st, make([]byte, 32), logger)
}

func TestHealthzReportsOK(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Status        string `json:"status"`
		SchemaVersion int    `json:"schemaVersion"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want %q", body.Status, "ok")
	}
	// The update command polls this after swapping the binary; a version of 0
	// would mean migrations had not run.
	if body.SchemaVersion < 1 {
		t.Errorf("schemaVersion = %d, want at least 1", body.SchemaVersion)
	}
}

func TestHealthzCarriesSecurityHeaders(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers are not applied to routed responses")
	}
}

func TestUnknownRouteReturnsTheErrorEnvelope(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("a 404 must still be the JSON error envelope, got %q", rec.Body.String())
	}
	if body.Error.Code != "not_found" {
		t.Errorf("code = %q, want %q", body.Error.Code, "not_found")
	}
}

func TestThereIsNoRegistrationRoute(t *testing.T) {
	srv := newTestServer(t)

	// Spec section 5: accounts exist only because an admin created them.
	// This is not a disabled flag — the route must not exist at all.
	for _, path := range []string{"/api/auth/register", "/api/register", "/api/signup", "/api/users"} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s returned %d; no registration route may exist", path, rec.Code)
		}
	}
}

func TestPanicInAHandlerBecomesA500(t *testing.T) {
	srv := newTestServer(t)
	srv.mux.HandleFunc("GET /api/test-panic", func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/test-panic", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}
```

- [ ] **Step 14: Run to verify it fails**

Run: `go test ./internal/httpapi/ -run 'TestHealthz|TestUnknownRoute|TestThereIsNo|TestPanic'`
Expected: FAIL — `undefined: New`.

- [ ] **Step 15: Implement the server and router**

`internal/httpapi/server.go`:

```go
package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/store"
)

// Server owns the routing table and the dependencies handlers need.
type Server struct {
	cfg    config.Config
	store  *store.Store
	secret []byte
	logger *slog.Logger
	mux    *http.ServeMux
}

// New builds the server and registers every route.
//
// Routing is stdlib ServeMux. Go 1.22's method-and-wildcard patterns
// ("POST /api/items/{id}") cover every route in spec section 4.3, so a router
// dependency would buy nothing.
func New(cfg config.Config, st *store.Store, secret []byte, logger *slog.Logger) *Server {
	s := &Server{
		cfg:    cfg,
		store:  st,
		secret: secret,
		logger: logger,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Anything unmatched is a 404 in the standard envelope rather than Go's
	// plain-text default, so a client only ever parses one error shape.
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, http.StatusNotFound, CodeNotFound, "no such endpoint")
	})

	// Deliberately absent: any registration or signup route. Accounts are
	// created by an admin (spec section 5). Adding one here is a design change,
	// not a feature.
}

// Handler returns the fully wrapped handler. Order matters: requestID must be
// outermost so the log and panic middlewares can reference the ID.
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	h = securityHeaders(h)
	h = recoverPanic(s.logger)(h)
	h = accessLog(s.logger)(h)
	h = requestID(h)
	return h
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	version, err := s.store.SchemaVersion(r.Context())
	if err != nil {
		s.logger.Error("healthz schema version", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "database is not reachable")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"schemaVersion": version,
	})
}
```

- [ ] **Step 16: Run to verify the server tests pass**

Run: `go test ./internal/httpapi/`
Expected: PASS — 18 tests.

- [ ] **Step 17: Implement `keyhole serve` and delete the stub**

Delete `cmd/keyhole/stubs.go`.

`cmd/keyhole/serve.go`:

```go
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ssan9876/keyhole/internal/config"
	"github.com/ssan9876/keyhole/internal/httpapi"
	"github.com/ssan9876/keyhole/internal/secret"
	"github.com/ssan9876/keyhole/internal/store"
)

func parseLevel(name string) slog.Level {
	switch strings.ToLower(name) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to config.yml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	}))

	serverSecret, err := secret.LoadOrCreate(cfg.SecretPath())
	if err != nil {
		return err
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()

	// Migrating on start means an operator who forgets `keyhole migrate` after
	// an upgrade still gets a working server rather than confusing errors.
	if err := st.Migrate(context.Background()); err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           httpapi.New(cfg, st, serverSecret, logger).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Addr, "base_url", cfg.BaseURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-shutdownCtx.Done():
		logger.Info("shutting down")
		graceCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(graceCtx)
	}
}
```

- [ ] **Step 18: Verify the whole build and the running server**

Run:

```bash
go build ./... && go vet ./... && go test ./...
```

Expected: all green.

Then start it against the scratch config and check health in another shell:

```bash
go run ./cmd/keyhole serve --config <scratch>/config.yml
```

Expected: a JSON log line `"msg":"listening"`. `curl -i http://127.0.0.1:8477/healthz` returns 200 with `{"schemaVersion":1,"status":"ok"}` and the `X-Content-Type-Options: nosniff` header. Ctrl-C logs `shutting down` and exits 0.

- [ ] **Step 19: Commit**

```bash
git add internal/httpapi internal/secret cmd/keyhole
git rm cmd/keyhole/stubs.go
git commit -m "feat(server): add HTTP skeleton, security middleware, and serve command"
```

---

### Task 4: Enrollment — server-side auth hashing and `POST /api/enroll/{token}`

**Files:**
- Create: `internal/auth/hash.go`
- Create: `internal/store/enroll.go`
- Create: `internal/httpapi/enroll.go`
- Modify: `internal/httpapi/server.go` (register the route in `routes()`)
- Test: `internal/auth/hash_test.go`
- Test: `internal/store/enroll_test.go`
- Test: `internal/httpapi/enroll_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.User`, `store.Invite`, `store.ErrNotFound`, `(*Store).CreatePendingUser`, `(*Store).CreateInvite`, `(*Store).InviteByToken`, `(*Store).UserByID` (Tasks 1–2); `httpapi.WriteError`, `WriteJSON`, `DecodeJSON`, `RequestIDFrom`, `Server` (Task 3).
- Produces:
  - `auth.HashAuthHash(authHash string) (string, error)` — returns `argon2id$<b64 salt>$<b64 digest>`
  - `auth.VerifyAuthHash(authHash, encoded string) bool` — constant-time, false on any parse failure
  - `store.EnrollmentInput` struct with string fields `KDFSalt, KDFParams, AuthHash, ProtectedUserKey, PublicKey, EncryptedPrivateKey, RecoverySalt, RecoveryProtectedUserKey, RecoveryKDFParams`
  - `(*Store).CompleteEnrollment(ctx context.Context, token string, in EnrollmentInput) (User, error)`

- [ ] **Step 1: Write the failing auth-hash test**

`internal/auth/hash_test.go`:

```go
package auth

import (
	"strings"
	"testing"
)

const sampleAuthHash = "eXQ1Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg=="

func TestHashAuthHashShape(t *testing.T) {
	encoded, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatalf("HashAuthHash: %v", err)
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 {
		t.Fatalf("encoded = %q, want three $-separated parts", encoded)
	}
	if parts[0] != "argon2id" {
		t.Errorf("algorithm = %q, want %q", parts[0], "argon2id")
	}
	// The client's auth hash must not be recoverable from what we store.
	if strings.Contains(encoded, sampleAuthHash) {
		t.Error("the encoded form contains the auth hash verbatim")
	}
}

func TestHashAuthHashUsesAFreshSaltEveryTime(t *testing.T) {
	first, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("two hashes of the same input are identical; the salt is not random")
	}
}

func TestVerifyAuthHashAcceptsTheOriginal(t *testing.T) {
	encoded, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyAuthHash(sampleAuthHash, encoded) {
		t.Error("VerifyAuthHash rejected the value it just hashed")
	}
}

func TestVerifyAuthHashRejectsAnythingElse(t *testing.T) {
	encoded, err := HashAuthHash(sampleAuthHash)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string]string{
		"different value": "not-the-auth-hash",
		"empty":           "",
		"prefix":          sampleAuthHash[:len(sampleAuthHash)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if VerifyAuthHash(candidate, encoded) {
				t.Error("VerifyAuthHash accepted a value it should not have")
			}
		})
	}
}

func TestVerifyAuthHashRejectsMalformedStoredValues(t *testing.T) {
	// A corrupted or empty column must fail closed, never panic and never
	// accidentally accept.
	for name, encoded := range map[string]string{
		"empty":            "",
		"no separators":    "argon2id",
		"wrong algorithm":  "bcrypt$c2FsdA==$aGFzaA==",
		"bad base64 salt":  "argon2id$!!!$aGFzaA==",
		"bad base64 digest": "argon2id$c2FsdA==$!!!",
		"too many parts":   "argon2id$a$b$c",
	} {
		t.Run(name, func(t *testing.T) {
			if VerifyAuthHash(sampleAuthHash, encoded) {
				t.Errorf("VerifyAuthHash accepted a malformed stored value %q", encoded)
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/auth/`
Expected: FAIL — `undefined: HashAuthHash`.

- [ ] **Step 3: Implement server-side auth hashing**

`internal/auth/hash.go`:

```go
// Package auth handles credential verification and session tokens.
//
// The value it hashes is the client's auth hash, not a password: the master
// password never reaches the server. Hashing it again server-side means a
// database dump yields nothing a caller could present at the login endpoint.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Server-side Argon2id parameters. Unrelated to the per-user client KDF
// params, which the server only stores and echoes back at prelogin.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashAuthHash returns "argon2id$<base64 salt>$<base64 digest>".
func HashAuthHash(authHash string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	digest := argon2.IDKey([]byte(authHash), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("argon2id$%s$%s",
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(digest),
	), nil
}

// VerifyAuthHash reports whether authHash produces the stored digest.
//
// It returns false for every malformed stored value rather than reporting a
// parse error: a caller that distinguished "wrong credential" from "corrupt
// row" would leak which accounts exist.
func VerifyAuthHash(authHash, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(want) == 0 {
		return false
	}

	got := argon2.IDKey([]byte(authHash), salt, argonTime, argonMemory, argonThreads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
```

- [ ] **Step 4: Run to verify the auth tests pass**

Run: `go test ./internal/auth/`
Expected: PASS — 5 test functions, 12 subtests.

- [ ] **Step 5: Write the failing enrollment-store test**

`internal/store/enroll_test.go`:

```go
package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func sampleEnrollment() EnrollmentInput {
	return EnrollmentInput{
		KDFSalt:                  "c2FsdHNhbHRzYWx0c2E=",
		KDFParams:                `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
		AuthHash:                 "argon2id$c2FsdA==$ZGlnZXN0",
		ProtectedUserKey:         `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"Y2lwaGVy"}`,
		PublicKey:                "cHVibGljS2V5MzJieXRlc2xvbmdoZXJl",
		EncryptedPrivateKey:      `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"cHJpdg=="}`,
		RecoverySalt:             "cmVjb3ZlcnlzYWx0MTY=",
		RecoveryProtectedUserKey: `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"cmVjb3Zlcnk="}`,
		RecoveryKDFParams:        `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
	}
}

func TestCompleteEnrollmentActivatesTheAccount(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	user := makeUser(t, s, "person@example.com")
	_, token, err := s.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	enrolled, err := s.CompleteEnrollment(ctx, token, sampleEnrollment())
	if err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}

	if enrolled.Status != "active" {
		t.Errorf("Status = %q, want %q", enrolled.Status, "active")
	}
	if enrolled.ID != user.ID {
		t.Errorf("enrolled a different user: %q, want %q", enrolled.ID, user.ID)
	}
	in := sampleEnrollment()
	if enrolled.ProtectedUserKey.String != in.ProtectedUserKey {
		t.Error("protected_user_key was not stored verbatim")
	}
	// recovery_kdf_params is its own column precisely so a later params change
	// cannot orphan the recovery blob.
	if enrolled.RecoveryKDFParams.String != in.RecoveryKDFParams {
		t.Error("recovery_kdf_params was not stored")
	}
}

func TestCompleteEnrollmentConsumesTheInvite(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	user := makeUser(t, s, "person@example.com")
	_, token, err := s.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteEnrollment(ctx, token, sampleEnrollment()); err != nil {
		t.Fatal(err)
	}

	// A replayed link must not overwrite an account that is already set up —
	// otherwise anyone who saw the invite URL could seize the vault later.
	if _, err := s.CompleteEnrollment(ctx, token, sampleEnrollment()); !errors.Is(err, ErrNotFound) {
		t.Errorf("second enrollment error = %v, want ErrNotFound", err)
	}
}

func TestCompleteEnrollmentRejectsUnknownToken(t *testing.T) {
	s := openTemp(t)
	if _, err := s.CompleteEnrollment(context.Background(), "no-such-token", sampleEnrollment()); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestCompleteEnrollmentRejectsIncompleteInput(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	user := makeUser(t, s, "person@example.com")

	// Each field is separately required. A client that forgets one — most
	// consequentially the recovery blob — must be told, not silently accepted
	// into a state where recovery is impossible.
	for _, field := range []string{
		"KDFSalt", "KDFParams", "AuthHash", "ProtectedUserKey", "PublicKey",
		"EncryptedPrivateKey", "RecoverySalt", "RecoveryProtectedUserKey", "RecoveryKDFParams",
	} {
		t.Run(field, func(t *testing.T) {
			_, token, err := s.CreateInvite(ctx, user.ID, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			in := sampleEnrollment()
			switch field {
			case "KDFSalt":
				in.KDFSalt = ""
			case "KDFParams":
				in.KDFParams = ""
			case "AuthHash":
				in.AuthHash = ""
			case "ProtectedUserKey":
				in.ProtectedUserKey = ""
			case "PublicKey":
				in.PublicKey = ""
			case "EncryptedPrivateKey":
				in.EncryptedPrivateKey = ""
			case "RecoverySalt":
				in.RecoverySalt = ""
			case "RecoveryProtectedUserKey":
				in.RecoveryProtectedUserKey = ""
			case "RecoveryKDFParams":
				in.RecoveryKDFParams = ""
			}
			if _, err := s.CompleteEnrollment(ctx, token, in); err == nil {
				t.Errorf("enrollment succeeded with %s empty", field)
			}
		})
	}
}

func TestCompleteEnrollmentLeavesNothingBehindOnFailure(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	user := makeUser(t, s, "person@example.com")
	_, token, err := s.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	bad := sampleEnrollment()
	bad.PublicKey = ""
	if _, err := s.CompleteEnrollment(ctx, token, bad); err == nil {
		t.Fatal("expected the enrollment to fail")
	}

	// The invite must still work: a client that sent a bad body should be able
	// to retry rather than be locked out of its own setup link.
	if _, err := s.InviteByToken(ctx, token); err != nil {
		t.Errorf("invite was consumed by a failed enrollment: %v", err)
	}
	after, err := s.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "pending" {
		t.Errorf("Status = %q after a failed enrollment, want %q", after.Status, "pending")
	}
}
```

- [ ] **Step 6: Run to verify it fails**

Run: `go test ./internal/store/ -run TestCompleteEnrollment`
Expected: FAIL — `undefined: EnrollmentInput`.

- [ ] **Step 7: Implement the enrollment store**

`internal/store/enroll.go`:

```go
package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// EnrollmentInput is everything a client uploads when it sets a master
// password. Every field is an opaque string the server stores verbatim and
// never parses; the auth hash arrives already hashed for storage.
type EnrollmentInput struct {
	KDFSalt                  string
	KDFParams                string
	AuthHash                 string
	ProtectedUserKey         string
	PublicKey                string
	EncryptedPrivateKey      string
	RecoverySalt             string
	RecoveryProtectedUserKey string
	RecoveryKDFParams        string
}

func (in EnrollmentInput) validate() error {
	required := map[string]string{
		"kdfSalt":                  in.KDFSalt,
		"params":                   in.KDFParams,
		"authHash":                 in.AuthHash,
		"protectedUserKey":         in.ProtectedUserKey,
		"publicKey":                in.PublicKey,
		"encryptedPrivateKey":      in.EncryptedPrivateKey,
		"recoverySalt":             in.RecoverySalt,
		"recoveryProtectedUserKey": in.RecoveryProtectedUserKey,
		"recoveryKdfParams":        in.RecoveryKDFParams,
	}
	for name, value := range required {
		if value == "" {
			return fmt.Errorf("enrollment field %q is required", name)
		}
	}
	return nil
}

// CompleteEnrollment consumes the invite and activates the account in one
// transaction.
//
// Both halves must land together. An account activated without its invite
// consumed leaves a replayable link; an invite consumed without the account
// activated leaves a user permanently unable to set up.
func (s *Store) CompleteEnrollment(ctx context.Context, token string, in EnrollmentInput) (User, error) {
	if err := in.validate(); err != nil {
		return User{}, err
	}

	invite, err := s.InviteByToken(ctx, token)
	if err != nil {
		return User{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339)

	// The used_at IS NULL condition makes this the point of serialization: two
	// concurrent enrollments race here and exactly one wins.
	result, err := tx.ExecContext(ctx,
		`UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		now, invite.ID)
	if err != nil {
		return User{}, fmt.Errorf("consume invite: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return User{}, fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return User{}, ErrNotFound
	}

	// status = 'pending' guards against enrolling over an already-active
	// account even if an invite row somehow survived.
	result, err = tx.ExecContext(ctx,
		`UPDATE users SET
			status = 'active',
			kdf_salt = ?, kdf_params = ?, auth_hash = ?,
			protected_user_key = ?, public_key = ?, encrypted_private_key = ?,
			recovery_salt = ?, recovery_protected_user_key = ?, recovery_kdf_params = ?,
			revision = revision + 1,
			updated_at = ?
		 WHERE id = ? AND status = 'pending'`,
		in.KDFSalt, in.KDFParams, in.AuthHash,
		in.ProtectedUserKey, in.PublicKey, in.EncryptedPrivateKey,
		in.RecoverySalt, in.RecoveryProtectedUserKey, in.RecoveryKDFParams,
		now, invite.UserID)
	if err != nil {
		return User{}, fmt.Errorf("activate user: %w", err)
	}
	if affected, err = result.RowsAffected(); err != nil {
		return User{}, fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return User{}, ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit enrollment: %w", err)
	}

	user, err := s.UserByID(ctx, invite.UserID)
	if err != nil {
		return User{}, errors.Join(errors.New("enrollment committed but reload failed"), err)
	}
	return user, nil
}
```

- [ ] **Step 8: Run to verify the store tests pass**

Run: `go test ./internal/store/`
Expected: PASS — including the 9 enrollment subtests.

- [ ] **Step 9: Write the failing enrollment endpoint test**

`internal/httpapi/enroll_test.go`:

```go
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

func enrollBody() map[string]string {
	return map[string]string{
		"kdfSalt":                  "c2FsdHNhbHRzYWx0c2E=",
		"params":                   `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
		"authHash":                 "YXV0aC1oYXNoLTMyLWJ5dGVzLWJhc2U2NA==",
		"protectedUserKey":         `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"Y2lwaGVy"}`,
		"publicKey":                "cHVibGljS2V5MzJieXRlc2xvbmdoZXJl",
		"encryptedPrivateKey":      `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"cHJpdg=="}`,
		"recoverySalt":             "cmVjb3ZlcnlzYWx0MTY=",
		"recoveryProtectedUserKey": `{"v":1,"alg":"A256GCM","n":"bm9uY2U=","ct":"cmVjb3Zlcnk="}`,
		"recoveryKdfParams":        `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`,
	}
}

// seedInvite creates a pending user and returns its one-time token.
func seedInvite(t *testing.T, srv *Server, email string) (store.User, string) {
	t.Helper()
	ctx := context.Background()

	user, err := srv.store.CreatePendingUser(ctx, email, "Test Person", "user")
	if err != nil {
		t.Fatalf("CreatePendingUser: %v", err)
	}
	_, token, err := srv.store.CreateInvite(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	return user, token
}

func postJSON(t *testing.T, srv *Server, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(encoded)))
	req.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestEnrollActivatesAndHashesTheAuthHash(t *testing.T) {
	srv := newTestServer(t)
	user, token := seedInvite(t, srv, "person@example.com")

	rec := postJSON(t, srv, "/api/enroll/"+token, enrollBody())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	stored, err := srv.store.UserByID(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "active" {
		t.Errorf("Status = %q, want %q", stored.Status, "active")
	}

	// The client's auth hash is a login credential. Storing it as received
	// would mean a database dump grants login to every account.
	sent := enrollBody()["authHash"]
	if stored.AuthHash.String == sent {
		t.Error("the auth hash was stored verbatim instead of being hashed")
	}
	if !auth.VerifyAuthHash(sent, stored.AuthHash.String) {
		t.Error("the stored auth hash does not verify against the value sent")
	}
}

func TestEnrollResponseLeaksNoKeyMaterial(t *testing.T) {
	srv := newTestServer(t)
	_, token := seedInvite(t, srv, "person@example.com")

	rec := postJSON(t, srv, "/api/enroll/"+token, enrollBody())
	body := rec.Body.String()

	for _, secret := range []string{
		enrollBody()["authHash"],
		enrollBody()["protectedUserKey"],
		enrollBody()["recoveryProtectedUserKey"],
	} {
		if strings.Contains(body, secret) {
			t.Errorf("the enrollment response echoed key material: %s", body)
		}
	}
}

func TestEnrollRejectsAReplayedToken(t *testing.T) {
	srv := newTestServer(t)
	_, token := seedInvite(t, srv, "person@example.com")

	if rec := postJSON(t, srv, "/api/enroll/"+token, enrollBody()); rec.Code != http.StatusOK {
		t.Fatalf("first enrollment failed: %d %s", rec.Code, rec.Body.String())
	}
	rec := postJSON(t, srv, "/api/enroll/"+token, enrollBody())
	if rec.Code != http.StatusNotFound {
		t.Errorf("replayed token status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestEnrollRejectsUnknownToken(t *testing.T) {
	srv := newTestServer(t)

	rec := postJSON(t, srv, "/api/enroll/does-not-exist", enrollBody())
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestEnrollRejectsAMissingRecoveryBlob(t *testing.T) {
	srv := newTestServer(t)
	_, token := seedInvite(t, srv, "person@example.com")

	body := enrollBody()
	delete(body, "recoveryProtectedUserKey")

	// Accepting this would produce an account with no recovery path — a fact
	// nobody discovers until the user has forgotten their master password.
	rec := postJSON(t, srv, "/api/enroll/"+token, body)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestEnrollRejectsAnUnknownField(t *testing.T) {
	srv := newTestServer(t)
	_, token := seedInvite(t, srv, "person@example.com")

	body := enrollBody()
	body["recoveryKdfParms"] = body["recoveryKdfParams"] // plausible typo

	rec := postJSON(t, srv, "/api/enroll/"+token, body)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
```

- [ ] **Step 10: Run to verify it fails**

Run: `go test ./internal/httpapi/ -run TestEnroll`
Expected: FAIL — the route is unregistered, so every case returns 404 and the first assertion fails.

- [ ] **Step 11: Implement the enrollment handler**

`internal/httpapi/enroll.go`:

```go
package httpapi

import (
	"errors"
	"net/http"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

// enrollRequest is what a client uploads after generating its key material.
// Field names match the crypto package's return values so a reader can follow
// one name from enrollUser() through to the database column.
type enrollRequest struct {
	KDFSalt                  string `json:"kdfSalt"`
	Params                   string `json:"params"`
	AuthHash                 string `json:"authHash"`
	ProtectedUserKey         string `json:"protectedUserKey"`
	PublicKey                string `json:"publicKey"`
	EncryptedPrivateKey      string `json:"encryptedPrivateKey"`
	RecoverySalt             string `json:"recoverySalt"`
	RecoveryProtectedUserKey string `json:"recoveryProtectedUserKey"`
	RecoveryKDFParams        string `json:"recoveryKdfParams"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		WriteError(w, http.StatusNotFound, CodeNotFound, "invalid setup link")
		return
	}

	var req enrollRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	// Hash the client's auth hash before it goes anywhere near the database.
	// It is a login credential; stored as received, a database dump would grant
	// login to every account on the server.
	hashed, err := auth.HashAuthHash(req.AuthHash)
	if err != nil {
		s.logger.Error("hash auth hash", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not complete setup")
		return
	}
	if req.AuthHash == "" {
		// Hashing an empty string succeeds, so check explicitly rather than
		// relying on the store to notice.
		WriteError(w, http.StatusBadRequest, CodeBadRequest, "enrollment field \"authHash\" is required")
		return
	}

	user, err := s.store.CompleteEnrollment(r.Context(), token, store.EnrollmentInput{
		KDFSalt:                  req.KDFSalt,
		KDFParams:                req.Params,
		AuthHash:                 hashed,
		ProtectedUserKey:         req.ProtectedUserKey,
		PublicKey:                req.PublicKey,
		EncryptedPrivateKey:      req.EncryptedPrivateKey,
		RecoverySalt:             req.RecoverySalt,
		RecoveryProtectedUserKey: req.RecoveryProtectedUserKey,
		RecoveryKDFParams:        req.RecoveryKDFParams,
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Unknown, expired, and already-used links are indistinguishable, so a
		// caller cannot probe which tokens ever existed.
		WriteError(w, http.StatusNotFound, CodeNotFound, "this setup link is no longer valid")
		return
	case err != nil:
		// A validation failure from the store is the client's fault; log the
		// detail and tell them without echoing the body back.
		s.logger.Warn("enrollment rejected", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}

	// Deliberately minimal: never echo key material, not even the caller's own.
	WriteJSON(w, http.StatusOK, map[string]any{
		"id":    user.ID,
		"email": user.Email,
		"name":  user.Name,
		"role":  user.Role,
	})
}
```

- [ ] **Step 12: Register the route**

In `internal/httpapi/server.go`, inside `routes()`, add above the catch-all `"/"` handler:

```go
	s.mux.HandleFunc("POST /api/enroll/{token}", s.handleEnroll)
```

- [ ] **Step 13: Run to verify the enrollment tests pass**

Run: `go test ./internal/httpapi/`
Expected: PASS — 24 tests.

- [ ] **Step 14: Verify the whole build**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green.

- [ ] **Step 15: Commit**

```bash
git add internal/auth internal/store/enroll.go internal/store/enroll_test.go internal/httpapi
git commit -m "feat(server): add enrollment endpoint with server-side auth hashing"
```

---

### Task 5: Prelogin, login, sessions, and the authentication middleware

**Files:**
- Create: `internal/auth/tokens.go`
- Create: `internal/store/sessions.go`
- Create: `internal/httpapi/auth.go`
- Modify: `internal/httpapi/server.go` (register routes)
- Test: `internal/auth/tokens_test.go`
- Test: `internal/store/sessions_test.go`
- Test: `internal/httpapi/auth_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1–4, notably `auth.VerifyAuthHash`, `store.HashToken`, `store.NewID`, `store.NormalizeEmail`, `store.ErrNotFound`, `(*Store).UserByEmail`, `(*Store).CompleteEnrollment`, `httpapi.Server.secret`.
- Produces:
  - `auth.NewToken() (string, error)` — 32 random bytes, base64url without padding
  - `auth.DecoySalt(serverSecret []byte, normalizedEmail string) string`
  - `auth.DefaultKDFParamsJSON` — the params string returned for unknown accounts
  - `store.Session` struct: `ID, UserID, DeviceLabel string`; `CreatedAt, LastSeenAt, ExpiresAt time.Time`; `RevokedAt sql.NullTime`
  - `(*Store).CreateSession(ctx, userID, deviceLabel string) (s Session, accessToken, refreshToken string, err error)`
  - `(*Store).SessionByAccessToken(ctx, token string) (Session, error)`
  - `(*Store).RotateSession(ctx, refreshToken string) (s Session, accessToken, newRefreshToken string, err error)`
  - `(*Store).TouchSession(ctx, sessionID string) error`
  - `(*Store).RevokeSession(ctx, sessionID string) error`
  - `httpapi.UserFrom(ctx context.Context) (store.User, bool)`
  - `(*Server).requireAuth(next http.HandlerFunc) http.HandlerFunc`

- [ ] **Step 1: Write the failing tokens test**

`internal/auth/tokens_test.go`:

```go
package auth

import (
	"encoding/base64"
	"testing"
)

func TestNewTokenIs256BitsOfBase64URL(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not raw base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("decoded length = %d, want 32", len(raw))
	}
}

func TestNewTokenDoesNotRepeat(t *testing.T) {
	seen := make(map[string]bool, 500)
	for i := 0; i < 500; i++ {
		token, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if seen[token] {
			t.Fatalf("NewToken returned a duplicate")
		}
		seen[token] = true
	}
}

func TestDecoySaltIsStableForTheSameAddress(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	// Stability across calls is the whole point: an address that answered with
	// one salt and then another would announce, by that inconsistency alone,
	// that no account exists behind it.
	first := DecoySalt(secret, "ghost@example.com")
	second := DecoySalt(secret, "ghost@example.com")
	if first != second {
		t.Errorf("DecoySalt is not deterministic: %q then %q", first, second)
	}
}

func TestDecoySaltDiffersByAddressAndBySecret(t *testing.T) {
	secretA := []byte("0123456789abcdef0123456789abcdef")
	secretB := []byte("fedcba9876543210fedcba9876543210")

	if DecoySalt(secretA, "a@example.com") == DecoySalt(secretA, "b@example.com") {
		t.Error("two addresses produced the same decoy salt")
	}
	// Keying by the server secret stops an attacker computing the decoy
	// offline and comparing it against a live response.
	if DecoySalt(secretA, "a@example.com") == DecoySalt(secretB, "a@example.com") {
		t.Error("the decoy salt does not depend on the server secret")
	}
}

func TestDecoySaltIsIndistinguishableFromARealSaltByLength(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	raw, err := base64.StdEncoding.DecodeString(DecoySalt(secret, "ghost@example.com"))
	if err != nil {
		t.Fatalf("decoy salt is not standard base64: %v", err)
	}
	// A real KDF salt is 16 bytes. A decoy of any other length would let a
	// caller distinguish real accounts from absent ones by inspection.
	if len(raw) != 16 {
		t.Errorf("decoy salt decodes to %d bytes, want 16 to match a real KDF salt", len(raw))
	}
}

func TestDefaultKDFParamsJSONMatchesTheSpec(t *testing.T) {
	want := `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`
	// If this drifts from what a real enrollment stores, the params field
	// itself distinguishes a decoy response from a real one.
	if DefaultKDFParamsJSON != want {
		t.Errorf("DefaultKDFParamsJSON = %q, want %q", DefaultKDFParamsJSON, want)
	}
}
```

- [ ] **Step 1b: Run to verify it fails**

Run: `go test ./internal/auth/ -run 'TestNewToken|TestDecoySalt|TestDefaultKDF'`
Expected: FAIL — `undefined: NewToken`.

- [ ] **Step 1c: Implement token minting and the decoy salt**

`internal/auth/tokens.go`:

```go
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const sessionTokenBytes = 32

// NewToken returns a 256-bit opaque token, base64url encoded without padding.
// Opaque rather than a JWT: revocation is a DELETE instead of a blocklist, and
// the token carries no claims a client could read or an attacker could forge.
func NewToken() (string, error) {
	buf := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// DefaultKDFParamsJSON is what prelogin reports for an address with no
// account. It must match what a real enrollment would use, or the shape of the
// response would itself distinguish real accounts from decoys.
const DefaultKDFParamsJSON = `{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4}`

// DecoySalt derives a stable fake salt for an unknown address.
//
// It must be deterministic: an address that returned one salt and then another
// on retry would reveal, by inconsistency, that no account exists. Keying it
// with the server secret stops an attacker computing the decoy offline and
// comparing it against a live response.
func DecoySalt(serverSecret []byte, normalizedEmail string) string {
	mac := hmac.New(sha256.New, serverSecret)
	mac.Write([]byte("keyhole:decoy-salt:v1"))
	mac.Write([]byte(normalizedEmail))
	// 16 bytes, matching a real KDF salt exactly.
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)[:16])
}
```

- [ ] **Step 1d: Run to verify the tokens tests pass**

Run: `go test ./internal/auth/`
Expected: PASS — the 6 new tokens tests plus the 5 hash tests from Task 4.

- [ ] **Step 2: Write the failing sessions test**

`internal/store/sessions_test.go`:

```go
package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// enrolledUser returns an active user, since sessions are only issued to those.
func enrolledUser(t *testing.T, s *Store, email string) User {
	t.Helper()
	ctx := context.Background()

	u := makeUser(t, s, email)
	_, token, err := s.CreateInvite(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := s.CompleteEnrollment(ctx, token, sampleEnrollment())
	if err != nil {
		t.Fatalf("CompleteEnrollment: %v", err)
	}
	return enrolled
}

func TestCreateSessionStoresOnlyHashes(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	sess, access, refresh, err := s.CreateSession(ctx, u.ID, "Firefox on Linux")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatal("CreateSession returned an empty token")
	}
	if access == refresh {
		t.Error("the access and refresh tokens are identical")
	}

	var storedAccess, storedRefresh string
	err = s.DB().QueryRow(`SELECT token_hash, refresh_hash FROM sessions WHERE id = ?`, sess.ID).
		Scan(&storedAccess, &storedRefresh)
	if err != nil {
		t.Fatal(err)
	}
	if storedAccess == access || storedRefresh == refresh {
		t.Error("a session token was stored in the clear")
	}
	if storedAccess != HashToken(access) || storedRefresh != HashToken(refresh) {
		t.Error("stored values are not the SHA-256 of the tokens")
	}
}

func TestSessionByAccessTokenRoundTrips(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	created, access, _, err := s.CreateSession(ctx, u.ID, "cli")
	if err != nil {
		t.Fatal(err)
	}
	found, err := s.SessionByAccessToken(ctx, access)
	if err != nil {
		t.Fatalf("SessionByAccessToken: %v", err)
	}
	if found.ID != created.ID || found.UserID != u.ID {
		t.Errorf("got session %q for user %q, want %q for %q", found.ID, found.UserID, created.ID, u.ID)
	}
}

func TestSessionLookupRejectsUnknownRevokedAndExpired(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	t.Run("unknown", func(t *testing.T) {
		if _, err := s.SessionByAccessToken(ctx, "nope"); !errors.Is(err, ErrNotFound) {
			t.Errorf("error = %v, want ErrNotFound", err)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		sess, access, _, err := s.CreateSession(ctx, u.ID, "cli")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeSession(ctx, sess.ID); err != nil {
			t.Fatal(err)
		}
		// "Sign out this device" must take effect immediately, not at expiry.
		if _, err := s.SessionByAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
			t.Errorf("revoked session error = %v, want ErrNotFound", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		sess, access, _, err := s.CreateSession(ctx, u.ID, "cli")
		if err != nil {
			t.Fatal(err)
		}
		past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
		if _, err := s.DB().Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, past, sess.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SessionByAccessToken(ctx, access); !errors.Is(err, ErrNotFound) {
			t.Errorf("expired session error = %v, want ErrNotFound", err)
		}
	})
}

func TestRotateSessionInvalidatesTheOldTokens(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	sess, oldAccess, oldRefresh, err := s.CreateSession(ctx, u.ID, "cli")
	if err != nil {
		t.Fatal(err)
	}

	rotated, newAccess, newRefresh, err := s.RotateSession(ctx, oldRefresh)
	if err != nil {
		t.Fatalf("RotateSession: %v", err)
	}
	if rotated.ID != sess.ID {
		t.Errorf("rotation created a new session %q, want the same %q", rotated.ID, sess.ID)
	}
	if newAccess == oldAccess || newRefresh == oldRefresh {
		t.Error("rotation reissued the same token")
	}

	// A refresh token is single-use. A leaked one must not stay usable after
	// the legitimate client has rotated.
	if _, _, _, err := s.RotateSession(ctx, oldRefresh); !errors.Is(err, ErrNotFound) {
		t.Errorf("reused refresh token error = %v, want ErrNotFound", err)
	}
	if _, err := s.SessionByAccessToken(ctx, oldAccess); !errors.Is(err, ErrNotFound) {
		t.Error("the old access token still works after rotation")
	}
	if _, err := s.SessionByAccessToken(ctx, newAccess); err != nil {
		t.Errorf("the new access token does not work: %v", err)
	}
}

func TestTouchSessionExtendsExpiry(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	u := enrolledUser(t, s, "person@example.com")

	sess, _, _, err := s.CreateSession(ctx, u.ID, "cli")
	if err != nil {
		t.Fatal(err)
	}

	// Wind the clock back so the sliding extension is observable.
	near := time.Now().UTC().Add(time.Minute).Format(time.RFC3339)
	if _, err := s.DB().Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, near, sess.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchSession(ctx, sess.ID); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}

	var after string
	if err := s.DB().QueryRow(`SELECT expires_at FROM sessions WHERE id = ?`, sess.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	extended, err := time.Parse(time.RFC3339, after)
	if err != nil {
		t.Fatal(err)
	}
	if !extended.After(time.Now().UTC().Add(20 * time.Minute)) {
		t.Errorf("expires_at = %s, want it pushed out by the full access lifetime", after)
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `go test ./internal/store/ -run 'TestCreateSession|TestSessionBy|TestRotateSession|TestTouchSession'`
Expected: FAIL — `undefined: (*Store).CreateSession`.

- [ ] **Step 4: Implement the sessions store**

`internal/store/sessions.go`:

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ssan9876/keyhole/internal/auth"
)

const (
	// AccessTokenLifetime is short and slides on use, so an intercepted token
	// stops working quickly once the legitimate client goes quiet.
	AccessTokenLifetime = 30 * time.Minute
	// RefreshTokenLifetime bounds how long a device stays signed in.
	RefreshTokenLifetime = 30 * 24 * time.Hour
)

type Session struct {
	ID          string
	UserID      string
	DeviceLabel string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time
	RevokedAt   sql.NullTime
}

// CreateSession issues a session and returns both tokens exactly once. Only
// their hashes are stored, so neither can be recovered from the database.
func (s *Store) CreateSession(ctx context.Context, userID, deviceLabel string) (Session, string, string, error) {
	accessToken, err := auth.NewToken()
	if err != nil {
		return Session{}, "", "", err
	}
	refreshToken, err := auth.NewToken()
	if err != nil {
		return Session{}, "", "", err
	}
	id, err := NewID()
	if err != nil {
		return Session{}, "", "", err
	}

	now := time.Now().UTC()
	expires := now.Add(AccessTokenLifetime)
	if deviceLabel == "" {
		deviceLabel = "unknown device"
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, token_hash, refresh_hash, device_label, created_at, last_seen_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, userID, HashToken(accessToken), HashToken(refreshToken), deviceLabel,
		now.Format(time.RFC3339), now.Format(time.RFC3339), expires.Format(time.RFC3339))
	if err != nil {
		return Session{}, "", "", fmt.Errorf("insert session: %w", err)
	}

	return Session{
		ID: id, UserID: userID, DeviceLabel: deviceLabel,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: expires,
	}, accessToken, refreshToken, nil
}

func scanSession(row interface{ Scan(...any) error }) (Session, error) {
	var sess Session
	var createdAt, lastSeenAt, expiresAt string
	err := row.Scan(&sess.ID, &sess.UserID, &sess.DeviceLabel,
		&createdAt, &lastSeenAt, &expiresAt, &sess.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("scan session: %w", err)
	}
	if sess.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return Session{}, fmt.Errorf("parse created_at: %w", err)
	}
	if sess.LastSeenAt, err = time.Parse(time.RFC3339, lastSeenAt); err != nil {
		return Session{}, fmt.Errorf("parse last_seen_at: %w", err)
	}
	if sess.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt); err != nil {
		return Session{}, fmt.Errorf("parse expires_at: %w", err)
	}
	return sess, nil
}

const sessionColumns = `id, user_id, device_label, created_at, last_seen_at, expires_at, revoked_at`

// SessionByAccessToken returns the session only if it is live. Revoked and
// expired sessions report ErrNotFound, so a caller cannot tell which.
func (s *Store) SessionByAccessToken(ctx context.Context, token string) (Session, error) {
	sess, err := scanSession(s.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE token_hash = ? AND revoked_at IS NULL`,
		HashToken(token)))
	if err != nil {
		return Session{}, err
	}
	if time.Now().UTC().After(sess.ExpiresAt) {
		return Session{}, ErrNotFound
	}
	return sess, nil
}

// RotateSession exchanges a refresh token for a fresh pair.
//
// The refresh token is single-use: the UPDATE matches on the old hash and
// replaces it, so a replay finds nothing. A leaked refresh token is therefore
// useful only until the real client next refreshes.
func (s *Store) RotateSession(ctx context.Context, refreshToken string) (Session, string, string, error) {
	sess, err := scanSession(s.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE refresh_hash = ? AND revoked_at IS NULL`,
		HashToken(refreshToken)))
	if err != nil {
		return Session{}, "", "", err
	}
	if time.Now().UTC().After(sess.CreatedAt.Add(RefreshTokenLifetime)) {
		return Session{}, "", "", ErrNotFound
	}

	newAccess, err := auth.NewToken()
	if err != nil {
		return Session{}, "", "", err
	}
	newRefresh, err := auth.NewToken()
	if err != nil {
		return Session{}, "", "", err
	}

	now := time.Now().UTC()
	expires := now.Add(AccessTokenLifetime)

	result, err := s.db.ExecContext(ctx,
		`UPDATE sessions
		 SET token_hash = ?, refresh_hash = ?, last_seen_at = ?, expires_at = ?
		 WHERE id = ? AND refresh_hash = ? AND revoked_at IS NULL`,
		HashToken(newAccess), HashToken(newRefresh),
		now.Format(time.RFC3339), expires.Format(time.RFC3339),
		sess.ID, HashToken(refreshToken))
	if err != nil {
		return Session{}, "", "", fmt.Errorf("rotate session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Session{}, "", "", fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return Session{}, "", "", ErrNotFound
	}

	sess.LastSeenAt = now
	sess.ExpiresAt = expires
	return sess, newAccess, newRefresh, nil
}

// TouchSession slides the access-token expiry forward on use.
func (s *Store) TouchSession(ctx context.Context, sessionID string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ? AND revoked_at IS NULL`,
		now.Format(time.RFC3339), now.Add(AccessTokenLifetime).Format(time.RFC3339), sessionID)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

func (s *Store) RevokeSession(ctx context.Context, sessionID string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339), sessionID)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}
```

- [ ] **Step 5: Run to verify the sessions tests pass**

Run: `go test ./internal/store/`
Expected: PASS — every store test.

- [ ] **Step 6: Write the failing auth endpoint test**

`internal/httpapi/auth_test.go`:

```go
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ssan9876/keyhole/internal/store"
)

// enrollUser seeds an active account and returns the raw auth hash it enrolled
// with, so tests can log in as that user.
func enrollTestUser(t *testing.T, srv *Server, email string) (store.User, string) {
	t.Helper()

	_, token := seedInvite(t, srv, email)
	body := enrollBody()
	if rec := postJSON(t, srv, "/api/enroll/"+token, body); rec.Code != http.StatusOK {
		t.Fatalf("enrollment failed: %d %s", rec.Code, rec.Body.String())
	}
	user, err := srv.store.UserByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return user, body["authHash"]
}

func TestPreloginReturnsRealSaltForKnownAccount(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	rec := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "PERSON@example.com"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		KDFSalt string `json:"kdfSalt"`
		Params  string `json:"params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.KDFSalt != enrollBody()["kdfSalt"] {
		t.Errorf("kdfSalt = %q, want the enrolled %q", body.KDFSalt, enrollBody()["kdfSalt"])
	}
	if body.Params == "" {
		t.Error("params is empty")
	}
}

func TestPreloginDecoyIsStableAndShapedLikeARealResponse(t *testing.T) {
	srv := newTestServer(t)

	first := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "ghost@example.com"})
	second := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "ghost@example.com"})

	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("status codes %d and %d, want 200 for an unknown address", first.Code, second.Code)
	}
	// An address that answered differently on retry would announce, by that
	// inconsistency alone, that no account exists.
	if first.Body.String() != second.Body.String() {
		t.Error("prelogin gave two different answers for the same unknown address")
	}

	var decoy, real struct {
		KDFSalt string `json:"kdfSalt"`
		Params  string `json:"params"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &decoy); err != nil {
		t.Fatal(err)
	}
	enrollTestUser(t, srv, "person@example.com")
	realRec := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "person@example.com"})
	if err := json.Unmarshal(realRec.Body.Bytes(), &real); err != nil {
		t.Fatal(err)
	}
	if len(decoy.KDFSalt) != len(real.KDFSalt) {
		t.Errorf("decoy salt is %d characters, real is %d; the length distinguishes them",
			len(decoy.KDFSalt), len(real.KDFSalt))
	}
	if decoy.Params != real.Params {
		t.Errorf("decoy params %q differ from real params %q", decoy.Params, real.Params)
	}
}

func TestPreloginDecoyDiffersBetweenAddresses(t *testing.T) {
	srv := newTestServer(t)

	a := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "a@example.com"})
	b := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "b@example.com"})
	if a.Body.String() == b.Body.String() {
		t.Error("two unknown addresses produced an identical salt; the decoy is not keyed by address")
	}
}

func TestLoginReturnsTokensAndWrappedKeys(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email":       "person@example.com",
		"authHash":    authHash,
		"deviceLabel": "Test Browser",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		AccessToken         string `json:"accessToken"`
		RefreshToken        string `json:"refreshToken"`
		ProtectedUserKey    string `json:"protectedUserKey"`
		EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// The client cannot unlock without these arriving in the login response —
	// that is the whole reason beginUnlock derives before it has them.
	if body.AccessToken == "" || body.RefreshToken == "" {
		t.Error("login did not return both tokens")
	}
	if body.ProtectedUserKey != enrollBody()["protectedUserKey"] {
		t.Error("login did not return the protected user key verbatim")
	}
	if body.EncryptedPrivateKey != enrollBody()["encryptedPrivateKey"] {
		t.Error("login did not return the encrypted private key verbatim")
	}
}

func TestLoginRejectsWrongAuthHashAndUnknownAccountIdentically(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	wrong := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": "wrong-value",
	})
	unknown := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "ghost@example.com", "authHash": "wrong-value",
	})

	if wrong.Code != http.StatusUnauthorized {
		t.Errorf("wrong auth hash status = %d, want %d", wrong.Code, http.StatusUnauthorized)
	}
	// Identical bodies and codes: otherwise the endpoint is an oracle for
	// which addresses have accounts on this server.
	if wrong.Code != unknown.Code {
		t.Errorf("status codes differ: %d for a real account, %d for an unknown one", wrong.Code, unknown.Code)
	}
	if wrong.Body.String() != unknown.Body.String() {
		t.Errorf("response bodies differ:\n real:    %s\n unknown: %s", wrong.Body.String(), unknown.Body.String())
	}
}

func TestLoginRejectsADisabledAccount(t *testing.T) {
	srv := newTestServer(t)
	user, authHash := enrollTestUser(t, srv, "person@example.com")

	if _, err := srv.store.DB().Exec(`UPDATE users SET status = 'disabled' WHERE id = ?`, user.ID); err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d for a disabled account", rec.Code, http.StatusUnauthorized)
	}
}

func TestRefreshRotatesAndInvalidatesTheOldToken(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	})
	var first struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}

	rec := postJSON(t, srv, "/api/auth/refresh", map[string]string{"refreshToken": first.RefreshToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	replay := postJSON(t, srv, "/api/auth/refresh", map[string]string{"refreshToken": first.RefreshToken})
	if replay.Code != http.StatusUnauthorized {
		t.Errorf("replayed refresh status = %d, want %d", replay.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuthGuardsProtectedRoutes(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	srv.mux.HandleFunc("GET /api/test-protected", srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFrom(r.Context())
		if !ok {
			t.Error("requireAuth did not put the user in the context")
		}
		WriteJSON(w, http.StatusOK, map[string]string{"email": user.Email})
	}))

	t.Run("no token", func(t *testing.T) {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/test-protected", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("garbage token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/test-protected", nil)
		req.Header.Set("Authorization", "Bearer not-a-real-token")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("valid token", func(t *testing.T) {
		login := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": authHash,
		})
		var body struct {
			AccessToken string `json:"accessToken"`
		}
		if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/test-protected", nil)
		req.Header.Set("Authorization", "Bearer "+body.AccessToken)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
		}
	})

	t.Run("token revoked mid-session", func(t *testing.T) {
		login := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": authHash,
		})
		var body struct {
			AccessToken string `json:"accessToken"`
		}
		if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		sess, err := srv.store.SessionByAccessToken(context.Background(), body.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.store.RevokeSession(context.Background(), sess.ID); err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/test-protected", nil)
		req.Header.Set("Authorization", "Bearer "+body.AccessToken)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		// Revocation must bite on the very next request, not at expiry.
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d after revocation, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

func TestLogoutRevokesTheSession(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	})
	var body struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+body.AccessToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if _, err := srv.store.SessionByAccessToken(context.Background(), body.AccessToken); err == nil {
		t.Error("the session still works after logout")
	}
}

func TestSessionExpiryIsSlidByUse(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	login := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	})
	var body struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	sess, err := srv.store.SessionByAccessToken(context.Background(), body.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	near := time.Now().UTC().Add(2 * time.Minute).Format(time.RFC3339)
	if _, err := srv.store.DB().Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, near, sess.ID); err != nil {
		t.Fatal(err)
	}

	srv.mux.HandleFunc("GET /api/test-slide", srv.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/test-slide", nil)
	req.Header.Set("Authorization", "Bearer "+body.AccessToken)
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	after, err := srv.store.SessionByAccessToken(context.Background(), body.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ExpiresAt.After(time.Now().UTC().Add(20 * time.Minute)) {
		t.Errorf("expiry = %s, want it slid forward by use", after.ExpiresAt)
	}
}
```

- [ ] **Step 7: Run to verify it fails**

Run: `go test ./internal/httpapi/ -run 'TestPrelogin|TestLogin|TestRefresh|TestRequireAuth|TestLogout|TestSessionExpiry'`
Expected: FAIL — routes unregistered, so every case 404s.

- [ ] **Step 8: Implement the auth endpoints and middleware**

`internal/httpapi/auth.go`:

```go
package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ssan9876/keyhole/internal/auth"
	"github.com/ssan9876/keyhole/internal/store"
)

const userContextKey contextKey = "user"

// UserFrom returns the authenticated user placed by requireAuth.
func UserFrom(ctx context.Context) (store.User, bool) {
	user, ok := ctx.Value(userContextKey).(store.User)
	return user, ok
}

type preloginRequest struct {
	Email string `json:"email"`
}

// handlePrelogin gives a client the salt and params it needs to derive.
//
// An unknown address gets a deterministic decoy of exactly the same shape.
// Anything else — a 404, a different field set, a different salt length —
// turns this endpoint into a way to enumerate who has an account here.
func (s *Server) handlePrelogin(w http.ResponseWriter, r *http.Request) {
	var req preloginRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	normalized := store.NormalizeEmail(req.Email)
	response := map[string]string{
		"kdfSalt": auth.DecoySalt(s.secret, normalized),
		"params":  auth.DefaultKDFParamsJSON,
	}

	user, err := s.store.UserByEmail(r.Context(), normalized)
	if err == nil && user.Status == "active" && user.KDFSalt.Valid && user.KDFParams.Valid {
		response["kdfSalt"] = user.KDFSalt.String
		response["params"] = user.KDFParams.String
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("prelogin lookup", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not process the request")
		return
	}

	WriteJSON(w, http.StatusOK, response)
}

type loginRequest struct {
	Email       string `json:"email"`
	AuthHash    string `json:"authHash"`
	DeviceLabel string `json:"deviceLabel"`
}

// invalidCredentials is the single response for every failed login. One
// message, one code, one status, whatever actually went wrong.
func invalidCredentials(w http.ResponseWriter) {
	WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "email or master password is incorrect")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	user, err := s.store.UserByEmail(r.Context(), req.Email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("login lookup", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not process the request")
		return
	}

	// Verify unconditionally, against a dummy value when the account does not
	// exist, so that the Argon2id cost is paid either way. Returning early
	// would make an unknown address measurably faster to probe.
	stored := "argon2id$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if err == nil && user.AuthHash.Valid {
		stored = user.AuthHash.String
	}
	ok := auth.VerifyAuthHash(req.AuthHash, stored)

	if err != nil || !ok || user.Status != "active" {
		invalidCredentials(w)
		return
	}

	session, accessToken, refreshToken, err := s.store.CreateSession(r.Context(), user.ID, req.DeviceLabel)
	if err != nil {
		s.logger.Error("create session", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not start a session")
		return
	}

	// The wrapped keys ride along with the tokens: the client derived its auth
	// hash before it had them, and needs them now to finish unlocking.
	WriteJSON(w, http.StatusOK, map[string]any{
		"accessToken":         accessToken,
		"refreshToken":        refreshToken,
		"expiresAt":           session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		"protectedUserKey":    user.ProtectedUserKey.String,
		"encryptedPrivateKey": user.EncryptedPrivateKey.String,
		"user": map[string]string{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	session, accessToken, refreshToken, err := s.store.RotateSession(r.Context(), req.RefreshToken)
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "this session is no longer valid")
		return
	}
	if err != nil {
		s.logger.Error("rotate session", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not refresh the session")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
		"expiresAt":    session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, ok := sessionFrom(r.Context())
	if !ok {
		WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "not signed in")
		return
	}
	if err := s.store.RevokeSession(r.Context(), session.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("revoke session", "id", RequestIDFrom(r.Context()), "error", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "could not sign out")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

const sessionContextKey contextKey = "session"

func sessionFrom(ctx context.Context) (store.Session, bool) {
	session, ok := ctx.Value(sessionContextKey).(store.Session)
	return session, ok
}

// requireAuth resolves the bearer token to a live session and an active user.
//
// Every rejection is the same 401 with the same body: distinguishing "no
// token" from "revoked" from "disabled account" would tell an attacker which
// tokens were once real.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token, found := strings.CutPrefix(header, "Bearer ")
		if !found || token == "" {
			WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
			return
		}

		session, err := s.store.SessionByAccessToken(r.Context(), token)
		if err != nil {
			WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
			return
		}

		user, err := s.store.UserByID(r.Context(), session.UserID)
		if err != nil || user.Status != "active" {
			WriteError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
			return
		}

		// Sliding expiry: an actively used session stays alive. A failure here
		// must not block the request — the session is valid, we simply did not
		// manage to extend it.
		if err := s.store.TouchSession(r.Context(), session.ID); err != nil {
			s.logger.Warn("touch session", "id", RequestIDFrom(r.Context()), "error", err)
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		ctx = context.WithValue(ctx, sessionContextKey, session)
		next(w, r.WithContext(ctx))
	}
}
```

- [ ] **Step 9: Register the routes**

In `internal/httpapi/server.go`, inside `routes()`, above the catch-all:

```go
	s.mux.HandleFunc("POST /api/auth/prelogin", s.handlePrelogin)
	s.mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/auth/refresh", s.handleRefresh)
	s.mux.HandleFunc("POST /api/auth/logout", s.requireAuth(s.handleLogout))
```

- [ ] **Step 10: Run to verify the auth tests pass**

Run: `go test ./internal/httpapi/`
Expected: PASS — 34 tests including the subtests.

- [ ] **Step 11: Verify the whole build**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green.

- [ ] **Step 12: Commit**

```bash
git add internal/auth/tokens.go internal/store/sessions.go internal/store/sessions_test.go internal/httpapi
git commit -m "feat(server): add prelogin, login, sessions, and bearer authentication"
```

---

### Task 6: Rate limiting and the security test suite

**Files:**
- Create: `internal/auth/ratelimit.go`
- Create: `internal/httpapi/security_test.go`
- Test: `internal/auth/ratelimit_test.go`
- Modify: `internal/httpapi/server.go` (hold a limiter, apply it to prelogin and login)
- Modify: `internal/httpapi/auth.go` (consult and record against the limiter)

**Interfaces:**
- Consumes: everything from Tasks 1–5.
- Produces:
  - `auth.Limiter` struct
  - `auth.NewLimiter(maxAttempts int, base, max time.Duration) *Limiter`
  - `(*Limiter).Allow(key string) (allowed bool, retryAfter time.Duration)`
  - `(*Limiter).RecordFailure(key string)`
  - `(*Limiter).Reset(key string)`
  - `(*Limiter).Sweep(olderThan time.Duration)`

- [ ] **Step 1: Write the failing limiter test**

`internal/auth/ratelimit_test.go`:

```go
package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestLimiterAllowsUpToTheThreshold(t *testing.T) {
	l := NewLimiter(5, time.Second, time.Minute)

	for i := 0; i < 5; i++ {
		if allowed, _ := l.Allow("ip:203.0.113.1"); !allowed {
			t.Fatalf("attempt %d was blocked; the first 5 must be allowed", i+1)
		}
		l.RecordFailure("ip:203.0.113.1")
	}
	if allowed, retryAfter := l.Allow("ip:203.0.113.1"); allowed {
		t.Error("the 6th attempt was allowed")
	} else if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want a positive duration", retryAfter)
	}
}

func TestLimiterBacksOffExponentially(t *testing.T) {
	l := NewLimiter(1, time.Second, time.Hour)

	var delays []time.Duration
	for i := 0; i < 4; i++ {
		l.RecordFailure("account:person@example.com")
		_, retryAfter := l.Allow("account:person@example.com")
		delays = append(delays, retryAfter)
	}

	for i := 1; i < len(delays); i++ {
		if delays[i] <= delays[i-1] {
			t.Errorf("delay %d (%v) did not exceed delay %d (%v); backoff is not growing",
				i, delays[i], i-1, delays[i-1])
		}
	}
}

func TestLimiterRespectsTheCeiling(t *testing.T) {
	ceiling := 5 * time.Second
	l := NewLimiter(1, time.Second, ceiling)

	for i := 0; i < 30; i++ {
		l.RecordFailure("account:person@example.com")
	}
	_, retryAfter := l.Allow("account:person@example.com")
	if retryAfter > ceiling {
		t.Errorf("retryAfter = %v, want no more than the ceiling %v", retryAfter, ceiling)
	}
}

func TestLimiterKeysAreIndependent(t *testing.T) {
	l := NewLimiter(1, time.Minute, time.Hour)

	for i := 0; i < 10; i++ {
		l.RecordFailure("ip:203.0.113.1")
	}
	// One client hammering the endpoint must not lock everyone else out.
	if allowed, _ := l.Allow("ip:198.51.100.7"); !allowed {
		t.Error("a different key was blocked by an unrelated key's failures")
	}
}

func TestResetClearsAKey(t *testing.T) {
	l := NewLimiter(2, time.Minute, time.Hour)

	for i := 0; i < 5; i++ {
		l.RecordFailure("account:person@example.com")
	}
	if allowed, _ := l.Allow("account:person@example.com"); allowed {
		t.Fatal("expected the key to be blocked before reset")
	}

	// A successful login clears the record, so a user who mistypes twice and
	// then succeeds is not still throttled on their next sign-in.
	l.Reset("account:person@example.com")
	if allowed, _ := l.Allow("account:person@example.com"); !allowed {
		t.Error("the key is still blocked after Reset")
	}
}

func TestSweepDropsStaleEntries(t *testing.T) {
	l := NewLimiter(1, time.Millisecond, time.Second)

	for i := 0; i < 100; i++ {
		l.RecordFailure(fmt.Sprintf("ip:198.51.100.%d", i))
	}
	time.Sleep(10 * time.Millisecond)
	l.Sweep(5 * time.Millisecond)

	// Without a sweep, an attacker cycling source addresses grows the map
	// without bound until the process runs out of memory.
	if n := l.size(); n != 0 {
		t.Errorf("%d entries survived the sweep, want 0", n)
	}
}

func TestLimiterIsSafeUnderConcurrentUse(t *testing.T) {
	l := NewLimiter(1000, time.Millisecond, time.Second)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := fmt.Sprintf("ip:203.0.113.%d", n%5)
			for j := 0; j < 50; j++ {
				l.Allow(key)
				l.RecordFailure(key)
			}
		}(i)
	}
	wg.Wait()
	// The assertion is that -race reports nothing; reaching here is the pass.
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/auth/ -run TestLimiter`
Expected: FAIL — `undefined: NewLimiter`.

- [ ] **Step 3: Implement the limiter**

`internal/auth/ratelimit.go`:

```go
package auth

import (
	"math"
	"sync"
	"time"
)

// Limiter throttles repeated failures per key with exponential backoff.
//
// In memory, because Keyhole runs as a single process against a single SQLite
// file. State is lost on restart, which is an acceptable trade for zero
// dependencies: an attacker who could restart the server has already won.
type Limiter struct {
	mu       sync.Mutex
	entries  map[string]*entry
	maxFree  int
	baseWait time.Duration
	maxWait  time.Duration
}

type entry struct {
	failures  int
	lastSeen  time.Time
	blockedTo time.Time
}

// NewLimiter allows maxFree failures per key before any delay, then backs off
// from base, doubling each failure, capped at max.
func NewLimiter(maxFree int, base, max time.Duration) *Limiter {
	return &Limiter{
		entries:  make(map[string]*entry),
		maxFree:  maxFree,
		baseWait: base,
		maxWait:  max,
	}
}

// Allow reports whether an attempt may proceed, and how long to wait if not.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[key]
	if !ok {
		return true, 0
	}
	now := time.Now()
	if now.Before(e.blockedTo) {
		return false, e.blockedTo.Sub(now)
	}
	return true, 0
}

// RecordFailure counts a failed attempt and extends the block.
func (l *Limiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[key]
	if !ok {
		e = &entry{}
		l.entries[key] = e
	}
	e.failures++
	e.lastSeen = time.Now()

	if e.failures <= l.maxFree {
		return
	}

	// Exponent grows with each failure past the free allowance. Shifting a
	// float and clamping avoids the overflow a plain 1<<n would hit.
	exponent := float64(e.failures - l.maxFree - 1)
	wait := time.Duration(float64(l.baseWait) * math.Pow(2, exponent))
	if wait > l.maxWait || wait <= 0 {
		wait = l.maxWait
	}
	e.blockedTo = e.lastSeen.Add(wait)
}

// Reset clears a key after a success, so an honest user who mistyped is not
// throttled on their next attempt.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Sweep drops entries untouched for longer than olderThan. Without it, an
// attacker cycling source addresses grows the map without bound.
func (l *Limiter) Sweep(olderThan time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-olderThan)
	for key, e := range l.entries {
		if e.lastSeen.Before(cutoff) {
			delete(l.entries, key)
		}
	}
}

// size is for tests only.
func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
```

- [ ] **Step 4: Run to verify the limiter tests pass, including under the race detector**

Run: `go test ./internal/auth/`
Expected: PASS — 7 limiter tests.

Run: `go test -race ./internal/auth/`
Expected: PASS with no race warnings.

- [ ] **Step 5: Wire the limiter into the server**

In `internal/httpapi/server.go`, add the import `"time"` and `"github.com/ssan9876/keyhole/internal/auth"`, then add a field to `Server`:

```go
	limiter *auth.Limiter
```

In `New`, construct it and start the sweeper:

```go
	s := &Server{
		cfg:    cfg,
		store:  st,
		secret: secret,
		logger: logger,
		mux:    http.NewServeMux(),
		// Five free attempts, then 2s, 4s, 8s… capped at five minutes. Generous
		// enough that a user mistyping their password never notices, harsh
		// enough that online guessing against a 64 MiB Argon2id is hopeless.
		limiter: auth.NewLimiter(5, 2*time.Second, 5*time.Minute),
	}
	s.routes()
	go s.sweepLimiter()
	return s
```

And add the sweeper:

```go
// sweepLimiter discards stale rate-limit entries. Runs for the life of the
// process; the server is a long-lived singleton, so there is nothing to stop.
func (s *Server) sweepLimiter() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.limiter.Sweep(time.Hour)
	}
}
```

- [ ] **Step 6: Apply the limiter in the login handler**

In `internal/httpapi/auth.go`, add `"fmt"` and `"strconv"` to the imports and a helper:

```go
// tooManyAttempts reports the throttle. Retry-After is advisory: an honest
// client can back off politely, and an attacker learns only what the timing
// already tells them.
func tooManyAttempts(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	WriteError(w, http.StatusTooManyRequests, CodeRateLimited,
		"too many attempts; please wait before trying again")
}
```

Then at the top of `handleLogin`, immediately after decoding the request:

```go
	// Two independent keys. The IP limit stops one host grinding through many
	// accounts; the account limit stops a distributed attempt on one account.
	// Both must pass, and the account key uses the normalized address so case
	// variations cannot buy extra attempts.
	ipKey := "ip:" + ClientIP(r)
	accountKey := "account:" + store.NormalizeEmail(req.Email)

	for _, key := range []string{ipKey, accountKey} {
		if allowed, retryAfter := s.limiter.Allow(key); !allowed {
			tooManyAttempts(w, retryAfter)
			return
		}
	}
```

Replace the failure branch so it records against both keys:

```go
	if err != nil || !ok || user.Status != "active" {
		s.limiter.RecordFailure(ipKey)
		s.limiter.RecordFailure(accountKey)
		invalidCredentials(w)
		return
	}
```

And after the session is created successfully, clear them:

```go
	s.limiter.Reset(ipKey)
	s.limiter.Reset(accountKey)
```

Apply the IP limit to `handlePrelogin` too, immediately after decoding — prelogin is unauthenticated and would otherwise be a free enumeration probe:

```go
	ipKey := "ip:" + ClientIP(r)
	if allowed, retryAfter := s.limiter.Allow(ipKey); !allowed {
		tooManyAttempts(w, retryAfter)
		return
	}
```

Note prelogin never calls `RecordFailure`: it has no notion of failure, since every address gets an answer. It shares the IP budget that login consumes, which is the intent — an attacker enumerating addresses is spending the same allowance either way.

- [ ] **Step 7: Write the failing security test suite**

`internal/httpapi/security_test.go`:

```go
package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginIsThrottledAfterRepeatedFailures(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	var lastCode int
	for i := 0; i < 8; i++ {
		rec := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": "wrong",
		})
		lastCode = rec.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("after 8 failures the status was %d, want %d", lastCode, http.StatusTooManyRequests)
	}
}

func TestThrottleResponseCarriesRetryAfter(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	var throttled *httptest.ResponseRecorder
	for i := 0; i < 10; i++ {
		rec := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": "wrong",
		})
		if rec.Code == http.StatusTooManyRequests {
			throttled = rec
			break
		}
	}
	if throttled == nil {
		t.Fatal("never got throttled")
	}
	if throttled.Header().Get("Retry-After") == "" {
		t.Error("Retry-After is not set on a throttled response")
	}
}

func TestSuccessfulLoginClearsTheThrottle(t *testing.T) {
	srv := newTestServer(t)
	_, authHash := enrollTestUser(t, srv, "person@example.com")

	// Four failures — under the five-attempt allowance.
	for i := 0; i < 4; i++ {
		postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": "wrong",
		})
	}
	if rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	}); rec.Code != http.StatusOK {
		t.Fatalf("the correct credential was rejected: %d %s", rec.Code, rec.Body.String())
	}

	// A user who mistypes a few times and then succeeds must not still be
	// throttled the next time they sign in.
	for i := 0; i < 4; i++ {
		rec := postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "person@example.com", "authHash": "wrong",
		})
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("throttled again after %d failures; the success did not reset the counter", i+1)
		}
	}
}

func TestASpoofedCFHeaderCannotEvadeTheIPLimit(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	attempt := func(forwarded string) int {
		body := `{"email":"other@example.com","authHash":"wrong"}`
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.50:5555" // NOT loopback
		req.Header.Set("CF-Connecting-IP", forwarded)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	// Every request cycles a different claimed address. Because the peer is not
	// loopback, the header must be ignored and all of them must count against
	// the one real address.
	var last int
	for i := 0; i < 10; i++ {
		last = attempt("198.51.100." + string(rune('0'+i%10)))
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("status = %d after 10 attempts with rotating spoofed IPs, want %d",
			last, http.StatusTooManyRequests)
	}
}

func TestUnknownAndRealAccountsAreTimingComparable(t *testing.T) {
	srv := newTestServer(t)
	enrollTestUser(t, srv, "person@example.com")

	measure := func(email string) time.Duration {
		start := time.Now()
		postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": email, "authHash": "definitely-wrong",
		})
		return time.Since(start)
	}

	// One measurement each, before either key is throttled.
	real := measure("person@example.com")
	unknown := measure("ghost@example.com")

	// The unknown-account path must still pay the Argon2id cost. Returning
	// early would make it dramatically faster and turn login into an oracle.
	// The bound is loose on purpose: this catches "no hashing at all", not
	// microsecond differences, which a network hides anyway.
	ratio := float64(real) / float64(unknown)
	if ratio > 5 || ratio < 0.2 {
		t.Errorf("timing differs too much: real %v, unknown %v (ratio %.2f)", real, unknown, ratio)
	}
}

func TestLoginResponseNeverLeaksStoredCredentialMaterial(t *testing.T) {
	srv := newTestServer(t)
	user, authHash := enrollTestUser(t, srv, "person@example.com")

	rec := postJSON(t, srv, "/api/auth/login", map[string]string{
		"email": "person@example.com", "authHash": authHash,
	})
	body := rec.Body.String()

	// The stored auth hash is a verifier. Echoing it would let anyone who saw
	// one response mount an offline attack against it.
	if strings.Contains(body, user.AuthHash.String) {
		t.Error("the login response contains the stored auth hash")
	}
	if strings.Contains(body, user.RecoveryProtectedUserKey.String) {
		t.Error("the login response contains the recovery blob, which login does not need")
	}
}

func TestPreloginIsThrottledPerIP(t *testing.T) {
	srv := newTestServer(t)

	var last int
	for i := 0; i < 12; i++ {
		// Cycling addresses to enumerate. All share one IP budget.
		rec := postJSON(t, srv, "/api/auth/prelogin", map[string]string{
			"email": "probe" + string(rune('a'+i)) + "@example.com",
		})
		last = rec.Code
	}
	// Prelogin records no failures itself, so it is only throttled once the
	// shared IP budget has been spent by failed logins.
	for i := 0; i < 8; i++ {
		postJSON(t, srv, "/api/auth/login", map[string]string{
			"email": "probe@example.com", "authHash": "wrong",
		})
	}
	rec := postJSON(t, srv, "/api/auth/prelogin", map[string]string{"email": "another@example.com"})
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("prelogin status = %d after the IP budget was spent, want %d (earlier probes returned %d)",
			rec.Code, http.StatusTooManyRequests, last)
	}
}

func TestErrorResponsesAreAlwaysTheEnvelope(t *testing.T) {
	srv := newTestServer(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"unknown route", http.MethodGet, "/api/nope", ""},
		{"bad json", http.MethodPost, "/api/auth/login", "{not json"},
		{"unknown enroll token", http.MethodPost, "/api/enroll/nope", "{}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			var body struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not the error envelope: %q", rec.Body.String())
			}
			if body.Error.Code == "" || body.Error.Message == "" {
				t.Errorf("envelope is incomplete: %q", rec.Body.String())
			}
		})
	}
}
```

- [ ] **Step 8: Run to verify the security tests pass**

Run: `go test ./internal/httpapi/`
Expected: PASS. If `TestUnknownAndRealAccountsAreTimingComparable` fails, the cause is almost certainly an early return on the unknown-account path in `handleLogin` — the dummy-verify must run unconditionally.

- [ ] **Step 9: Run the whole suite under the race detector**

Run: `go test -race ./...`
Expected: PASS with no race warnings. The limiter is shared across concurrent requests, so this is the run that matters.

- [ ] **Step 10: Verify the full build**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all green.

- [ ] **Step 11: Commit**

```bash
git add internal/auth/ratelimit.go internal/auth/ratelimit_test.go internal/httpapi
git commit -m "feat(server): add per-IP and per-account rate limiting with security tests"
```

---

## Definition of done

- `go build ./...` and `go vet ./...` are clean.
- `go test ./...` passes, and `go test -race ./...` reports no data races. The rate limiter is shared across concurrent requests, so the race run is not optional.
- `keyhole migrate` creates every table in spec §4.2 and is idempotent.
- `keyhole admin create` produces exactly one admin and a working one-time setup link; running it twice for the same address fails cleanly.
- A fresh binary can be enrolled into and logged into over HTTP end to end.
- **No registration route exists in the routing table** — verified by a test, not by inspection.
- The stored auth hash never equals what the client sent, and never appears in a response body.
- An unknown email and a wrong auth hash are indistinguishable by status code, body, or gross timing.
- `CF-Connecting-IP` from a non-loopback peer is ignored, verified by a test that rotates spoofed addresses and still gets throttled.

### Explicitly not in this plan

These are Plan 2b, and their absence is not a gap in this one: `GET /api/sync`, items and folders CRUD and bulk import, collections and memberships and pending grants, `/api/account/*`, `/api/admin/*` (including the admin-creates-a-user endpoint behind spec §5 step 3 — the CLI covers step 1 only), the audit log, and the tombstone retention job. `backup`, `restore`, and `update` are Plan 4.

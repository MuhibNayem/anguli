// Package store provides durable persistence behind one interface, with SQLite
// as the default driver and PostgreSQL as an opt-in.
//
// The problem this solves: templates, policies and access logs lived only in
// process memory, so every restart wiped them. For an access-control system
// that is disqualifying on its own - a door controller that forgets who is
// enrolled when it reboots is not deployable, and the previous state meant
// RPO = infinity with no recovery path.
//
// SQLite is the default because it needs no separate service and is fully
// ACID with WAL enabled, which is the right trade for a single-node or
// edge deployment. PostgreSQL is available without any code change for
// multi-instance deployments that need a shared, replicated store.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	// Drivers are registered for their side effects. Both are pure Go, so
	// neither needs CGO - which matters because the runtime images are Alpine.
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Driver identifies a supported storage backend.
type Driver string

const (
	// DriverSQLite is the default: embedded, single-node, ACID.
	DriverSQLite Driver = "sqlite"
	// DriverPostgres is opt-in for multi-instance deployments.
	DriverPostgres Driver = "postgres"
)

// ErrNotFound is returned when a row does not exist. Storage backends wrap
// this so callers can use errors.Is regardless of driver.
var ErrNotFound = errors.New("store: record not found")

// Config describes how to open the store.
type Config struct {
	// Driver selects the backend. Defaults to sqlite.
	Driver Driver
	// DSN is the driver-specific data source name.
	//
	// For sqlite an empty DSN is replaced with a local file under DataDir.
	// For postgres this is a full postgres:// URL and is required.
	DSN string
	// DataDir is where the default SQLite file lives. Defaults to ./data.
	DataDir string
	// MaxOpenConns bounds the connection pool. SQLite is write-serialised, so
	// leaving this at 1 avoids SQLITE_BUSY under write contention; Postgres
	// benefits from a larger pool.
	MaxOpenConns int
	// MaxIdleConns bounds idle connections.
	MaxIdleConns int
	// ConnMaxLifetime recycles connections to bound failure impact.
	ConnMaxLifetime time.Duration
	// OpenTimeout bounds connection establishment at startup.
	OpenTimeout time.Duration
}

// Store is a durable, driver-agnostic handle.
type Store struct {
	db      *sql.DB
	driver  Driver
	dsn     string
	ownsDSN bool
}

// Driver reports the backend in use.
func (s *Store) Driver() Driver { return s.driver }

// DB exposes the underlying *sql.DB for callers that need raw access.
func (s *Store) DB() *sql.DB { return s.db }

// Open connects to the configured backend and applies the schema.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	driver := cfg.Driver
	if driver == "" {
		driver = DriverSQLite
	}
	if driver != DriverSQLite && driver != DriverPostgres {
		return nil, fmt.Errorf("store: unsupported driver %q (want %q or %q)",
			driver, DriverSQLite, DriverPostgres)
	}

	dsn := cfg.DSN
	ownsDSN := false
	if driver == DriverSQLite && dsn == "" {
		dir := cfg.DataDir
		if dir == "" {
			dir = "data"
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("store: create data dir %q: %w", dir, err)
		}
		dsn = "file:" + filepath.Join(dir, "anguli.db") +
			"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
		ownsDSN = true
	}
	if driver == DriverPostgres && dsn == "" {
		return nil, errors.New("store: postgres driver requires a DSN (STORAGE_DSN)")
	}

	openCfg := cfg
	if openCfg.OpenTimeout <= 0 {
		openCfg.OpenTimeout = 10 * time.Second
	}
	db, err := sql.Open(string(driver), dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", driver, err)
	}

	if driver == DriverSQLite {
		// SQLite serialises writers. A single connection removes SQLITE_BUSY
		// under load; WAL still lets readers proceed concurrently.
		db.SetMaxOpenConns(1)
	} else {
		if cfg.MaxOpenConns > 0 {
			db.SetMaxOpenConns(cfg.MaxOpenConns)
		}
		if cfg.MaxIdleConns > 0 {
			db.SetMaxIdleConns(cfg.MaxIdleConns)
		}
	}
	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}

	openCtx, cancel := context.WithTimeout(ctx, openCfg.OpenTimeout)
	defer cancel()
	if err := db.PingContext(openCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping %s: %w", driver, err)
	}

	s := &Store{db: db, driver: driver, dsn: dsn, ownsDSN: ownsDSN}
	if err := s.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the connection pool.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// DSN returns the effective data source name.
func (s *Store) DSN() string { return s.dsn }

// ---------------------------------------------------------------------------
// Dialect
// ---------------------------------------------------------------------------

// Rebind converts '?' placeholders into the driver's own form. Queries are
// written once with '?' and rebound for postgres, which uses $1..$n.
func (s *Store) Rebind(query string) string {
	if s.driver != DriverPostgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

// BlobType returns the column type for binary data.
func (s *Store) BlobType() string {
	if s.driver == DriverPostgres {
		return "BYTEA"
	}
	return "BLOB"
}

// NowUnix returns the current unix timestamp in seconds.
func NowUnix() int64 { return time.Now().Unix() }

// itoa renders a small non-negative int without importing strconv at every
// call site. Used only by Rebind.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// FromEnv builds a Config from the standard environment variables:
// STORAGE_DRIVER, STORAGE_DSN and STORAGE_DATA_DIR.
func FromEnv() Config {
	cfg := Config{Driver: Driver(strings.ToLower(strings.TrimSpace(os.Getenv("STORAGE_DRIVER"))))}
	if cfg.Driver == "" {
		cfg.Driver = DriverSQLite
	}
	cfg.DSN = os.Getenv("STORAGE_DSN")
	cfg.DataDir = os.Getenv("STORAGE_DATA_DIR")
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	return cfg
}

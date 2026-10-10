package store_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"finger-scanner/pkg/store"
)

// TestOpenRejectsAnUnknownDriver matters because "memory" is a value operators
// try: falling back silently would give them a service that loses all state on
// restart while reporting itself healthy.
func TestOpenRejectsAnUnknownDriver(t *testing.T) {
	_, err := store.Open(context.Background(), store.Config{Driver: "memory"})
	if err == nil {
		t.Fatal("an unsupported driver was accepted")
	}
	for _, want := range []string{"unsupported driver", "memory", "sqlite", "postgres"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestOpenDefaultsToSQLiteAndDerivesADSN(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(context.Background(), store.Config{DataDir: dir})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = st.Close() }()

	if st.Driver() != store.DriverSQLite {
		t.Fatalf("driver = %q, want sqlite when unset", st.Driver())
	}
	// An unset directory must not put the database in the process working
	// directory, where it would be lost on restart.
	path := sqlitePath(t, st.DSN())
	if !strings.HasPrefix(path, filepath.ToSlash(dir)) && !strings.HasPrefix(path, dir) {
		t.Fatalf("DSN resolves to %q, which is not under the configured data dir %q", path, dir)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database was not created at the advertised DSN (%q): %v", path, err)
	}
}

// sqlitePath extracts the filesystem path from a "file:<path>?<params>" DSN.
func sqlitePath(t *testing.T, dsn string) string {
	t.Helper()
	path := strings.TrimPrefix(dsn, "file:")
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return path
}

func TestOpenAppliesSchemaOnEveryBoot(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := store.Config{Driver: store.DriverSQLite, DataDir: dir}

	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// Second boot must be a no-op rather than a constraint failure.
	st2, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("reopening an already-migrated database failed: %v", err)
	}
	defer func() { _ = st2.Close() }()

	v, err := st2.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v <= 0 {
		t.Fatalf("schema version is %d, want a recorded migration", v)
	}
}

func TestSchemaVersionOnAnEmptyDatabase(t *testing.T) {
	// COALESCE(MAX(version), 0) means a migrated-but-empty schema_migrations
	// table reads 0 rather than failing, which is what makes COALESCE load-bearing.
	st := openStore(t)
	v, err := st.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v <= 0 {
		t.Fatalf("schema version = %d", v)
	}
}

func TestNilStoreAccessorsAreSafe(t *testing.T) {
	var st *store.Store
	// A nil store must not panic: these are called from shutdown paths where a
	// half-constructed store is normal.
	if err := st.Close(); err != nil {
		t.Fatalf("Close on nil: %v", err)
	}
	if err := st.ClaimFacility(context.Background(), "x"); err == nil {
		t.Fatal("ClaimFacility on a nil store succeeded")
	}
	if _, err := st.FacilityID(context.Background()); err == nil {
		t.Fatal("FacilityID on a nil store succeeded")
	}
	if got := st.Driver(); got != "" {
		t.Fatalf("Driver on nil = %q", got)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	st := openStore(t)
	if err := st.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	// Closing twice is normal in a deferred-cleanup path next to an explicit one.
	if err := st.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestFromEnv(t *testing.T) {
	cases := []struct {
		name                 string
		driver, dsn, dataDir string
		wantDriver           store.Driver
		wantDataDir          string
	}{
		{"all defaults", "", "", "", store.DriverSQLite, "data"},
		{"explicit sqlite", "sqlite", "", "/data", store.DriverSQLite, "/data"},
		{"postgres", "postgres", "postgres://u:p@h/db", "", store.DriverPostgres, "data"},
		{"case and space are normalised", "  Postgres  ", "", "", store.DriverPostgres, "data"},
		{"dsn is passed through verbatim", "postgres", "postgres://u:p@h/db?sslmode=require", "", store.DriverPostgres, "data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("STORAGE_DRIVER", tc.driver)
			t.Setenv("STORAGE_DSN", tc.dsn)
			t.Setenv("STORAGE_DATA_DIR", tc.dataDir)

			cfg := store.FromEnv()
			if cfg.Driver != tc.wantDriver {
				t.Errorf("driver = %q, want %q", cfg.Driver, tc.wantDriver)
			}
			if cfg.DSN != tc.dsn {
				t.Errorf("DSN = %q, want %q", cfg.DSN, tc.dsn)
			}
			if cfg.DataDir != tc.wantDataDir {
				t.Errorf("data dir = %q, want %q", cfg.DataDir, tc.wantDataDir)
			}
		})
	}
}

// TestFacilityIDFromEnvLivesWithTheRestOfTheConfig keeps the facility identity
// configured the same way as the storage it guards.
func TestFacilityIDFromEnvLivesWithTheRestOfTheConfig(t *testing.T) {
	t.Setenv("STORAGE_DATA_DIR", "/data")
	t.Setenv("STORAGE_DRIVER", "sqlite")
	t.Setenv("FACILITY_ID", "london-hq")

	cfg := store.FromEnv()
	if cfg.DataDir != "/data" {
		t.Fatalf("data dir = %q", cfg.DataDir)
	}
	if got := store.FacilityIDFromEnv(); got != "london-hq" {
		t.Fatalf("facility = %q", got)
	}
}

func TestClaimConfiguredFacilityUsesTheEnvironment(t *testing.T) {
	t.Setenv("FACILITY_ID", "dublin-office")
	st := openStore(t)

	if err := store.ClaimConfiguredFacility(context.Background(), st, nil); err != nil {
		t.Fatalf("claim: %v", err)
	}
	id, err := st.FacilityID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != "dublin-office" {
		t.Fatalf("facility = %q, want dublin-office", id)
	}

	// The helper must refuse a mismatch too, not just claim the first time.
	t.Setenv("FACILITY_ID", "london-hq")
	if err := store.ClaimConfiguredFacility(context.Background(), st, nil); err == nil {
		t.Fatal("the env-driven helper let a second facility claim the database")
	}
}

func TestNowUnixIsPlausible(t *testing.T) {
	got := store.NowUnix()
	// 2020-01-01, well below any plausible clock and above the epoch.
	if got < 1577836800 {
		t.Fatalf("NowUnix = %d, which is not a real timestamp", got)
	}
}

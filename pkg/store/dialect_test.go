package store

import "testing"

// The postgres dialect helpers are only reachable through a Store carrying the
// postgres driver, which normally means a live server. These tests exercise the
// pure SQL-rendering logic directly, because getting placeholder conversion or
// column types wrong fails at runtime against production and nowhere else.
func TestRebindConvertsPlaceholdersForPostgres(t *testing.T) {
	s := &Store{driver: DriverPostgres}

	cases := map[string]string{
		"":                       "",
		"SELECT 1":               "SELECT 1",
		"SELECT ?":               "SELECT $1",
		"?":                      "$1",
		"SELECT ?, ?":            "SELECT $1, $2",
		"WHERE a = ? AND b = ?":  "WHERE a = $1 AND b = $2",
		"VALUES (?, ?, ?, ?, ?)": "VALUES ($1, $2, $3, $4, $5)",
		"UPDATE t SET a = ? WHERE b = ? AND c = ?": "UPDATE t SET a = $1 WHERE b = $2 AND c = $3",
		// More than nine placeholders: a hand-rolled converter that wrote digits
		// one at a time would produce "$10" as "$1" followed by "0".
		"?,?,?,?,?,?,?,?,?,?,?,?": "$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12",
	}
	for in, want := range cases {
		if got := s.Rebind(in); got != want {
			t.Errorf("Rebind(%q) = %q, want %q", in, got, want)
		}
	}
}

// A '?' inside a quoted string is data, not a placeholder. Converting it would
// corrupt the query, so the pass-through dialects must leave it alone and the
// caller must not rely on conversion happening inside literals.
func TestRebindLeavesSQLiteUntouched(t *testing.T) {
	sqlite := &Store{driver: DriverSQLite}
	query := "SELECT * FROM t WHERE name = 'why?' AND id = ?"
	if got := sqlite.Rebind(query); got != query {
		t.Fatalf("sqlite Rebind rewrote the query: %q", got)
	}
}

func TestBlobTypePerDriver(t *testing.T) {
	if got := (&Store{driver: DriverPostgres}).BlobType(); got != "BYTEA" {
		t.Errorf("postgres BlobType = %q, want BYTEA", got)
	}
	if got := (&Store{driver: DriverSQLite}).BlobType(); got != "BLOB" {
		t.Errorf("sqlite BlobType = %q, want BLOB", got)
	}
}

func TestBoolLiteralPerDriver(t *testing.T) {
	if got := boolLiteral(DriverPostgres); got != "FALSE" {
		t.Errorf("postgres boolLiteral = %q, want FALSE", got)
	}
	if got := boolLiteral(DriverSQLite); got != "0" {
		t.Errorf("sqlite boolLiteral = %q, want 0", got)
	}
}

func TestAutoIncTypePerDriver(t *testing.T) {
	if got := autoIncType(DriverPostgres); got != "BIGSERIAL PRIMARY KEY" {
		t.Errorf("postgres autoIncType = %q", got)
	}
	if got := autoIncType(DriverSQLite); got != "INTEGER PRIMARY KEY AUTOINCREMENT" {
		t.Errorf("sqlite autoIncType = %q", got)
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{
		0: "0", 1: "1", 9: "9", 10: "10", 99: "99", 100: "100", 12345: "12345",
	}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}

// firstLine feeds the migration error message, so a statement that begins with a
// newline still names itself rather than logging an empty string.
func TestFirstLine(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"CREATE TABLE x":      "CREATE TABLE x",
		"CREATE TABLE x\n(a)": "CREATE TABLE x",
		"\n  CREATE INDEX i":  "CREATE INDEX i",
		"   \t  ":             "",
		"no newline at all":   "no newline at all",
	}
	for in, want := range cases {
		if got := firstLine(in); got != want {
			t.Errorf("firstLine(%q) = %q, want %q", in, got, want)
		}
	}
}

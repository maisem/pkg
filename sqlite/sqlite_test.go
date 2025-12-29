package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func (c *fakeClock) AdvanceTo(t time.Time) {
	c.now = t
}

func TestScrubBackups(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := NewNoWorkers(dbPath, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &fakeClock{
		now: start,
	}
	db.timeNowUTC = c.Now

	// Create backup directory
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Helper to create a backup file with a specific timestamp
	createBackup := func(age time.Duration, slug string) string {
		c.AdvanceTo(start.Add(-age))
		db.dbChanged.Store(true)
		p, err := db.Backup(context.Background(), slug)
		if err != nil {
			t.Fatal(err)
		}
		return filepath.Base(p)
	}

	// Create test backups
	// Last hour (should all be kept)
	recent := []string{
		createBackup(10*time.Minute, ""),
		createBackup(30*time.Minute, ""),
		createBackup(50*time.Minute, ""),
	}

	// Last 24 hours (one per hour should be kept)
	hourly := []string{
		createBackup(2*time.Hour, ""),
		createBackup(2*time.Hour-5*time.Minute, ""), // Should be deleted (same hour)
		createBackup(5*time.Hour, ""),
		createBackup(10*time.Hour, ""),
	}

	day := 24 * time.Hour

	// Last 30 days (one per day should be kept)
	daily := []string{
		createBackup(2*day, ""),
		createBackup(2*day-2*time.Hour, ""), // Should be deleted (same day)
		createBackup(5*day, ""),
		createBackup(10*day, ""),
	}

	// Old backups (should all be deleted)
	old := []string{
		createBackup(31*day, ""),
		createBackup(45*day, ""),
		createBackup(60*day, ""),
	}

	// Run the scrubber
	c.AdvanceTo(start)
	if err := db.ScrubBackups(context.Background(), 0); err != nil {
		t.Fatal(err)
	}

	// Helper to check if a backup file exists
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(backupDir, name))
		return err == nil
	}

	// Verify recent backups (all should exist)
	for _, name := range recent {
		if !exists(name) {
			t.Errorf("recent backup %q was incorrectly deleted", name)
		}
	}

	// Verify hourly backups
	hourlyKept := 0
	for _, name := range hourly {
		if exists(name) {
			hourlyKept++
		}
	}
	if hourlyKept != 3 { // We created backups in 3 different hours
		t.Errorf("expected 3 hourly backups, got %d", hourlyKept)
	}

	// Verify daily backups
	dailyKept := 0
	for _, name := range daily {
		if exists(name) {
			dailyKept++
			t.Logf("daily backup %q kept", name)
		}
	}
	if dailyKept != 3 { // We created backups in 3 different days
		t.Errorf("expected 3 daily backups, got %d", dailyKept)
	}

	// Verify old backups (none should exist)
	for _, name := range old {
		if exists(name) {
			t.Errorf("old backup %q was not deleted", name)
		}
	}
}

func TestOnlyReallyOldBackups(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := NewNoWorkers(dbPath, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &fakeClock{
		now: start,
	}
	db.timeNowUTC = c.Now

	// Create backup directory
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Helper to create a backup file with a specific timestamp
	createBackup := func(age time.Duration, slug string) string {
		c.AdvanceTo(start.Add(-age))
		db.dbChanged.Store(true)
		p, err := db.Backup(context.Background(), slug)
		if err != nil {
			t.Fatal(err)
		}
		return filepath.Base(p)
	}

	day := 24 * time.Hour

	// Old backups (should all be deleted)
	old := []string{
		createBackup(32*day, ""),
		createBackup(45*day, ""),
		createBackup(60*day, ""),
	}

	// Run the scrubber
	c.AdvanceTo(start)
	if err := db.ScrubBackups(context.Background(), 30); err != nil {
		t.Fatal(err)
	}

	// Helper to check if a backup file exists
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(backupDir, name))
		return err == nil
	}

	// Verify old backups (none should exist)
	for _, name := range old {
		if !exists(name) {
			t.Errorf("old backup %q was deleted", name)
		}
	}
}

func TestScrubBackupsWithSlugs(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := NewNoWorkers(dbPath, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Create backup directory
	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}

	basePrefix := "test.db-"
	now := time.Now().UTC()

	// Helper to create a backup file with a specific timestamp
	createBackup := func(age time.Duration, slug string) string {
		ts := now.Add(-age).Format(time.RFC3339)
		name := basePrefix + ts
		if slug != "" {
			name += "-" + slug
		}
		path := filepath.Join(backupDir, name)
		if err := os.WriteFile(path, []byte("backup"), 0600); err != nil {
			t.Fatal(err)
		}
		// Set the modification time to match the timestamp in the filename
		if err := os.Chtimes(path, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
		return name
	}

	// Create test backups with different slugs
	backups := []string{
		createBackup(30*time.Minute, "v1"),
		createBackup(31*time.Minute, "v2"),
		createBackup(2*time.Hour, "v1"),
		createBackup(2*time.Hour+1*time.Minute, "v2"),
	}

	// Run the scrubber
	if err := db.ScrubBackups(context.Background(), 0); err != nil {
		t.Fatal(err)
	}

	// Helper to check if a backup file exists
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(backupDir, name))
		return err == nil
	}

	// All recent backups with different slugs should be kept
	for _, name := range backups[:2] { // First two are within the hour
		if !exists(name) {
			t.Errorf("recent backup %q was incorrectly deleted", name)
		}
	}

	// For the same hour backups, only one should be kept
	kept := 0
	for _, name := range backups[2:] {
		if exists(name) {
			kept++
		}
	}
	if kept != 1 {
		t.Errorf("expected 1 backup for the 2-hour mark, got %d", kept)
	}
}

func TestIsConstraintError(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := NewNoWorkers(dbPath, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := NewContext()

	// Create a table with id as a unique constraint
	err = db.Write(ctx, "create-table", func(tx *Tx) error {
		_, err := tx.Exec("CREATE TABLE test_table (id INTEGER UNIQUE, value TEXT)")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Insert first row
	err = db.Write(ctx, "insert-first", func(tx *Tx) error {
		_, err := tx.Exec("INSERT INTO test_table (id, value) VALUES (?, ?)", 1, "first")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Try to insert second row with same id
	err = db.Write(ctx, "insert-duplicate", func(tx *Tx) error {
		_, err := tx.Exec("INSERT INTO test_table (id, value) VALUES (?, ?)", 1, "second")
		return err
	})

	// Verify we got a constraint error
	if err == nil {
		t.Fatal("expected constraint error, got nil")
	}

	if !IsConstraintError(err) {
		t.Fatalf("expected IsConstraintError to return true, got false for error: %v (%T)", err, err)
	}
}

func TestIsTableNotFoundError(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := NewNoWorkers(dbPath, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := NewContext()

	// Try to query a table that doesn't exist
	err = db.Read(ctx, func(tx *Tx) error {
		_, err := tx.Query("SELECT * FROM nonexistent_table")
		return err
	})

	// Verify we got a table not found error
	if err == nil {
		t.Fatal("expected table not found error, got nil")
	}

	if !IsTableNotFoundError(err) {
		t.Fatalf("expected IsTableNotFoundError to return true, got false for error: %v (%T)", err, err)
	}
}

// reserveSafeID generates a new SafeID of the specified type and stores it in the database.
// It uses collision-resistant generation with retry logic.
func reserveSafeID[T ~int64](ctx context.Context, db *DB) (T, error) {
	var out T
	err := db.Write(ctx, "store_safe_id", func(tx *Tx) error {
		var err error
		out, err = ReserveSafeIDTx[T](tx)
		return err
	})
	return out, err
}

func mustDo(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewSafeIDsAreAtLeast1000(t *testing.T) {
	td := t.TempDir()
	db, err := New(filepath.Join(td, "test.sqlite"), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustDo(t, db.InitSchema(`CREATE TABLE safe_ids (
  ID INTEGER PRIMARY KEY,
  Type TEXT NOT NULL
) STRICT;`))

	ctx := NewContext()

	// Generate several IDs and ensure they're all >= 1000
	for i := 0; i < 20; i++ {
		userID, err := reserveSafeID[int64](ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if int64(userID) < 1000 {
			t.Errorf("Generated ID %d is less than 1000", userID)
		}
	}
}

func TestIsValidTableName(t *testing.T) {
	tests := []struct {
		name     string
		table    tableName
		expected bool
	}{
		// Valid cases - simple table names
		{"simple table", "users", true},
		{"single letter", "a", true},
		{"single underscore", "_", true},
		{"table with numbers", "users123", true},
		{"table with underscores", "user_profiles", true},
		{"table starting with underscore", "_internal", true},
		{"uppercase table", "USERS", true},
		{"mixed case table", "UserProfiles", true},
		{"table with many underscores", "very_long_table_name", true},

		// Valid cases - schema.table
		{"schema.table", "schema.users", true},
		{"underscore schema", "my_schema.my_table", true},
		{"schema with numbers", "schema123.table456", true},
		{"schema starting with underscore", "_schema._table", true},
		{"underscore schema with underscore table", "_._", true},
		{"uppercase schema", "SCHEMA.TABLE", true},
		{"single letter schema and table", "s.t", true},

		// Invalid cases - empty or whitespace
		{"empty string", "", false},
		{"whitespace only", " ", false},
		{"multiple spaces", "   ", false},
		{"leading space", " users", false},
		{"trailing space", "users ", false},
		{"both spaces", " users ", false},

		// Invalid cases - starting with number
		{"starting with number", "123users", false},
		{"only numbers", "123", false},
		{"schema starting with number", "123schema.table", false},
		{"table starting with number", "schema.123table", false},

		// Invalid cases - special characters
		{"hyphen in name", "user-profiles", false},
		{"space in name", "user profiles", false},
		{"at symbol", "user@table", false},
		{"hash symbol", "user#table", false},
		{"dollar sign", "user$table", false},
		{"percent sign", "user%table", false},
		{"ampersand", "user&table", false},
		{"asterisk", "user*table", false},
		{"parentheses", "user(table)", false},
		{"brackets", "user[table]", false},
		{"braces", "user{table}", false},
		{"pipe", "user|table", false},
		{"backslash", "user\\table", false},
		{"forward slash", "user/table", false},
		{"question mark", "user?table", false},
		{"exclamation", "user!table", false},
		{"plus sign", "user+table", false},
		{"equals sign", "user=table", false},
		{"comma", "user,table", false},
		{"semicolon", "user;table", false},
		{"colon", "user:table", false},

		// Invalid cases - SQL injection attempts
		{"SQL comment", "users--", false},
		{"SQL injection attempt", "users; DROP TABLE", false},
		{"single quote", "user'table", false},
		{"double quote", "user\"table", false},
		{"backtick", "user`table", false},

		// Invalid cases - multiple dots
		{"three parts", "schema1.schema2.table", false},
		{"four parts", "a.b.c.d", false},
		{"multiple consecutive dots", "schema..table", false},

		// Invalid cases - incomplete schema
		{"schema only with dot", "schema.", false},
		{"only dot", ".", false},
		{"dot only at start", ".table", false},

		// Edge cases
		{"very long name", tableName(strings.Repeat("a", 1000)), true}, // Valid but long
		{"unicode characters", "täblé", false},
		{"newline", "user\ntable", false},
		{"tab character", "user\ttable", false},
		{"carriage return", "user\rtable", false},
		{"null byte", "user\x00table", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidTableName(tt.table)
			if result != tt.expected {
				t.Errorf("isValidTableName(%q) = %v, want %v", tt.table, result, tt.expected)
			}
		})
	}
}

package equality

import (
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"pkg.maisem.dev/sqlite"
	"pkg.maisem.dev/sqlite/schema"
	"tailscale.com/util/must"
)

func dbWithSchema(t testing.TB, m *schema.Manager, schemaVer int) string {
	f := filepath.Join(t.TempDir(), "db.sqlite")
	sdb, err := sqlite.New(f, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	s := m.Schema(schemaVer)
	if err := sdb.InitSchema(s); err != nil {
		t.Fatal(err)
	}
	return f
}

func cleanWhitespace(input string) string {
	// First, replace multiple spaces with a single space
	re1 := regexp.MustCompile(`\s+`)
	temp := re1.ReplaceAllString(input, " ")

	// Remove spaces before specific punctuation
	re2 := regexp.MustCompile(`\s+([\),\.]|,)`)
	return re2.ReplaceAllString(temp, "$1")
}

func mustDo(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSchemaEquality(t *testing.T, m *schema.Manager) {
	type SchemaObject struct {
		Name string
		Type string
		SQL  string
	}

	// Helper to remove comments and normalize whitespace
	normalizeSQL := func(sql string) string {
		lines := strings.Split(sql, "\n")
		var result []string
		for _, line := range lines {
			// Normalize whitespace
			line = strings.TrimSpace(line)
			// Skip comment lines and empty lines
			if strings.HasPrefix(line, "--") || line == "" {
				continue
			}
			// Remove inline comments
			if idx := strings.Index(line, "--"); idx >= 0 {
				line = line[:idx]
			}
			// Normalize whitespace again
			line = strings.TrimSpace(line)
			if line != "" {
				result = append(result, line)
			}
		}
		return cleanWhitespace(strings.Join(result, " "))
	}

	// Query to get all schema objects from sqlite_master
	schemaQuery := `
		SELECT name, type, sql
		FROM sqlite_master
		WHERE name NOT LIKE 'sqlite_%'
		  AND type IN ('table', 'index', 'view', 'trigger')
		ORDER BY type, name;
	`

	// Helper function to extract schemas from rows
	getSchemas := func(db *sqlite.DB) (map[string]SchemaObject, error) {
		rx, err := db.ReadTx(sqlite.NewContext())
		if err != nil {
			return nil, fmt.Errorf("failed to start read tx: %w", err)
		}
		defer rx.Rollback()
		rows, err := rx.Query(sqlite.UnsafeQueryString(schemaQuery))
		if err != nil {
			return nil, fmt.Errorf("failed to query schema: %w", err)
		}
		schemas := make(map[string]SchemaObject)
		for rows.Next() {
			var s SchemaObject
			if err := rows.Scan(&s.Name, &s.Type, &s.SQL); err != nil {
				return nil, fmt.Errorf("failed to scan row: %w", err)
			}
			// Skip empty SQL statements (like autoindexes)
			if s.SQL == "" {
				continue
			}
			// Use type+name as key to handle same name across different types
			key := fmt.Sprintf("%s:%s", s.Type, s.Name)
			schemas[key] = s
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating rows: %w", err)
		}
		return schemas, nil
	}
	td := t.TempDir()
	latestSchemaDB, err := sqlite.New(filepath.Join(td, "latest.sqlite"), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer latestSchemaDB.Close()
	mustDo(t, m.Init(sqlite.NewContext(), latestSchemaDB, t.Logf))
	schemas1 := must.Get(getSchemas(latestSchemaDB))

	for i := m.MinSchemaVersion(); i < m.LatestSchemaVersion(); i++ {
		t.Run(fmt.Sprintf("schema-%d", i), func(t *testing.T) {
			f := dbWithSchema(t, m, i)
			migratedDB, err := sqlite.New(f, t.Logf)
			if err != nil {
				t.Fatal(err)
			}
			mustDo(t, m.Init(sqlite.NewContext(), migratedDB, t.Logf))
			defer migratedDB.Close()
			schemas2 := must.Get(getSchemas(migratedDB))

			// Compare each table schema
			for tableName, schema1 := range schemas1 {
				schema2, exists := schemas2[tableName]
				if !exists {
					t.Errorf("table %q exists in first database but not in second", tableName)
					continue
				}

				if schema1.Type != schema2.Type {
					t.Errorf("type mismatch for table %q: db1=%q, db2=%q",
						tableName, schema1.Type, schema2.Type)
				}
				sql1 := normalizeSQL(schema1.SQL)
				sql2 := normalizeSQL(schema2.SQL)
				if sql1 != sql2 {
					t.Errorf("schema mismatch for table %q:\ndb1: %s\ndb2: %s",
						tableName, sql1, sql2)
				}
			}

			// Check for tables in second DB that aren't in first
			for tableName := range schemas2 {
				if _, exists := schemas1[tableName]; !exists {
					t.Errorf("table %q exists in second database but not in first", tableName)
				}
			}

			// Compare number of tables
			if len(schemas1) != len(schemas2) {
				t1 := slices.Sorted(maps.Keys(schemas1))
				t2 := slices.Sorted(maps.Keys(schemas2))
				t.Fatalf("table count mismatch: %v", cmp.Diff(t1, t2))
			}
		})
		if t.Failed() {
			return
		}
	}
}

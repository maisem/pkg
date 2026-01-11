// Copyright (c) 2025 AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package schema

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"pkg.maisem.dev/sqlite"
	"tailscale.com/types/logger"
)

// tableExists checks if a table exists in the database.
func tableExists(tx *sqlite.Tx, name string) (bool, error) {
	return sqlite.ScanSingle[bool](tx.QueryRow(`SELECT count(*) > 0 FROM sqlite_master WHERE type='table' AND name=?`, name))
}

// dbCurSchema returns the current schema version of the database.
func dbCurSchema(ctx context.Context, db *sqlite.DB, name string) (int, error) {
	rx, err := db.ReadTx(ctx)
	if err != nil {
		return 0, err
	}
	defer rx.Rollback()
	if exists, err := tableExists(rx, "schema_version"); err == nil && exists {
		return sqlite.ScanSingle[int](rx.QueryRow(`SELECT Version from schema_version WHERE Name=?`, name))
	}
	return -1, nil
}

type Manager struct {
	Schemata   *embed.FS
	SchemaName string
	Migrators  map[int]Migrator
}

// MinSchemaVersion returns the minimum schema version that is supported by the
// manager. This is the lowest schema version that has a migrator.
// If there are no migrators, it returns the latest schema version.
func (m *Manager) MinSchemaVersion() int {
	out := m.LatestSchemaVersion()
	for k := range m.Migrators {
		if k < out {
			out = k
		}
	}
	return out
}

// Init initializes the database schema if needed or performs migrations.
func (m *Manager) Init(ctx context.Context, db *sqlite.DB, logf logger.Logf) (err error) {
	curVer, err := dbCurSchema(ctx, db, m.SchemaName)
	if err != nil {
		return err
	}
	latestSchemaVersion := m.AllSchemas().Len()
	if curVer < 0 {
		return db.InitSchema(string(m.LatestSchema()))
	}
	logf("%s schema version: %d, latest: %d", m.SchemaName, curVer, latestSchemaVersion)
	if curVer > latestSchemaVersion {
		return fmt.Errorf("database schema version %d is newer than the current schema version %d", curVer, latestSchemaVersion)
	}
	if curVer == latestSchemaVersion {
		return nil // nothing to do
	}
	if _, err := db.Backup(ctx, fmt.Sprintf("%s_v%d", m.SchemaName, curVer)); err != nil {
		return err
	}
	c, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	// Run everything in a transaction.
	if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE;"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if _, err2 := c.ExecContext(ctx, "ROLLBACK;"); err2 != nil {
				logf("rollback failed: %v", err2)
			}
		}
	}()
	for dv := curVer; dv < latestSchemaVersion; dv++ {
		up, ok := m.Migrators[dv]
		if !ok {
			return fmt.Errorf("no upgrader for schema version %d", dv)
		}
		logf("Running upgrader for schema version %d", dv)
		t0 := time.Now()
		if err := up(ctx, c); err != nil {
			logf("Upgrader for schema version %d failed: %v", dv, err)
			return err
		}
		logf("Upgrader for schema version %d took %v", dv, time.Since(t0))
		if _, err := c.ExecContext(ctx, `UPDATE schema_version SET Version = ? WHERE Name = ?;`, dv+1, m.SchemaName); err != nil {
			return err
		}
	}
	_, err = c.ExecContext(ctx, "COMMIT;")
	return err
}

// A schema upgrader function takes a transaction and upgrades the
// schema from one version to the next.
type Migrator func(ctx context.Context, conn *sql.Conn) error

// ExecStatements executes a list of SQL statements in order
func ExecStatements(ctx context.Context, conn *sql.Conn, statements ...string) error {
	for _, stmt := range statements {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to execute statement: %w", err)
		}
	}
	return nil
}

// Schemas is a slice of all embedded Schemas, sorted by version.
type Schemas struct {
	Schemas []struct {
		ver  int
		path string
	}
}

// AllSchemas returns a schemas instance containing all embedded schemas.
func (m *Manager) AllSchemas() *Schemas {
	files, err := fs.ReadDir(m.Schemata, "schemas")
	if err != nil {
		log.Fatalf("reading embedded schemas: %v", err)
	}

	var s Schemas
	for _, file := range files {
		name := file.Name()
		if !strings.HasPrefix(name, "v") || !strings.HasSuffix(name, ".sql.gz") {
			continue
		}
		verS := strings.TrimPrefix(strings.TrimSuffix(name, ".sql.gz"), "v")
		ver, err := strconv.Atoi(verS)
		if err != nil {
			log.Fatalf("parsing schema version from %q: %v", name, err)
		}
		s.Schemas = append(s.Schemas, struct {
			ver  int
			path string
		}{
			ver:  ver,
			path: fmt.Sprintf("schemas/%s", name),
		})
	}
	// Sort schemas in increasing version order.
	sort.Slice(s.Schemas, func(i, j int) bool {
		return s.Schemas[i].ver < s.Schemas[j].ver
	})
	return &s
}

// Len returns the number of schemas.
func (s *Schemas) Len() int {
	return len(s.Schemas)
}

// LatestSchemaVersion returns the highest schema version that is supported by
// the manager.
func (m *Manager) LatestSchemaVersion() int {
	s := m.AllSchemas()
	if s.Len() == 0 {
		log.Fatalf("no schemas found")
	}
	return s.Schemas[s.Len()-1].ver
}

// LatestSchema returns the schema with the highest version.
func (m *Manager) LatestSchema() []byte {
	s := m.AllSchemas()
	if s.Len() == 0 {
		log.Fatalf("no schemas found")
	}
	latest := s.Schemas[s.Len()-1]
	bs, err := fs.ReadFile(m.Schemata, latest.path)
	if err != nil {
		log.Fatalf("reading schema %q: %v", latest.path, err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		log.Fatalf("creating gzip reader for schema %q: %v", latest.path, err)
	}
	bs, err = io.ReadAll(gz)
	if err != nil {
		log.Fatalf("reading schema %q: %v", latest.path, err)
	}
	return bs
}

// Schema returns the schema for a specific version.
func (m *Manager) Schema(version int) string {
	s := m.AllSchemas()
	for _, schema := range s.Schemas {
		if schema.ver == version {
			bs, err := fs.ReadFile(m.Schemata, schema.path)
			if err != nil {
				log.Fatalf("reading schema %q: %v", schema.path, err)
			}
			gz, err := gzip.NewReader(bytes.NewReader(bs))
			if err != nil {
				log.Fatalf("creating gzip reader for schema %q: %v", schema.path, err)
			}
			bs, err = io.ReadAll(gz)
			if err != nil {
				log.Fatalf("reading schema %q: %v", schema.path, err)
			}
			return string(bs)
		}
	}
	log.Fatalf("schema version %d not found", version)
	return ""
}

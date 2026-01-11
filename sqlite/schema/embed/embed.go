// Copyright (c) 2025 AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"

	"pkg.maisem.dev/sqlite"
)

func readVersion(schema, schemaName string) (int, error) {
	ctx := sqlite.NewContext()
	tmp, err := os.CreateTemp("", "schema-*.db")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	db, err := sqlite.New(tmp.Name(), log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := db.InitSchema(schema); err != nil {
		log.Fatal(err)
	}
	rx, err := db.ReadTx(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer rx.Rollback()
	return sqlite.QuerySingle[int](rx, "SELECT Version FROM schema_version WHERE Name=?", schemaName)
}

func writeSchema(schema []byte, version int) error {
	os.MkdirAll("schemas", 0755)
	path := fmt.Sprintf("schemas/v%d.sql.gz", version)
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(schema); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	prev, err := os.ReadFile(path)
	if err == nil && bytes.Equal(prev, buf.Bytes()) {
		log.Printf("no change to %s", path)
		return nil
	}
	if err := os.WriteFile(path, buf.Bytes(), 0666); err != nil {
		return err
	}
	log.Printf("wrote %s", path)
	return nil
}

func main() {
	schemaFile := flag.String("f", "", "schema file to read")
	schemaName := flag.String("schema", "main", "schema name for schema_version table")
	flag.Parse()

	schemaBytes, err := os.ReadFile(*schemaFile)
	if err != nil {
		log.Fatalf("reading schema file: %v", err)
	}
	version, err := readVersion(string(schemaBytes), *schemaName)
	if err != nil {
		log.Fatalf("reading version: %v", err)
	}
	if err := writeSchema(schemaBytes, version); err != nil {
		log.Fatalf("writing schema: %v", err)
	}
}

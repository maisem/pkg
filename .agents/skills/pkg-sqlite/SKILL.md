---
name: pkg-sqlite
description: SQLite workflow guidance for pkg.maisem.dev/sqlite including transaction tracking, typed queries, schema generation, and migration patterns. Use when implementing or debugging database access, schema evolution, or sqlite-backed tests in this repository.
---

# pkg/sqlite

## Overview
`pkg/sqlite` wraps SQLite with strict transaction tracking, typed query helpers, backup management, and schema tooling (`sqlgen`, `embed`, `schema.Manager`).

Core rule: always run DB operations inside `db.Read`/`db.Write` (or `ReadTx`/`WriteTx`) using a tracker context from `sqlite.NewContext()` or `sqlite.AttachTracker(ctx)`.

## Quick Reference
| Task | Pattern |
|---|---|
| Open DB | `db, err := sqlite.New(path, logf)` (`NewNoWorkers` for tests) |
| Context | `ctx := sqlite.NewContext()` |
| Read txn | `db.Read(ctx, func(tx *sqlite.Tx) error { ... })` |
| Write txn | `db.Write(ctx, "reason", func(tx *sqlite.Tx) error { ... })` |
| Scalar query | `sqlite.QuerySingle[T](tx, sql, args...)` |
| Multi-row query | `sqlite.QueryTypedRows[T](tx, sql, args...)` |
| JSON row decode | `sqlite.QueryJSONRow[T](tx, sql, args...)` |
| Upsert object | `sqlite.Put(tx, &obj)` (implements `ObjectWithMetadata`) |
| Init schema | `db.InitSchema(string(schemaBytes))` |
| Run migrations | `manager.Init(ctx, db, logf)` |

## Schema Workflow
1. Define types with `sql` tags (`stored`, `virtual`, `unique`, `index`, `omitempty`, `fk:Type.Field`, `,inline`).
2. Add directives:
```go
//go:generate go run pkg.maisem.dev/sqlite/schema/sqlgen -type User,UserProject -output example_schema.sql
//go:generate go run pkg.maisem.dev/sqlite/schema/embed -f example_schema.sql
```
3. Run `go generate ./...` from the package.
4. Commit generated `*_tables.go` and `schemas/vN.sql.gz` outputs.

## Common Mistakes
- Missing tracker context: calling DB methods with plain `context.Background()`.
- Nested/overlapping tx in same context: tracker will panic on active tx misuse.
- Performing writes in read tx: use `db.Write` when mutating.
- Hand-editing generated schema/table files instead of regenerating.
- Skipping backup before risky migration logic.

## Test Pattern
- Use `t.TempDir()` + `sqlite.NewNoWorkers(dbPath, t.Logf)`.
- Create fresh tracker context per test path (`sqlite.NewContext()`).
- Prefer table-driven tests for query helpers and migration steps.

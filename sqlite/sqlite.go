// Package sqlite provides a Go wrapper around SQLite with transaction management,
// automatic backups, and type-safe query helpers.
//
// # Features
//
//   - WAL Mode: Uses Write-Ahead Logging for better concurrent read performance
//   - Single-Writer/Multi-Reader: Serialized writes with concurrent reads via separate connection pools
//   - Automatic Backups: Periodic background backups with smart retention policies
//   - Transaction Tracking: Context-based tracking to prevent nested transactions
//   - Type-Safe Queries: Generic helpers for scanning rows into typed values
//   - JSON Object Storage: Store and retrieve Go structs as JSON blobs
//   - Schema Generation: Code generators for SQL schemas from Go structs
//
// # Creating a Database
//
// Use [New] to create a database with background workers (periodic backups),
// or [NewNoWorkers] for tests and situations where background work is not desired:
//
//	db, err := sqlite.New("/path/to/db.sqlite", log.Printf)
//	if err != nil {
//	    return err
//	}
//	defer db.Close()
//
// # Transactions
//
// All database operations require a context with a transaction tracker.
// Use [NewContext] to create one:
//
//	ctx := sqlite.NewContext()
//
//	// Read-only transaction
//	err := db.Read(ctx, func(tx *sqlite.Tx) error {
//	    count, err := sqlite.QuerySingle[int](tx, "SELECT COUNT(*) FROM users")
//	    return err
//	})
//
//	// Read/Write transaction
//	err := db.Write(ctx, "create-user", func(tx *sqlite.Tx) error {
//	    _, err := tx.Exec("INSERT INTO users (name) VALUES (?)", "alice")
//	    return err
//	})
//
// # Type-Safe Queries
//
// Generic helpers scan rows into typed values:
//
//	// Single value
//	count, err := sqlite.QuerySingle[int](tx, "SELECT COUNT(*) FROM users")
//
//	// Single row as JSON
//	user, err := sqlite.QueryJSONRow[User](tx, "SELECT JSONObj FROM users WHERE id = ?", id)
//
//	// Multiple rows
//	ids, err := sqlite.QueryTypedRows[int64](tx, "SELECT id FROM users")
//
// # JSON Object Storage
//
// Store Go structs implementing [ObjectWithMetadata] using [Put]:
//
//	type User struct {
//	    ID        int64     `json:"id"`
//	    Name      string    `json:"name"`
//	    UpdatedAt time.Time `json:"updated_at"`
//	}
//
//	func (u User) GetID() int64              { return u.ID }
//	func (u *User) SetUpdatedAt(t time.Time) { u.UpdatedAt = t }
//	func (u User) TableName() string         { return "users" }
//
//	err := sqlite.Put(tx, &user)
//
// # Schema Generation
//
// The schema subpackage provides tools for generating SQL schemas from Go structs
// and managing schema migrations. Use go:generate directives:
//
//	//go:generate go run pkg.maisem.dev/sqlite/schema/sqlgen -type User -output schema.sql
//	//go:generate go run pkg.maisem.dev/sqlite/schema/embed -f schema.sql
//
// The sqlgen tool generates:
//   - schema.sql: CREATE TABLE statements with JSONObj blob storage
//   - <pkg>_tables.go: TableName() methods for each type
//
// Tables use a JSONObj BLOB column to store the struct as JSON, with generated
// columns for indexed fields. Use struct tags to control column generation:
//
//	type User struct {
//	    ID        int64  `json:"id"`
//	    Email     string `json:"email" sql:"stored,unique"`
//	    TenantID  int64  `json:"tenant_id" sql:"stored,index,fk:Tenant.ID"`
//	    DeletedAt *time.Time `json:"deleted_at,omitempty" sql:"stored,omitempty"`
//	}
//
// Supported sql tag options:
//   - stored: Create a STORED generated column
//   - virtual: Create a VIRTUAL generated column
//   - unique: Add a unique index on the column
//   - index: Add a non-unique index on the column
//   - omitempty: Allow NULL values (for optional fields)
//   - fk:<Type>.<Field>: Add a foreign key constraint
//   - inline: Embed metadata fields (for Metadata[ID] pattern)
//
// For custom SQL statements (composite indexes, etc.), use //sqlgen: comments
// inside the struct definition:
//
//	type UserProject struct {
//	    UserID    UserID    `sql:"stored"`
//	    ProjectID ProjectID `sql:"stored"`
//	    //sqlgen: CREATE UNIQUE INDEX user_project_unique ON user_projects (UserID, ProjectID);
//	}
//
// The embed tool compresses schema.sql into schemas/v<N>.sql.gz for versioned
// migrations managed by [schema.Manager].
//
// # Backup Retention
//
// Automatic backups follow this retention policy:
//   - Keep all backups from the last hour
//   - Keep one backup per hour for the last 24 hours
//   - Keep one backup per day for the last 30 days
//   - Delete older backups (while respecting a minimum count)
//
// # Error Handling
//
// Use [IsConstraintError] to check for constraint violations (UNIQUE, etc.)
// and [IsTableNotFoundError] to check for missing tables.
package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"pkg.maisem.dev/deferr"
	"pkg.maisem.dev/safeid"
	"modernc.org/sqlite"
	sqliteh "modernc.org/sqlite/lib"
	"tailscale.com/metrics"
	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

// DB is a Read/Write wrapper around a sqlite database.
// It is safe to use DB from multiple goroutines.
type DB struct {
	db *sql.DB
	ro *sql.DB

	// timeNowUTC returns the current time in UTC.
	// It exists to make testing easier.
	timeNowUTC func() time.Time

	closed         atomic.Bool
	closedCh       chan struct{}
	dbChanged      atomic.Bool  // true if the db was changed since the last backup
	backupsSkipped atomic.Int64 // number of backups consecutively skipped

	dbPath   string
	bgCtx    context.Context
	cancelBg context.CancelFunc
	wg       sync.WaitGroup
	writeSem syncs.Semaphore
	logf     logger.Logf
}

var ErrNeedWriteTx = errors.New("need write tx")

type RxManager struct {
	db            *DB
	ctx           context.Context
	activeRx      *Tx
	closed        bool
	stopAfterFunc func() bool
}

func (h *RxManager) Close() {
	if h.closed {
		return
	}
	h.closed = true
	h.Rollback()
	h.stopAfterFunc()
}

func (h *RxManager) Rollback() {
	if h.activeRx != nil {
		h.activeRx.Rollback()
		h.activeRx = nil
	}
}

func (h *RxManager) Rx() (*Tx, error) {
	if h.closed {
		return nil, errors.New("rx manager closed")
	}
	if h.activeRx != nil {
		return h.activeRx, nil
	}
	rx, err := h.db.ReadTx(h.ctx)
	if err != nil {
		return nil, err
	}
	h.activeRx = rx
	return rx, nil
}

func (db *DB) RxManager(ctx context.Context) *RxManager {
	m := &RxManager{db: db, ctx: ctx}
	m.stopAfterFunc = context.AfterFunc(ctx, m.Rollback)
	return m
}

type connector struct {
	driver sqlite.Driver
	path   string
}

func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	return c.driver.Open(c.path)
}

func (c *connector) Driver() driver.Driver {
	return &c.driver
}

func constructConnString(path string) string {
	path = strings.TrimSuffix(path, "file:")
	path, query, _ := strings.Cut(path, "?")
	if query != "" {
		query += "&"
	}
	query += "_pragma=journal_mode(WAL)"
	return path + "?" + query
}

// NewNoWorkers creates a new DB instance without starting the background backup
// worker.
func NewNoWorkers(path string, logf logger.Logf) (*DB, error) {
	connString := constructConnString(path)
	wr := sql.OpenDB(&connector{path: connString + "&_txlock=immediate"})
	wr.SetMaxOpenConns(1)
	c, err := wr.Conn(context.Background())
	if err != nil {
		return nil, err
	}
	c.Close()

	ro := sql.OpenDB(&connector{path: connString + "&mode=ro"})
	ro.SetMaxOpenConns(runtime.GOMAXPROCS(0))

	ctx, cancel := context.WithCancel(context.Background())

	db := &DB{
		db:         wr,
		dbPath:     path,
		timeNowUTC: func() time.Time { return time.Now().UTC() },
		ro:         ro,
		closedCh:   make(chan struct{}),
		writeSem:   syncs.NewSemaphore(1),
		bgCtx:      ctx,
		cancelBg:   cancel,
		logf:       logf,
	}
	return db, nil
}

// New creates a new DB instance and starts all background workers.
func New(path string, logf logger.Logf) (*DB, error) {
	db, err := NewNoWorkers(path, logf)
	if err != nil {
		return nil, err
	}
	db.dbChanged.Store(true) // initial backup
	db.wg.Go(db.backupPeriodic)

	return db, nil
}

func (db *DB) backupPeriodic() {
	ctx := db.bgCtx
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_, err := db.Backup(ctx, "")
			if err != nil {
				db.logf("error backing up db: %v", err)
			}
			// Run backup scrubbing after each backup
			if err := db.ScrubBackups(ctx, 30); err != nil {
				db.logf("error scrubbing backups: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (db *DB) checkpointTruncateLocked(ctx context.Context) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

func (db *DB) backupDir() string {
	return filepath.Join(filepath.Dir(db.dbPath), "backups")
}

// Backup creates a new backup of the database. It returns the path to the
// backup file.
//
// If the database has not changed since the last backup, it skips the backup
// and returns an empty string.
func (db *DB) Backup(ctx context.Context, slug string) (string, error) {
	if !db.dbChanged.Load() {
		n := db.backupsSkipped.Add(1)
		if n == 1 || n%10 == 0 {
			db.logf("db not changed, skipping backup (attempt=%d)", n)
		}
		return "", nil
	}
	releaseOnce, err := db.acquireWriteLock(ctx)
	if err != nil {
		return "", err
	}
	defer releaseOnce()
	if err := db.checkpointTruncateLocked(ctx); err != nil {
		return "", err
	}
	bd := db.backupDir()
	if err := os.MkdirAll(bd, 0700); err != nil {
		return "", err
	}
	backupPath := filepath.Join(bd, fmt.Sprintf("%s-%s", filepath.Base(db.dbPath), db.timeNowUTC().Format(time.RFC3339)))
	if slug != "" {
		backupPath += "-" + slug
	}
	db.logf("backing up db to %s", backupPath)
	if err := copyFile(db.dbPath, backupPath); err != nil {
		return "", err
	}
	db.logf("backup complete")
	db.dbChanged.Store(false)
	db.backupsSkipped.Store(0)
	return backupPath, nil
}

func copyFile(src, dst string) error {
	srcf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcf.Close()
	tmp := dst + ".tmp"
	dstf, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer dstf.Close()
	if _, err := io.Copy(dstf, srcf); err != nil {
		dstf.Close()
		os.Remove(tmp)
		return err
	}
	if err := dstf.Sync(); err != nil {
		dstf.Close()
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (db *DB) Conn(ctx context.Context) (*sql.Conn, error) {
	return db.db.Conn(ctx)
}

// Close closes the DB.
func (db *DB) Close() error {
	if db.closed.Swap(true) {
		// already closed
		return nil
	}
	defer close(db.closedCh)
	db.cancelBg()
	db.wg.Wait()

	var eg errgroup.Group
	eg.Go(db.db.Close)
	eg.Go(db.ro.Close)
	return eg.Wait()
}

// ReadTx creates a new read-only transaction.
func (db *DB) ReadTx(ctx context.Context) (_ *Tx, err error) {
	return db.ReadTxWithWhy(ctx, callerName())
}

func (db *DB) ReadTxWithWhy(ctx context.Context, why string) (_ *Tx, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	tracker, ok := txTrackerKey.ValueOk(ctx)
	if !ok {
		panic("tx tracker not found in context")
	}
	var release deferr.ErrCloser
	defer release.CloseOnErr(&err)

	release.Add(tracker.Track(why))
	var now time.Time
	if fn, ok := UTCNowKey.ValueOk(ctx); ok {
		now = fn()
	} else {
		now = db.timeNowUTC()
	}
	release.Add(func() {
		metricRxDurationNanoseconds.Add(why, db.timeNowUTC().Sub(now).Nanoseconds())
	})
	stx, err := db.ro.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	return &Tx{ctx: ctx, stx: stx, db: db, release: &release, isRO: true, utcNow: now}, nil
}

func (db *DB) acquireWriteLock(ctx context.Context) (releaseOnce func(), err error) {
	if !db.writeSem.AcquireContext(ctx) {
		return nil, ctx.Err()
	}
	return sync.OnceFunc(db.writeSem.Release), nil
}

var (
	metricTxDurationNanoseconds = &metrics.LabelMap{
		Label: "why",
	}
	metricRxDurationNanoseconds = &metrics.LabelMap{
		Label: "why",
	}
)

func init() {
	expvar.Publish("counter_sqlite_tx_duration_ns", metricTxDurationNanoseconds)
	expvar.Publish("counter_sqlite_rx_duration_ns", metricRxDurationNanoseconds)
}

// callerName returns the function name of the callers caller.
func callerName() string {
	pc, _, _, ok := runtime.Caller(2)
	if !ok {
		return "unknown"
	}
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "unknown"
	}
	return fn.Name()
}

// Tx creates a new read/write transaction.
func (db *DB) Tx(ctx context.Context, why string) (_ *Tx, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	tracker, ok := txTrackerKey.ValueOk(ctx)
	if !ok {
		panic("tx tracker not found in context")
	}
	var release deferr.ErrCloser
	defer release.CloseOnErr(&err)

	release.Add(tracker.Track(why))
	releaseOnce, err := db.acquireWriteLock(ctx)
	if err != nil {
		return nil, err
	}
	release.Add(releaseOnce)
	stx, err := db.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	var now time.Time
	if fn, ok := UTCNowKey.ValueOk(ctx); ok {
		now = fn()
	} else {
		now = db.timeNowUTC()
	}
	release.Add(func() {
		metricTxDurationNanoseconds.Add(why, db.timeNowUTC().Sub(now).Nanoseconds())
	})
	return &Tx{ctx: ctx, stx: stx, db: db, release: &release, utcNow: now}, nil
}

var ErrSkipCommit = errors.New("skip commit")

func (db *DB) Read(ctx context.Context, fn func(*Tx) error) error {
	return db.ReadWithWhy(ctx, callerName(), fn)
}

func (db *DB) CondWrite(ctx context.Context, why string, fn func(*Tx) error) error {
	readErr := db.ReadWithWhy(ctx, why, fn)
	if readErr == nil {
		return nil
	}
	if !errors.Is(readErr, ErrNeedWriteTx) {
		return readErr
	}
	return db.Write(ctx, why, fn)
}

// ReadWithWhy executes a function in a read-only transaction with the specified reason.
// The reason is used for monitoring and debugging purposes.
func (db *DB) ReadWithWhy(ctx context.Context, why string, fn func(*Tx) error) error {
	rx, err := db.ReadTxWithWhy(ctx, why)
	if err != nil {
		return err
	}
	defer rx.Rollback()
	return fn(rx)
}

// Write executes a function in a new transaction and commits the transaction.
// If the function returns ErrSkipCommit, the transaction is rolled back without
// returning an error to the caller.
func (db *DB) Write(ctx context.Context, why string, fn func(*Tx) error) error {
	tx, err := db.Tx(ctx, why)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		if errors.Is(err, ErrSkipCommit) {
			return nil
		}
		return err
	}
	return tx.Commit()
}

// Result is a wrapper around sql.Result.
type Result struct {
	RowsAffected int64
	LastInsertID int64
}

// Tx is a wrapper around sql.Tx.
type Tx struct {
	isRO   bool
	ctx    context.Context
	stx    *sql.Tx
	db     *DB
	utcNow time.Time

	runCallbacksOnce    sync.Once
	onCommitCallbacks   []func()
	onRollbackCallbacks []func()

	release *deferr.ErrCloser
}

// UTCNow returns the time at which the Tx was created.
func (tx *Tx) UTCNow() time.Time {
	return tx.utcNow
}

func (tx *Tx) Writable() bool {
	return !tx.isRO
}

// OnCommit registers a callback to be called when the transaction is committed,
// but before the application-level write lock is released.
func (tx *Tx) OnCommit(fn func()) {
	tx.onCommitCallbacks = append(tx.onCommitCallbacks, fn)
}

// OnRollback registers a callback to be called when the transaction is rolled back.
// Exactly one of OnCommit and OnRollback will be called, but not both.
func (tx *Tx) OnRollback(fn func()) {
	tx.onRollbackCallbacks = append(tx.onRollbackCallbacks, fn)
}

// Commit commits the transaction.
func (tx *Tx) Commit() error {
	// We always want to rollback the tx in case Commit returns an error and
	// doesn't actually close the Tx.
	defer tx.Rollback()
	if err := tx.stx.Commit(); err != nil {
		return err
	}
	tx.db.dbChanged.Store(true)
	tx.runCallbacksOnce.Do(func() {
		for _, fn := range tx.onCommitCallbacks {
			fn()
		}
	})
	return nil
}

func (tx *Tx) close() {
	tx.release.Close()
}

// Rollback rolls back the transaction.
func (tx *Tx) Rollback() error {
	defer tx.close()
	tx.runCallbacksOnce.Do(func() {
		for _, fn := range tx.onRollbackCallbacks {
			fn()
		}
	})
	return tx.stx.Rollback()
}

// queryString is a type representing a query passed to the database.
// It exists to make it harder for the caller to pass unsafe queries to the database.
// This effectively means that preferred way of writing queries is to use constants.
//
// As an escape hatch, [UnsafeQueryString] can be used to create a [queryString] from a string.
type (
	queryString string
	tableName   string
)

// Query executes QueryContext on the transaction using the transaction's context.
func (tx *Tx) Query(query queryString, args ...any) (*sql.Rows, error) {
	return tx.stx.QueryContext(tx.ctx, string(query), args...)
}

// Exec executes ExecContext on the transaction using the transaction's context.
func (tx *Tx) Exec(query queryString, args ...any) (sql.Result, error) {
	return tx.stx.ExecContext(tx.ctx, string(query), args...)
}

// QueryRow executes QueryRowContext on the transaction using the transaction's context.
func (tx *Tx) QueryRow(query queryString, args ...any) *sql.Row {
	return tx.stx.QueryRowContext(tx.ctx, string(query), args...)
}

// Prepare prepares a statement for execution.
func (tx *Tx) Prepare(query queryString) (*Stmt, error) {
	stmt, err := tx.stx.PrepareContext(tx.ctx, string(query))
	if err != nil {
		return nil, err
	}
	return &Stmt{stmt: stmt, tx: tx}, nil
}

// Stmt is a wrapper around sql.Stmt.
type Stmt struct {
	stmt *sql.Stmt
	tx   *Tx
}

// QueryRow executes QueryRowContext on the statement using the statement's context.
func (s *Stmt) QueryRow(args ...any) *sql.Row {
	return s.stmt.QueryRowContext(s.tx.ctx, args...)
}

// Close closes the statement.
func (s *Stmt) Close() error {
	return s.stmt.Close()
}

// Exec executes ExecContext on the statement using the statement's context.
func (s *Stmt) Exec(args ...any) (sql.Result, error) {
	return s.stmt.ExecContext(s.tx.ctx, args...)
}

// Query executes QueryContext on the statement using the statement's context.
func (s *Stmt) Query(args ...any) (*sql.Rows, error) {
	return s.stmt.QueryContext(s.tx.ctx, args...)
}

// IsConstraintError reports whether err represents a SQLITE_CONSTRAINT error.
func IsConstraintError(err error) bool {
	return isErrCode(err, sqliteh.SQLITE_CONSTRAINT)
}

func isErrCode(err error, code int) bool {
	var e *sqlite.Error
	if errors.As(err, &e) {
		// SQLite returns extended error codes, but we want to match against the primary code.
		// The primary code is the lower 8 bits.
		primaryCode := e.Code() & 0xFF
		return primaryCode == code
	}
	return false
}

func IsTableNotFoundError(err error) bool {
	var e *sqlite.Error
	return errors.As(err, &e) && e.Code() == sqliteh.SQLITE_ERROR && strings.Contains(e.Error(), "no such table")
}

type Scanner interface {
	Scan(dest ...any) error
}

// ScanSingle scans a single value from a row.
func ScanSingle[T any](row Scanner) (T, error) {
	var v T
	err := row.Scan(&v)
	return v, err
}

// QueryTypedRow executes a query and returns the result as a single value of the given type.
// The query must return a single column.
func QueryTypedRow[T any](rx *Tx, query queryString, args ...any) (T, error) {
	row := rx.QueryRow(query, args...)
	return ScanSingle[T](row)
}

// QueryTypedRows executes a query and returns the results as a slice of the given type.
// The query must return a single column.
func QueryTypedRows[T any](rx *Tx, query queryString, args ...any) ([]T, error) {
	rows, err := rx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var v []T
	for rows.Next() {
		var t T
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		v = append(v, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return v, nil
}

func QueryJSONRows[T any](rx *Tx, query queryString, args ...any) ([]T, error) {
	rows, err := rx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var v []T
	for rows.Next() {
		var b sql.RawBytes
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		var t T
		if err := json.Unmarshal(b, &t); err != nil {
			return nil, err
		}
		v = append(v, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return v, nil
}

func QueryJSONRow[T any](rx *Tx, query queryString, args ...any) (T, error) {
	row := rx.QueryRow(query, args...)
	return ScanSingleJSON[T](row)
}

// UnsafeQueryString creates a [queryString] from a string. This is unsafe
// because it allows the caller to pass constructed queries to the database
// which may lead to SQL injection if not used carefully.
func UnsafeQueryString(s string) queryString {
	return queryString(s)
}

func QuerySingle[T any](rx *Tx, query queryString, args ...any) (T, error) {
	row := rx.QueryRow(query, args...)
	return ScanSingle[T](row)
}

// ScanSingleJSON scans a single JSON value from a row.
func ScanSingleJSON[T any](row Scanner) (T, error) {
	var zero T
	var v []byte
	err := row.Scan(&v)
	if err != nil {
		return zero, err
	}
	var t T
	if err := json.Unmarshal(v, &t); err != nil {
		return zero, err
	}
	return t, nil
}

func (db *DB) Path() string {
	return db.dbPath
}

type Key interface {
	~int64 | ~string
}

type ObjectWithMetadata[ID Key] interface {
	GetID() ID
	SetUpdatedAt(time.Time)
	TableName() string
}

var (
	tableRegex         = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*\.)?[a-zA-Z_][a-zA-Z0-9_]*$`)
	memoizedTableNames syncs.Map[tableName, bool]
	memoizedPutQueries syncs.Map[tableName, queryString]
)

func isValidTableName(table tableName) bool {
	v, _ := memoizedTableNames.LoadOrInit(table, func() bool {
		return tableRegex.MatchString(string(table))
	})
	return v
}

// Put inserts or replaces an object in the table with the given ID.
func Put[O ObjectWithMetadata[ID], ID Key](tx *Tx, obj O) error {
	// Validate table name (SQLite safe identifier, letters, numbers,
	// underscores, dots allowed for schemas, non-empty)
	tableName := tableName(obj.TableName())
	if !isValidTableName(tableName) {
		return fmt.Errorf("invalid table name: %q", obj.TableName())
	}
	var zero ID
	if obj.GetID() == zero {
		return fmt.Errorf("ID is required")
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = tx.Exec(tablePutQuery(tableName), b, obj.GetID(), b)
	return err
}

func tablePutQuery(table tableName) queryString {
	const rawQ = `INSERT INTO %s (JSONObj, ID) VALUES (?, ?) ON CONFLICT(ID) DO UPDATE SET JSONObj = ?`
	q, _ := memoizedPutQueries.LoadOrInit(table, func() queryString {
		return UnsafeQueryString(fmt.Sprintf(rawQ, table))
	})
	return q
}

func InsertWithAutoID[T any](tx *Tx, table tableName, obj T) (int64, error) {
	if !isValidTableName(table) {
		return 0, fmt.Errorf("invalid table name: %q", table)
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(UnsafeQueryString(fmt.Sprintf(`INSERT INTO %s (JSONObj) VALUES (?)`, table)), b)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

// ScrubBackups removes old backups according to retention policies:
// - Keep all backups from the last hour
// - Keep one backup per hour for the last 24 hours
// - Keep one backup per day for the last 30 days
// - Delete everything else
func (db *DB) ScrubBackups(ctx context.Context, keepAtLeast int) error {
	bd := db.backupDir()
	entries, err := os.ReadDir(bd)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// backup represents a database backup file with its metadata
	type backup struct {
		path    string    // Path to the backup file
		modTime time.Time // Modification time of the backup file
	}

	var backups []backup
	basePrefix := filepath.Base(db.dbPath) + "-"
	now := db.timeNowUTC()

	// Collect all backup files and their timestamps
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), basePrefix) {
			continue
		}
		_, modTimeStr, ok := strings.Cut(entry.Name(), "-")
		if !ok {
			db.logf("error parsing mod time for %s", entry.Name())
			continue
		}
		if modTimeStr[len(modTimeStr)-1] != 'Z' {
			if lastHyphen := strings.LastIndex(modTimeStr, "-"); lastHyphen != -1 {
				modTimeStr = modTimeStr[:lastHyphen]
			} else {
				db.logf("error parsing mod time for %s: no hyphen found", entry.Name())
				continue
			}
		}
		modTime, err := time.Parse(time.RFC3339, modTimeStr)
		if err != nil {
			db.logf("error parsing mod time for %s: %v", entry.Name(), err)
			continue
		}
		backups = append(backups, backup{
			path:    filepath.Join(bd, entry.Name()),
			modTime: modTime,
		})
	}

	// Sort backups by time, newest first
	slices.SortFunc(backups, func(a, b backup) int {
		return b.modTime.Compare(a.modTime)
	})

	if len(backups) == 0 {
		return nil
	}

	// Track which backups to keep
	toKeep := set.Set[string]{}

	// Keep all backups from last hour
	for _, b := range backups {
		age := now.Sub(b.modTime)
		if age <= time.Hour {
			toKeep.Add(b.path)
		}
	}

	// Keep one backup per hour for last 24 hours
	seenHours := set.Set[time.Time]{}
	for _, b := range backups {
		age := now.Sub(b.modTime)
		if age > time.Hour && age <= 24*time.Hour {
			hour := b.modTime.Truncate(time.Hour)
			if !seenHours.Contains(hour) {
				seenHours.Add(hour)
				toKeep.Add(b.path)
			}
		}
	}

	// Keep one backup per day for last 30 days
	seenDays := set.Set[time.Time]{}
	for _, b := range backups {
		age := now.Sub(b.modTime)
		if age > 24*time.Hour && age <= 30*24*time.Hour {
			day := b.modTime.Truncate(24 * time.Hour)
			if !seenDays.Contains(day) {
				seenDays.Add(day)
				toKeep.Add(b.path)
			}
		}
	}

	if need := keepAtLeast - len(toKeep); need > 0 {
		for _, b := range backups {
			if !toKeep.Contains(b.path) {
				toKeep.Add(b.path)
				need--
				if need <= 0 {
					break
				}
			}
		}
	}

	// Delete backups that aren't in the keep set
	for _, b := range backups {
		if !toKeep.Contains(b.path) {
			if err := os.Remove(b.path); err != nil {
				db.logf("error removing backup %s: %v", b.path, err)
			}
		}
	}

	return nil
}

// ExecAndReturnLastInsertID executes a query and returns the last insert ID.
func (tx *Tx) ExecAndReturnLastInsertID(query queryString, args ...any) (int64, error) {
	res, err := tx.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ExecAndReturnRowsAffected executes a query and returns the number of rows affected.
func (tx *Tx) ExecAndReturnRowsAffected(query queryString, args ...any) (int64, error) {
	res, err := tx.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CreateWithSafeID attempts to create an object with a unique ID by retrying
// with different IDs when constraint errors occur. It calls the create function
// with generated IDs until successful or max attempts reached.
func CreateWithSafeID[T any, ID ~int64](create func(id ID) (T, error)) (T, error) {
	var zero T
	for attempt := 0; attempt < 100; attempt++ {
		id := safeid.New[ID](attempt)
		t, err := create(id)
		if err != nil {
			if IsConstraintError(err) {
				continue
			}
			return zero, err
		}
		return t, nil
	}
	return zero, fmt.Errorf("failed to generate a safe ID after 100 attempts")
}

func Read[T any](ctx context.Context, db *DB, fn func(*Tx) (T, error)) (T, error) {
	var out T
	err := db.Read(ctx, func(tx *Tx) error {
		t, err := fn(tx)
		if err != nil {
			return err
		}
		out = t
		return nil
	})
	return out, err
}

// QueryToCSV executes a SQL query and returns the results formatted as CSV.
// The first row contains column names, and subsequent rows contain the data.
// NULL values are represented as "NULL", and strings containing commas, quotes,
// newlines, tabs or spaces are properly quoted.
func QueryToCSV(tx *Tx, query queryString, args ...any) (string, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var sb strings.Builder

	// Get column names
	cols, err := rows.Columns()
	if err != nil {
		return "", err
	}

	// Write header row
	for i, col := range cols {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(col)
	}
	sb.WriteString("\n")

	// Create a slice of any to hold column values
	values := make([]any, len(cols))
	valuePtrs := make([]any, len(cols))
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	// Read rows
	for rows.Next() {
		if err := rows.Scan(valuePtrs...); err != nil {
			return "", err
		}

		// Write row values
		for i, val := range values {
			if i > 0 {
				sb.WriteString(",")
			}
			// Handle NULL values and convert to string
			if val == nil {
				sb.WriteString("NULL")
			} else {
				switch v := val.(type) {
				case []byte:
					sb.WriteString(string(v))
				case string:
					// Escape quotes and commas in CSV
					if strings.ContainsAny(v, ",\"\n\t ") {
						sb.WriteString(strconv.Quote(v))
					} else {
						sb.WriteString(v)
					}
				default:
					fmt.Fprint(&sb, v)
				}
			}
		}
		sb.WriteString("\n")
	}

	if err := rows.Err(); err != nil {
		return "", err
	}

	return sb.String(), nil
}

// ReserveSafeIDTx generates a new SafeID of the specified type and stores it in the database using the provided transaction.
// It uses collision-resistant generation with retry logic.
func ReserveSafeIDTx[T ~int64](tx *Tx) (T, error) {
	return CreateWithSafeID(func(id safeid.ID) (T, error) {
		err := InsertSafeID(tx, T(id))
		return T(id), err
	})
}

// InsertSafeID stores a SafeID in the database with its type using the provided transaction.
func InsertSafeID[T ~int64](tx *Tx, id T) error {
	const insertSafeID = "INSERT INTO safe_ids (ID, Type) VALUES (?, ?)"
	idType := reflect.TypeFor[T]().Name()
	_, err := tx.Exec(insertSafeID, int64(id), idType)
	return err
}

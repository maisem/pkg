package sqlite

// InitSchema initializes the database schema by executing the provided SQL script.
// This is typically called during database initialization to create necessary tables.
func (db *DB) InitSchema(schema string) error {
	ctx := NewContext()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.ExecContext(ctx, schema)
	return err
}

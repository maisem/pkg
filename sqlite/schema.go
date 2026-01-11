// Copyright (c) 2025 AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

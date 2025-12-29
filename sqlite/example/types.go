package example

import (
	"time"

	"pkg.maisem.dev/safeid"
	"pkg.maisem.dev/sqlite"
)

//go:generate go run pkg.maisem.dev/sqlite/schema/sqlgen -type User,UserProject -output example_schema.sql
//go:generate go run pkg.maisem.dev/sqlite/schema/embed -f example_schema.sql

type Metadata[ID ~int64] struct {
	ID        ID
	CreatedAt time.Time `sql:",stored"`
	UpdatedAt time.Time `sql:",stored"`
}

func (m *Metadata[ID]) SetUpdatedAt(t time.Time) {
	m.UpdatedAt = t
}

func (m *Metadata[ID]) GetID() ID {
	return m.ID
}

type User struct {
	Metadata[UserID] `json:",inline" sql:",inline"`
	Email            string `json:"email" sql:"stored,unique"`
}

type UserProject struct {
	Metadata[UserProjectID] `json:",inline" sql:",inline"`
	UserID                  UserID    `sql:",stored"`
	ProjectID               ProjectID `sql:",stored"`

	// Create custom indexes using the sqlgen comment.
	//sqlgen: CREATE UNIQUE INDEX user_project_unique ON user_projects (UserID, ProjectID);
}

var _ sqlite.ObjectWithMetadata[UserID] = (*User)(nil)

type UserID safeid.ID
type UserProjectID safeid.ID
type ProjectID safeid.ID

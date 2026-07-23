package samples

import (
	"database/sql"
	"fmt"
)

func FindReport(db *sql.DB, owner string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM reports WHERE owner = '%s'", owner)
	return db.Query(query)
}


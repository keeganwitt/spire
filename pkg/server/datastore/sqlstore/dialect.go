package sqlstore

import (
	"context"

	"github.com/jinzhu/gorm"
)

type dialect interface {
	connect(ctx context.Context, cfg *configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error)
	isConstraintViolation(err error) bool
	// isDeadlock reports whether err is a transient transaction-deadlock that is
	// safe to retry (the transaction was rolled back). MySQL/Postgres can deadlock
	// on a concurrent first-acquire of a row that does not yet exist.
	isDeadlock(err error) bool
}

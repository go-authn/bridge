// SPDX-License-Identifier: BSD-3-Clause

package main

// The database drivers the app_passwords block can use, imported by the
// program and not by a library, as in go-authn/authnd: a driver is a choice a
// deployment makes.
import (
	_ "github.com/go-sql-driver/mysql" // mysql
	_ "github.com/jackc/pgx/v5/stdlib" // postgres
	_ "modernc.org/sqlite"             // sqlite, in pure Go: no cgo
)

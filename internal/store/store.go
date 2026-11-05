// Package store persists daily totals in SQLite.
package store

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/dansimau/filetop-reporter/internal/agg"
)

type Store struct{ db *sql.DB }

const schema = `CREATE TABLE IF NOT EXISTS daily (
	date TEXT NOT NULL,
	path TEXT NOT NULL,
	comm TEXT NOT NULL,
	container TEXT NOT NULL,
	reads INTEGER NOT NULL,
	writes INTEGER NOT NULL,
	rbytes INTEGER NOT NULL,
	wbytes INTEGER NOT NULL,
	dbytes INTEGER NOT NULL DEFAULT 0,
	mbytes INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (date, path, comm, container)
) WITHOUT ROWID`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrate creates the table and brings databases written by older versions
// up to the current schema.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	// Columns added after the first release.
	for _, col := range []string{"dbytes", "mbytes"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('daily') WHERE name = ?`, col).Scan(&n); err == nil && n == 0 {
			if _, err := db.Exec(`ALTER TABLE daily ADD COLUMN ` + col + ` INTEGER NOT NULL DEFAULT 0`); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
		}
	}
	// The table used to be a rowid table, which stores every key twice (the
	// row plus the automatic primary-key index) and leaves a day's rows in
	// first-seen order, so each flush rewrote most of the day's pages. A
	// WITHOUT ROWID table is half the size and clusters rows by path. Rebuild
	// old databases once; VACUUM then returns the freed pages and compacts
	// the file, a one-time write of its size.
	var ddl string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'daily'`).Scan(&ddl); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if strings.Contains(strings.ToUpper(ddl), "WITHOUT ROWID") {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		strings.Replace(schema, "IF NOT EXISTS daily", "daily_new", 1),
		`INSERT INTO daily_new SELECT date, path, comm, container, reads, writes, rbytes, wbytes, dbytes, mbytes FROM daily`,
		`DROP TABLE daily`,
		`ALTER TABLE daily_new RENAME TO daily`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if _, err := db.Exec(`VACUUM`); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

// SaveDay upserts the rows changed since the last successful save. Totals
// are absolute for the day, so repeated saves overwrite rather than
// accumulate.
func (s *Store) SaveDay(d *agg.Day) error {
	rows := d.Dirty()
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO daily (date, path, comm, container, reads, writes, rbytes, wbytes, dbytes, mbytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(date, path, comm, container) DO UPDATE SET
		reads=excluded.reads, writes=excluded.writes, rbytes=excluded.rbytes, wbytes=excluded.wbytes, dbytes=excluded.dbytes, mbytes=excluded.mbytes`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(d.Date, r.Path, r.Comm, r.Container, int64(r.Reads), int64(r.Writes), int64(r.RBytes), int64(r.WBytes), int64(r.DBytes), int64(r.MBytes)); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	d.Flushed()
	return nil
}

// LoadDay returns the stored totals for a date (empty Day if none).
func (s *Store) LoadDay(date string) (*agg.Day, error) {
	d := agg.NewDay(date)
	rows, err := s.db.Query(`SELECT path, comm, container, reads, writes, rbytes, wbytes, dbytes, mbytes FROM daily WHERE date = ?`, date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k agg.RowKey
		var reads, writes, rbytes, wbytes, dbytes, mbytes int64
		if err := rows.Scan(&k.Path, &k.Comm, &k.Container, &reads, &writes, &rbytes, &wbytes, &dbytes, &mbytes); err != nil {
			return nil, err
		}
		d.Add(k, agg.Row{Reads: uint64(reads), Writes: uint64(writes), RBytes: uint64(rbytes), WBytes: uint64(wbytes), DBytes: uint64(dbytes), MBytes: uint64(mbytes)})
	}
	d.Flushed() // what we just read is already on disk
	return d, rows.Err()
}

// Dates lists the dates with data, newest first.
func (s *Store) Dates() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT date FROM daily ORDER BY date DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

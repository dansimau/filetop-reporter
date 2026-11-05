package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dansimau/filetop-reporter/internal/agg"
)

// oldSchema is the table as written by the first release: a rowid table
// without the dbytes/mbytes columns.
const oldSchema = `CREATE TABLE daily (
	date TEXT NOT NULL,
	path TEXT NOT NULL,
	comm TEXT NOT NULL,
	container TEXT NOT NULL,
	reads INTEGER NOT NULL,
	writes INTEGER NOT NULL,
	rbytes INTEGER NOT NULL,
	wbytes INTEGER NOT NULL,
	PRIMARY KEY (date, path, comm, container)
)`

func tableDDL(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var ddl string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'daily'`).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	return ddl
}

func TestOpenMigratesRowidTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filetop.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(oldSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO daily VALUES ('2026-11-04', '/a', 'p', 'c', 1, 2, 3, 4), ('2026-11-05', '/b', 'q', '', 5, 6, 7, 8)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if ddl := tableDDL(t, path); !strings.Contains(ddl, "WITHOUT ROWID") {
		t.Fatalf("table not rebuilt: %s", ddl)
	}
	d, err := st.LoadDay("2026-11-05")
	if err != nil {
		t.Fatal(err)
	}
	r := d.Rows[agg.RowKey{Path: "/b", Comm: "q"}]
	if r == nil || r.Reads != 5 || r.Writes != 6 || r.RBytes != 7 || r.WBytes != 8 || r.DBytes != 0 || r.MBytes != 0 {
		t.Fatalf("row after migration: %+v", r)
	}
	if dates, _ := st.Dates(); len(dates) != 2 {
		t.Fatalf("dates after migration: %v", dates)
	}

	// Upserts work on the rebuilt table and a reopen leaves it alone.
	d.Add(agg.RowKey{Path: "/b", Comm: "q"}, agg.Row{Writes: 1, DBytes: 4096})
	d.Add(agg.RowKey{Path: "/c", Comm: "q"}, agg.Row{Reads: 1})
	if err := st.SaveDay(d); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	d, err = st.LoadDay("2026-11-05")
	if err != nil {
		t.Fatal(err)
	}
	if r := d.Rows[agg.RowKey{Path: "/b", Comm: "q"}]; r == nil || r.Writes != 7 || r.DBytes != 4096 {
		t.Fatalf("row after save: %+v", r)
	}
	if len(d.Rows) != 2 {
		t.Fatalf("rows after save: %d", len(d.Rows))
	}
}

func TestOpenNewDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filetop.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if ddl := tableDDL(t, path); !strings.Contains(ddl, "WITHOUT ROWID") {
		t.Fatalf("new table: %s", ddl)
	}
}

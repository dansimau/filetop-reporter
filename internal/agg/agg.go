// Package agg turns periodic snapshots of the kernel counters into per-day
// totals keyed by (path, comm, container).
package agg

import (
	"fmt"
	"time"

	"github.com/dansimau/filetop-reporter/internal/collector"
	"github.com/dansimau/filetop-reporter/internal/container"
)

// Row is one line of a day's totals.
type Row struct {
	Path      string
	Comm      string
	Container string
	Reads     uint64
	Writes    uint64
	RBytes    uint64
	WBytes    uint64
	DBytes    uint64 // bytes dirtied in the page cache: what reaches the disk
	MBytes    uint64 // filesystem metadata bytes dirtied by fsyncs of this file
}

// Disk is everything that will be written back: data plus metadata.
func (r Row) Disk() uint64 { return r.DBytes + r.MBytes }

func (r Row) Ops() uint64 { return r.Reads + r.Writes }

// Day holds totals for one calendar date (local time).
type Day struct {
	Date string // YYYY-MM-DD
	Rows map[RowKey]*Row

	dirty map[RowKey]bool // rows changed since the last Flushed()
}

type RowKey struct{ Path, Comm, Container string }

func NewDay(date string) *Day {
	return &Day{Date: date, Rows: map[RowKey]*Row{}, dirty: map[RowKey]bool{}}
}

// Dirty returns the rows changed since the last call to Flushed.
func (d *Day) Dirty() []*Row {
	out := make([]*Row, 0, len(d.dirty))
	for k := range d.dirty {
		out = append(out, d.Rows[k])
	}
	return out
}

// Flushed marks every row as persisted.
func (d *Day) Flushed() { d.dirty = map[RowKey]bool{} }

// MarkAllDirty forces the next flush to write every row.
func (d *Day) MarkAllDirty() {
	for k := range d.Rows {
		d.dirty[k] = true
	}
}

// Add folds delta's counters into the row for k.
func (d *Day) Add(k RowKey, delta Row) {
	d.dirty[k] = true
	r := d.Rows[k]
	if r == nil {
		r = &Row{Path: k.Path, Comm: k.Comm, Container: k.Container}
		d.Rows[k] = r
	}
	r.Reads += delta.Reads
	r.Writes += delta.Writes
	r.RBytes += delta.RBytes
	r.WBytes += delta.WBytes
	r.DBytes += delta.DBytes
	r.MBytes += delta.MBytes
}

// SnapshotStats describes what one Snapshot did.
type SnapshotStats struct {
	Keys       int
	Active     int
	Evicted    int
	Unresolved int
	Forgotten  int
}

// Tracker remembers the previous snapshot so it can compute deltas, and
// evicts idle entries from the kernel map.
type Tracker struct {
	Day *Day

	// IdleSnapshots is how many consecutive snapshots without activity
	// before an entry is evicted from the kernel.
	IdleSnapshots int
	// UnresolvedSnapshots is how long to wait for a path before giving up.
	UnresolvedSnapshots int

	n          int
	prev       map[collector.Key]collector.Val
	lastActive map[collector.Key]int
	firstSeen  map[collector.Key]int
	loc        *time.Location
	now        func() time.Time
}

func NewTracker(loc *time.Location) *Tracker {
	t := &Tracker{
		IdleSnapshots:       2,
		UnresolvedSnapshots: 5,
		prev:                map[collector.Key]collector.Val{},
		lastActive:          map[collector.Key]int{},
		firstSeen:           map[collector.Key]int{},
		loc:                 loc,
		now:                 time.Now,
	}
	t.Day = NewDay(t.today())
	return t
}

func (t *Tracker) today() string { return t.now().In(t.loc).Format("2006-01-02") }

// Rollover returns the finished day and starts a new one if the local date
// has changed since the current Day began.
func (t *Tracker) Rollover() *Day {
	today := t.today()
	if today == t.Day.Date {
		return nil
	}
	done := t.Day
	t.Day = NewDay(today)
	return done
}

// Snapshot reads the kernel counters once and folds the deltas into Day.
func (t *Tracker) Snapshot(c *collector.Collector, res *container.Resolver) (SnapshotStats, error) {
	t.n++
	var st SnapshotStats
	seen := map[collector.Key]bool{}
	var evict []collector.Key

	err := c.Iterate(func(k collector.Key, v collector.Val) {
		st.Keys++
		seen[k] = true
		if _, ok := t.firstSeen[k]; !ok {
			t.firstSeen[k] = t.n
		}
		p, ok := c.Path(k.File())
		path := p.Path
		if !ok {
			age := t.n - t.firstSeen[k]
			if age < t.UnresolvedSnapshots {
				if age >= 1 {
					c.ReprobePath(k.Dentry)
				}
				return // leave the counters alone until the path arrives
			}
			st.Unresolved++
			path = fmt.Sprintf("[unresolved dentry %#x]", k.Dentry)
		}

		prev := t.prev[k]
		var d collector.Val
		if v.Reads < prev.Reads || v.Writes < prev.Writes ||
			v.RBytes < prev.RBytes || v.WBytes < prev.WBytes || v.DBytes < prev.DBytes || v.MBytes < prev.MBytes {
			d = v // entry was recreated since last time
		} else {
			d = collector.Val{Reads: v.Reads - prev.Reads, Writes: v.Writes - prev.Writes,
				RBytes: v.RBytes - prev.RBytes, WBytes: v.WBytes - prev.WBytes, DBytes: v.DBytes - prev.DBytes, MBytes: v.MBytes - prev.MBytes}
		}
		t.prev[k] = v
		if d.Reads|d.Writes|d.RBytes|d.WBytes|d.DBytes|d.MBytes != 0 {
			t.lastActive[k] = t.n
			st.Active++
			rk := RowKey{Path: res.RewritePath(path), Comm: k.CommString(), Container: res.ContainerOf(k.Tgid)}
			t.Day.Add(rk, Row{Reads: d.Reads, Writes: d.Writes, RBytes: d.RBytes, WBytes: d.WBytes, DBytes: d.DBytes, MBytes: d.MBytes})
		} else if t.n-t.lastActive[k] >= t.IdleSnapshots {
			evict = append(evict, k)
		}
	})
	if err != nil {
		return st, err
	}

	for k := range t.prev {
		if !seen[k] {
			delete(t.prev, k)
			delete(t.lastActive, k)
			delete(t.firstSeen, k)
		}
	}
	for _, k := range evict {
		if err := c.Delete(k); err != nil {
			return st, fmt.Errorf("evict: %w", err)
		}
		delete(t.prev, k)
		delete(t.lastActive, k)
		delete(t.firstSeen, k)
		st.Evicted++
	}
	// Forget paths for files no longer referenced by any live key, so a
	// recycled dentry gets its path re-sent.
	live := map[collector.File]bool{}
	for k := range t.prev {
		live[k.File()] = true
	}
	for _, k := range evict {
		if !live[k.File()] {
			c.Forget(k.File())
			st.Forgotten++
		}
	}
	return st, nil
}

// Package report renders a day's totals as Markdown.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dansimau/filetop-reporter/internal/agg"
)

type Options struct {
	Top    int
	By     string // dirtied | wbytes | rbytes | ops; only used by WriteTable
	Prefix string // only rows whose path starts with this
	Footer []string
}

func sortKey(by string) func(*agg.Row) uint64 {
	switch by {
	case "dirtied", "disk":
		return func(r *agg.Row) uint64 { return r.Disk() }
	case "rbytes":
		return func(r *agg.Row) uint64 { return r.RBytes }
	case "ops":
		return func(r *agg.Row) uint64 { return r.Ops() }
	default:
		return func(r *agg.Row) uint64 { return r.WBytes }
	}
}

func filtered(d *agg.Day, prefix string) []*agg.Row {
	rows := make([]*agg.Row, 0, len(d.Rows))
	for _, r := range d.Rows {
		if prefix == "" || strings.HasPrefix(r.Path, prefix) {
			rows = append(rows, r)
		}
	}
	return rows
}

func topN(rows []*agg.Row, by string, n int) []*agg.Row {
	key := sortKey(by)
	sort.Slice(rows, func(i, j int) bool {
		a, b := key(rows[i]), key(rows[j])
		if a != b {
			return a > b
		}
		return rows[i].Path < rows[j].Path
	})
	if n > 0 && len(rows) > n {
		rows = rows[:n]
	}
	return rows
}

// Write renders the full daily report.
func Write(w io.Writer, d *agg.Day, o Options) error {
	if o.Top <= 0 {
		o.Top = 50
	}
	rows := filtered(d, o.Prefix)
	var tot agg.Row
	for _, r := range rows {
		tot.Reads += r.Reads
		tot.Writes += r.Writes
		tot.RBytes += r.RBytes
		tot.WBytes += r.WBytes
		tot.DBytes += r.DBytes
		tot.MBytes += r.MBytes
	}
	fmt.Fprintf(w, "# File I/O report for %s\n\n", d.Date)
	if o.Prefix != "" {
		fmt.Fprintf(w, "Filtered to paths under `%s`.\n\n", o.Prefix)
	}
	fmt.Fprintf(w, "**Written** is bytes passed to write calls. **Dirtied** is file data that became dirty in the page cache and will be written back; small fsync'd writes dirty whole 4 KiB pages, so it can be much larger. **Meta** is filesystem metadata (btrfs tree blocks) dirtied by fsyncs of that file. Dirtied + Meta is what iotop and `/proc/<pid>/io` report as disk writes.\n\n")
	fmt.Fprintf(w, "| Files seen | Writes | Written | Dirtied | Meta | Reads | Read |\n|---:|---:|---:|---:|---:|---:|---:|\n")
	fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s |\n\n", num(uint64(len(rows))), num(tot.Writes), bytes(tot.WBytes), bytes(tot.DBytes), bytes(tot.MBytes), num(tot.Reads), bytes(tot.RBytes))

	section(w, "Top files by disk writes (dirtied + meta)", topN(append([]*agg.Row(nil), rows...), "dirtied", o.Top))
	section(w, "Top files by bytes written", topN(append([]*agg.Row(nil), rows...), "wbytes", o.Top))
	section(w, "Top files by bytes read", topN(append([]*agg.Row(nil), rows...), "rbytes", o.Top))
	section(w, "Top files by operations", topN(append([]*agg.Row(nil), rows...), "ops", o.Top))

	grouped(w, "By directory (depth 3)", rows, func(r *agg.Row) string { return dir(r.Path, 3) }, o.Top, "dirtied")
	grouped(w, "By directory (depth 5)", rows, func(r *agg.Row) string { return dir(r.Path, 5) }, o.Top, "dirtied")
	grouped(w, "By container", rows, func(r *agg.Row) string {
		if r.Container == "" {
			return "(host)"
		}
		return r.Container
	}, 0, "dirtied")
	grouped(w, "By process", rows, func(r *agg.Row) string { return r.Comm }, 30, "dirtied")

	if len(o.Footer) > 0 {
		fmt.Fprintf(w, "## Collection notes\n\n")
		for _, l := range o.Footer {
			fmt.Fprintf(w, "- %s\n", l)
		}
		fmt.Fprintln(w)
	}
	return nil
}

// WriteTable renders just one top-N table (for the CLI). Group may be
// "process", "container", "dir" (depth 3) or empty for per-file rows.
func WriteTable(w io.Writer, d *agg.Day, o Options, group string) {
	if o.Top <= 0 {
		o.Top = 50
	}
	rows := filtered(d, o.Prefix)
	title := fmt.Sprintf("%s: top %d by %s", d.Date, o.Top, o.By)
	switch group {
	case "process":
		grouped(w, title+" per process", rows, func(r *agg.Row) string { return r.Comm }, o.Top, o.By)
	case "container":
		grouped(w, title+" per container", rows, func(r *agg.Row) string {
			if r.Container == "" {
				return "(host)"
			}
			return r.Container
		}, o.Top, o.By)
	case "dir":
		grouped(w, title+" per directory", rows, func(r *agg.Row) string { return dir(r.Path, 3) }, o.Top, o.By)
	default:
		section(w, title, topN(rows, o.By, o.Top))
	}
}

func section(w io.Writer, title string, rows []*agg.Row) {
	fmt.Fprintf(w, "## %s\n\n", title)
	if len(rows) == 0 {
		fmt.Fprintf(w, "_nothing_\n\n")
		return
	}
	fmt.Fprintf(w, "| # | Path | Container | Process | Writes | Written | Dirtied | Meta | Reads | Read |\n|---:|---|---|---|---:|---:|---:|---:|---:|---:|\n")
	for i, r := range rows {
		fmt.Fprintf(w, "| %d | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |\n", i+1, esc(r.Path), r.Container, r.Comm,
			num(r.Writes), bytes(r.WBytes), bytes(r.DBytes), bytes(r.MBytes), num(r.Reads), bytes(r.RBytes))
	}
	fmt.Fprintln(w)
}

func grouped(w io.Writer, title string, rows []*agg.Row, keyOf func(*agg.Row) string, n int, by string) {
	g := map[string]*agg.Row{}
	for _, r := range rows {
		k := keyOf(r)
		a := g[k]
		if a == nil {
			a = &agg.Row{Path: k}
			g[k] = a
		}
		a.Reads += r.Reads
		a.Writes += r.Writes
		a.RBytes += r.RBytes
		a.WBytes += r.WBytes
		a.DBytes += r.DBytes
		a.MBytes += r.MBytes
	}
	list := make([]*agg.Row, 0, len(g))
	for _, r := range g {
		list = append(list, r)
	}
	list = topN(list, by, n)
	fmt.Fprintf(w, "## %s\n\n", title)
	if len(list) == 0 {
		fmt.Fprintf(w, "_nothing_\n\n")
		return
	}
	fmt.Fprintf(w, "| # | Group | Writes | Written | Dirtied | Meta | Reads | Read |\n|---:|---|---:|---:|---:|---:|---:|---:|\n")
	for i, r := range list {
		fmt.Fprintf(w, "| %d | `%s` | %s | %s | %s | %s | %s | %s |\n", i+1, esc(r.Path), num(r.Writes), bytes(r.WBytes), bytes(r.DBytes), bytes(r.MBytes), num(r.Reads), bytes(r.RBytes))
	}
	fmt.Fprintln(w)
}

// dir truncates a path to its first n components, keeping a leading
// "[container]" marker as a component.
func dir(p string, n int) string {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) <= n {
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			return p[:i] + "/"
		}
		return p
	}
	prefix := ""
	if strings.HasPrefix(p, "/") {
		prefix = "/"
	}
	return prefix + strings.Join(parts[:n], "/") + "/"
}

func esc(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func num(n uint64) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func bytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

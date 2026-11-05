// filetop-reporter: per-file I/O counters for a Synology NAS via eBPF.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/dansimau/filetop-reporter/internal/agg"
	"github.com/dansimau/filetop-reporter/internal/collector"
	"github.com/dansimau/filetop-reporter/internal/container"
	"github.com/dansimau/filetop-reporter/internal/report"
	"github.com/dansimau/filetop-reporter/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: levelFromEnv()}))
	var err error
	switch os.Args[1] {
	case "run":
		err = run(log, os.Args[2:])
	case "report":
		err = reportCmd(os.Args[2:])
	case "selftest":
		err = selftestCmd(log, os.Args[2:])
	case "top":
		err = topCmd(log, os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: filetop-reporter run|report|top|selftest [flags]")
	os.Exit(2)
}

func levelFromEnv() slog.Level {
	if strings.EqualFold(os.Getenv("LOG_LEVEL"), "debug") {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

type common struct {
	data, reports, sock, layerdb, sentinelHost string
}

func commonFlags(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.data, "data", envOr("DATA_DIR", "/data"), "directory for the SQLite database and sentinel file")
	fs.StringVar(&c.reports, "reports", envOr("REPORTS_DIR", "/reports"), "directory for daily Markdown reports")
	fs.StringVar(&c.sock, "docker-sock", envOr("DOCKER_SOCK", "/var/run/docker.sock"), "Docker socket for container names (empty to disable)")
	fs.StringVar(&c.layerdb, "layerdb", envOr("DOCKER_LAYERDB", "/host/layerdb"), "Docker btrfs layerdb mounts dir, for container rootfs paths (empty to disable)")
	fs.StringVar(&c.sentinelHost, "sentinel-host-path", envOr("SENTINEL_HOST_PATH", "/volume1/docker/filetop-reporter/data/.sentinel"), "host path of <data>/.sentinel, used to verify path resolution")
	return c
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	c := commonFlags(fs)
	interval := fs.Duration("interval", 60*time.Second, "how often to snapshot the kernel counters")
	flush := fs.Duration("flush", 5*time.Minute, "how often to persist today's totals")
	top := fs.Int("top", 50, "rows per report table")
	skipSelftest := fs.Bool("skip-selftest", false, "do not verify path resolution at startup")
	if err := fs.Parse(args); err != nil {
		return err
	}
	loc := time.Local
	if _, err := os.Stat(c.layerdb); err != nil {
		log.Warn("layerdb not available; container rootfs paths will show subvolume ids", "dir", c.layerdb)
		c.layerdb = ""
	}

	st, err := store.Open(filepath.Join(c.data, "filetop.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	collector.CleanStaleTracefs(log)
	res := container.New(c.sock, c.layerdb)
	col, err := collector.New(log, func(tgid uint32) { res.Resolve(tgid) })
	if err != nil {
		return err
	}
	defer col.Close()
	log.Info("probes attached")

	if !*skipSelftest {
		if err := selftest(col, res, c); err != nil {
			return fmt.Errorf("selftest: %w (struct offsets may be wrong for this kernel; use -skip-selftest to run anyway)", err)
		}
		log.Info("selftest passed", "path", c.sentinelHost)
	}

	tr := agg.NewTracker(loc)
	if d, err := st.LoadDay(tr.Day.Date); err == nil && len(d.Rows) > 0 {
		tr.Day = d
		log.Info("resumed today's totals", "rows", len(d.Rows))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	lastFlush := time.Now()
	save := func(d *agg.Day) {
		if err := st.SaveDay(d); err != nil {
			log.Error("save", "date", d.Date, "err", err)
		}
	}
	writeReport := func(d *agg.Day) {
		if err := os.MkdirAll(c.reports, 0o755); err != nil {
			log.Error("reports dir", "err", err)
			return
		}
		p := filepath.Join(c.reports, d.Date+".md")
		f, err := os.Create(p)
		if err != nil {
			log.Error("report", "err", err)
			return
		}
		defer f.Close()
		if err := report.Write(f, d, report.Options{Top: *top, Footer: footer(col)}); err != nil {
			log.Error("report", "err", err)
			return
		}
		log.Info("wrote report", "path", p, "rows", len(d.Rows))
	}

	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down; saving")
			if _, err := tr.Snapshot(col, res); err != nil {
				log.Error("final snapshot", "err", err)
			}
			save(tr.Day)
			return nil
		case <-tick.C:
		}
		col.ExpirePending(10 * time.Second)
		s, err := tr.Snapshot(col, res)
		if err != nil {
			log.Error("snapshot", "err", err)
			continue
		}
		log.Debug("snapshot", "keys", s.Keys, "active", s.Active, "evicted", s.Evicted, "unresolved", s.Unresolved, "rows", len(tr.Day.Rows))
		if done := tr.Rollover(); done != nil {
			save(done)
			writeReport(done)
			lastFlush = time.Now()
		} else if time.Since(lastFlush) >= *flush {
			save(tr.Day)
			lastFlush = time.Now()
			cs := col.Stats()
			_, misses, _ := collector.KprobeMisses()
			log.Info("flushed", "rows", len(tr.Day.Rows), "changed", s.Active, "keys", s.Keys, "events", cs.Events, "lost", cs.LostSamples, "partial", cs.Partial, "kretprobe_misses", misses)
		}
	}
}

func footer(col *collector.Collector) []string {
	cs := col.Stats()
	hits, misses, _ := collector.KprobeMisses()
	return []string{
		"Counts are VFS-level file operations (read/write/readv/writev/splice/iter), including page-cache hits; they are not disk IOPS.",
		"Dirtied bytes come from account_page_dirtied, the same accounting iotop uses, attributed to the file through its inode. Metadata pages dirtied during an fsync are charged to the fsynced file as Meta; metadata dirtied outside any fsync is charged to the process under " + collector.MetadataPath + ".",
		fmt.Sprintf("Since daemon start the page-dirty hook saw %s; %s could not be attributed, %s were dropped.", humanBytes(col.TotalDirtied()), humanBytes(col.UnattributedDirtied()), humanBytes(col.DroppedDirtied())),
		"Not covered: mmap'd reads, native AIO (io_submit), and disk reads (page-cache misses) as a separate number.",
		fmt.Sprintf("Since daemon start: %d path events, %d lost samples, %d paths resolved (%d partial, %d truncated), %d stale.", cs.Events, cs.LostSamples, cs.Resolved, cs.Partial, cs.Truncated, cs.PendingStale),
		fmt.Sprintf("kprobe hits %d, kretprobe misses %d (a miss leaves the requested byte count in place of the actual one).", hits, misses),
	}
}

// selftest writes and reads a sentinel file and checks the resolved path for
// it matches the expected host path, proving the struct offsets are right.
func selftest(col *collector.Collector, res *container.Resolver, c *common) error {
	p := filepath.Join(c.data, ".sentinel")
	if err := os.WriteFile(p, []byte("filetop-reporter sentinel\n"), 0o644); err != nil {
		return err
	}
	if _, err := os.ReadFile(p); err != nil {
		return err
	}
	me := uint32(os.Getpid())
	deadline := time.Now().Add(5 * time.Second)
	var seen []string
	for time.Now().Before(deadline) {
		seen = seen[:0]
		found := false
		err := col.Iterate(func(k collector.Key, v collector.Val) {
			if k.Tgid != me {
				return
			}
			rp, ok := col.Path(k.File())
			if !ok {
				return
			}
			got := res.RewritePath(rp.Path)
			seen = append(seen, got)
			if got == c.sentinelHost && v.Writes >= 1 && v.Reads >= 1 {
				found = true
			}
		})
		if err != nil {
			return err
		}
		if found {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("sentinel %s not resolved; saw %v", c.sentinelHost, seen)
}

func selftestCmd(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	c := commonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	res := container.New(c.sock, c.layerdb)
	col, err := collector.New(log, func(tgid uint32) { res.Resolve(tgid) })
	if err != nil {
		return err
	}
	defer col.Close()
	if err := selftest(col, res, c); err != nil {
		return err
	}
	fmt.Println("selftest OK:", c.sentinelHost)
	return nil
}

// topCmd is a live iotop-style view: attach, count for a while, print.
func topCmd(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	c := commonFlags(fs)
	dur := fs.Duration("duration", 10*time.Second, "how long to count")
	top := fs.Int("top", 30, "rows to print")
	by := fs.String("by", "dirtied", "sort by dirtied (disk writes: dirtied+meta)|wbytes|rbytes|ops")
	prefix := fs.String("prefix", "", "only paths starting with this")
	group := fs.String("group", "", "aggregate rows per process|container|dir instead of per file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(c.layerdb); err != nil {
		c.layerdb = ""
	}
	res := container.New(c.sock, c.layerdb)
	col, err := collector.New(log, func(tgid uint32) { res.Resolve(tgid) })
	if err != nil {
		return err
	}
	defer col.Close()
	tr := agg.NewTracker(time.Local)
	tr.UnresolvedSnapshots = 0
	tr.Day.Date = fmt.Sprintf("%s over %s", time.Now().Format("15:04:05"), *dur)
	hits0 := collector.KprobeHits("account_page_dirtied")
	seen0 := col.TotalDirtied()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(*dur):
	}
	time.Sleep(200 * time.Millisecond) // let the last path events land
	hits1 := collector.KprobeHits("account_page_dirtied")
	seen1 := col.TotalDirtied()
	if _, err := tr.Snapshot(col, res); err != nil {
		return err
	}
	report.WriteTable(os.Stdout, tr.Day, report.Options{Top: *top, By: *by, Prefix: *prefix}, *group)
	var sum uint64
	for _, r := range tr.Day.Rows {
		sum += r.Disk()
	}
	fmt.Printf("dirtied bytes: hook saw %s, rows hold %s, dropped %s, not attributable %s\n",
		humanBytes(seen1-seen0), humanBytes(sum), humanBytes(col.DroppedDirtied()), humanBytes(col.UnattributedDirtied()))
	var calls uint64
	for i := range hits0 {
		if i < len(hits1) && hits1[i]-hits0[i] > calls {
			calls = hits1[i] - hits0[i]
		}
	}
	if calls > 0 {
		fmt.Printf("kernel entered account_page_dirtied %d times in the window = %s (this is what /proc write_bytes counts)\n",
			calls, humanBytes(calls*4096))
	}
	return nil
}

func humanBytes(n uint64) string {
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

func reportCmd(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	c := commonFlags(fs)
	date := fs.String("date", "", "YYYY-MM-DD (default: today)")
	top := fs.Int("top", 50, "rows per table")
	by := fs.String("by", "", "print one table sorted by dirtied|wbytes|rbytes|ops instead of the full report")
	prefix := fs.String("prefix", "", "only paths starting with this")
	group := fs.String("group", "", "with -by: aggregate per process|container|dir instead of per file")
	list := fs.Bool("list", false, "list dates with data")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(c.data, "filetop.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	if *list {
		dates, err := st.Dates()
		if err != nil {
			return err
		}
		for _, d := range dates {
			fmt.Println(d)
		}
		return nil
	}
	if *date == "" {
		*date = time.Now().Format("2006-01-02")
	}
	d, err := st.LoadDay(*date)
	if err != nil {
		return err
	}
	if len(d.Rows) == 0 {
		return errors.New("no data for " + *date + " (note: today's totals are only flushed every -flush interval, 5 minutes by default)")
	}
	o := report.Options{Top: *top, By: *by, Prefix: *prefix}
	if *by != "" {
		report.WriteTable(os.Stdout, d, o, *group)
		return nil
	}
	return report.Write(os.Stdout, d, o)
}

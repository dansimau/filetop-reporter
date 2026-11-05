// Package collector loads the eBPF programs, attaches them to the VFS entry
// points, and turns the stream of path-component events into file paths.
package collector

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	bpfobj "github.com/dansimau/filetop-reporter/internal/bpf"
)

// Key mirrors struct file_key in bpf/filetop.c.
type Key struct {
	Dentry uint64
	Inode  uint64
	Tgid   uint32
	Pad    uint32
	Comm   [16]byte
}

// File identifies a file as the kernel side sees it.
type File struct{ Dentry, Inode uint64 }

func (k Key) File() File { return File{k.Dentry, k.Inode} }

// Val mirrors struct file_val in bpf/filetop.c.
type Val struct {
	Reads  uint64
	Writes uint64
	RBytes uint64
	WBytes uint64
	DBytes uint64 // page-cache bytes dirtied (what reaches the disk)
	MBytes uint64 // filesystem metadata bytes dirtied while fsyncing this file
}

// MetadataPath is the pseudo-path for metadata dirtied outside any fsync
// (transaction commits, delayed refs), keyed only by process.
const MetadataPath = "[filesystem metadata]"

// CommString returns the process name without trailing NULs.
func (k Key) CommString() string { return cstr(k.Comm[:]) }

// Path is a resolved file path for a dentry.
type Path struct {
	Path      string
	Inode     uint64
	Truncated bool // walk hit PATH_DEPTH before the root, or a name was cut
	Partial   bool // some components were lost; the path is incomplete
}

const (
	eventSize     = 184
	keyEventSize  = 32
	pathDepth     = 16
	nameLong      = 128
	flagRoot      = 1
	flagTruncated = 2
)

type pending struct {
	inode   uint64
	comps   [pathDepth + 1]string
	have    [pathDepth + 1]bool
	started time.Time
}

// Stats are cumulative counters about the collector itself.
type Stats struct {
	Events       uint64
	LostSamples  uint64
	Resolved     uint64
	Partial      uint64
	Truncated    uint64
	PendingStale uint64
}

type Collector struct {
	// OnNewKey is called (from the event reader goroutine) with the tgid of
	// each process that starts touching a file, while it is still alive.
	OnNewKey func(tgid uint32)

	objs  bpfobj.FiletopObjects
	links []link.Link
	rd    *perf.Reader
	done  chan struct{}

	mu      sync.Mutex
	paths   map[File]Path
	pending map[File]*pending

	events, lost, resolved, partial, truncated, stale atomic.Uint64
}

var hooks = []struct {
	symbol string
	entry  func(*bpfobj.FiletopPrograms) *ebpf.Program
	ret    func(*bpfobj.FiletopPrograms) *ebpf.Program
}{
	{"vfs_read", func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KprobeVfsRead }, func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KretprobeVfsRead }},
	{"vfs_write", func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KprobeVfsWrite }, func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KretprobeVfsWrite }},
	{"vfs_readv", func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KprobeVfsReadv }, func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KretprobeVfsReadv }},
	{"vfs_writev", func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KprobeVfsWritev }, func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KretprobeVfsWritev }},
	{"vfs_iter_read", func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KprobeVfsIterRead }, func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KretprobeVfsIterRead }},
	{"vfs_iter_write", func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KprobeVfsIterWrite }, func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KretprobeVfsIterWrite }},
	{"generic_file_splice_read", func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KprobeSpliceRead }, func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KretprobeSpliceRead }},
	{"account_page_dirtied", func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KprobePageDirtied }, nil},
	{"vfs_fsync_range", func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KprobeFsync }, func(p *bpfobj.FiletopPrograms) *ebpf.Program { return p.KretprobeFsync }},
}

// New loads and attaches the programs and starts consuming path events.
func New(log *slog.Logger, onNewKey func(tgid uint32)) (*Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}
	c := &Collector{
		OnNewKey: onNewKey,
		done:     make(chan struct{}),
		paths:    make(map[File]Path),
		pending:  make(map[File]*pending),
	}
	if err := bpfobj.LoadFiletopObjects(&c.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load bpf: %+v", ve)
		}
		return nil, fmt.Errorf("load bpf: %w", err)
	}
	skip := map[string]bool{}
	for _, sym := range strings.Split(os.Getenv("FILETOP_SKIP_HOOKS"), ",") {
		if sym != "" {
			skip[sym] = true
		}
	}
	for _, h := range hooks {
		if skip[h.symbol] {
			log.Warn("skipping hook by request", "symbol", h.symbol)
			continue
		}
		l, err := link.Kprobe(h.symbol, h.entry(&c.objs.FiletopPrograms), nil)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("kprobe %s: %w", h.symbol, err)
		}
		c.links = append(c.links, l)
		if h.ret == nil {
			continue
		}
		l, err = link.Kretprobe(h.symbol, h.ret(&c.objs.FiletopPrograms), nil)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("kretprobe %s: %w", h.symbol, err)
		}
		c.links = append(c.links, l)
		log.Debug("attached", "symbol", h.symbol)
	}
	rd, err := perf.NewReader(c.objs.Events, 4<<20)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("perf reader: %w", err)
	}
	c.rd = rd
	go c.readLoop()
	return c, nil
}

func (c *Collector) Close() {
	if c.rd != nil {
		c.rd.Close()
		<-c.done
	}
	for _, l := range c.links {
		l.Close()
	}
	c.objs.Close()
}

func (c *Collector) readLoop() {
	defer close(c.done)
	for {
		rec, err := c.rd.Read()
		if err != nil {
			return
		}
		if rec.LostSamples > 0 {
			c.lost.Add(rec.LostSamples)
		}
		switch {
		case len(rec.RawSample) >= eventSize:
			c.events.Add(1)
			c.handle(rec.RawSample)
		case len(rec.RawSample) >= keyEventSize:
			if c.OnNewKey != nil {
				c.OnNewKey(le32(rec.RawSample[8:]))
			}
		}
	}
}

func (c *Collector) handle(b []byte) {
	dentry := le64(b[0:])
	inode := le64(b[8:])
	depth := le32(b[24:])
	nlen := le32(b[28:])
	flags := le32(b[32:])
	name := b[56 : 56+nameLong]

	comp := ""
	cut := false
	if nlen > nameLong {
		nlen = nameLong
		cut = true
	}
	if flags&flagTruncated == 0 {
		comp = string(name[:nlen])
	}
	if depth > pathDepth {
		return
	}

	f := File{dentry, inode}
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending[f]
	if p == nil {
		p = &pending{inode: inode, started: time.Now()}
		c.pending[f] = p
	}
	p.comps[depth] = comp
	p.have[depth] = true
	if flags&(flagRoot|flagTruncated) == 0 {
		return
	}

	// Terminal component: assemble. Components run file -> root.
	res := Path{Inode: inode, Truncated: cut || flags&flagTruncated != 0}
	var sb strings.Builder
	if flags&flagTruncated != 0 {
		sb.WriteString("[...]")
	}
	last := int(depth)
	if flags&flagRoot != 0 {
		last = int(depth) - 1 // the root dentry's own name ("/") is not a component
	}
	for i := last; i >= 0; i-- {
		sb.WriteByte('/')
		if !p.have[i] {
			sb.WriteString("[?]")
			res.Partial = true
			continue
		}
		sb.WriteString(p.comps[i])
	}
	if last < 0 {
		sb.WriteByte('/')
	}
	res.Path = sb.String()
	c.paths[f] = res
	delete(c.pending, f)
	c.resolved.Add(1)
	if res.Partial {
		c.partial.Add(1)
	}
	if res.Truncated {
		c.truncated.Add(1)
	}
}

// Path returns the resolved path for a file, if known yet.
func (c *Collector) Path(f File) (Path, bool) {
	if f.Dentry == 0 {
		return Path{Path: MetadataPath}, true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.paths[f]
	return p, ok
}

// Forget drops the userspace path cache and the kernel markers for a file,
// so the next access re-sends its path.
func (c *Collector) Forget(f File) {
	c.mu.Lock()
	delete(c.paths, f)
	delete(c.pending, f)
	c.mu.Unlock()
	_ = c.objs.Known.Delete(f.Dentry)
	_ = c.objs.InodeDentry.Delete(f.Inode)
}

// UnattributedDirtied returns bytes dirtied that could not be charged to any
// process (the counters map refused a metadata pseudo-key).
func (c *Collector) UnattributedDirtied() uint64 { return c.stat(0) }

// TotalDirtied is every byte the page-dirty hook saw, attributed or not.
func (c *Collector) TotalDirtied() uint64 { return c.stat(1) }

// DroppedDirtied is bytes lost because the counters map refused a new key.
func (c *Collector) DroppedDirtied() uint64 { return c.stat(2) }

func (c *Collector) stat(i uint32) uint64 {
	var v uint64
	_ = c.objs.Stats.Lookup(i, &v)
	return v
}

// ReprobePath clears the kernel's marker for a dentry so its next access
// re-sends the path, without touching anything already resolved.
func (c *Collector) ReprobePath(dentry uint64) {
	_ = c.objs.Known.Delete(dentry)
}

// ExpirePending drops half-assembled paths older than maxAge (lost events).
func (c *Collector) ExpirePending(maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for f, p := range c.pending {
		if p.started.Before(cutoff) {
			delete(c.pending, f)
			_ = c.objs.Known.Delete(f.Dentry)
			c.stale.Add(1)
		}
	}
}

// Iterate calls fn for every entry in the kernel counters map.
func (c *Collector) Iterate(fn func(Key, Val)) error {
	var k Key
	var v Val
	it := c.objs.Counters.Iterate()
	for it.Next(&k, &v) {
		fn(k, v)
	}
	return it.Err()
}

// Delete removes a counter entry from the kernel map.
func (c *Collector) Delete(k Key) error {
	err := c.objs.Counters.Delete(k)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (c *Collector) Stats() Stats {
	return Stats{
		Events:       c.events.Load(),
		LostSamples:  c.lost.Load(),
		Resolved:     c.resolved.Load(),
		Partial:      c.partial.Load(),
		Truncated:    c.truncated.Load(),
		PendingStale: c.stale.Load(),
	}
}

// CleanStaleTracefs removes kprobe events left in tracefs by earlier
// processes that were killed before detaching. Events still in use by a live
// process are refused by the kernel (EBUSY) and left alone.
func CleanStaleTracefs(log *slog.Logger) {
	var path string
	var b []byte
	var err error
	for _, p := range []string{"/sys/kernel/tracing/kprobe_events", "/sys/kernel/debug/tracing/kprobe_events"} {
		if b, err = os.ReadFile(p); err == nil {
			path = p
			break
		}
	}
	if err != nil {
		return
	}
	removed := 0
	for _, line := range strings.Split(string(b), "\n") {
		// e.g. "p:ebpf_1a2b3c/vfs_read vfs_read"
		f := strings.Fields(line)
		if len(f) < 2 || !strings.Contains(f[0], ":ebpf_") {
			continue
		}
		name := f[0][strings.IndexByte(f[0], ':')+1:]
		fh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return
		}
		if _, err := fh.WriteString("-:" + name + "\n"); err == nil {
			removed++
		}
		fh.Close()
	}
	if removed > 0 {
		log.Info("removed stale kprobe events from tracefs", "count", removed)
	}
}

// KprobeHits returns the kernel's own hit count for every registered probe
// on symbol, in file order. A hit is counted whether or not a BPF program
// ran for it, so comparing deltas with what the program saw shows whether
// any invocations were skipped. Stale (disabled) events stay at their old
// count, so callers should look at the largest delta.
func KprobeHits(symbol string) []uint64 {
	var b []byte
	var err error
	for _, p := range []string{"/sys/kernel/tracing/kprobe_profile", "/sys/kernel/debug/tracing/kprobe_profile"} {
		if b, err = os.ReadFile(p); err == nil {
			break
		}
	}
	if err != nil {
		return nil
	}
	var hits []uint64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != symbol {
			continue
		}
		h, _ := strconv.ParseUint(f[1], 10, 64)
		hits = append(hits, h)
	}
	return hits
}

// KprobeMisses sums the "misses" column of tracefs kprobe_profile, which
// counts kretprobe returns that were dropped because maxactive was exceeded.
func KprobeMisses() (hits, misses uint64, err error) {
	var b []byte
	for _, p := range []string{"/sys/kernel/tracing/kprobe_profile", "/sys/kernel/debug/tracing/kprobe_profile"} {
		if b, err = os.ReadFile(p); err == nil {
			break
		}
	}
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		h, _ := strconv.ParseUint(f[1], 10, 64)
		m, _ := strconv.ParseUint(f[2], 10, 64)
		hits += h
		misses += m
	}
	return hits, misses, nil
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func le64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

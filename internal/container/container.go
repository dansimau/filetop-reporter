// Package container maps pids and btrfs subvolume paths to Docker container
// names, using the host's /proc (the daemon runs with pid: host), the Docker
// socket, and Docker's btrfs layerdb.
package container

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Resolver is safe for concurrent use.
type Resolver struct {
	sock     string
	layerdb  string
	procRoot string
	ttl      time.Duration
	missTTL  time.Duration

	mu        sync.Mutex
	refreshed time.Time
	names     map[string]string // container id -> name
	mountIDs  map[string]string // btrfs subvolume (mount-id) -> container name
	pidCache  map[uint32]pidEntry
	client    *http.Client
}

type pidEntry struct {
	name string
	at   time.Time
}

var cgroupRe = regexp.MustCompile(`docker[/-]([0-9a-f]{12,64})`)

// New returns a resolver. sock may be empty to disable name lookups, and
// layerdb may be empty to disable subvolume rewriting.
func New(sock, layerdb string) *Resolver {
	r := &Resolver{
		sock:     sock,
		layerdb:  layerdb,
		procRoot: "/proc",
		ttl:      60 * time.Second,
		missTTL:  2 * time.Second,
		names:    map[string]string{},
		mountIDs: map[string]string{},
		pidCache: map[uint32]pidEntry{},
	}
	if sock != "" {
		r.client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", sock)
				},
			},
		}
	}
	return r
}

// ContainerOf returns the container name for a pid, or "" for host
// processes. Cached answers are kept even after the process exits, because
// counters are read after short-lived processes are gone; Resolve refreshes
// the cache while a process is alive.
func (r *Resolver) ContainerOf(tgid uint32) string {
	r.mu.Lock()
	e, ok := r.pidCache[tgid]
	r.mu.Unlock()
	if ok {
		return e.name
	}
	name, _ := r.Resolve(tgid)
	return name
}

// Resolve reads /proc/<tgid>/cgroup now. ok is false if the process is gone,
// in which case any cached name is left in place and returned.
func (r *Resolver) Resolve(tgid uint32) (name string, ok bool) {
	b, err := os.ReadFile(filepath.Join(r.procRoot, itoa(tgid), "cgroup"))
	if err != nil {
		r.mu.Lock()
		e, had := r.pidCache[tgid]
		r.mu.Unlock()
		return e.name, had
	}
	if m := cgroupRe.FindSubmatch(b); m != nil {
		name = r.nameFor(string(m[1]))
	}
	r.mu.Lock()
	r.pidCache[tgid] = pidEntry{name: name, at: time.Now()}
	r.mu.Unlock()
	return name, true
}

// nameFor maps a container id (any prefix length) to its name, refreshing
// from Docker on a miss.
func (r *Resolver) nameFor(id string) string {
	for attempt := 0; attempt < 2; attempt++ {
		r.mu.Lock()
		for full, name := range r.names {
			if strings.HasPrefix(full, id) {
				r.mu.Unlock()
				return name
			}
		}
		// On a miss, refresh unless we just did (new containers appear
		// at any time, and a pid must be resolved while it is alive).
		stale := time.Since(r.refreshed) > r.missTTL
		r.mu.Unlock()
		if !stale {
			break
		}
		r.refresh()
	}
	if len(id) > 12 {
		id = id[:12]
	}
	return id
}

// RewritePath maps a dentry-walked path (relative to its filesystem root) to
// something a human recognises: the btrfs subvolume prefix becomes the
// volume mount point, and container rootfs subvolumes become [name].
func (r *Resolver) RewritePath(p string) string {
	const subvolPrefix = "/@syno/@docker/btrfs/subvolumes/"
	if strings.HasPrefix(p, subvolPrefix) {
		rest := p[len(subvolPrefix):]
		id, tail, _ := strings.Cut(rest, "/")
		r.mu.Lock()
		if time.Since(r.refreshed) > r.ttl {
			r.mu.Unlock()
			r.refresh()
			r.mu.Lock()
		}
		name, ok := r.mountIDs[id]
		if !ok && time.Since(r.refreshed) > r.missTTL {
			r.mu.Unlock()
			r.refresh()
			r.mu.Lock()
			name, ok = r.mountIDs[id]
		}
		r.mu.Unlock()
		if ok {
			return "[" + name + "]/" + tail
		}
		return "[layer " + short(id) + "]/" + tail
	}
	if strings.HasPrefix(p, "/@syno/") {
		return "/volume1/" + p[len("/@syno/"):]
	}
	return p
}

// Refresh reloads container names and subvolume ids from Docker.
func (r *Resolver) refresh() {
	names := map[string]string{}
	if r.client != nil {
		resp, err := r.client.Get("http://docker/containers/json?all=1")
		if err == nil {
			var list []struct {
				ID    string   `json:"Id"`
				Names []string `json:"Names"`
			}
			if json.NewDecoder(resp.Body).Decode(&list) == nil {
				for _, c := range list {
					if len(c.Names) > 0 {
						names[c.ID] = strings.TrimPrefix(c.Names[0], "/")
					}
				}
			}
			resp.Body.Close()
		}
	}
	mountIDs := map[string]string{}
	if r.layerdb != "" {
		entries, _ := os.ReadDir(r.layerdb)
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(r.layerdb, e.Name(), "mount-id"))
			if err != nil {
				continue
			}
			name, ok := names[e.Name()]
			if !ok {
				name = short(e.Name())
			}
			mountIDs[strings.TrimSpace(string(b))] = name
		}
	}
	r.mu.Lock()
	if len(names) > 0 || r.client == nil {
		r.names = names
	}
	r.mountIDs = mountIDs
	r.refreshed = time.Now()
	r.mu.Unlock()
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func itoa(n uint32) string {
	var buf [10]byte
	i := len(buf)
	for {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	return string(buf[i:])
}

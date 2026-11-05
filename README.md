# filetop-reporter

Daily per-file I/O report for a Synology NAS (DSM 7.2, kernel 4.4.302+),
collected with eBPF kprobes. Answers "which files, processes and containers
generated today's reads and writes?" with op counts and byte totals.

## How it works

- kprobe/kretprobe pairs on `vfs_read`, `vfs_write`, `vfs_readv`, `vfs_writev`,
  `vfs_iter_read`, `vfs_iter_write` (LIO/VM disks, splice writes) and
  `generic_file_splice_read` (sendfile) keep counters in a kernel hash map
  keyed by `(dentry, tgid, comm)`. Only regular files are counted.
- The first time a dentry is seen, the program walks `d_parent` (up to 16
  levels) and sends the path components to userspace over a perf ring.
- Every minute the daemon snapshots the map, adds the deltas to today's
  totals keyed by `(path, process, container)`, and evicts idle entries.
- Totals are flushed to SQLite every 5 minutes (`-flush`), on shutdown, and
  at local midnight, when a Markdown report for the finished day is written
  to `/reports/YYYY-MM-DD.md`.

Columns:

- **Writes / Written, Reads / Read**: VFS-level operations and bytes passed
  to read/write calls, including page-cache hits. Not disk IOPS.
- **Dirtied**: file data pages that became dirty (`account_page_dirtied`),
  attributed to the writing process. This is what iotop and
  `/proc/<pid>/io` call disk writes. A 16-byte write followed by fsync
  dirties a whole 4 KiB page, so this is often much larger than Written.
- **Meta**: filesystem metadata pages (btrfs tree blocks) dirtied while the
  process was inside fsync of that file. Small fsync-heavy workloads
  (SQLite journals, atomic config rewrites) can cost ~1 MiB of metadata per
  fsync on btrfs. Metadata dirtied outside any fsync (transaction commits by
  `btrfs-transaction`, kworkers) is charged to the process under the
  `[filesystem metadata]` pseudo-path.

Dirtied + Meta per process matches `/proc/<pid>/io` write_bytes. Not
covered: mmap'd reads, native AIO, and disk reads (page-cache misses).

## Kernel notes

DSM's 4.4 kernel has no BTF, no CO-RE, no bounded loops and no
`bpf_probe_read_str` for kprobe programs, so `bpf/filetop.c` hard-codes the
few struct offsets it needs (`bpf/offsets.h`) and unrolls the path walk. The
daemon verifies those offsets at startup by writing and reading a sentinel
file and checking the resolved path matches `SENTINEL_HOST_PATH`.

## Deploy

See `deploy/compose.yaml`. The container must be privileged with `pid: host`
and `/sys/kernel/debug` mounted. Create the data dir with `chattr +C` first.

```
docker exec filetop-reporter /filetop-reporter report --date 2026-11-04
docker exec filetop-reporter /filetop-reporter report --by dirtied --top 20 --prefix /volume1/docker
docker exec filetop-reporter /filetop-reporter report --by dirtied --group container
docker exec filetop-reporter /filetop-reporter report --list
# live, iotop-style, for 10 seconds:
docker exec filetop-reporter /filetop-reporter top --duration 10s --group process
```

Today's totals are flushed to SQLite every 5 minutes, so `report` for today
lags by up to that much. Each flush rewrites the SQLite pages holding every
row that changed, which on a busy day is most of today's rows, so the flush
interval is the main knob for SSD wear: pass `-flush 1h` (or longer) in the
compose `command` to trade a staler `report` for today, and up to that much
lost data on a crash, for far fewer writes. The in-memory totals are
unaffected, and `top` is always live.

## Build

`make docker` needs Docker; `make nas-build` rsyncs the tree to the NAS and
builds there, which is handy on a Mac without Docker. It needs the NAS's ssh
host in `local.mk` (gitignored); see `local.mk.example`. `make nas-selftest`
then runs the offset self-test on the NAS.

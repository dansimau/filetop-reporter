/* filetop: per-file read/write op and byte counters, attributed to the
 * calling process, for Linux 4.4 (Synology DSM 7.2).
 *
 * Constraints of that kernel, which shape this file:
 *   - no BTF / CO-RE: struct offsets are hard-coded in offsets.h
 *   - no bounded loops: the path walk is unrolled to PATH_DEPTH levels
 *   - no bpf_probe_read_str: names are copied with fixed-size reads
 *   - helper arguments pointing at memory must be on the BPF stack
 *   - no global data / .rodata: no string literals, no static tables
 */
#include "common.h"
#include "offsets.h"

#define PATH_DEPTH 16
#define NAME_SHORT 32  /* DNAME_INLINE_LEN: names this long live inside the dentry */
#define NAME_LONG 128

#define FLAG_ROOT 1      /* this component is the filesystem root */
#define FLAG_TRUNCATED 2 /* walk ran out of levels before reaching the root */

/* The inode is part of the key so that a dentry recycled for another file
 * starts a fresh entry instead of clobbering (or deleting) the old one before
 * userspace has read it. */
struct file_key {
	u64 dentry;
	u64 inode;
	u32 tgid;
	u32 _pad;
	char comm[16];
};

struct file_val {
	u64 reads;
	u64 writes;
	u64 rbytes;
	u64 wbytes;
	u64 dbytes; /* page-cache bytes dirtied: what will reach the disk */
	u64 mbytes; /* filesystem metadata bytes dirtied while fsyncing this file */
};

struct fsync_val {
	struct file_key key;
};

struct inflight_val {
	struct file_key key;
	u64 requested;
	u64 is_write;
};

/* Sent once per new counters key, so userspace can map the pid to a
 * container while the process still exists. Distinguished from path_event
 * by its size. */
struct key_event {
	u64 dentry;
	u32 tgid;
	u32 pid;
	char comm[16];
};

struct path_event {
	u64 dentry;
	u64 inode;
	u32 tgid;
	u32 pid;
	u32 depth; /* 0 = the file itself, 1 = its directory, ... */
	u32 len;   /* real length of the component name */
	u32 flags;
	u32 _pad;
	char comm[16];
	char name[NAME_LONG];
};

/* (dentry, tgid, comm) -> counters */
struct bpf_map_def SEC("maps") counters = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct file_key),
	.value_size = sizeof(struct file_val),
	.max_entries = 131072,
};

/* pid_tgid -> what the entry probe saw, for the return probe */
struct bpf_map_def SEC("maps") inflight = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(struct inflight_val),
	.max_entries = 8192,
};

/* dentry -> inode: dentries whose path has already been sent to userspace */
struct bpf_map_def SEC("maps") known = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),
	.max_entries = 131072,
};

/* inode -> dentry, so page dirtying (which only knows the inode) can be
 * attributed to a file we have seen through the VFS. */
struct bpf_map_def SEC("maps") inode_dentry = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),
	.max_entries = 131072,
};

/* pid_tgid -> file being fsynced, so metadata dirtied by the fsync (btrfs
 * log tree blocks) can be charged to that file. */
struct bpf_map_def SEC("maps") inflight_fsync = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(struct fsync_val),
	.max_entries = 8192,
};

/* [0] dirtied bytes that could not be attributed at all
 * [1] all dirtied bytes seen by the hook (for cross-checking the rows)
 * [2] dirtied bytes dropped because the counters map rejected the key */
#define STAT_UNATTRIBUTED_DIRTY 0
#define STAT_TOTAL_DIRTY 1
#define STAT_DROPPED_DIRTY 2
struct bpf_map_def SEC("maps") stats = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 4,
};

#define PAGE_SIZE 4096

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 0,
};

struct qstr_hdr {
	u32 hash;
	u32 len;
	const char *name;
};

/* Emit one path component. Returns the parent dentry, or 0 at the root. */
static __always_inline void *emit_component(struct pt_regs *ctx, struct path_event *ev, void *cur, u32 depth)
{
	struct qstr_hdr q = {};
	void *parent = 0;

	bpf_probe_read(&q, sizeof(q), cur + OFF_DENTRY_QSTR);
	bpf_probe_read(&parent, sizeof(parent), cur + OFF_DENTRY_PARENT);

	ev->depth = depth;
	ev->len = q.len;
	ev->flags = (parent == cur || parent == 0) ? FLAG_ROOT : 0;
	if (q.len < NAME_SHORT)
		bpf_probe_read(ev->name, NAME_SHORT, q.name);
	else
		bpf_probe_read(ev->name, NAME_LONG, q.name);
	bpf_perf_event_output(ctx, &events, bpf_get_smp_processor_id(), ev, sizeof(*ev));

	if (ev->flags & FLAG_ROOT)
		return 0;
	return parent;
}

/* Walk d_parent from the file's dentry to the filesystem root, sending one
 * perf event per component. Unrolled: the 4.4 verifier rejects loops. */
static __always_inline void emit_path(struct pt_regs *ctx, void *dentry, void *inode, u64 pid_tgid)
{
	struct path_event ev = {};
	void *cur = dentry;

	ev.dentry = (u64)dentry;
	ev.inode = (u64)inode;
	ev.tgid = pid_tgid >> 32;
	ev.pid = (u32)pid_tgid;
	bpf_get_current_comm(ev.comm, sizeof(ev.comm));

#define STEP(i)                                                                \
	cur = emit_component(ctx, &ev, cur, i);                                    \
	if (!cur)                                                                  \
		return;
	STEP(0) STEP(1) STEP(2) STEP(3) STEP(4) STEP(5) STEP(6) STEP(7)
	STEP(8) STEP(9) STEP(10) STEP(11) STEP(12) STEP(13) STEP(14) STEP(15)
#undef STEP

	ev.depth = PATH_DEPTH;
	ev.len = 0;
	ev.flags = FLAG_TRUNCATED;
	bpf_perf_event_output(ctx, &events, bpf_get_smp_processor_id(), &ev, sizeof(ev));
}

static __always_inline void stat_add(u32 idx, u64 n)
{
	u64 *v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		__sync_fetch_and_add(v, n);
}

/* Find the counters entry for key, creating it (and telling userspace about
 * the pid) if needed. key must live on the BPF stack. */
static __always_inline struct file_val *get_or_create(struct pt_regs *ctx, struct file_key *key, u64 pid_tgid)
{
	struct file_val *v = bpf_map_lookup_elem(&counters, key);
	if (!v) {
		struct file_val init = {};
		bpf_map_update_elem(&counters, key, &init, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&counters, key);
		if (!v)
			return 0;
		struct key_event ke = {};
		ke.dentry = key->dentry;
		ke.tgid = pid_tgid >> 32;
		ke.pid = (u32)pid_tgid;
		__builtin_memcpy(ke.comm, key->comm, sizeof(ke.comm));
		bpf_perf_event_output(ctx, &events, bpf_get_smp_processor_id(), &ke, sizeof(ke));
	}
	return v;
}

/* Send the path for (dentry, inode) to userspace unless already done. */
static __always_inline void ensure_path(struct pt_regs *ctx, void *dentry, void *inode, u64 pid_tgid)
{
	u64 dkey = (u64)dentry;
	u64 *kn = bpf_map_lookup_elem(&known, &dkey);
	if (!kn || *kn != (u64)inode) {
		u64 ino = (u64)inode;
		bpf_map_update_elem(&known, &dkey, &ino, BPF_ANY);
		bpf_map_update_elem(&inode_dentry, &ino, &dkey, BPF_ANY);
		emit_path(ctx, dentry, inode, pid_tgid);
	}
}

static __always_inline int on_entry(struct pt_regs *ctx, void *file, u64 requested, int is_write)
{
	void *dentry = 0;
	void *inode = 0;
	u16 mode = 0;

	bpf_probe_read(&dentry, sizeof(dentry), file + OFF_FILE_DENTRY);
	bpf_probe_read(&inode, sizeof(inode), dentry + OFF_DENTRY_INODE);
	bpf_probe_read(&mode, sizeof(mode), inode + OFF_INODE_MODE);
	if ((mode & S_IFMT) != S_IFREG)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct inflight_val iv = {};
	iv.key.dentry = (u64)dentry;
	iv.key.inode = (u64)inode;
	iv.key.tgid = pid_tgid >> 32;
	bpf_get_current_comm(iv.key.comm, sizeof(iv.key.comm));
	iv.requested = requested;
	iv.is_write = is_write;

	struct file_val *v = get_or_create(ctx, &iv.key, pid_tgid);
	if (!v)
		return 0;
	/* The byte add is guarded: for readv/writev "requested" is a constant 0
	 * and LLVM would turn fetch_add(0) into atomic_fetch_or, which the 4.4
	 * verifier rejects ("BPF_STX uses reserved fields"). */
	if (is_write) {
		__sync_fetch_and_add(&v->writes, 1);
		if (requested)
			__sync_fetch_and_add(&v->wbytes, requested);
	} else {
		__sync_fetch_and_add(&v->reads, 1);
		if (requested)
			__sync_fetch_and_add(&v->rbytes, requested);
	}

	bpf_map_update_elem(&inflight, &pid_tgid, &iv, BPF_ANY);
	ensure_path(ctx, dentry, inode, pid_tgid);
	return 0;
}

static __always_inline int on_return(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct inflight_val *iv = bpf_map_lookup_elem(&inflight, &pid_tgid);
	if (!iv)
		return 0;

	s64 ret = (s64)PT_REGS_RC(ctx);
	u64 actual = ret > 0 ? (u64)ret : 0;
	u64 delta = actual - iv->requested; /* wraps negative on purpose */
	struct file_key k = iv->key;
	u64 is_write = iv->is_write;

	struct file_val *v = bpf_map_lookup_elem(&counters, &k);
	if (v) {
		if (is_write)
			__sync_fetch_and_add(&v->wbytes, delta);
		else
			__sync_fetch_and_add(&v->rbytes, delta);
	}
	bpf_map_delete_elem(&inflight, &pid_tgid);
	return 0;
}

/* ssize_t vfs_read(struct file *, char __user *, size_t count, loff_t *) */
SEC("kprobe/vfs_read")
int kprobe_vfs_read(struct pt_regs *ctx)
{
	return on_entry(ctx, (void *)PT_REGS_PARM1(ctx), PT_REGS_PARM3(ctx), 0);
}
SEC("kretprobe/vfs_read")
int kretprobe_vfs_read(struct pt_regs *ctx) { return on_return(ctx); }

SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx)
{
	return on_entry(ctx, (void *)PT_REGS_PARM1(ctx), PT_REGS_PARM3(ctx), 1);
}
SEC("kretprobe/vfs_write")
int kretprobe_vfs_write(struct pt_regs *ctx) { return on_return(ctx); }

/* ssize_t vfs_readv(struct file *, const struct iovec __user *, unsigned long vlen, loff_t *)
 * The byte count is only known at return. */
SEC("kprobe/vfs_readv")
int kprobe_vfs_readv(struct pt_regs *ctx)
{
	return on_entry(ctx, (void *)PT_REGS_PARM1(ctx), 0, 0);
}
SEC("kretprobe/vfs_readv")
int kretprobe_vfs_readv(struct pt_regs *ctx) { return on_return(ctx); }

SEC("kprobe/vfs_writev")
int kprobe_vfs_writev(struct pt_regs *ctx)
{
	return on_entry(ctx, (void *)PT_REGS_PARM1(ctx), 0, 1);
}
SEC("kretprobe/vfs_writev")
int kretprobe_vfs_writev(struct pt_regs *ctx) { return on_return(ctx); }

/* ssize_t vfs_iter_read(struct file *, struct iov_iter *, loff_t *)
 * Used by the LIO fileio backstore (VM disks) and splice writes. */
static __always_inline u64 iter_count(struct pt_regs *ctx)
{
	u64 n = 0;
	bpf_probe_read(&n, sizeof(n), (void *)PT_REGS_PARM2(ctx) + OFF_IOV_ITER_COUNT);
	return n;
}
SEC("kprobe/vfs_iter_read")
int kprobe_vfs_iter_read(struct pt_regs *ctx)
{
	return on_entry(ctx, (void *)PT_REGS_PARM1(ctx), iter_count(ctx), 0);
}
SEC("kretprobe/vfs_iter_read")
int kretprobe_vfs_iter_read(struct pt_regs *ctx) { return on_return(ctx); }

SEC("kprobe/vfs_iter_write")
int kprobe_vfs_iter_write(struct pt_regs *ctx)
{
	return on_entry(ctx, (void *)PT_REGS_PARM1(ctx), iter_count(ctx), 1);
}
SEC("kretprobe/vfs_iter_write")
int kretprobe_vfs_iter_write(struct pt_regs *ctx) { return on_return(ctx); }

/* ssize_t generic_file_splice_read(struct file *in, loff_t *, struct pipe_inode_info *, size_t len, unsigned) */
SEC("kprobe/generic_file_splice_read")
int kprobe_splice_read(struct pt_regs *ctx)
{
	return on_entry(ctx, (void *)PT_REGS_PARM1(ctx), PT_REGS_PARM4(ctx), 0);
}
SEC("kretprobe/generic_file_splice_read")
int kretprobe_splice_read(struct pt_regs *ctx) { return on_return(ctx); }

/* void account_page_dirtied(struct page *, struct address_space *mapping, ...)
 * Called once per page on its clean->dirty transition, by the process doing
 * the writing. This is what iotop's and /proc/<pid>/io's write_bytes count,
 * so it reflects what will actually be written back to disk. */
SEC("kprobe/account_page_dirtied")
int kprobe_page_dirtied(struct pt_regs *ctx)
{
	void *mapping = (void *)PT_REGS_PARM2(ctx);
	u64 inode = 0;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct file_key k = {};
	struct file_val *v;

	stat_add(STAT_TOTAL_DIRTY, PAGE_SIZE);
	bpf_probe_read(&inode, sizeof(inode), mapping + OFF_MAPPING_HOST);
	u64 *dp = bpf_map_lookup_elem(&inode_dentry, &inode);
	if (dp) {
		/* Data page of a file we know: charge it to the writer. */
		k.dentry = *dp;
		k.inode = inode;
		k.tgid = pid_tgid >> 32;
		bpf_get_current_comm(k.comm, sizeof(k.comm));
		v = get_or_create(ctx, &k, pid_tgid);
		if (v)
			__sync_fetch_and_add(&v->dbytes, PAGE_SIZE);
		else
			stat_add(STAT_DROPPED_DIRTY, PAGE_SIZE);
		return 0;
	}

	/* Not a file we have seen: almost always filesystem metadata (the
	 * btrfs btree inode). If this task is inside fsync, the fsync caused it. */
	struct fsync_val *fv = bpf_map_lookup_elem(&inflight_fsync, &pid_tgid);
	if (fv) {
		k = fv->key;
		v = get_or_create(ctx, &k, pid_tgid);
		if (v)
			__sync_fetch_and_add(&v->mbytes, PAGE_SIZE);
		else
			stat_add(STAT_DROPPED_DIRTY, PAGE_SIZE);
		return 0;
	}

	/* Otherwise charge it to the process under the "metadata" pseudo-file
	 * (dentry 0), so per-process totals still match iotop. */
	k.dentry = 0;
	k.inode = 0;
	k.tgid = pid_tgid >> 32;
	bpf_get_current_comm(k.comm, sizeof(k.comm));
	v = get_or_create(ctx, &k, pid_tgid);
	if (v)
		__sync_fetch_and_add(&v->mbytes, PAGE_SIZE);
	else
		stat_add(STAT_UNATTRIBUTED_DIRTY, PAGE_SIZE);
	return 0;
}

/* int vfs_fsync_range(struct file *file, loff_t start, loff_t end, int datasync)
 * Covers fsync, fdatasync, O_SYNC writes and msync. Directories are allowed:
 * SQLite fsyncs the directory after deleting a journal. */
SEC("kprobe/vfs_fsync_range")
int kprobe_fsync(struct pt_regs *ctx)
{
	void *file = (void *)PT_REGS_PARM1(ctx);
	void *dentry = 0;
	void *inode = 0;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct fsync_val fv = {};

	bpf_probe_read(&dentry, sizeof(dentry), file + OFF_FILE_DENTRY);
	bpf_probe_read(&inode, sizeof(inode), dentry + OFF_DENTRY_INODE);
	if (!dentry)
		return 0;
	fv.key.dentry = (u64)dentry;
	fv.key.inode = (u64)inode;
	fv.key.tgid = pid_tgid >> 32;
	bpf_get_current_comm(fv.key.comm, sizeof(fv.key.comm));
	bpf_map_update_elem(&inflight_fsync, &pid_tgid, &fv, BPF_ANY);

	/* Make sure the file has a counters entry and a path, even if it was
	 * only ever written through a path we do not hook. */
	if (!get_or_create(ctx, &fv.key, pid_tgid))
		return 0;
	ensure_path(ctx, dentry, inode, pid_tgid);
	return 0;
}
SEC("kretprobe/vfs_fsync_range")
int kretprobe_fsync(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&inflight_fsync, &pid_tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

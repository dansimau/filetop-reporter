/* Minimal BPF support header for the Synology DSM 7.2 kernel (4.4.302+, x86_64).
 *
 * No kernel headers, no BTF, no CO-RE: everything the program needs is
 * declared here with the uapi helper numbers and the x86_64 pt_regs layout.
 */
#ifndef FILETOP_COMMON_H
#define FILETOP_COMMON_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

/* Legacy map definition, section "maps". Works on every kernel. */
struct bpf_map_def {
	u32 type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
};

enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
};

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

/* x86_64 pt_regs as seen by kprobes. Arg1..4 = di, si, dx, cx; return = ax. */
struct pt_regs {
	u64 r15, r14, r13, r12, bp, bx, r11, r10, r9, r8;
	u64 ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss;
};
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_RC(x) ((x)->ax)

/* Helpers, by uapi number (include/uapi/linux/bpf.h). */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read)(void *dst, u32 size, const void *src) = (void *)4;
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static u32 (*bpf_get_smp_processor_id)(void) = (void *)8;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, u32 size) = (void *)16;
static long (*bpf_perf_event_output)(void *ctx, void *map, u64 index, void *data, u64 size) = (void *)25;
static u64 (*bpf_get_current_task)(void) = (void *)35;
static long (*bpf_probe_read_str)(void *dst, u32 size, const void *unsafe_ptr) = (void *)45;

#endif

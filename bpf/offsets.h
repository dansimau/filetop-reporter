/* Struct offsets for Linux 4.4 on x86_64 (Synology DSM 7.2, kernel 4.4.302+).
 *
 * All of these sit at the head of their structs, before any config-dependent
 * members, so they do not depend on the kernel configuration. They are
 * validated at daemon startup by the sentinel self-test.
 */
#ifndef FILETOP_OFFSETS_H
#define FILETOP_OFFSETS_H

/* struct file: f_u (16 bytes), then struct path f_path { mnt, dentry } */
#define OFF_FILE_DENTRY 24

/* struct dentry: d_flags(4) d_seq(4) d_hash(16) d_parent(8) d_name(16) d_inode(8) */
#define OFF_DENTRY_PARENT 24
#define OFF_DENTRY_QSTR 32 /* struct qstr { u32 hash; u32 len; const char *name; } */
#define OFF_DENTRY_INODE 48

/* struct inode: umode_t i_mode is the first member */
#define OFF_INODE_MODE 0

/* struct address_space: struct inode *host is the first member */
#define OFF_MAPPING_HOST 0

/* struct iov_iter (4.4): int type; size_t iov_offset; size_t count; */
#define OFF_IOV_ITER_COUNT 16

#define S_IFMT 0170000
#define S_IFREG 0100000

#endif

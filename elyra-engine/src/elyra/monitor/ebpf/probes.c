#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <net/sock.h>

#define EVENT_PROCESS_EXEC 1
#define EVENT_PROCESS_EXIT 2
#define EVENT_FILE_WRITE 3
#define EVENT_FILE_RENAME 4
#define EVENT_NETWORK_CONNECT 5

struct event_t {
    u32 event_type;
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    s32 exit_code;
    u64 device;
    u64 inode;
    u32 daddr;
    u16 dport;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(ignored_tgids, u32, u8, 1024);
BPF_HASH(monitored_uids, u32, u8, 256);
BPF_ARRAY(filter_flags, u32, 1);

static __always_inline int should_emit(u32 tgid, u32 uid) {
    u8 *ignored = ignored_tgids.lookup(&tgid);
    if (ignored)
        return 0;
    u32 zero = 0;
    u32 *uid_filter_enabled = filter_flags.lookup(&zero);
    if (uid_filter_enabled && *uid_filter_enabled) {
        u8 *allowed = monitored_uids.lookup(&uid);
        if (!allowed)
            return 0;
    }
    return 1;
}

static __always_inline u32 read_current_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    u32 ppid = 0;
    if (task == NULL)
        return 0;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent != NULL)
        bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
    return ppid;
}

static __always_inline void fill_common(struct event_t *event, u32 kind) {
    u64 id = bpf_get_current_pid_tgid();
    u64 ugid = bpf_get_current_uid_gid();
    event->event_type = kind;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = (u32)id;
    event->tgid = id >> 32;
    event->ppid = read_current_ppid();
    event->uid = (u32)ugid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

/*
 * Pardus 25 / Linux 6.12 exposes data_loc_filename in the generated BCC
 * tracepoint structure. The loader verifies that field from tracefs before
 * compiling this source and can substitute the legacy spelling when needed.
 */
TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct event_t event = {};
    fill_common(&event, EVENT_PROCESS_EXEC);
    if (!should_emit(event.tgid, event.uid))
        return 0;
    unsigned int offset = args->ELYRA_EXEC_FILENAME_FIELD & 0xFFFF;
    bpf_probe_read_str(event.filename, sizeof(event.filename), (void *)args + offset);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct event_t event = {};
    fill_common(&event, EVENT_PROCESS_EXIT);
    if (!should_emit(event.tgid, event.uid))
        return 0;
    /* sched_process_exit does not expose a portable exit_code field. */
    event.exit_code = 0;
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

int on_vfs_write(struct pt_regs *ctx, struct file *file) {
    struct event_t event = {};
    fill_common(&event, EVENT_FILE_WRITE);
    if (!should_emit(event.tgid, event.uid) || file == NULL)
        return 0;
    struct inode *inode = NULL;
    bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
    if (inode == NULL)
        return 0;
    bpf_probe_read_kernel(&event.inode, sizeof(event.inode), &inode->i_ino);
    struct super_block *sb = NULL;
    bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);
    if (sb != NULL)
        bpf_probe_read_kernel(&event.device, sizeof(event.device), &sb->s_dev);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

/*
 * The loader injects probes only for rename-family syscall tracepoints that
 * actually exist on the running kernel. This covers rename, renameat and
 * renameat2 without assuming which libc/Python wrapper will be used.
 * The captured old-name value is a user-supplied identifier, not a verified
 * canonical full path.
 */
ELYRA_RENAME_PROBES

int on_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    struct event_t event = {};
    fill_common(&event, EVENT_NETWORK_CONNECT);
    if (!should_emit(event.tgid, event.uid) || sk == NULL)
        return 0;
    bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&event.dport, sizeof(event.dport), &sk->__sk_common.skc_dport);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

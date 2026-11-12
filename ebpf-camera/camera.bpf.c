#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define PATH_LEN 256
#define EVENT_EXEC 1
#define EVENT_CONNECT 2

struct event_t {
    __u32 kind;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u64 ts_ns;
    __u32 uid;
    __u32 reserved;
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    char filename[PATH_LEN];
    __u32 daddr;
    __u16 dport;
    __u16 family;
    __u8 addr6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} dropped SEC(".maps");

static __always_inline void note_drop(__u32 key)
{
    __u64 *counter = bpf_map_lookup_elem(&dropped, &key);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline void fill_identity(struct event_t *e)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->ts_ns = bpf_ktime_get_ns();
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (!task)
        return;
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent) {
        e->ppid = BPF_CORE_READ(parent, tgid);
        BPF_CORE_READ_STR_INTO(&e->parent_comm, parent, comm);
    }
}

struct trace_event_raw_sched_process_exec_local {
    struct trace_entry ent;
    __u32 __data_loc_filename;
    __u32 pid;
    __u32 old_pid;
    char __data[0];
};

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec_local *ctx)
{
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_drop(0);
        return 0;
    }
    e->kind = EVENT_EXEC;
    fill_identity(e);
    __u32 loc = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
                              (void *)ctx + loc);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct trace_event_raw_sys_enter_local {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
    char __data[0];
};

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter_local *ctx)
{
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_drop(1);
        return 0;
    }
    e->kind = EVENT_CONNECT;
    fill_identity(e);

    void *uaddr = (void *)ctx->args[1];
    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), uaddr) == 0) {
        e->family = family;
        if (family == 2) {
            __u16 port = 0;
            __u32 addr = 0;
            bpf_probe_read_user(&port, sizeof(port), uaddr + 2);
            bpf_probe_read_user(&addr, sizeof(addr), uaddr + 4);
            e->dport = __builtin_bswap16(port);
            e->daddr = addr;
        } else if (family == 10) {
            __u16 port = 0;
            bpf_probe_read_user(&port, sizeof(port), uaddr + 2);
            e->dport = __builtin_bswap16(port);
            bpf_probe_read_user(&e->addr6, sizeof(e->addr6), uaddr + 8);
        }
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

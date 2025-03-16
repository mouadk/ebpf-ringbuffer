#include "vmlinux.h"
#include "bpf_helpers.h"


#define FILE_NAME_LEN 64
const char LOG_FILE[] = "file_access.log";

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    char filename[FILE_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} events SEC(".maps");


static __inline int strcmp(const char *s1, const char *s2) {
#pragma unroll
    for (int i = 0; i < FILE_NAME_LEN; i++) {
        if (s1[i] != s2[i]) return 1;
        if (s1[i] == '\0') break;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->filename, FILE_NAME_LEN, filename);

    // If I don't do this the collector will have too much work to get my attention i.e ring_buffer__poll nevers returns
    if (strcmp(e->filename, LOG_FILE) == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

#include <stdio.h>
#include <stdlib.h>
#include "syscall.skel.h"
#include "signal.h"
#include "bpf.h"
#include "libbpf.h"
#define LOG_FILE "file_access.log"
#define TASK_COMM_LEN 16
#define FILE_NAME_LEN 256

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    char filename[FILE_NAME_LEN];
};

static volatile sig_atomic_t exiting = 0;

static void on_sig(int sig) {
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_size) {
    struct event *e = (struct event *)data;

    FILE *file = fopen(LOG_FILE, "a");
    if (!file) {
        perror("Failed to open log file");
        return 0;
    }
    fprintf(file, "pid=%d, comm=%s, filename=%s\n", e->pid, e->comm, e->filename);
    fflush(file);
    fclose(file);
    return 0;
}

int main(int argc, char **argv) {
    struct syscall_bpf *skel;
    struct ring_buffer *rb;

    fprintf(stdout, "ebpf loader starting...\n");
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    skel = syscall_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to load BPF program.\n");
       return 1;
    }

    if (syscall_bpf__attach(skel)) {
        fprintf(stderr, "failed to attach BPF program.\n");
        goto teardown;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer.\n");
        goto teardown;
    }

    printf("successfully started, events are logged at %s, press Ctrl+C to exit.\n", LOG_FILE);
    while (!exiting) {
        int err = ring_buffer__poll(rb, 100);
        //printf(poll returned %d, exiting=%d\n", err, exiting);

        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll() failed: %d\n", err);
            break;
        }
    }
teardown:
    printf("shutting down...:)\n");
    ring_buffer__free(rb);
    syscall_bpf__destroy(skel);
    return 0;
}

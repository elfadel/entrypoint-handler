// +build ignore
#include "entrypoint.bpf.h"

// #define SYS_OPEN            1
// #define SYS_CONNECT         2
// #define SYS_EXECVE          3

static __always_inline
int trace_open(void *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    // if (pid != my_pid)
    //     return 0;

    bpf_printk("open() triggered from PID %d.\n", pid);

    return 0;
}

SEC("kprobe/sys_open")
int kprobe__sys_open(void *ctx)
{
    return trace_open(ctx);
}

SEC("kprobe/sys_openat")
int kprobe__sys_openat(void *ctx)
{
    return trace_open(ctx);
}

// Example: tracing a message on a kprobe
SEC("kprobe/sys_execve")
int kprobe__sys_execve(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk("exec() triggered from PID %d.\n", pid);
    return 0;
}

// Example of passing data using a perf map
// Similar to bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count();}'
BPF_PERF_OUTPUT(events)
SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(void *ctx)
{
    char data[100];
    bpf_get_current_comm(&data, 100);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);
    return 0;
}
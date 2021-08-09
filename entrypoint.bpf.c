// +build ignore
#include "entrypoint.bpf.h"

// #define SYS_OPEN            1
// #define SYS_CONNECT         2
// #define SYS_EXECVE          3

static __always_inline
int trace_open(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk("open() triggered from PID %d.\n", pid);

    return 0;
}

SEC("kprobe/sys_open")
int kprobe__sys_open(struct pt_regs *ctx)
{
    return trace_open(ctx);
}

SEC("kprobe/sys_openat")
int kprobe__sys_openat(struct pt_regs *ctx)
{
    return trace_open(ctx);
}

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk("exec() triggered from PID %d.\n", pid);
    return 0;
}

BPF_PERF_OUTPUT(events)
SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(void *ctx)
{
    char data[100];
    bpf_get_current_comm(&data, 100);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);
    return 0;
}
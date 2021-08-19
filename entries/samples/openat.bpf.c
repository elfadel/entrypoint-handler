// +build ignore
// Generated file. Please, do not edit.
// Source: entry.tpl.c
// Event name: openat
// Event args: [{int dirfd 1} {char pathname 2} {int flags 3} {mode_t mode 4}]

#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>

#include "entry.bpf.h"

SEC("kprobe/sys_openat")
int kprobe__sys_openat(struct pt_regs *ctx) {
	__u64 pid = bpf_get_current_pid_tgid() >> 32;

	bpf_printk("KPROBE ENTER ============================\n");
	
	
	int dirfd = (int)PT_REGS_PARM1(ctx);
	bpf_printk("\tdirfd = %d\n", dirfd);
	
	char pathname[128];
	bpf_probe_read(pathname, sizeof(pathname), (void *)PT_REGS_PARM2(ctx));
	bpf_printk("\tpathname = %s\n", pathname);
	
	
	int flags = (int)PT_REGS_PARM3(ctx);
	bpf_printk("\tflags = %d\n", flags);
	
	
	return 0;
}

SEC("kretprobe/sys_openat")
int kretprobe__sys_openat(struct pt_regs *ctx) {
	int ret = PT_REGS_RC(ctx);
	bpf_printk("KRETPROBE EXIT with RET = %d  ============================\n", ret);

	return 0;	
}
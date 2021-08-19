// +build ignore
// Generated file. Please, do not edit.
// Source: entry.tpl.c
// Event name: execve
// Event args: [{char pathname 1} {const char*const* argv 2} {const char*const* envp 3}]

#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>

#include "entry.bpf.h"

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx) {
	__u64 pid = bpf_get_current_pid_tgid() >> 32;

	bpf_printk("KPROBE ENTER ============================\n");
	
	
	char pathname[128];
	bpf_probe_read(pathname, sizeof(pathname), (void *)PT_REGS_PARM1(ctx));
	bpf_printk("\tpathname = %s\n", pathname);
	
	
	
	
	return 0;
}

SEC("kretprobe/sys_execve")
int kretprobe__sys_execve(struct pt_regs *ctx) {
	int ret = PT_REGS_RC(ctx);
	bpf_printk("KRETPROBE EXIT with RET = %d  ============================\n", ret);

	return 0;	
}
// The below define fixes the 
// "use of undeclared identifier 'KBUILD_MODNAME" error
#define KBUILD_MODNAME "foo"

#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#include "entry.bpf.h"

SEC("kprobe/sys_socket")
int kprobe__sys_socket(struct pt_regs *ctx) {
	bpf_printk("KPROBE ENTER \n");

	int family = (int)PT_REGS_PARM1(ctx);
    int type = (int)PT_REGS_PARM2(ctx);
    int protocol = (int)PT_REGS_PARM3(ctx);

	bpf_printk("\n\tfamily = %d;\n\ttype = %d;\n\tproto = %d\n", family, type, protocol);

	return 0;
}

SEC("kretprobe/sys_socket")
int kretprobe__sys_socket(struct pt_regs *ctx) {
	int ret = PT_REGS_RC(ctx);
	bpf_printk("KRETPROBE EXIT with RET = %d\n", ret);

	return 0;
}
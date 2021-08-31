// The below define fixes the 
// "use of undeclared identifier 'KBUILD_MODNAME" error
#define KBUILD_MODNAME "foo"

#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#include "entry.bpf.h"

struct ip4_tuple {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
};

static __always_inline
int build_ip4_tuple(struct ip4_tuple *ip_tuple, struct sock *skp) {
	u32 src_addr = 0, dst_addr = 0;
	u16 src_port = 0, dst_port = 0;

	bpf_probe_read(&src_addr, sizeof(src_addr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&dst_addr, sizeof(dst_addr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&src_port, sizeof(src_addr), &((struct inet_sock *)skp)->inet_sport);
	bpf_probe_read(&dst_port, sizeof(dst_port), &skp->__sk_common.skc_dport);

	ip_tuple->saddr = src_addr; // bpf_ntohl(src_addr);
	ip_tuple->daddr = dst_addr; // bpf_ntohl(dst_addr);
	ip_tuple->sport = src_port; // bpf_ntohs(src_port);
	ip_tuple->dport = dst_port; // bpf_ntohs(dst_port);

	return 1;
}

SEC("kprobe/sys_accept")
int kprobe__sys_accept(struct pt_regs *ctx) {
	bpf_printk("KPROBE ENTER \n");

	struct sock *sock;
	struct socket *socket;

	socket = (struct socket*) PT_REGS_PARM1(ctx);
	sock = BPF_CORE_READ(socket, sk);

	struct ip4_tuple t = { };
	if (!build_ip4_tuple(&t, sock)) {
		bpf_printk("build_ip4_tuple() failed.\n");
		return 0;
	}

	bpf_printk("src addr = %d -- dst addr = %d\n", 
				t.saddr, t.daddr);
	bpf_printk("src port = %d -- dst port = %d\n",
				t.sport, t.dport);

	return 0;
}

SEC("kretprobe/sys_accept")
int kretprobe__sys_accept(struct pt_regs *ctx) {
	int ret = PT_REGS_RC(ctx);
	bpf_printk("KRETPROBE EXIT with RET = %d\n", ret);

	return 0;
}
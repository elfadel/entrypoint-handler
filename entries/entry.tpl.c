{{/* Top comment printed in all generated eBPF code */}}
// Generated file. Please, do not edit.
// Source: entry.tpl.c
// Event name: {{ .Name }}
{{/* // Event args: {{ .Args }} */}}

// +build ignore
#include "entrypoint.bpf.h"

SEC("kprobe/sys_{{ .Name }}")
int kprobe__sys_{{ .Name }}(struct pt_regs *ctx) {
	int pid = bpf_get_current_pid_tgid() >> 32;

	bpf_printk("open() triggered from PID %d.\n", pid);

	return 0;
}
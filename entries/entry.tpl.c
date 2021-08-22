// +build ignore
// Generated file. Please, do not edit.
// Source: entry.tpl.c
// Event name: {{ .Name }}
// Event args: {{ .Args }}

#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>

#include "entry.bpf.h"

SEC("kprobe/sys_{{ .Name }}")
int kprobe__sys_{{ .Name }}(struct pt_regs *ctx) {
	__u64 pid = bpf_get_current_pid_tgid() >> 32;

	bpf_printk("\nKPROBE ENTER \n");
	{{range $index, $elmt := .Args }}
	{{if eq $elmt.Type "char"}}
	const char *{{ $elmt.Name }};
	char buf[256];
	bpf_probe_read(&{{ $elmt.Name }}, sizeof({{ $elmt.Name }}), PT_REGS_PARM{{ $elmt.Position }}(ctx));
	bpf_probe_read_str(buf, sizeof(buf), {{ $elmt.Name }});
	bpf_printk("\t{{ $elmt.Name }} = %s\n", buf);
	{{else if eq $elmt.Type "int"}}
	int {{ $elmt.Name }} = ({{ $elmt.Type }})PT_REGS_PARM{{ $elmt.Position }}(ctx);
	bpf_printk("\t{{ $elmt.Name }} = %d\n", {{ $elmt.Name }});
	{{- end -}}
	{{- end }}
	
	return 0;
}

SEC("kretprobe/sys_{{ .Name }}")
int kretprobe__sys_{{ .Name }}(struct pt_regs *ctx) {
	int ret = PT_REGS_RC(ctx);
	bpf_printk("KRETPROBE EXIT with RET = %d\n", ret);

	return 0;	
}
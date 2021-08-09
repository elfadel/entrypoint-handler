{{/* Top comment printed in all generated eBPF code */}}
// Generated file. Please, do not edit.
// Source: entry.tpl.c
// Event name: {{ .Name }}
// Event args: {{ .Args }}

// +build ignore
#include "entrypoint.bpf.h"

BPF_HASH({{ .Name }}_args_map, __u64, struct pt_regs);

SEC("kprobe/sys_{{ .Name }}")
int kprobe__sys_{{ .Name }}(struct pt_regs *ctx) {
	__u64 pid = bpf_get_current_pid_tgid() >> 32;

	struct pt_regs args = { };
	bpf_probe_read(&args, sizeof(args), ctx);

	bpf_map_update_elem(&{{ .Name }}_args_map, &pid, &args, BPF_ANY);

	return 0;
}

SEC("kretprobe/sys_{{ .Name }}")
int kretprobe__sys_{{ .Name }}(struct pt_regs *ctx) {
	struct pt_regs *args;
	__u64 pid = bpf_get_current_pid_tgid();

	args = bpf_map_lookup_elem(&{{ .Name }}_args_map, &pid);
	if(!args)
		return 0;
	bpf_map_delete_elem(&{{ .Name }}_args_map, &pid);

	bpf_printk("KPROBE/KRETPROBE ENTER ============================\n");
	{{range $index, $elmt := .Args }}
	{{if eq $elmt.Type "char"}}
	char {{ $elmt.Name }}[128];
	bpf_probe_read(&{{ $elmt.Name }}, sizeof({{ $elmt.Name }}), (void *) PT_REGS_PARM{{ $elmt.Position }}(args));
	bpf_printk("\t{{ $elmt.Name }} = %s\n", {{ $elmt.Name }});
	{{else if eq $elmt.Type "int"}}
	int {{ $elmt.Name }} = ({{ $elmt.Type }})PT_REGS_PARM{{ $elmt.Position }}(args);
	bpf_printk("\t{{ $elmt.Name }} = %d\n", {{ $elmt.Name }});
	{{- end }}
	{{- end }}
	bpf_printk("KPROBE/KRETPROBE EXIT  ============================\n");

	return 0;	
}
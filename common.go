// +build amd64

package main

import (
	"github.com/aquasecurity/tracee/tracee-ebpf/external"
)

type hookType uint8

const (
    sysCall        hookType = iota
    kprobe
    kretprobe
    tracepoint
    rawTracepoint
)

type Hook struct {
    progName       string
    attachName     string
    Type           hookType
}

type EventConfig struct {
    ID             int32
    Name           string
    Hooks          []Hook
    // vars
}

var allEvents = map[int32]EventConfig{
    OpenEventID:        {ID: OpenEventID, Name: "open", Hooks: []Hook{{progName: "open", attachName: "__x64_sys_open", Type: kprobe}}},
    OpenatEventID:      {ID: OpenatEventID, Name: "openat", Hooks: []Hook{{progName: "openat", attachName: "__x64_sys_openat", Type: kprobe}}},
    ExecveEventID:      {ID: ExecveEventID, Name: "execve", Hooks: []Hook{{progName: "execve", attachName: "__x64_sys_execve", Type: kprobe}}},
}

var allEventsParams = map[int32][]external.ArgMeta{
	OpenEventID:                   {{Type: "const char*", Name: "pathname"}, {Type: "int", Name: "flags"}, {Type: "mode_t", Name: "mode"}},
	OpenatEventID:                 {{Type: "int", Name: "dirfd"}, {Type: "const char*", Name: "pathname"}, {Type: "int", Name: "flags"}, {Type: "mode_t", Name: "mode"}},
	ExecveEventID:                 {{Type: "const char*", Name: "pathname"}, {Type: "const char*const*", Name: "argv"}, {Type: "const char*const*", Name: "envp"}},
}
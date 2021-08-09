// +build amd64

package main

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

type ArgsWithPos struct {
    Type           string
    Name           string
    Position       int32
}

type Event4Gen struct {
    Name           string
    Args           []ArgsWithPos       
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

var allEventsParams = map[int32][]ArgsWithPos{
	OpenEventID:                   {{Type: "char", Name: "pathname", Position: 1}, {Type: "int", Name: "flags", Position: 2}, {Type: "mode_t", Name: "mode", Position: 3}},
	OpenatEventID:                 {{Type: "int", Name: "dirfd", Position: 1}, {Type: "char", Name: "pathname", Position: 2}, {Type: "int", Name: "flags", Position: 3}, {Type: "mode_t", Name: "mode", Position: 4}},
	ExecveEventID:                 {{Type: "char", Name: "pathname", Position: 1}, {Type: "const char*const*", Name: "argv", Position: 2}, {Type: "const char*const*", Name: "envp", Position: 3}},
}
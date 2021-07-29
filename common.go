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

type EventConfig struct {
    ID             int32
    Name           string
    Hooks          []Hook
}

var allEvents = map[int32]EventConfig{
    OpenEventID:        {ID: OpenEventID, Name: "open", Hooks: []Hook{{progName: "open", attachName: "__x64_sys_open", Type: kprobe}}},
    OpenatEventID:      {ID: OpenatEventID, Name: "openat", Hooks: []Hook{{progName: "openat", attachName: "__x64_sys_openat", Type: kprobe}}},
    ExecveEventID:      {ID: ExecveEventID, Name: "execve", Hooks: []Hook{{progName: "execve", attachName: "__x64_sys_execve", Type: kprobe}}},
}
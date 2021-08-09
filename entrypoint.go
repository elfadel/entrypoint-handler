package main

import (
	"C"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)
import (
	"fmt"
	"os"
	"os/signal"
)

//var

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	var userRequiredEvents map[int32]bool

	userRequiredEvents = make(map[int32]bool)

	// TODO: Fill dynamically userRequiredEvents.
	//       Should required parsing of Policies.
	userRequiredEvents[OpenEventID] = false
	userRequiredEvents[OpenatEventID] = true
	userRequiredEvents[ExecveEventID] = true

	generateBpfSources(userRequiredEvents, "./entries/entry.tpl.c", "./entries")

	bpfModule, err := bpf.NewModuleFromFile("entrypoint.bpf.o")
	must(err)
	defer bpfModule.Close()

	prog, err := bpfModule.GetProgram("") // TODO: rm

	for _, event := range allEvents {
		for _, hk := range event.Hooks {
			switch hk.Type {
			case sysCall:
				prog, _ = bpfModule.GetProgram(fmt.Sprintf("syscall__sys_%s", hk.progName))
			case kprobe:
				prog, _ = bpfModule.GetProgram(fmt.Sprintf("kprobe__sys_%s", hk.progName))
			case tracepoint:
				prog, _ = bpfModule.GetProgram(fmt.Sprintf("tp__sys_%s", hk.progName))
			}

			if prog == nil {
				continue
			}

			if _, ret := userRequiredEvents[event.ID]; !ret {
				err = prog.SetAutoload(false)
				must(err)
				continue
			}
		}
	}

	err = bpfModule.BPFLoadObject()
	must(err)

	for e, t := range userRequiredEvents {

		if !t {
			continue
		}

		event, ret := allEvents[e]
		if !ret {
			continue
		}

		for _, hk := range event.Hooks {
			switch hk.Type {
			case kprobe:
				prog, err = bpfModule.GetProgram(fmt.Sprintf("kprobe__sys_%s", hk.progName))
				must(err)
				_, err = prog.AttachKprobe(hk.attachName)
				must(err)
			case tracepoint:
				prog, err = bpfModule.GetProgram(fmt.Sprintf("tp__sys_%s", hk.progName))
				must(err)
				_, err = prog.AttachTracepoint(hk.attachName)
				must(err)

				// TODO: add cases
			}
		}
	}

	go bpf.TracePrint()

	prog, err = bpfModule.GetProgram("raw_tracepoint__sys_enter")
	must(err)
	_, err = prog.AttachRawTracepoint("sys_enter")
	must(err)

	e := make(chan []byte, 300)
	p, err := bpfModule.InitPerfBuf("events", e, nil, 1024)
	must(err)

	p.Start()

	counter := make(map[string]int, 350)
	go func() {
		for data := range e {
			comm := string(data)
			counter[comm]++
		}
	}()

	<-sig
	p.Stop()
	for comm, n := range counter {
		fmt.Printf("%s: %d\n", comm, n)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

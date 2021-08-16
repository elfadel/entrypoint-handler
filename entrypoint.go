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
	userRequiredEvents[ExecveEventID] = false
	userRequiredEvents[ExecveatEventID] = false

	generateBpfSources(userRequiredEvents, "./entries/entry.tpl.c", "./entries")

	for e, t := range userRequiredEvents {
		if !t {
			continue
		}

		event, ret := allEvents[e]
		if !ret {
			continue
		}

		eBPFSrcFile := fmt.Sprintf("./entries/%s.bpf.o", event.Name)

		bpfModule, err := bpf.NewModuleFromFile(eBPFSrcFile)
		must(err)
		defer bpfModule.Close()

		err = bpfModule.BPFLoadObject()
		must(err)

		for _, hk := range event.Hooks {
			switch hk.Type {
			case kprobe:
				prog, err := bpfModule.GetProgram(fmt.Sprintf("kprobe__sys_%s", hk.progName))
				must(err)
				_, err = prog.AttachKprobe(hk.attachName)
				must(err)

				prog, err = bpfModule.GetProgram(fmt.Sprintf("kretprobe__sys_%s", hk.progName))
				must(err)
				_, err = prog.AttachKretprobe(hk.attachName)
				must(err)

			// TODO: add other cases
			}
		}
	}

	go bpf.TracePrint()

	<-sig
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

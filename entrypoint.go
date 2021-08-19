package main

import (
	"C"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)
import (
	"flag"
	"fmt"
	"os"
	"os/exec"
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

	boolAttach		:= flag.Bool("attach", false, "compile and load eBPF progs")
	boolGenerate 	:= flag.Bool("generate", false, "generate eBPF code")
	boolMake 		:= flag.Bool("make", false, "compile eBPF src")

	flag.Parse();

	if *boolGenerate {
		generateBpfSources(userRequiredEvents, "./entries/entry.tpl.c", "./entries")
		fmt.Printf("eBPF code generated. Look at ./entries folder\n");
	}

	if *boolMake {
		real_cmd := "make"

		arg0 := "-f"
		arg1 := "ebpf.mk"
		arg2 := "all"

		go_cmd := exec.Command(real_cmd, arg0, arg1, arg2)
		_, err := go_cmd.Output()
		must(err)
		fmt.Printf("eBPF code compiled. Look at ./entries folder\n");
	}

	if *boolAttach {
		fmt.Printf("Attach of eBPF progs: Start.\n")
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
		fmt.Printf("Attach of eBPF progs: End.\n")

		go bpf.TracePrint()
	}

	if !*boolGenerate && !*boolAttach && !*boolMake {
		fmt.Printf("Nothing to do. Use Ctrl+C to exit.\n")
	}

	<-sig
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

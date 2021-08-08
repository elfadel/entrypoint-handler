package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"
)

func fileExists(path string) bool {
	if f, err := os.Stat(path); err != nil {
                if os.IsNotExist(err) {
                        return false
                }
                if f.IsDir() {
                        return false
                }
        }
        return true
}

func buildSource(evtCfg *EventConfig, tplFile string, destDir string) error {
        tplText, err := ioutil.ReadFile(tplFile)
        if err != nil { // TODO: modify error handling
                return fmt.Errorf("could not read template: %v", err)
        }

        t := template.New("eBPF Source")

        t, err = t.Parse(string(tplText))
        if err != nil { // TODO: +1
                return fmt.Errorf("could not parse template: %v", err)
        }

        evtPath := fmt.Sprintf("%s.bpf.c", evtCfg.Name)

        fi, err := os.Create(filepath.Join(destDir, evtPath))
        if err != nil { // TODO: +2
                return fmt.Errorf("could not create eBPF source file: %v", err)
        }
        defer fi.Close()

        if err = t.Execute(fi, evtCfg); err != nil { // ???
                return fmt.Errorf("could not execute template: %v", err)
        }

        return nil
}

func generateBpfSources(requiredEvents map[int32]bool, tplFile string, destDir string) error {
        if !fileExists(tplFile) {
                return fmt.Errorf("template file doesn't exist")
        }

        if f, err := os.Stat(destDir); err != nil || !f.IsDir() {
                return fmt.Errorf("invalid destination directory: %v", err)
        }

        for e, t := range requiredEvents {
                if !t {
                        continue
                }

                event, ret := allEvents[e]
                if !ret {
                        continue
                }

                // eventParams, ret__ := allEventsParams[e]
                // if !ret__ {
                //         continue
                // }

                if err := buildSource(&event, tplFile, destDir); err != nil {
                        return fmt.Errorf("could not build source: %v", err)
                }
        }
        return nil
}
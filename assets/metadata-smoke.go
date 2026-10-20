// SPDX-License-Identifier: Apache-2.0
// Static workload for the CPU KVM metadata CDI smoke scenarios.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func read(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fail("read %s: %v", path, err)
	}
	return data
}

func main() {
	// The missing-Init-Data case must fail before this first instruction.
	fmt.Println("METADATA_APPLICATION_STARTED")
	if len(os.Args) != 2 {
		fail("expected selected or unselected")
	}
	if !bytes.Equal(read("/etc/os-release"), read("/expected-container-os-release")) {
		fail("container /etc/os-release changed")
	}
	mountinfo := string(read("/proc/self/mountinfo"))
	selected := os.Args[1] == "selected"
	for _, path := range []string{"/run/podvm/os-release", "/run/podvm/initdata.toml"} {
		found := false
		for _, line := range strings.Split(mountinfo, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 6 || fields[4] != path {
				continue
			}
			found = true
			for _, flag := range []string{"ro", "nosuid", "nodev", "noexec"} {
				if !strings.Contains(","+fields[5]+",", ","+flag+",") {
					fail("%s missing mount flag %s", path, flag)
				}
			}
		}
		if !selected {
			if _, err := os.Stat(path); found || !errors.Is(err, os.ErrNotExist) {
				fail("unselected metadata exposed: %s", path)
			}
			continue
		}
		if !found {
			fail("metadata mount absent: %s", path)
		}
		// Require EROFS specifically, not a permission error on a writable bind.
		if err := os.WriteFile(path, []byte("tamper"), 0644); !errors.Is(err, syscall.EROFS) {
			fail("%s write did not fail with EROFS: %v", path, err)
		}
	}
	if selected {
		if !bytes.Equal(read("/run/podvm/initdata.toml"), read("/expected-initdata.toml")) {
			fail("Init-Data bytes differ")
		}
		var identity map[string]string
		if err := json.Unmarshal(read("/expected-identity.json"), &identity); err != nil {
			fail("invalid expected identity: %v", err)
		}
		values := map[string]string{}
		for _, line := range strings.Split(string(read("/run/podvm/os-release")), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok {
				values[key] = strings.Trim(value, "\"'")
			}
		}
		for key, value := range identity {
			if values[key] != value {
				fail("guest identity mismatch: %s", key)
			}
		}
	}
	fmt.Println("METADATA_CDI_OK")
}

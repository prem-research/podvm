// SPDX-License-Identifier: Apache-2.0
// Static container fixture: successful output proves the agent completed its
// model gate and exposed directories, before executing any workload code.
package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

func main() {
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mount info unavailable:", err)
		os.Exit(1)
	}
	for _, path := range os.Args[1:] {
		hardened := false
		for _, line := range strings.Split(string(mountinfo), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 6 && fields[4] == path {
				options := "," + fields[5] + ","
				hardened = true
				for _, required := range []string{"ro", "nodev", "nosuid", "noexec"} {
					hardened = hardened && strings.Contains(options, ","+required+",")
				}
			}
		}
		if !hardened {
			fmt.Fprintln(os.Stderr, "model mount lacks required flags:", path)
			os.Exit(1)
		}
		data, err := os.ReadFile(path + "/weights")
		if err != nil || !bytes.HasPrefix(data, []byte("verified model bytes")) {
			fmt.Fprintln(os.Stderr, "model read failed:", path, err)
			os.Exit(1)
		}
		if os.WriteFile(path+"/weights", []byte("tamper"), 0644) == nil {
			fmt.Fprintln(os.Stderr, "model mount is writable:", path)
			os.Exit(1)
		}
	}
	fmt.Println("MODEL_MOUNTS_OK")
}

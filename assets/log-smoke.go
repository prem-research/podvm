// SPDX-License-Identifier: Apache-2.0
// Static workload for the CPU KVM log-policy smoke scenarios.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Each stream receives 1 MiB, far beyond a 64 KiB pipe buffer, so a reader
// that stops draining the pipe blocks this workload before it can exit.
const lines = 16384

func emit(w io.Writer, name string) {
	for i := 0; i < lines; i++ {
		line := fmt.Sprintf("LOG_SMOKE_%s %06d ", name, i)
		if _, err := io.WriteString(w, line+strings.Repeat(".", 63-len(line))+"\n"); err != nil {
			os.Exit(1)
		}
	}
}

func main() {
	emit(os.Stdout, "STDOUT")
	emit(os.Stderr, "STDERR")
	fmt.Println("LOG_SMOKE_DONE")
}

#!/bin/bash
set -euo pipefail
cd /model-mount
go test -mod=readonly ./...
modelwrap_version=$(go list -m -f '{{.Version}}' github.com/tinfoilsh/modelwrap)
cp "$(go env GOPATH)/pkg/mod/cache/download/github.com/tinfoilsh/modelwrap/@v/${modelwrap_version}.info" /out/modelwrap.info
CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -o /out/podvm-model-mount .
cd /kata/src/agent
# Make only generates the version constants; cargo uses the upstream lock.
make LIBC=gnu src/version.rs
# eBPF object net_policy.rs embeds; -nostdinc limits includes to the kernel UAPI headers.
clang-16 -target bpfel -mcpu=v3 -O2 -g0 -Wall -Wextra -Werror \
  -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-protector -nostdinc \
  -isystem /usr/include/x86_64-linux-gnu -isystem /usr/include \
  -c src/net_policy.bpf.c -o src/net_policy.bpf.o
install -m 0644 src/net_policy.bpf.o /out/net_policy.bpf.o
cd /kata
cargo test --locked -p kata-agent --features agent-policy,init-data,seccomp model_mounts::tests
cargo test --locked -p kata-agent --features agent-policy,init-data,seccomp cdi
cargo test --locked -p kata-agent --features agent-policy,init-data,seccomp time_sync::tests
cargo test --locked -p kata-agent --features agent-policy,init-data,seccomp net_policy::tests
cargo test --locked -p kata-agent --features agent-policy,init-data,seccomp test_host_clock_setting_is_rejected
cargo test --locked -p kata-agent --features agent-policy,init-data,seccomp test_ephemeral_mount_updates_are_rejected
cargo build --locked --release -p kata-agent --features agent-policy,init-data,seccomp
install -m 0755 target/release/kata-agent /out/kata-agent
sha256sum /out/kata-agent /out/podvm-model-mount /out/net_policy.bpf.o

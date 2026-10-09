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
cd /kata
cargo test --locked -p kata-agent --features agent-policy,init-data,seccomp model_mounts::tests
cargo build --locked --release -p kata-agent --features agent-policy,init-data,seccomp
install -m 0755 target/release/kata-agent /out/kata-agent
sha256sum /out/kata-agent /out/podvm-model-mount

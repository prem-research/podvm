# Measured CoCo PodVM

This repository builds one Ubuntu 24.04 x86_64 PodVM for Confidential
Containers peer pods. The image contains Kata Agent, the Cloud API Adaptor
forwarder, Confidential Data Hub, API Server REST, process-user-data, and both
the Intel TDX and AMD SEV-SNP attestation agents.

Every dependency in `versions.yaml` is immutable. CI checks each OCI tag against
its locked digest and verifies GitHub artifact attestations for Kata Containers
and guest-components before building. The Ubuntu guest is built with the CoCo
v0.22.0 mkosi production profile against the locked Ubuntu snapshot.

## Release contents

Each published release has exactly three assets:

- `podvm-ubuntu-24.04-x86_64-<tag>.tar.zst`
- `measurements.json`
- `SHA256SUMS`

The bundle contains `podvm.qcow2`, the direct-boot kernel, initrd, dm-verity
command line, TDX and SEV-SNP firmware, launch profiles, a launch helper,
component provenance, and per-file hashes. The qcow2 can be imported through
the normal CoCo/peer-pod provider flow. The measurements apply to the fixed
direct-boot QEMU profiles in the bundle; a provider that changes firmware,
kernel parameters, CPU model, memory, vCPU count, or virtual hardware must
publish measurements for that launch profile.

The TDX ACPI generation runs on ordinary KVM by omitting the runtime-only
`tdx-guest` object and `confidential-guest-support` machine property. It uses
QEMU's built-in hubport backend because the measurement tool's minimal QEMU
build omits libslirp; the released runtime uses user networking. Both paths
keep the same virtio-net device and PCI ordering. The measurement shape and
runtime additions are recorded in the TDX launch profile.

`measurements.json` exposes the TDX `mr_td`, `rtmr_0`, `rtmr_1`, and `rtmr_2`
values plus the SEV-SNP launch measurement. Its `rvps.reference_values` object
maps those values to Trustee claim names directly. The document links to its
JSON Schema at the immutable release source revision, and the schema is also in
the bundle.

## Local commands

The full build needs Docker with buildx, ORAS, GitHub CLI, QEMU/KVM, `objcopy`,
`zstd`, and Python 3.10 or newer.

```console
make verify
make build
make smoke
make measure
make package RELEASE_VERSION=v1.0.0 SOURCE_REVISION=$(git rev-parse HEAD)
make validate
```

After the tools are installed, the same sequence is available as
`make all RELEASE_VERSION=v1.0.0 SOURCE_REVISION=$(git rev-parse HEAD)`.

Install the pinned measurement tools and expose them as `tdx-measure` and
`sev-snp-measure`, or set `TDX_MEASURE` and `SEV_SNP_MEASURE` to their paths.
CI downloads the upstream TDX release binary and SEV-SNP Python wheel and
checks both against the SHA-256 values in `versions.yaml`. `make test` and
`make verify-offline` require only Python.

Pushing any Git tag runs the same verify, build, boot, measure, and package path
as pull requests. A successful tag run creates a GitHub Release named after the
tag and uploads the three assets. Workflow reruns replace those assets on the
existing release. GitHub artifact attestations are generated for the bundle,
measurement document, and checksum file before the release is created.

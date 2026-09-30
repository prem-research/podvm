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
the normal CoCo/peer-pod provider flow. Every named profile configured in
`config/launch-profiles.json` is measured and published; a provider that
changes firmware, kernel parameters, CPU model, memory, vCPU count, or virtual
hardware must add and publish that launch profile.

The TDX ACPI generation runs on ordinary KVM by omitting the runtime-only
`tdx-guest` object and `confidential-guest-support` machine property. It uses
QEMU's built-in hubport backend because the measurement tool's minimal QEMU
build omits libslirp. That build also omits `pc-bios`, so ACPI generation
disables the virtio-net option ROM. The released runtime uses user networking
and its normal option ROM. Both paths keep the same virtio-net device and PCI
ordering. The measurement shape and runtime additions are recorded in the TDX
launch profile.

`measurements.json` is a profile catalog. Each TDX entry keeps `mr_td`,
`rtmr_0`, `rtmr_1`, and `rtmr_2` together, and each SEV-SNP entry contains its
launch measurement. A relying party selects the TEE catalog and accepts an
attestation only when all measurements match one complete profile record.
SEV-SNP memory size is runtime metadata rather than a launch-digest input, so
one SNP measurement can legitimately match multiple profiles that differ only
in memory. The document links to its JSON Schema at the immutable release
source revision, and the schema is also in the bundle.

## Launch profiles

Profiles are explicit, named entries under `tdx.profiles` and
`sev_snp.profiles` in `config/launch-profiles.json`. TDX profiles select vCPU
count and memory. SEV-SNP profiles additionally select the QEMU vCPU type, VMM
type, and guest features. To use another profile file, pass
`--profiles path/to/profiles.json` or set `PROFILES` for Make targets.

The bundled helper requires both the TEE and profile ID and accepts no topology
overrides:

```console
./launch-podvm.sh tdx 2vcpu-8g
./launch-podvm.sh sev-snp epyc-v4-2vcpu-8g
```

## Local commands

The full build needs Docker with buildx, ORAS, GitHub CLI, QEMU/KVM, `objcopy`,
`make`, Mike Farah's `yq` v4, `tar`, `xz`, `zstd`, and Python 3.10 or newer.

CI installs each job's host dependencies with apt, using the official GitHub
CLI and Docker package repositories where needed. It installs the CAA-pinned
`yq` binary, and installs the checksum-verified SEV-SNP wheel and its
`cryptography` dependency in a Python virtual environment. The ARC runner must
provide root or passwordless sudo, a Docker daemon accessible to the runner
user, and KVM device access for the build and measurement jobs.
The runner workspace must be mounted at the same absolute path in the Docker
daemon container. TDX ACPI generation places its temporary files beside the
staged metadata in that shared workspace: the runner's `/tmp` is not shared
with an ARC Docker sidecar. The upstream ACPI generator's missing
`kvmvapic.bin` and disconnected hub warnings are expected; failure to create
`acpi_tables.bin` indicates an output mount or permissions problem.

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

# Measured local Kata PodVM

This repository builds an Ubuntu 24.04 x86_64 guest for local Kata QEMU
sandboxes, with Intel TDX and AMD SEV-SNP firmware. Kata Agent starts directly
on vsock port 1024. Attestation Agent, Confidential Data Hub and API Server
REST start locally; agent startup does not depend on cloud userdata or their
readiness.

The workflow retains the pinned Cloud API Adaptor payload build and mkosi
Ubuntu snapshot. mkosi exports a directory rootfs without a distribution
kernel or UKI. Kata's pinned image builder turns that rootfs into an ext4 raw
disk with root and dm-verity hash partitions. The separately pinned Kata
kernel includes the storage, dm-verity and vsock drivers needed to boot
without an initrd. `/run`, `/tmp` and `/var` hold writable guest state while
the root filesystem stays read-only.

The guest contains a regular `/etc/resolv.conf` mount target. Kata Agent
bind-mounts the sandbox DNS configuration there during sandbox creation,
before CDH pulls workload images. A systemd-resolved stub symlink can dangle
under the Kata startup target and cause the agent to silently skip DNS setup.
The build checks this mount target before generating the measured disk.

## Build and check

The build needs Linux, Docker/buildx with privileged containers and loop
mounts, ORAS 1.2.0, GitHub CLI with artifact attestation support, `make`, Mike
Farah's `yq` v4, `tar`, `xz`, `zstd`, and Python 3.10+ with `requirements.txt`.
The smoke test and TDX ACPI generation need accessible `/dev/kvm` and
`/dev/vhost-vsock`; confidential hardware is not required for these checks.
Docker must see the workspace at the same absolute path as the runner.
The image builder installs `udev` and shares the Docker daemon's `/dev`, as
Kata's upstream container build does. Docker-in-Docker can still miss newly
allocated device nodes. The builder creates only its selected loop and
partition nodes using the major/minor numbers reported by sysfs, including
loops beyond the initial eight, without detaching other builds' devices.
Partition discovery uses `losetup -P` once, waits before creating nodes, and
checks that the partition can be opened. This avoids stale device numbers
when the sizing loop detaches and reuses the same loop device.
The Docker host kernel must already provide the loop driver.
The tracked `kata-image-builder-errors.patch` makes sizing failures fatal and
releases loops when partition discovery fails, rather than exhausting loop
devices and falling through to a zero-size image.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
make test
make verify-offline
make build
make smoke
make tools
make measure
make package RELEASE_VERSION=dev
make validate
```

`make all RELEASE_VERSION=dev` runs build, smoke, tool installation,
measurement and packaging. `make verify` resolves every OCI tag to its locked
digest and checks upstream GitHub attestations; the build repeats verification.
All source revisions and OCI inputs are locked in `versions.yaml`. The
smoke-only runtime/shim payload is explicitly verified by digest: the pinned
upstream shim build job publishes no attestations. Kernel, firmware, agent,
guest components, QEMU and virtiofsd still require upstream attestations.

The smoke test extracts the pinned Kata runtime, QEMU and virtiofsd into a
temporary workspace. Inside an isolated privileged container it starts a
private containerd daemon and uses `ctr` with the pinned Kata shim and asset
annotations to execute `/pause -v` from the pinned pause image. Its `/dev/shm`
limit matches the selected profile's guest RAM: Kata's virtio-fs memory
backend needs this space, and Docker's default 64 MiB can cause QEMU to report
`kvm run failed Bad address` before the agent starts. The exported pause
rootfs is shared through virtio-fs with container rootfs block-device
hotplug disabled; the runner's backing disk is not attached to the guest.
The container creation RPC has an explicit 60-second timeout, since omitting
this setting in the pinned Go runtime's configuration produces an immediate
deadline. A second run
changes the verity root hash and must fail with
evidence of a corrupt or unmountable root filesystem. It does not change the
host's installed Kata or containerd configuration. This checks the agent RPC
and container execution path; it does not validate TEE attestation reports.
The valid run requires exit status zero and pause's `pause.c v3.9-` banner on
stdout.
This smoke test uses a host-provided rootfs; it does not exercise guest DNS
or CDH registry pulls.
Full logs, extracted guest-console output, and the launch configuration are
retained under `build/smoke-logs/` (beside a custom staging directory). CI
uploads these as `podvm-smoke-diagnostics`, including on failure. Failure
messages include early hypervisor errors and guest-console output separately
from runtime cleanup logs.

## Use through pod annotations

Extract the bundle to `/opt/podvm` on every eligible node. Merge
`kata/configuration.toml.fragment` into the relevant Kata QEMU configuration,
keeping the node's existing hypervisor and TEE settings. Enable the listed
hypervisor annotations, use ext4 with `disable_image_nvdimm = true`, and
clear the configured initrd. Set static sandbox resource management so pod
resource requests do not silently change the measured CPU/memory profile.
Containerd's runtime entry must pass `pod_annotations = ["io.katacontainers.*"]`
to Kata. These are deployment examples; this repository does not apply them
to any host.

The bundle generates `kata/pod-snp-2vcpu-8g.yaml` and
`kata/pod-tdx-2vcpu-8g.yaml`, and equivalents for each configured profile.
Their annotations select:

- `io.katacontainers.config.hypervisor.kernel`: `/opt/podvm/vmlinuz`
- `io.katacontainers.config.hypervisor.image`: `/opt/podvm/podvm.raw`
- `io.katacontainers.config.hypervisor.firmware`: the matching bundled firmware
- `io.katacontainers.config.hypervisor.kernel_verity_params`: the **entire** contents of `kernel_verity_params`
- `io.katacontainers.config.hypervisor.kernel_params`: the contents of `kernel_params`
- `default_vcpus`, `default_max_vcpus`, `default_memory`: the profile dimensions (memory in MiB)

There is no initrd annotation. `kernel_verity_params` contains Kata's five
comma-separated values: root hash, salt, data block count, data block size,
and hash block size. Kata generates the `/dev/vda1`, `/dev/vda2` and
`dm-mod.create` arguments itself. The bundled `cmdline` is the full command
line used for reference measurements and the standalone launcher; **do not
paste it into the kernel_params annotation**, which contains only additional
parameters. See [Kata's annotation documentation](https://github.com/kata-containers/kata-containers/blob/cf82bb35c80320178bf7570252fe75d6fb263209/docs/how-to/how-to-set-sandbox-config-kata.md).

When replacing a bundle, update saved pod manifests with the new bundle's
`kernel_verity_params` and recreate the affected pods. The image, root hash,
and salt must come from the same build. An old annotation with a new image
prevents the guest from mounting its root filesystem and can surface as
`timed out connecting to vsock ...:1024`, before any image pull occurs.

## Verified model volumes

The guest can replace read-only model-pack file volumes with dm-verity
verified EROFS directories before creating workload containers. The optional
`[data]."model-mounts.json"` entry in initdata is a JSON array:

```toml
[data]
"model-mounts.json" = '''
[
  {
    "modelid": "organization/model@exact-packer-revision",
    "mount_path": "/models/example",
    "parameters": {
      "root_hash": "<64 lowercase hexadecimal characters>",
      "hash_offset": 1048576
    }
  }
]
'''
```

Set the root hash and byte offset from the packer's `.info` output; `modelid`
must exactly match the identity passed to the packer, including its revision.
These values come from initdata, never from metadata inside the untrusted
pack. The agent derives the input file's actual guest path from the incoming
OCI mount at `mount_path`; node paths and generated guest filenames do not
belong in this JSON. Destinations must be normalized paths under `/models/`.
The contract is described by `schemas/model-mounts.schema.json`, with an
initdata template in `assets/model-mounts.example.toml`.

Use the usual Kubernetes file-volume declaration:

```yaml
volumes:
  - name: model
    hostPath:
      path: /srv/models/example.mpk
      type: File
containers:
  - name: inference
    image: your-inference-image
    volumeMounts:
      - name: model
        mountPath: /models/example
        readOnly: true
```

Pass the initdata through Kata's existing
`io.katacontainers.config.hypervisor.cc_init_data` annotation (base64-encoded
gzip of the complete TOML document). Include `cc_init_data` in the node's
hypervisor annotation allowlist. Merge this entry with any existing
`policy.rego`, `aa.toml`, or `cdh.toml` entries.

The infrastructure/pause container may initialize first. The first init
container, or first application container if there are no init containers,
must declare **every configured model volume**. All models must mount before
that container is created; missing inputs fail immediately. Later containers
can request a subset and reuse the verified mounts, including after a
container restart. Keep all model volume mounts read-only and avoid `subPath`
or mount propagation. No CSI driver, StorageClass, or container mount
privileges are needed.

Policy evaluates the original file mount before transformation. Existing
policies generated from the pod manifest need no `/run/modelwrap` source
allowances. The measured agent replaces only configured destinations with
private guest mounts and enforces `ro,nodev,nosuid,noexec`. Additional mounts
that could shadow a configured destination are rejected. A failed model gate
blocks workload creation until the sandbox is recreated; partial mounts are
rolled back, and sandbox teardown releases model resources.

Absent initdata, an absent key, and an empty array preserve ordinary startup.
Malformed present configuration fails agent initialization. The helper
supports plaintext `.mpk` artifacts; encrypted artifacts are not supported.
dm-verity verifies blocks as they are read, without a full weight scan at
startup. Unread corrupted blocks fail when accessed. This feature does not
add an attestation endpoint or a claim about which model an inference request
used.

The build compiles the patched agent and a static Go consumer helper using
locked toolchains and dependencies. It records their hashes and source/patch
provenance in `/etc/modelwrap-build.json`; normal guest image measurements
cover these installed components. `make smoke` also exercises model mounts
with real fixture packs.

## Measurements and launch profiles

`config/launch-profiles.yaml` keeps named CPU/memory pairs and per-profile
SNP overrides. The default remains 2 vCPUs / 8 GiB. SNP reference measurements
cover `EPYC-v4`, `EPYC-Milan-v2`, `EPYC-Genoa-v1`, and `EPYC-Turin` with the
existing QEMU VMM and guest-feature settings. The pinned Go Kata runtime
selects `EPYC-v4` for SNP. The other records apply to launches that actually
select those guest models; host CPU generation does not select a record.
Annotations cannot replace Kata's hardcoded SNP CPU model.

```yaml
profiles:
  2vcpu-8g:
    cpus: 2
    memory: "8G"
  32vcpu-64g:
    cpus: 32
    memory: "64G"
    sev:
      vcpu_types: [EPYC-Genoa-v1, EPYC-Turin]
```

Use `--profiles path/to/profiles.yaml` or `PROFILES=...` for Make targets.
An SNP CPU-model override replaces the default list and inherits other
settings. Every configured profile/model is measured twice and compared.
The SNP tool receives the exact firmware, kernel and full command line with
no `--initrd` argument. Memory remains launch metadata even when different
memory sizes produce the same SNP digest.

TDX uses the existing `tdx-measure` source with a small tracked patch in
`assets/patches/tdx-measure-no-initrd.patch`. The patch accepts a nullable
initrd and omits the firmware's initrd command-line suffix and RTMR2 event
when none is present. Initrd-present behavior has regression tests. `make
tools` builds the CLI with its upstream Cargo locks in a digest-pinned Rust
container and records the source revision, patch hash, builder digest and
binary hash. Measurements verify that provenance before using the binary.

The ACPI dumper uses the same upstream QEMU 11.0.1 commit as the pinned Kata
QEMU payload (Kata has no patches for that release). It substitutes a null
block backend for the root disk, a hubport for user networking and disables
the NIC option ROM; it omits the TDX guest object so it can run on ordinary
KVM. Disk content is bound by the verity root hash in the measured command
line. The device order is recorded explicitly in the profiles.

The ACPI container runs as UID/GID 0 with explicit `/dev/kvm` and
`/dev/vhost-vsock` mappings. These devices must exist on the Docker daemon
host (the sidecar on ARC); the runner's device permissions and group IDs
do not establish access inside that container. This avoids depending on
matching `kvm` groups across containers and does not require `--privileged`
for measurement. Missing-ROM warnings such as `kvmvapic.bin` are expected
from the minimal ACPI QEMU build, which skips `pc-bios`.

The published values are **reference predictions for the recorded launch
configuration**. Selecting the bundled assets through annotations makes the
guest bootable; it does not make every node's complete QEMU topology match
the reference. Before endorsing a TDX record, align PCI bridges, console,
vsock, shared filesystem, networking, machine options and firmware behavior
with the actual Kata launch. Kernel debug settings and extra agent/config
parameters also change measurements. Add or update a launch profile when
those inputs change, and compare predictions with real reports on the
intended TEE before using them as an attestation policy.

The standalone reference launcher accepts no topology overrides:

```sh
./launch-podvm.sh tdx 2vcpu-8g
./launch-podvm.sh sev-snp 2vcpu-8g EPYC-v4
```

## Release contract

Each release still contains exactly three assets:

- `podvm-ubuntu-24.04-x86_64-<version>.tar.zst`
- `measurements.json`
- `SHA256SUMS`

The bundle contains `podvm.raw`, `vmlinuz`, `kernel.config`,
`kernel_verity_params`, additional `kernel_params`, full `cmdline`, both
firmwares, annotation/configuration examples, launch profiles, the launch
helper, schemas, provenance and a per-file hash manifest. There is no qcow2
or initrd. `initrd` is explicitly null in the measurement records.

`measurements.json` keeps all four TDX registers together per profile and
SNP launch digests keyed by guest CPU model. It includes immutable inputs,
local asset hashes and patched measurement-tool provenance. Raw measurements
fingerprint the exact disk, kernel, kernel configuration, verity parameters,
command lines, firmware, build inputs, profiles and local patches; packaging
rejects changes made after measurement. Its JSON Schema is linked at the
immutable release source revision and included in the bundle.

CI runs build → Kata smoke → measurements → package, then publishes and
attests those three assets for tags. The build and measurement jobs use the
existing KVM ARC runner group.

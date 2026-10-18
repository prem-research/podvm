# Measured local Kata PodVM

This repository builds an Ubuntu 24.04 x86_64 CPU guest for local Kata QEMU
sandboxes, with Intel TDX and AMD SEV-SNP firmware, plus a separate NVIDIA GPU
guest variant. In the CPU guest, Kata Agent starts directly
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
mounts, ORAS 1.2.0, GitHub CLI with artifact attestation support, `make`, `file`,
`readelf`, `modinfo`, Mike
Farah's `yq` v4, `tar`, `xz`, `zstd`, and Python 3.10+ with `requirements.txt`.
The smoke test and TDX ACPI generation need accessible `/dev/kvm` and
`/dev/vhost-vsock`; confidential hardware is not required for these checks.
Docker must see the workspace at the same absolute path as the runner.
The image builder installs `udev` and shares the Docker daemon's `/dev`, as
Kata's upstream container build does. Docker-in-Docker can still miss newly
allocated device nodes. The builder creates only its selected loop and
partition nodes using the major/minor numbers reported by sysfs, including
loops beyond the initial eight, without detaching other builds' devices.
The NVIDIA rootfs composer uses the same node handling for its EROFS loop
partition.
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
python3 -m pip install -r requirements-test.txt
make test
make verify-offline
make build RELEASE_VERSION=dev
make smoke
make tools
make measure
make package RELEASE_VERSION=dev
make all VARIANT=nvidia RELEASE_VERSION=dev
make assemble
make validate
```

`make all RELEASE_VERSION=dev` runs the CPU build, smoke, tool installation,
measurement and packaging for that variant. Run it again with `VARIANT=nvidia`,
then use `make assemble` to produce the unified release. `make verify` resolves every CPU OCI tag to its locked
digest and checks upstream GitHub attestations; the build repeats verification.
All source revisions and OCI inputs are locked in `versions.yaml`. The
smoke-only runtime/shim payload is explicitly verified by digest: the pinned
upstream shim build job publishes no attestations. Kernel, firmware, agent,
guest components and QEMU still require upstream attestations.

## NVIDIA GPU variant

Use `--variant nvidia` or `VARIANT=nvidia` with the same commands. Both variants
read `config/launch-profiles.yaml`: profiles with a `gpu` block use NVIDIA,
and profiles without one use CPU. Work, staging, raw measurements and private
package directories remain separate. For example, after preparing the CPU package:

```sh
make verify VARIANT=nvidia
make build VARIANT=nvidia RELEASE_VERSION=dev
make tools
make measure VARIANT=nvidia
make package VARIANT=nvidia RELEASE_VERSION=dev
make assemble
make validate VARIANT=nvidia
```

The NVIDIA build starts from Kata's pinned `nvidia-gpu-confidential` EROFS
image and matching NVIDIA kernel artifact. It keeps NVRC, NVIDIA drivers,
CDI tooling, fabric services and NVIDIA-capable CoCo components, and overlays
the patched PodVM agent, verified model-mount helper and required utilities.
The image builder creates a new dm-verity protected ext4 disk with an
initrd-free NVRC command line. It checks the NVIDIA module vermagic against
the kernel before staging. The upstream rootfs OCI artifact has no Sigstore
referrer: the lock checks its manifest, payload and version digests, but cannot
cryptographically prove upstream source provenance. The NVIDIA kernel does
have an upstream attestation.

GPU profiles are named `<gpu>-<platform>-<count>-<memory>`.
GPU profiles may use any CPU and memory size. Hopper HGX examples request all four
NVSwitches and require the node's `nvidia.com/cc.mode=ppcie` label. Blackwell
HGX examples request all eight GPUs.
The generated pods use `kata-qemu-nvidia-gpu-snp` and
`kata-qemu-nvidia-gpu-tdx`, with stock `nvidia.com/pgpu` and
`nvidia.com/nvswitch` resources. On a heterogeneous cluster, configure the
sandbox device plugin's model-specific resource aliases and update the pod
resource request. The default alias alone cannot select a model. Host GPU
Operator, VFIO ownership and RuntimeClass setup are prerequisites; the build
does not install them.

`build/tdx-candidates-nvidia.json` records pinned boot inputs and a diagnostic
for each NVIDIA profile. The default profiles omit concrete guest NUMA, PCIe
endpoints/bridges and MMIO apertures, so no GPU TDX prediction is produced.
You can add a complete `tdx_topology` to a profile to pass NUMA, QEMU objects,
synthetic offline PCI devices, bridge order, MMIO globals and firmware
configuration to the pinned TDX tool. Any result remains an **unqualified
candidate**. It needs repeatable real GPU TDX quotes matching MRTD and
RTMR0–2 before a profile can be published as qualified. The NVIDIA release
therefore has SNP records only; CPU measurements do not attest GPU identity
or confidential mode. Compare quotes from different GPU models under otherwise
matching configurations before sharing a reference measurement. H200,
Blackwell, HGX and TDX hardware validation remain outstanding. The ordinary
`smoke` command tests only the CPU guest. NVIDIA boot, CDI, CUDA, Init-Data,
model-mount and invalid-root-hash checks require a GPU host and the generated
Kubernetes examples.

The smoke test extracts the pinned Kata runtime and QEMU into a temporary
workspace. Inside an isolated privileged container it starts a private
containerd daemon and uses `ctr` with the pinned Kata shim and asset
annotations to execute `/pause -v` from the pinned pause image. The harness
creates an ext4 filesystem without a journal containing the exported pause and model-check
rootfs and attaches it through an owned writable host loop device. The pinned
Kata runtime opens rootfs block backends writable even for an OCI read-only
rootfs, so this disposable test image must allow that open. Its host mount
and OCI root remain read-only. The test filesystem is fully initialized and
synchronized before guest use; it has no host journal state for the guest
to replay. Model fixtures use owned read-only host loop
attachments. Filesystem sharing
is disabled (`shared_fs = "none"`), block-device use is enabled, and both
virtio-scsi and virtio-blk model delivery are exercised. Cleanup checks the
recorded backing identity before detaching each test device; it never uses
fixed loop, guest disk, or dm-device numbers.
The smoke runner creates only the kernel-selected loop nodes in its private
`/dev`, using sysfs device numbers. It also recreates owned nodes during
timeout recovery, since a fresh cleanup container does not inherit them.
The container creation RPC has an explicit 60-second timeout, since omitting
this setting in the pinned Go runtime's configuration produces an immediate
deadline. A second run
changes the verity root hash and must fail with
evidence of a corrupt or unmountable root filesystem. It does not change the
host's installed Kata or containerd configuration. This checks the agent RPC
and container execution path; it does not validate TEE attestation reports.
The valid run requires exit status zero and pause's `pause.c v3.9-` banner on
stdout.
The metadata CDI scenarios then compare the complete projected Init-Data
against the supplied bytes (including comments and line endings), verify the
guest's build identity and the container's unchanged `/etc/os-release`, and
check `ro,nosuid,nodev,noexec` plus rejected writes. Unselected containers are
tested with and without Init-Data. Selecting metadata without Init-Data must
fail before the application starts, with missing-source mount evidence; a
timeout cannot pass this check.
This smoke test uses a host-provided rootfs; it does not exercise guest DNS
or CDH registry pulls.
Full logs, extracted guest-console output, and the launch configuration are
retained under `build/smoke-logs/` (beside a custom staging directory). CI
uploads these as `podvm-smoke-diagnostics` if the CPU build job fails. Failure
messages include early hypervisor errors and guest-console output separately
from runtime cleanup logs.

## Guest image version

Read the PodVM identity from `/etc/os-release` inside the guest OS:

```sh
grep -E '^(IMAGE_ID|IMAGE_VERSION|PODVM_SOURCE_REVISION)=' /etc/os-release
```

For example, a release build contains:

```ini
IMAGE_ID="podvm"
IMAGE_VERSION="v1.2.3"
PODVM_SOURCE_REVISION="<full PodVM repository commit SHA>"
```

`IMAGE_ID` identifies the PodVM image, `IMAGE_VERSION` identifies its release,
and `PODVM_SOURCE_REVISION` records this repository's full commit SHA.
Ubuntu's `ID`, `VERSION_ID`, and other distribution fields are preserved.
Run the command in the guest OS; a workload container normally has its own
`/etc/os-release` describing its container image.

Each CI path derives the same version before building and uses it for the
guest image and release metadata:

| Build | `IMAGE_VERSION` |
| --- | --- |
| GitHub tag | Exact tag, such as `v1.2.3` |
| Pull request | `pr-<number>-<first 12 characters of GITHUB_SHA>` |
| Manual workflow | `manual-<first 12 characters of GITHUB_SHA>` |
| Local default | `dev` |

For a local build with a specific version, run:

```sh
make all RELEASE_VERSION=v1.2.3
```

When running the stages separately, pass the same `RELEASE_VERSION` to
`make build` and `make package`. `SOURCE_REVISION` defaults to the checkout's
commit in Make; the Python CLI uses `GITHUB_SHA` when set, otherwise the
checkout's commit. To override it, pass `SOURCE_REVISION=<full commit SHA>`
to both Make targets or once to `make all`. The CLI equivalents are
`--release-version` and `--source-revision`.

Versions must start with a letter or digit and contain only letters, digits,
`.`, `_`, `+`, `~`, `^`, or `-`. These fields are embedded before dm-verity
generation and checked in the built rootfs. Packaging rejects a version or
revision that differs from the staged image. Changing either requires
rebuilding and remeasuring; existing images built without this identity must
also be rebuilt.

## Opt-in guest metadata through CDI

Both CPU and NVIDIA guests enable Kata's native `VISIBLE_CDI_DEVICES`
selection. To expose guest metadata to one container, add:

```yaml
env:
  - name: VISIBLE_CDI_DEVICES
    value: "podvm.local/metadata=all"
```

Supply a complete Init-Data document using the Pod's `cc_init_data` annotation
as described below. The two projected files are:

| Guest source | Container destination |
| --- | --- |
| `/etc/os-release` | `/run/podvm/os-release` |
| `/run/confidential-containers/initdata/initdata.toml` | `/run/podvm/initdata.toml` |

These are bind mounts with `bind,ro,nosuid,nodev,noexec`. The container's own
`/etc/os-release` remains intact. The Init-Data projection exposes the **entire
original document**, unchanged, including policy and any other data entries.
Only authorize this selector for containers that may read all of that data.
The agent policy must authorize the requesting container and its
`VISIBLE_CDI_DEVICES` environment value in `CreateContainerRequest`; the
selector itself is not an authorization boundary. Policy evaluates the
request before the agent applies CDI edits.

Requesting metadata without Init-Data fails container creation because its
bind source is absent. There is no empty-document fallback or optional mount.
Containers without this selector continue to start when Init-Data is absent.
Generated deployment Pods retain that behavior. The separate
[`metadata-container.example.yaml`](assets/metadata-container.example.yaml)
fragment is copied into each bundle's `kata/` directory for explicit opt-in.

Both variants bake the same CDI 0.6.0 definition into
`/etc/cdi/podvm-metadata.yaml` with mode `0644` on the measured, read-only
root filesystem. The shared agent patch reads `/etc/cdi` and `/var/run/cdi`;
NVIDIA continues generating its GPU definitions in `/var/run/cdi`. The CDI
library gives the runtime directory precedence for duplicate device names.
A missing runtime directory is allowed, so CPU metadata needs no runtime
installation. Bind sources are checked when the container requests them,
after the agent has initialized Init-Data.

CPU starts the agent directly through systemd after `var.mount` and sets
`visible_cdi_devices = true` in its agent TOML. NVIDIA retains NVRC as init
and places the real agent binary at `/usr/bin/kata-agent`.
This follows [NVRC's pinned agent entrypoint](https://github.com/NVIDIA/nvrc/blob/v0.1.5/src/kata_agent.rs).
NVIDIA retains command-line configuration, including
`agent.visible_cdi_devices=true`, because
[Kata's config-file handling](https://github.com/kata-containers/kata-containers/blob/cf82bb35c80320178bf7570252fe75d6fb263209/src/agent/src/config.rs)
would otherwise replace its command-line settings. The selector flag is in
both variants' measured command lines, staging `kernel_params`, and deployment
annotations. `assets/patches/kata-static-cdi.patch` extends Kata's CDI search
directories for both variants; NVRC uses its existing agent entrypoint.
Before creating either disk image, the build runs the agent's `--version`
inside that guest rootfs to check its executable and library dependencies.

For NVIDIA hardware acceptance, use a generated GPU Pod's RuntimeClass,
annotations and resource limits, supply known Init-Data bytes, and choose a
CUDA workload image. Request both devices in the same container:

```yaml
env:
  - name: VISIBLE_CDI_DEVICES
    value: "podvm.local/metadata=all:nvidia.com/gpu=0"
```

Verify both projected files, compare Init-Data byte-for-byte with the supplied
document, compare the PodVM identity with the bundle's `inputs.json`, and
confirm the container's OS identity is unchanged. Check `/proc/self/mountinfo`
for `ro,nosuid,nodev,noexec` on both files and confirm writes fail. Run
`nvidia-smi` and a CUDA computation in that same container. Also check
unselected and missing-Init-Data cases. Record the GPU model/count, driver,
confidential mode, bundle identity and workload results separately from CPU
KVM smoke results; CPU smoke does not qualify NVIDIA hardware or attestation.

Existing images and measurement catalogs predate this change and must be
rebuilt and remeasured. Use the existing `make build`, `make smoke` (CPU),
`make measure`, and `make package` pipeline, with `VARIANT=nvidia` for NVIDIA
build/measure/package and the same release identity throughout. Build input
fingerprints include the CDI assets and reject stale staging inputs.
Deployment, publication and real GPU qualification remain separate steps.

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

## Pack Init-Data

Start with a complete `initdata.toml`, including the top-level `algorithm`
and `version` fields and all required `[data]` entries. See
[`assets/model-mounts.example.toml`](assets/model-mounts.example.toml) for
the format used by this repository.

Compress the TOML directly into a gzip binary, then base64-encode it for the
pod annotation, following the
[Confidential Containers Init-Data format](https://confidentialcontainers.org/docs/features/initdata/):

```sh
gzip -n -c initdata.toml > initdata.gz
base64 -w0 initdata.gz > initdata.b64
```

`initdata.gz` contains the compressed TOML bytes. `-c` preserves the source
file, and `-n` omits the filename and timestamp from the gzip header so the
output is reproducible. `base64 -w0` (GNU coreutils) produces a single-line
annotation value. Compress the complete TOML document directly, without a
tar archive.

Copy the contents of `initdata.b64` into the pod's metadata:

```yaml
metadata:
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: "<contents of initdata.b64>"
```

Include `cc_init_data` in the node's hypervisor annotation allowlist, as
described above. Verify that decoding and decompressing recovers the exact
source file:

```sh
base64 --decode initdata.b64 | gzip -dc | cmp - initdata.toml
```

`cmp` exits successfully with no output when the files match.

## Verified model volumes

The guest replaces read-only model-pack **block-device** volumes with dm-verity
verified EROFS directories before creating workload containers. The optional
`[data]."model-mounts.json"` entry in initdata is a JSON array:

```toml
[data]
"model-mounts.json" = '''
[
  {
    "modelid": "organization/model@exact-packer-revision",
    "mount_path": "/models/example",
    "info": "<ROOTHASH_OFFSET_VERITYUUID>"
  }
]
'''
```

Set `info` to the complete string from the packer's `.info` output, without
its trailing newline: `ROOTHASH_OFFSET_VERITYUUID`, as described in the
[modelwrap documentation](https://github.com/tinfoilsh/modelwrap/blob/v0.2.1/README.md).
The root hash is 64 lowercase hexadecimal characters, the offset is a decimal
byte offset (a positive multiple of 4096, at most 2^62), and the verity UUID
uses lowercase hexadecimal in `8-4-4-4-12` form. `modelid`
must exactly match the identity passed to the packer, including its revision.
These values come from initdata, never from metadata inside the untrusted
pack. The agent connects the original, policy-authorized OCI bind at
`mount_path` to exactly one raw block-storage request, using Kata's block
driver constants. Kata resolves and binds the raw device without mounting
its filesystem, then the helper verifies and mounts EROFS. Node paths,
transport addresses and guest device names do not belong in this JSON.
The UUID is validated and retained in `info`; verification uses explicit
parameters without trusting the pack's verity superblock. The former
`parameters` object is no longer accepted. Regular files, character devices,
symlinks and devices with insufficient capacity are rejected.
Destinations must be normalized paths under `/models/`.
The contract is described by `schemas/model-mounts.schema.json`, with an
initdata template in `assets/model-mounts.example.toml`.

Each consuming container declares a read-only block-device volume at its
configured destination:

```yaml
volumes:
  - name: model
    hostPath:
      path: /dev/podvm-models/example
      type: BlockDevice
containers:
  - name: inference
    image: your-inference-image
    volumeMounts:
      - name: model
        mountPath: /models/example
        readOnly: true
```

Merge this entry with any existing `policy.rego`, `aa.toml`, or `cdh.toml`
entries, then [pack the complete Init-Data document](#pack-init-data) and
pass it through Kata's `io.katacontainers.config.hypervisor.cc_init_data`
annotation.

Containers can request any subset of the configured models, including none.
An init container can finish without declaring models used by later
containers. Each consumer gets its own read-only dm-linear input views,
dm-verity mappings, mount directories and cleanup journal. The input views
let the pinned modelwrap/veritysetup opener use exclusive device access
without conflicting with another consumer of the same raw device. Cleanup
releases each verity mapping before its input view and raw Kata storage;
it never detaches caller-owned devices. Removal or restart releases only that consumer's
resources; other containers can continue reading the same caller-owned
block device. Setup failure rolls back that container and permits subsequent
creation in the sandbox. Container destruction precedes model cleanup,
which precedes Kata's release of raw block storage. Sandbox teardown also
cleans up interrupted creation. Keep all model mounts read-only and avoid
`subPath`, mount propagation and overlapping mounts.

Prepare existing `.mpk` files on each eligible node, for example:

```sh
model_device=$(sudo losetup --find --show --read-only /srv/models/example.mpk)
sudo mkdir -p /dev/podvm-models
sudo ln -s "$model_device" /dev/podvm-models/example
```

This is host preparation; the guest never allocates loop devices. The node
symlink provides a stable Kubernetes path; Kata delivers the actual block
device and the guest helper opens its resolved bind without following
symlinks. Check the attachment's backing file and read-only status before
using it. For physical disks or partitions, prefer stable `/dev/disk/by-id/`
paths. Use node labels and pod node affinity to schedule only where every
requested pack is attached. Recreate attachments and stable paths during
node boot **before** making the node eligible for consuming pods; loop
numbers are not stable across reboot. Stop and remove all consuming pods
before detaching the exact host device with
`sudo losetup --detach "$model_device"`. Do not replace its backing pack while
consumers exist.
No CSI driver, StorageClass or container mount privileges are required.

For the pinned Go runtime, configure the selected hypervisor with:

```toml
shared_fs = "none"
disable_block_device_use = false
block_device_driver = "virtio-scsi" # or "virtio-blk"
```

Container images must also have a delivery route that works without shared
filesystems: use a block-backed containerd snapshotter/rootfs or Kata guest
image pulling (`image_guest_pull`) with the appropriate image and policy
configuration. An ordinary directory rootfs on overlayfs cannot be delivered
with this configuration. The smoke harness explicitly mounts its test block
filesystem to provide a block-backed rootfs.

Policy authorizes the **original** block bind and storage request. Upstream
genpolicy does not automatically emit the needed raw block-storage records
for this `hostPath` case. After generating policy, replace each consuming
container's model entry in `policy_data.containers[].OCI.Mounts` with the
`mount` object in [the block policy example](assets/model-block-policy.example.json),
adjusting its destination, and add the example's `storage` object to that
container's `storages` array for each distinct model device. Retain its
image/rootfs and other storage records. Set `policy_data.common.spath` to
`/run/kata-containers/sandbox/storage` for this pinned runtime.

The example's empty policy driver is intentional: upstream rules validate
`scsi` and `blk` transport addresses, substitute `$(b64_device_id)` from the
request, and enforce the exact raw-bind options. The empty driver follows
upstream's generic block-volume templates and lets its exact-options rule
run for either transport. The model agent separately
requires unique matching storage provenance and read-only options. The
example is tested against the pinned upstream policy rules for both drivers,
including denied storage, writable requests, and substituted internal paths.
Match the runtime's actual original options and `shared` flag if your
container delivery differs, keeping `ro` and private propagation. Do not
permit `/run/modelwrap` sources or modify genpolicy to authorize internal
verified mounts. Review the completed policy, include it in initdata, and
recreate the pod. The measured agent rewrites only configured destinations
and enforces `ro,nodev,nosuid,noexec`.

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
cover these installed components. The guest also requires `dmsetup` to
manage the owned input views. `make smoke` also exercises model mounts
with real fixture packs. After this change, rebuild the guest bundle and
remeasure it, update endorsed measurements, boot annotations and initdata
policies, and recreate consuming pods. Existing `.mpk` packs and complete
`info` strings remain valid. KVM smoke results cover ordinary VM transport
and lifecycle; SNP and TDX validation requires separate runs on the
corresponding hardware.

## Measurements and launch profiles

`config/launch-profiles.yaml` keeps CPU and GPU profiles together under one
`profiles` mapping, with shared `tdx` and `sev` settings and per-profile SNP
overrides. The CPU default remains 2 vCPUs / 8 GiB. SNP reference measurements
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
  h100-pcie-1-96g:
    cpus: 4
    memory: "96G"
    gpu: {family: H100, platform: pcie, count: 1, nvswitch_count: 0}
```

Use `--profiles path/to/profiles.yaml` or `PROFILES=...` for every stage, including
assembly and validation. Profile names are unique across the entire file.
There is no `variant` field in the configuration: the presence of `gpu`
determines the variant. `--variant` selects which profiles a stage processes.
Each bundle includes only its selected profiles and deployment examples.
An SNP CPU-model override replaces the default list and inherits other
settings. Every configured profile/model is measured twice and compared.
The SNP tool receives the exact firmware, kernel and full command line with
no `--initrd` argument. Memory remains launch metadata even when different
memory sizes produce the same SNP digest.

TDX uses the existing `tdx-measure` source with tracked patches in
`assets/patches/tdx-measure-no-initrd.patch` and
`assets/patches/tdx-measure-numa.patch`. The first patch accepts a nullable
initrd and omits the firmware's initrd command-line suffix and RTMR2 event
when none is present; the second passes concrete guest NUMA options to QEMU
for offline topology reproduction. Initrd-present behavior has regression tests. `make
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

After building, measuring, and packaging each configured variant, assemble
one release:

```sh
make all RELEASE_VERSION=dev
make all VARIANT=nvidia RELEASE_VERSION=dev
make assemble
make validate
```

The variant `package` stage writes an archive and private `catalog-part.json`
to `build/packages/cpu` or `build/packages/nvidia`. `make assemble` reads these
packages and writes four public assets to `dist` for the default mixed config:

- `podvm-ubuntu-24.04-x86_64-<version>.tar.zst`
- `podvm-nvidia-ubuntu-24.04-x86_64-<version>.tar.zst`
- `measurements.json`
- `SHA256SUMS`

For custom package locations, use repeatable CLI arguments:

```sh
python3 podvm.py assemble --profiles path/to/profiles.yaml \
  --package-dir build/custom-cpu --package-dir build/custom-nvidia \
  --dist-dir dist
python3 podvm.py validate --profiles path/to/profiles.yaml --dist-dir dist
```

The Make equivalents are `PACKAGE_DIR` for an individual package stage,
`PACKAGE_DIRS="build/custom-cpu build/custom-nvidia"` for assembly, and `DIST`
for the final output. CPU-only and GPU-only configurations use the same
commands and catalog format; assembly requires only the variants present in
the configuration. Every configured profile must have a result. Assembly
rejects incomplete or duplicate packages, inconsistent release identities,
changed profile settings/provenance, and bundle checksum mismatches. It
validates the new output before replacing an existing release.

Each bundle contains `podvm.raw`, `vmlinuz`, `kernel.config`,
`kernel_verity_params`, additional `kernel_params`, full `cmdline`, both
firmwares, annotation/configuration examples, its selected launch profiles,
the launch helper, schemas, provenance and a per-file hash manifest. There
is no qcow2 or initrd. `initrd` is explicitly null in measurement records.

The unified `measurements.json` has five top-level fields:

| Field | Contents |
| --- | --- |
| `schema` | JSON Schema URL at the immutable source revision |
| `release` | Shared version, source repository, and source revision |
| `artifacts` | Bundle name, SHA-256, and media type keyed by `cpu` or `nvidia` |
| `inputs` | Build and measurement provenance keyed by the same variants |
| `profiles` | One flat mapping of all configured profile records |

CPU records retain `tdx` and `sev`; NVIDIA records retain `gpu` and `sev`.
A record with `gpu` refers to `artifacts.nvidia` and `inputs.nvidia`; every
other record refers to `artifacts.cpu` and `inputs.cpu`. Paths inside each
record are relative to its bundle. All four TDX registers stay together,
and SNP launch digests remain keyed by guest CPU model. Equal digests do not
collapse distinct profile records.

Raw measurements fingerprint the exact disk, kernel, kernel configuration,
verity parameters, command lines, firmware, build inputs, selected profiles
and local patches; packaging rejects changes made after measurement. Each
variant's `inputs` includes those immutable inputs, local asset hashes,
measurement-tool provenance, `measurement_fingerprint`, and
`launch_profiles_sha256`. The latter hashes the selected profiles and shared
settings, enabling assembly to check the current configuration without staged
images. Changes to GPU-only profiles do not invalidate CPU measurements;
changes to shared settings affect both variants.

This replaces the previous per-variant catalog formats. Migrate GPU entries
into the shared `profiles` mapping and remove the old top-level `variant`.
Regenerate raw measurements and packages; the old NVIDIA catalog and separate
checksum file are no longer published. Catalog consumers must use `artifacts`
and variant-keyed `inputs` in place of the old singular artifact/provenance.

CI runs independent CPU and NVIDIA build-and-measure paths in parallel. The
CPU path runs the Kata smoke test. PRs, manual runs and tags all assemble and
validate the unified release after both paths succeed. Tag publication attests
and uploads only the four assembled assets. NVIDIA TDX candidate records stay
outside the release. The build and measurement jobs use the existing KVM ARC
runner group.

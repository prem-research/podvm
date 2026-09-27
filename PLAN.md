# CoCo PodVM Build, Measurement, and Release Pipeline

## Summary

Create a greenfield pipeline based on the CoCo reference-values workflow, using CoCo v0.22.0 Cloud API Adaptor as the PodVM baseline and verified binaries from guest-components. It builds one production Ubuntu 24.04 x86_64 PodVM supporting native TDX and SEV-SNP attesters, calculates measurements with tdx-measure and sev-snp-measure, and publishes only GitHub Release assets.

The published qcow2 remains suitable for normal CoCo/peer-pod image import. The supplied measurements describe the bundled fixed direct-boot QEMU profile. Provider-controlled UEFI launches require provider-specific measurements.

## Build and Input Management

- Add a validated `versions.yaml` as the single source of truth, seeded with CoCo v0.22.0, Kata Containers 4.0.0, its matching guest-components commit, pinned measurement-tool revisions, mkosi v26, container-image digests, and an Ubuntu Noble package snapshot.
- Resolve and commit immutable OCI digests for Kata agent, TDX and AMD/SNP attestation-agent artifacts, TDX and SNP firmware, confidential-data-hub, api-server-rest, pause image, and build images. Verify upstream GitHub artifact attestations before extraction.
- Add a `podvm.py` CLI with `verify`, `build`, `measure`, `package`, and `all` commands and matching Make targets. Reject mutable tags, abbreviated commits, digest mismatches, missing attestations, or unsafe output paths.
- Build from pinned Cloud API Adaptor source using `ARCH=x86_64`, the verified TDX guest-components input, `VERIFY_PROVENANCE=yes`, and the production Ubuntu 24.04 mkosi profile; add the separately verified SNP agent before mkosi assembles the image.
- Include kata-agent, agent-protocol-forwarder, attestation-agent, confidential-data-hub, api-server-rest, process-user-data, pause bundle, policies, configuration, and systemd units.
- Export qcow2, kernel, initrd, and the exact UKI command line. Require the command line to contain the dm-verity root hash.

## Release and Measurement Contract

- Use a fixed direct-boot profile with 2 vCPUs and 8 GiB.
- Calculate TDX `mr_td`, `rtmr_0`, `rtmr_1`, and `rtmr_2` with tdx-measure.
- Calculate the SEV-SNP launch measurement with sev-snp-measure using QEMU, `EPYC-v4`, two vCPUs, and guest features `0x1`.
- Publish `podvm-ubuntu-24.04-x86_64-${TAG}.tar.zst`, `measurements.json`, and `SHA256SUMS` as the only GitHub Release assets.
- Include qcow2, kernel, initrd, command line, both firmware files, launch configurations, a launch helper, per-file hashes, source revisions, and licenses in the bundle.
- Make `measurements.json` self-describing and include Trustee/RVPS mappings for `mr_td`, `rtmr_0`, `rtmr_1`, `rtmr_2`, and `snp_launch_measurement`.

## CI, Publishing, and Tests

- Run the full verify, build, boot-smoke, measurement, and packaging path on pull requests, manual dispatch, and published releases.
- Publish only for `release: published`; use minimal permissions, immutable action references, and no OCI output.
- Validate image structure, guest binaries and services, direct boot, measurement sizes and determinism, JSON schema, checksums, release tag consistency, and GitHub artifact attestations.

## Assumptions

- The artifact is x86_64 Ubuntu 24.04, contains one dual-TEE guest, and targets Intel TDX plus AMD SEV-SNP.
- The host supplies compatible QEMU/KVM and TEE hardware.
- GitHub-hosted x64 runners expose `/dev/kvm`; measurement jobs fail clearly when it is unavailable.
- Dependency updates occur through reviewed changes to `versions.yaml`.

## Implementation Notes

- CoCo v0.22.0 did not publish a combined all-attesters OCI artifact. The build
  installs the separately attested TDX and AMD/SNP attestation-agent artifacts
  and selects the correct binary from the guest device at service startup.
- The fixed disk topology uses a virtio-SCSI PCI controller. The measurement
  shape includes the controller; the runtime adds the non-PCI SCSI disk backed
  by the bundled qcow2, which does not change PCI or ACPI topology.

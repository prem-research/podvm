#!/usr/bin/env python3
"""Build, measure, validate, and package a dual-TEE CoCo PodVM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "versions.yaml"
DEFAULT_PROFILES = ROOT / "config" / "launch-profiles.yaml"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX384 = re.compile(r"^[0-9a-f]{96}$")
PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MEMORY_SIZE = re.compile(r"^[1-9][0-9]*[MG]$")
GUEST_FEATURES = re.compile(r"^0x[0-9a-f]+$")
SNP_VCPU_TYPES = {
    "EPYC",
    "EPYC-v1",
    "EPYC-v2",
    "EPYC-IBPB",
    "EPYC-v3",
    "EPYC-v4",
    "EPYC-Rome",
    "EPYC-Rome-v1",
    "EPYC-Rome-v2",
    "EPYC-Rome-v3",
    "EPYC-Milan",
    "EPYC-Milan-v1",
    "EPYC-Milan-v2",
    "EPYC-Genoa",
    "EPYC-Genoa-v1",
    "EPYC-Turin",
}
REQUIRED_GUEST_FILES = (
    "usr/local/bin/kata-agent",
    "usr/local/bin/attestation-agent",
    "usr/local/bin/confidential-data-hub",
    "usr/local/bin/api-server-rest",
)


class PodVMError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"podvm: {message}", file=sys.stderr, flush=True)


class ConfigurationLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate and non-string mapping keys."""


def configuration_mapping(loader: ConfigurationLoader, node: yaml.MappingNode) -> dict[str, Any]:
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in mapping:
            raise yaml.constructor.ConstructorError(
                None, None, f"invalid or duplicate configuration key: {key!r}", key_node.start_mark
            )
        mapping[key] = loader.construct_object(value_node)
    return mapping


ConfigurationLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, configuration_mapping
)


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.load(path.read_text(), Loader=ConfigurationLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise PodVMError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PodVMError(f"{path} must contain a configuration mapping")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise PodVMError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PodVMError(f"{path} must contain a JSON object")
    return value


def dump_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise PodVMError(f"required command is unavailable: {name}")
    return found


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    log("+ " + " ".join(command))
    merged = os.environ.copy()
    if env:
        merged.update(env)
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=merged,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        raise PodVMError(
            f"command failed ({exc.returncode}): {' '.join(command)}"
            + (f"\n{detail}" if detail else "")
        ) from exc


def capture(command: list[str], *, cwd: Path | None = None) -> str:
    return run(command, cwd=cwd, capture=True).stdout.strip()


def safe_clean(path: Path, allowed_root: Path) -> None:
    resolved = path.resolve()
    root = allowed_root.resolve()
    if resolved == root or root not in resolved.parents:
        raise PodVMError(f"refusing to remove unsafe path: {resolved}")
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True)


def validate_lock(config: dict[str, Any]) -> None:
    if set(config) != {"platform", "build_inputs", "sources", "oci"}:
        raise PodVMError("versions.yaml has an invalid top-level shape")
    platform = config.get("platform", {})
    if (platform.get("architecture"), platform.get("distribution"), platform.get("release")) != (
        "x86_64",
        "ubuntu",
        "24.04",
    ):
        raise PodVMError("only the locked Ubuntu 24.04 x86_64 platform is supported")
    build_inputs = config.get("build_inputs", {})
    if not re.fullmatch(r"rust@sha256:[0-9a-f]{64}", build_inputs.get("rust_container", "")):
        raise PodVMError("Rust measurement builder must be locked by digest")
    if build_inputs.get("ubuntu_container") != (
        "ubuntu@sha256:0d39fcc8335d6d74d5502f6df2d30119ff4790ebbb60b364818d5112d9e3e932"
    ):
        raise PodVMError("the CAA v0.22.0 Ubuntu builder image digest is not locked")
    for name, source in config.get("sources", {}).items():
        revision = source.get("revision", "")
        if not HEX40.fullmatch(revision):
            raise PodVMError(f"sources.{name}.revision must be a full lowercase commit SHA")
        if not str(source.get("repository", "")).startswith("https://github.com/"):
            raise PodVMError(f"sources.{name}.repository must be an HTTPS GitHub URL")
    for name in ("tdx_measure", "sev_snp_measure"):
        artifact = config.get("sources", {}).get(name, {}).get("artifact", {})
        if not str(artifact.get("url", "")).startswith("https://"):
            raise PodVMError(f"sources.{name}.artifact.url must be an HTTPS URL")
        if not re.fullmatch(r"[0-9a-f]{64}", artifact.get("sha256", "")):
            raise PodVMError(f"sources.{name}.artifact.sha256 must be a SHA-256 digest")
    required_oci = {
        "kata_agent",
        "attestation_agent_tdx",
        "attestation_agent_snp",
        "confidential_data_hub",
        "api_server_rest",
        "ovmf_tdx",
        "ovmf_snp",
        "pause",
        "kernel", "runtime", "qemu", "virtiofsd",
    }
    if set(config.get("oci", {})) != required_oci:
        raise PodVMError("versions.yaml OCI input set is incomplete or contains unknown inputs")
    for name, item in config["oci"].items():
        provenance = item.get("provenance", "required")
        if provenance != "required" and not (name == "runtime" and provenance == "digest-only-smoke"):
            raise PodVMError(f"oci.{name} cannot bypass upstream attestation verification")
        if name != "pause" and not (item.get("source_repository") and item.get("source_revision")):
            raise PodVMError(f"oci.{name} requires upstream source provenance metadata")
        if not DIGEST.fullmatch(item.get("digest", "")):
            raise PodVMError(f"oci.{name}.digest must be a sha256 digest")
        if not item.get("repository") or not item.get("tag"):
            raise PodVMError(f"oci.{name} requires repository and tag")
        source_revision = item.get("source_revision")
        if source_revision is not None and not HEX40.fullmatch(source_revision):
            raise PodVMError(f"oci.{name}.source_revision must be a full commit SHA")


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise PodVMError(f"{label} must contain exactly {sorted(expected)}")
    return value


def require_string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise PodVMError(f"{label} must be a list of non-empty strings")
    return value


def validate_profile_dimensions(profile_id: str, profile: dict[str, Any], label: str) -> None:
    if not isinstance(profile_id, str) or not PROFILE_ID.fullmatch(profile_id):
        raise PodVMError(f"{label} profile ID is invalid: {profile_id!r}")
    cpus = profile.get("cpus")
    if not isinstance(cpus, int) or isinstance(cpus, bool) or cpus < 1:
        raise PodVMError(f"{label}.{profile_id}.cpus must be a positive integer")
    memory = profile.get("memory")
    if not isinstance(memory, str) or not MEMORY_SIZE.fullmatch(memory):
        raise PodVMError(f"{label}.{profile_id}.memory must use a canonical M or G size")


def validate_profiles(profiles: dict[str, Any]) -> None:
    require_exact_keys(profiles, {"tdx", "sev", "profiles"}, "launch profiles")
    tdx = require_exact_keys(
        profiles["tdx"],
        {"acpi_distribution", "qemu_source_version", "qemu"},
        "tdx",
    )
    if not all(isinstance(tdx[name], str) and tdx[name] for name in ("acpi_distribution", "qemu_source_version")):
        raise PodVMError("TDX ACPI distribution and QEMU source version must be non-empty strings")
    tdx_qemu = require_exact_keys(
        tdx["qemu"],
        {
            "measurement_machine",
            "runtime_machine",
            "cpu",
            "accel",
            "measurement_objects",
            "runtime_objects",
            "netdevs",
            "measurement_netdevs",
            "measurement_devices",
            "runtime_devices",
        },
        "tdx.qemu",
    )
    for name in ("measurement_machine", "runtime_machine", "cpu", "accel"):
        if not isinstance(tdx_qemu[name], str) or not tdx_qemu[name]:
            raise PodVMError(f"tdx.qemu.{name} must be a non-empty string")
    for name in (
        "measurement_objects",
        "runtime_objects",
        "netdevs",
        "measurement_netdevs",
        "measurement_devices",
        "runtime_devices",
    ):
        require_string_list(tdx_qemu[name], f"tdx.qemu.{name}")
    catalog = profiles["profiles"]
    if not isinstance(catalog, dict) or not catalog:
        raise PodVMError("profiles must contain at least one profile")
    for profile_id, profile in catalog.items():
        if not isinstance(profile, dict) or not {"cpus", "memory"} <= set(profile) <= {"cpus", "memory", "sev"}:
            raise PodVMError(f"profiles.{profile_id} requires cpus, memory, and optional sev")
        validate_profile_dimensions(profile_id, profile, "profiles")
        if profile["cpus"] > 255:
            raise PodVMError(f"profiles.{profile_id}.cpus exceeds the TDX measurement-tool limit")
        if "sev" in profile:
            validate_snp_settings(profile["sev"], f"profiles.{profile_id}.sev", partial=True)

    snp = require_exact_keys(profiles["sev"], {"qemu", "defaults"}, "sev")
    snp_qemu = require_exact_keys(
        snp["qemu"],
        {"machine", "memory_backend", "guest", "netdevs", "runtime_devices"},
        "sev.qemu",
    )
    if not isinstance(snp_qemu["machine"], str) or not snp_qemu["machine"]:
        raise PodVMError("sev.qemu.machine must be a non-empty string")
    memory_backend = require_exact_keys(
        snp_qemu["memory_backend"], {"id", "share", "prealloc"}, "sev.qemu.memory_backend"
    )
    if not isinstance(memory_backend["id"], str) or not memory_backend["id"]:
        raise PodVMError("sev.qemu.memory_backend.id must be a non-empty string")
    if not all(isinstance(memory_backend[name], bool) for name in ("share", "prealloc")):
        raise PodVMError("SEV-SNP memory backend flags must be booleans")
    guest = require_exact_keys(
        snp_qemu["guest"],
        {"id", "cbitpos", "reduced_phys_bits", "kernel_hashes"},
        "sev.qemu.guest",
    )
    if not isinstance(guest["id"], str) or not guest["id"]:
        raise PodVMError("sev.qemu.guest.id must be a non-empty string")
    if not all(isinstance(guest[name], int) and not isinstance(guest[name], bool) for name in ("cbitpos", "reduced_phys_bits")):
        raise PodVMError("SEV-SNP cbitpos and reduced_phys_bits must be integers")
    if not isinstance(guest["kernel_hashes"], bool):
        raise PodVMError("sev.qemu.guest.kernel_hashes must be a boolean")
    for name in ("netdevs", "runtime_devices"):
        require_string_list(snp_qemu[name], f"sev.qemu.{name}")
    if tdx_qemu["runtime_devices"] != snp_qemu["runtime_devices"]:
        raise PodVMError("TDX and SEV-SNP runtime device order must match")
    if tdx_qemu["netdevs"] != snp_qemu["netdevs"]:
        raise PodVMError("TDX and SEV-SNP runtime network backends must match")
    if tdx_qemu["measurement_netdevs"] != ["hubport,id=network0,hubid=0"]:
        raise PodVMError("TDX ACPI generation must use the release QEMU hubport backend")
    measurement_devices = [
        device.replace(",romfile=", "") for device in tdx_qemu["measurement_devices"]
    ]
    runtime_pci_devices = [
        device for device in tdx_qemu["runtime_devices"] if not device.startswith("scsi-hd,")
    ]
    if measurement_devices != runtime_pci_devices:
        raise PodVMError("TDX ACPI devices must match runtime devices except for disabled option ROMs")
    if f"memory-backend={memory_backend['id']}" not in snp_qemu["machine"]:
        raise PodVMError("SEV-SNP machine does not reference its memory backend")
    if f"confidential-guest-support={guest['id']}" not in snp_qemu["machine"]:
        raise PodVMError("SEV-SNP machine does not reference its guest object")

    validate_snp_settings(snp["defaults"], "sev.defaults")
    for profile_id in catalog:
        validate_snp_settings(snp_settings(profiles, profile_id), f"profiles.{profile_id}.sev")


def validate_snp_settings(settings: Any, label: str, *, partial: bool = False) -> None:
    expected = {"vcpu_types", "vmm_type", "guest_features"}
    if not isinstance(settings, dict):
        raise PodVMError(f"{label} must be a mapping")
    valid_keys = set(settings) <= expected if partial else set(settings) == expected
    if not valid_keys:
        raise PodVMError(f"{label} must contain {'only ' if partial else ''}{sorted(expected)}")
    if "vcpu_types" in settings:
        models = require_string_list(settings["vcpu_types"], f"{label}.vcpu_types")
        if not models or len(set(models)) != len(models):
            raise PodVMError(f"{label}.vcpu_types must be non-empty and unique")
        for model in models:
            if model not in SNP_VCPU_TYPES:
                raise PodVMError(f"unsupported SEV-SNP vcpu_type: {model!r}")
    if "vmm_type" in settings and settings["vmm_type"] != "QEMU":
        raise PodVMError("the bundled launcher supports only the QEMU SEV-SNP VMM type")
    if "guest_features" in settings:
        features = settings["guest_features"]
        if not isinstance(features, str) or not GUEST_FEATURES.fullmatch(features):
            raise PodVMError(f"{label}.guest_features must be quoted lowercase hex")


def snp_settings(profiles: dict[str, Any], profile_id: str) -> dict[str, Any]:
    return {**profiles["sev"]["defaults"], **profiles["profiles"][profile_id].get("sev", {})}


def resolved_profile(
    profiles: dict[str, Any], profile_id: str, tee: str, cpu_model: str | None = None
) -> dict[str, Any]:
    profile = profiles["profiles"][profile_id]
    resolved = {"cpus": profile["cpus"], "memory": profile["memory"]}
    if tee == "tdx":
        return resolved
    if tee != "sev":
        raise PodVMError(f"unsupported TEE: {tee!r}")
    settings = snp_settings(profiles, profile_id)
    if cpu_model not in settings["vcpu_types"]:
        raise PodVMError(f"CPU model {cpu_model!r} is not endorsed for profile {profile_id}")
    return {
        **resolved,
        "vcpu_type": cpu_model,
        "vmm_type": settings["vmm_type"],
        "guest_features": settings["guest_features"],
    }


def oci_tag_ref(item: dict[str, Any]) -> str:
    return f"{item['repository']}:{item['tag']}"


def oci_digest_ref(item: dict[str, Any]) -> str:
    return f"{item['repository']}@{item['digest']}"


def verify_oci(config: dict[str, Any], provenance: bool) -> None:
    require_tool("oras")
    for name, item in config["oci"].items():
        resolved = capture(["oras", "resolve", oci_tag_ref(item)]).splitlines()[-1]
        if resolved != item["digest"]:
            raise PodVMError(
                f"OCI tag drift for {name}: locked {item['digest']}, registry returned {resolved}"
            )
        log(f"verified OCI digest: {name} {resolved}")
        if provenance and item.get("provenance") == "digest-only-smoke":
            log(f"{name}: digest-verified smoke tooling; upstream shim job publishes no attestation")
        elif provenance and item.get("source_repository"):
            verify_attestation(name, item)


def verify_attestation(name: str, item: dict[str, Any]) -> None:
    require_tool("gh")
    expected = item["source_revision"]
    matches = []
    subject = oci_digest_ref(item)
    try:
        discovery = json.loads(capture(["oras", "discover", subject, "--format", "json"]))
    except json.JSONDecodeError as exc:
        raise PodVMError(f"invalid OCI referrer discovery output for {name}") from exc
    manifests = [
        entry
        for entry in discovery.get("manifests", [])
        if "sigstore.bundle" in str(entry.get("artifactType", ""))
    ]
    if not manifests:
        raise PodVMError(f"{name} has no Sigstore attestation referrer")
    with tempfile.TemporaryDirectory(prefix="podvm-attestation-") as temporary:
        for manifest_index, manifest in enumerate(manifests):
            manifest_ref = f"{item['repository']}@{manifest['digest']}"
            try:
                descriptor = json.loads(
                    capture(["oras", "manifest", "fetch", manifest_ref, "--format", "json"])
                )
            except json.JSONDecodeError as exc:
                raise PodVMError(f"invalid attestation manifest for {name}") from exc
            layers = [
                layer
                for layer in descriptor.get("content", descriptor).get("layers", [])
                if "sigstore.bundle" in str(layer.get("mediaType", ""))
            ]
            for layer_index, layer in enumerate(layers):
                bundle = Path(temporary) / f"{manifest_index}-{layer_index}.jsonl"
                run(
                    [
                        "oras",
                        "blob",
                        "fetch",
                        "--no-tty",
                        f"{item['repository']}@{layer['digest']}",
                        "--output",
                        str(bundle),
                    ]
                )
                output = capture(
                    [
                        "gh",
                        "attestation",
                        "verify",
                        "oci://" + subject,
                        "--bundle",
                        str(bundle),
                        "--repo",
                        item["source_repository"],
                        "--format",
                        "json",
                    ]
                )
                try:
                    attestations = json.loads(output)
                except json.JSONDecodeError as exc:
                    raise PodVMError(f"invalid gh attestation output for {name}") from exc
                for entry in attestations if isinstance(attestations, list) else []:
                    cert = (
                        entry.get("verificationResult", {})
                        .get("signature", {})
                        .get("certificate", {})
                    )
                    if (
                        cert.get("sourceRepositoryDigest") == expected
                        and cert.get("githubWorkflowSHA") == expected
                        and cert.get("githubWorkflowRef") == "refs/heads/main"
                        and cert.get("githubWorkflowTrigger") in {"push", "workflow_dispatch"}
                        and cert.get("runnerEnvironment") == "github-hosted"
                    ):
                        matches.append(cert)
    if not matches:
        raise PodVMError(f"{name} has no acceptable GitHub-hosted attestation for {expected}")
    log(f"verified upstream provenance: {name}")


def clone_exact(source: dict[str, Any], destination: Path) -> None:
    destination.mkdir(parents=True)
    run(["git", "init", "--quiet"], cwd=destination)
    run(["git", "remote", "add", "origin", source["repository"]], cwd=destination)
    run(["git", "fetch", "--depth=1", "origin", source["revision"]], cwd=destination)
    run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=destination)
    actual = capture(["git", "rev-parse", "HEAD"], cwd=destination)
    if actual != source["revision"]:
        raise PodVMError(f"source checkout mismatch: expected {source['revision']}, got {actual}")


def patch_caa(caa: Path, config: dict[str, Any]) -> None:
    podvm = caa / "src" / "cloud-api-adaptor" / "podvm"
    dockerfile = podvm / "Dockerfile.mkosi"
    text = dockerfile.read_text()
    expected_base = "FROM " + config["build_inputs"]["ubuntu_container"] + " AS builder"
    if expected_base not in text:
        raise PodVMError("CAA mkosi builder base does not match versions.yaml")
    binaries_dockerfile = (podvm / "Dockerfile.podvm_binaries").read_text()
    if expected_base not in binaries_dockerfile:
        raise PodVMError("CAA binaries builder base does not match versions.yaml")
    upstream_versions = (caa / "src" / "cloud-api-adaptor" / "versions.yaml").read_text()
    expected_tool_lines = (
        f"golang: {config['build_inputs']['go']}",
        f"mkosi: {config['build_inputs']['mkosi']}",
        f"oras: {config['build_inputs']['oras']}",
        f"protoc: {config['build_inputs']['protoc']}",
    )
    if any(line not in upstream_versions for line in expected_tool_lines):
        raise PodVMError("CAA build tool versions do not match versions.yaml")
    old_clone = 'RUN git clone -b "$MKOSI_VERSION" https://github.com/systemd/mkosi'
    new_clone = (
        'RUN git init mkosi && git -C mkosi remote add origin https://github.com/systemd/mkosi '
        '&& git -C mkosi fetch --depth=1 origin "$MKOSI_VERSION" '
        '&& git -C mkosi reset --hard FETCH_HEAD'
    )
    if old_clone not in text or "COPY --from=builder /image/build/system.raw /" not in text:
        raise PodVMError("pinned CAA Dockerfile no longer matches the expected v0.22.0 layout")
    text = text.replace(old_clone, new_clone)
    text = text.replace("COPY --from=builder /image/build/system.raw /", "COPY --from=builder /image/build/ /")
    dockerfile.write_text(text)

    mkosi_conf = podvm / "mkosi.conf"
    text = mkosi_conf.read_text()
    marker = "Release=noble\n"
    if marker not in text:
        raise PodVMError("cannot configure the Ubuntu snapshot in mkosi.conf")
    snapshot = config["platform"]["snapshot"]
    text = text.replace(marker, marker + f"Snapshot={snapshot}\n")
    mkosi_conf.write_text(text)

    system = podvm / "mkosi.images" / "system"
    (system / "mkosi.conf").write_text(
        "[Content]\nBootable=no\n[Output]\nFormat=directory\nOutput=system\nManifestFormat=json\n"
    )
    ubuntu = system / "mkosi.conf.d" / "ubuntu.conf"
    # A non-bootable mkosi directory does not add an init provider automatically.
    # Ubuntu ships /sbin/init in systemd-sysv, separately from systemd itself.
    ubuntu.write_text(ubuntu.read_text().replace("    linux-image-generic\n", "    systemd-sysv\n"))
    (system / "mkosi.conf.d/ubuntu-bootable.conf").unlink()
    # Discard cloud platform presets, repart definitions and unit drop-ins.
    skeleton = system / "mkosi.skeleton"
    for relative in ("usr/lib/systemd/system", "usr/lib/systemd/system-preset", "usr/lib/repart.d"):
        shutil.rmtree(skeleton / relative)
    # A directory rootfs needs neither the CAA UKI nor its initrd dependency.
    shutil.rmtree(podvm / "mkosi.images" / "initrd")
    finalize = system / "mkosi.finalize.chroot"
    text = finalize.read_text().split("# Conditional SFTP support:")[0]
    finalize.write_text(text + "\nsystemctl set-default kata-containers.target\n")
    makefile = podvm / "Makefile"
    text = makefile.read_text()
    conversion = "\tqemu-img convert -f raw -O qcow2 build/system.raw build/podvm-ubuntu-$(DISTRO_ARCH).qcow2\n"
    if conversion not in text:
        raise PodVMError("pinned CAA image conversion changed")
    makefile.write_text(text.replace(conversion, ""))


def patch_image_builder(kata: Path) -> None:
    run(["git", "apply", str(ROOT / "assets/patches/kata-image-builder-errors.patch")], cwd=kata)
    shutil.copy2(ROOT / "assets/image-builder-loop.sh",
                 kata / "tools/osbuilder/image-builder/podvm-loop.sh")


def install_local_guest(podvm: Path, kata: Path) -> None:
    tree = podvm / "resources" / "binaries-tree"
    units = tree / "etc/systemd/system"
    units.mkdir(parents=True, exist_ok=True)
    # The CAA overlay owns these units: replace its peerpod boot orchestration.
    for path in list(units.iterdir()):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    for name in ("agent-protocol-forwarder", "process-user-data", "kata-agent-clean", "setup-nat-for-imds.sh",
                 "setup-scratch-storage", "luks-encrypt-storage"):
        (tree / "usr/local/bin" / name).unlink(missing_ok=True)
    shutil.copytree(ROOT / "assets/guest", tree, dirs_exist_ok=True)
    for name in ("auth.conf", "policy.conf"):
        (tree / "etc/tmpfiles.d" / name).unlink(missing_ok=True)
    policy = tree / "etc/kata-opa/default-policy.rego"
    policy.unlink(missing_ok=True)
    policy.symlink_to("allow-all.rego")
    service = (kata / "src/agent/kata-agent.service.in").read_text()
    service = service.replace("@BINDIR@/@AGENT_NAME@", "/usr/local/bin/kata-agent --config /etc/agent-config.toml")
    (units / "kata-agent.service").write_text(service)
    target = (kata / "src/agent/kata-containers.target").read_text()
    target += "Requires=var.mount\nWants=attestation-agent.service confidential-data-hub.service api-server-rest.service\n"
    (units / "kata-containers.target").write_text(target)
    preset = tree / "etc/systemd/system-preset/30-coco.preset"
    preset.parent.mkdir(parents=True, exist_ok=True)
    preset.write_text("disable *\n")


def verity_fields(value: str) -> dict[str, str]:
    try:
        pairs = [item.split("=", 1) for item in value.strip().split(",")]
        fields = dict(pairs)
    except ValueError as exc:
        raise PodVMError("invalid kernel_verity_params") from exc
    expected = {"root_hash", "salt", "data_blocks", "data_block_size", "hash_block_size"}
    if len(pairs) != 5 or set(fields) != expected:
        raise PodVMError("kernel_verity_params requires exactly five Kata verity fields")
    if not re.fullmatch(r"[0-9a-f]{64}", fields["root_hash"]) or not re.fullmatch(r"[0-9a-f]+", fields["salt"]):
        raise PodVMError("invalid verity root hash or salt")
    for name in ("data_blocks", "data_block_size", "hash_block_size"):
        if not fields[name].isdigit() or int(fields[name]) <= 0:
            raise PodVMError(f"invalid verity {name}")
    if int(fields["data_block_size"]) % 512:
        raise PodVMError("verity data block size must be a multiple of 512")
    return fields


ADDITIONAL_KERNEL_PARAMS = "cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1"


def kata_cmdline(verity: str) -> str:
    v = verity_fields(verity)
    sectors = int(v["data_blocks"]) * (int(v["data_block_size"]) // 512)
    dm = (f"dm-verity,,,ro,0 {sectors} verity 1 /dev/vda1 /dev/vda2 "
          f"{v['data_block_size']} {v['hash_block_size']} {v['data_blocks']} 0 sha256 {v['root_hash']} {v['salt']}")
    return ("tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1 "
            "i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 noreplace-smp reboot=k "
            "cryptomgr.notests net.ifnames=0 pci=lastbus=0 "
            f'dm-mod.create="{dm}" root=/dev/dm-0 rootflags=data=ordered,errors=remount-ro '
            "ro rootfstype=ext4 console=hvc0 console=hvc1 quiet systemd.show_status=false "
            "panic=1 selinux=0 systemd.unit=kata-containers.target "
            "systemd.mask=systemd-networkd.service systemd.mask=systemd-networkd.socket "
            "scsi_mod.scan=none agent.launch_process_timeout=6 " + ADDITIONAL_KERNEL_PARAMS)


def install_kernel(staging: Path, config: dict[str, Any], temp: Path) -> None:
    pulled, unpacked = temp / "kernel", temp / "kernel-unpacked"
    pull_oci(config["oci"]["kernel"], pulled)
    extract_archive(only_archive(pulled), unpacked)
    for pattern, output in (("vmlinuz-*", "vmlinuz"), ("config-*", "kernel.config")):
        candidates = [p for p in unpacked.rglob(pattern) if p.is_file() and not p.is_symlink()]
        if len(candidates) != 1:
            raise PodVMError(f"cannot uniquely locate Kata {output}")
        shutil.copy2(candidates[0], staging / output)
    text = (staging / "kernel.config").read_text()
    for name in ("EXT4_FS", "VIRTIO_BLK", "VIRTIO_PCI", "BLK_DEV_DM", "DM_INIT", "DM_VERITY",
                 "VIRTIO_VSOCKETS", "SEV_GUEST", "INTEL_TDX_GUEST", "TDX_GUEST_DRIVER"):
        if f"CONFIG_{name}=y\n" not in text:
            raise PodVMError(f"Kata kernel requires CONFIG_{name}=y for initrd-free boot")


def validate_rootfs(rootfs: Path) -> None:
    systemd = rootfs / "usr/lib/systemd/systemd"
    if not systemd.is_file() or not os.access(systemd, os.X_OK):
        raise PodVMError("mkosi rootfs is missing executable /usr/lib/systemd/systemd")
    init = rootfs / "sbin/init"
    # Ubuntu uses merged /usr. Accept its init symlink even when an absolute
    # link cannot resolve outside the guest, as Kata's rootfs check does.
    if not init.is_symlink() and not os.access(init, os.X_OK):
        raise PodVMError("mkosi rootfs is missing /sbin/init; install systemd-sysv in the guest")


def build_raw_image(rootfs: Path, kata: Path, staging: Path, config: dict[str, Any]) -> None:
    validate_rootfs(rootfs)
    image = "podvm-image-builder:" + config["sources"]["kata_containers"]["revision"][:12]
    run(["docker", "build", "--build-arg", f"BUILDER={config['build_inputs']['ubuntu_container']}",
         "-f", str(ROOT / "assets/image-builder.Dockerfile"), "-t", image, str(ROOT / "assets")])
    run(["docker", "run", "--rm", "--privileged", "-v", "/dev:/dev",
         "-v", f"{rootfs.resolve()}:/rootfs:ro",
         "-v", f"{kata.resolve()}:/kata:ro", "-v", f"{staging.resolve()}:/output",
         "-e", "MEASURED_ROOTFS=yes", "-e", "SKIP_DAX_HEADER=yes", "-e", "AGENT_INIT=no",
         "-e", "BUILD_VARIANT=local", "-e", f"USER={os.getuid()}", "-e", f"GROUP={os.getgid()}",
         image, "-f", "ext4", "-o", "/output/podvm.raw", "/rootfs"])
    verity = staging / "root_hash_local.txt"
    verity.rename(staging / "kernel_verity_params")
    params = (staging / "kernel_verity_params").read_text().strip()
    (staging / "cmdline").write_text(kata_cmdline(params) + "\n")
    (staging / "kernel_params").write_text(ADDITIONAL_KERNEL_PARAMS + "\n")


def pull_oci(item: dict[str, Any], destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    run(["oras", "pull", "--output", str(destination), oci_digest_ref(item)])


def extract_archive(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    if archive.name.endswith(".tar.zst"):
        run(["tar", "--zstd", "-xf", str(archive), "-C", str(destination)])
    elif archive.name.endswith((".tar.xz", ".tar.gz", ".tgz", ".tar")):
        run(["tar", "-xf", str(archive), "-C", str(destination)])
    else:
        raise PodVMError(f"unsupported OCI payload: {archive}")


def only_archive(directory: Path) -> Path:
    archives = [p for p in directory.rglob("*") if p.is_file() and ".tar" in p.name]
    if len(archives) != 1:
        raise PodVMError(f"expected one archive in {directory}, found {len(archives)}")
    return archives[0]


def install_dual_attester(podvm: Path, config: dict[str, Any], temp: Path) -> None:
    tree = podvm / "resources" / "binaries-tree"
    tdx = tree / "usr" / "local" / "bin" / "attestation-agent"
    if not tdx.is_file():
        raise PodVMError("CAA did not produce the TDX attestation-agent")
    libexec = tree / "usr" / "local" / "libexec"
    libexec.mkdir(parents=True, exist_ok=True)
    shutil.move(tdx, libexec / "attestation-agent-tdx")

    pull_dir = temp / "snp-attester"
    pull_oci(config["oci"]["attestation_agent_snp"], pull_dir)
    unpack = temp / "snp-attester-unpacked"
    extract_archive(only_archive(pull_dir), unpack)
    candidates = [p for p in unpack.rglob("attestation-agent") if p.is_file()]
    if len(candidates) != 1:
        raise PodVMError("cannot locate the SEV-SNP attestation-agent payload")
    shutil.copy2(candidates[0], libexec / "attestation-agent-snp")
    shutil.copy2(ROOT / "assets" / "attestation-agent-dispatcher", tdx)
    for executable in (tdx, libexec / "attestation-agent-tdx", libexec / "attestation-agent-snp"):
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    for relative in REQUIRED_GUEST_FILES:
        if not (tree / relative).is_file():
            raise PodVMError(f"guest payload is missing {relative}")


def install_firmware(staging: Path, config: dict[str, Any], temp: Path) -> None:
    firmware_dir = staging / "firmware"
    firmware_dir.mkdir(parents=True, exist_ok=True)
    for key, output_name, names in (
        ("ovmf_tdx", "OVMF.inteltdx.fd", ("OVMF.inteltdx.fd",)),
        ("ovmf_snp", "AMDSEV.fd", ("AMDSEV.fd", "OVMF.fd")),
    ):
        pulled = temp / key
        unpacked = temp / f"{key}-unpacked"
        pull_oci(config["oci"][key], pulled)
        extract_archive(only_archive(pulled), unpacked)
        candidates = [p for p in unpacked.rglob("*") if p.is_file() and p.name in names]
        if len(candidates) != 1:
            raise PodVMError(f"cannot uniquely locate firmware for {key}")
        shutil.copy2(candidates[0], firmware_dir / output_name)


def build(args: argparse.Namespace, config: dict[str, Any], profiles: dict[str, Any]) -> None:
    for tool in ("git", "docker", "oras", "tar"):
        require_tool(tool)
    verify_oci(config, provenance=True)
    work, staging = args.work_dir.resolve(), args.staging_dir.resolve()
    safe_clean(work, args.workspace)
    safe_clean(staging, args.workspace)
    caa, kata = work / "cloud-api-adaptor", work / "kata-containers"
    clone_exact(config["sources"]["cloud_api_adaptor"], caa)
    clone_exact(config["sources"]["kata_containers"], kata)
    patch_image_builder(kata)
    patch_caa(caa, config)
    podvm = caa / "src/cloud-api-adaptor/podvm"
    env = {"ARCH": "x86_64", "TEE_PLATFORM": "tdx", "VERIFY_PROVENANCE": "yes",
           "MKOSI_VERSION": config["sources"]["mkosi"]["revision"]}
    run(["make", "podvm-binaries"], cwd=podvm, env=env)
    install_dual_attester(podvm, config, work / "oci")
    install_local_guest(podvm, kata)
    run(["make", "image"], cwd=podvm, env=env)
    rootfs = podvm / "build/system"
    build_raw_image(rootfs, kata, staging, config)
    install_kernel(staging, config, work / "oci")
    install_firmware(staging, config, work / "oci")
    dump_json(staging / "inputs.json", {
        "platform": config["platform"], "build_inputs": config["build_inputs"],
        "sources": config["sources"], "oci": config["oci"],
        "local_assets": local_asset_hashes(),
    })
    write_kata_examples(staging, profiles)
    validate_staging(staging)
    verify_oci(config, provenance=False)
    log(f"PodVM staged at {staging}")


def local_asset_hashes() -> dict[str, str]:
    return {p.relative_to(ROOT).as_posix(): sha256(p)
            for p in sorted((ROOT / "assets").rglob("*")) if p.is_file()}


def tdx_tool_provenance(config: dict[str, Any]) -> dict[str, Any]:
    return {"source": config["sources"]["tdx_measure"],
            "patch_sha256": sha256(ROOT / "assets/patches/tdx-measure-no-initrd.patch"),
            "builder": config["build_inputs"]["rust_container"],
            "qemu_source": config["sources"]["qemu"]}


def install_tools(args: argparse.Namespace, config: dict[str, Any], profiles: dict[str, Any]) -> None:
    del profiles
    require_tool("docker")
    destination = ROOT / ".work/bin"
    destination.mkdir(parents=True, exist_ok=True)
    source = ROOT / ".work/tools/tdx-source"
    if source.exists():
        shutil.rmtree(source)
    clone_exact(config["sources"]["tdx_measure"], source)
    run(["git", "apply", str(ROOT / "assets/patches/tdx-measure-no-initrd.patch")], cwd=source)
    command = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
               "-e", "CARGO_HOME=/src/.cargo", "-v", f"{source}:/src", "-w", "/src",
               config["build_inputs"]["rust_container"], "bash", "-euc",
               "cargo test --locked --lib && cargo build --locked --release --manifest-path cli/Cargo.toml"]
    run(command)
    binary = destination / "tdx-measure"
    shutil.copy2(source / "cli/target/release/tdx-measure", binary)
    binary.chmod(0o755)
    dump_json(destination / "tdx-measure.provenance.json",
              {**tdx_tool_provenance(config), "binary_sha256": sha256(binary)})
    artifact = config["sources"]["sev_snp_measure"]["artifact"]
    wheel = destination / artifact["url"].rsplit("/", 1)[-1]
    run(["curl", "--fail", "--location", "--retry", "3", "--output", str(wheel), artifact["url"]])
    if sha256(wheel) != artifact["sha256"]:
        raise PodVMError("SEV-SNP measurement wheel checksum mismatch")
    venv = ROOT / ".work/tools/sev-snp-measure"
    run([sys.executable, "-m", "venv", str(venv)])
    run([str(venv / "bin/python"), "-m", "pip", "install", str(wheel)])
    link = destination / "sev-snp-measure"
    link.unlink(missing_ok=True)
    link.symlink_to(venv / "bin/sev-snp-measure")
    wheel.unlink()


def measurement_fingerprint(staging: Path, config: dict[str, Any], profiles: dict[str, Any]) -> str:
    files = ("podvm.raw", "vmlinuz", "kernel.config", "kernel_verity_params", "kernel_params",
             "cmdline", "firmware/AMDSEV.fd", "firmware/OVMF.inteltdx.fd", "inputs.json")
    data = {"files": {name: sha256(staging / name) for name in files},
            "config": config, "profiles": profiles, "assets": local_asset_hashes()}
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def validate_build_inputs(staging: Path, config: dict[str, Any]) -> None:
    expected = {key: config[key] for key in ("platform", "build_inputs", "sources", "oci")}
    expected["local_assets"] = local_asset_hashes()
    if load_json(staging / "inputs.json") != expected:
        raise PodVMError("staged build provenance does not match current locked inputs/assets; rebuild")


def kata_annotations(staging: Path, profile: dict[str, Any], tee: str, base: str) -> dict[str, str]:
    prefix = "io.katacontainers.config.hypervisor."
    firmware = "OVMF.inteltdx.fd" if tee == "tdx" else "AMDSEV.fd"
    memory = int(profile["memory"][:-1]) * (1024 if profile["memory"].endswith("G") else 1)
    return {prefix + key: str(value) for key, value in {
        "kernel": f"{base}/vmlinuz", "image": f"{base}/podvm.raw",
        "firmware": f"{base}/firmware/{firmware}",
        "kernel_verity_params": (staging / "kernel_verity_params").read_text().strip(),
        "kernel_params": (staging / "kernel_params").read_text().strip(),
        "default_vcpus": profile["cpus"], "default_max_vcpus": profile["cpus"],
        "default_memory": memory,
    }.items()}


def write_kata_examples(staging: Path, profiles: dict[str, Any]) -> None:
    destination = staging / "kata"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir()
    for name, profile in profiles["profiles"].items():
        for tee in ("tdx", "snp"):
            document = {"apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": f"podvm-{tee}-{name}", "annotations":
                    kata_annotations(staging, profile, tee, "/opt/podvm")},
                "spec": {"runtimeClassName": f"kata-qemu-{tee}", "containers":
                    [{"name": "pause", "image": "registry.k8s.io/pause:3.9"}]}}
            (destination / f"pod-{tee}-{name}.yaml").write_text(yaml.safe_dump(document, sort_keys=False))
    (destination / "configuration.toml.fragment").write_text(
        '[hypervisor.qemu]\n'
        'enable_annotations = ["kernel", "image", "firmware", "kernel_verity_params", "kernel_params", '
        '"default_vcpus", "default_max_vcpus", "default_memory"]\n'
        'disable_image_nvdimm = true\nrootfs_type = "ext4"\n'
        'disable_guest_selinux = true\nenable_debug = false\n'
        'kernel_params = ""\ninitrd = ""\nblock_device_driver = "virtio-scsi"\n'
        '[runtime]\nstatic_sandbox_resource_mgmt = true\n')


def measurement_value(value: Any, label: str) -> str:
    if isinstance(value, list) and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
        result = bytes(value).hex()
    elif isinstance(value, str):
        result = value.lower().removeprefix("0x")
    else:
        raise PodVMError(f"unexpected {label} encoding from measurement tool")
    if not HEX384.fullmatch(result):
        raise PodVMError(f"{label} must be a 48-byte SHA-384 value, got {result!r}")
    return result


def tdx_metadata(staging: Path, profiles: dict[str, Any], profile_id: str) -> dict[str, Any]:
    tdx = profiles["tdx"]
    profile = resolved_profile(profiles, profile_id, "tdx")
    qemu = tdx["qemu"]
    return {
        "boot_config": {
            "cpus": profile["cpus"],
            "memory": profile["memory"],
            "bios": "../../../firmware/OVMF.inteltdx.fd",
            "acpi_tables": "acpi_tables.bin",
            "rsdp": None,
            "table_loader": None,
            "boot_order": None,
            "path_boot_xxxx": None,
            "qemu": {
                "machine": qemu["measurement_machine"],
                "cpu": qemu["cpu"],
                "accel": qemu["accel"],
                "globals": [],
                "objects": qemu["measurement_objects"],
                "netdevs": qemu["measurement_netdevs"],
                "devices": qemu["measurement_devices"],
                "fw_cfg": [],
            },
        },
        "direct": {
            "kernel": "../../../vmlinuz",
            "initrd": None,
            "cmdline": (staging / "cmdline").read_text().strip(),
        },
    }


def run_tdx(
    metadata: Path,
    tdx: dict[str, Any],
    create_acpi: bool,
    output: Path,
    config: dict[str, Any] | None = None,
) -> dict[str, str]:
    tool = os.environ.get("TDX_MEASURE", str(ROOT / ".work/bin/tdx-measure"))
    require_tool(tool)
    binary = Path(shutil.which(tool) or tool).resolve()
    provenance = load_json(binary.with_name(binary.name + ".provenance.json"))
    if provenance.get("binary_sha256") != sha256(binary):
        raise PodVMError("TDX tool binary does not match its recorded provenance")
    expected = tdx_tool_provenance(config if config is not None else load_yaml(DEFAULT_CONFIG))
    if {k: v for k, v in provenance.items() if k != "binary_sha256"} != expected:
        raise PodVMError("TDX tool provenance does not match the pinned no-initrd patch")
    command = [tool, str(metadata), "--json-file", str(output)]
    if create_acpi:
        command.extend(["--create-acpi-tables", tdx["acpi_distribution"], tdx["qemu_source_version"]])
        # ARC's runner and Docker sidecar share the workspace, but not /tmp.
        # The tool bind-mounts its temporary output directory into Docker;
        # keep it beside the metadata so both containers see the same files.
        with tempfile.TemporaryDirectory(prefix=".tdx-acpi-", dir=metadata.resolve().parent) as temporary:
            run(command, env={"TMPDIR": temporary})
    else:
        run(command)
    raw = load_json(output)
    return {
        "mr_td": measurement_value(raw.get("mrtd"), "mr_td"),
        "rtmr_0": measurement_value(raw.get("rtmr0"), "rtmr_0"),
        "rtmr_1": measurement_value(raw.get("rtmr1"), "rtmr_1"),
        "rtmr_2": measurement_value(raw.get("rtmr2"), "rtmr_2"),
    }


def run_snp(staging: Path, profile: dict[str, Any]) -> str:
    tool = os.environ.get("SEV_SNP_MEASURE", str(ROOT / ".work/bin/sev-snp-measure"))
    require_tool(tool)
    output = capture(
        [
            tool,
            "--mode",
            "snp",
            f"--vcpus={profile['cpus']}",
            f"--vcpu-type={profile['vcpu_type']}",
            f"--vmm-type={profile['vmm_type']}",
            f"--ovmf={staging / 'firmware' / 'AMDSEV.fd'}",
            f"--kernel={staging / 'vmlinuz'}",
            f"--append={(staging / 'cmdline').read_text().strip()}",
            f"--guest-features={profile['guest_features']}",
            "--output-format=hex",
        ]
    )
    matches = re.findall(r"(?<![0-9a-fA-F])([0-9a-fA-F]{96})(?![0-9a-fA-F])", output)
    if len(matches) != 1:
        raise PodVMError(f"could not parse SEV-SNP measurement from: {output}")
    return measurement_value(matches[0], "snp_launch_measurement")


def bool_qemu(value: bool) -> str:
    return "true" if value else "false"


def on_off_qemu(value: bool) -> str:
    return "on" if value else "off"


def snp_runtime_objects(profiles: dict[str, Any], profile_id: str) -> list[str]:
    snp = profiles["sev"]
    profile = profiles["profiles"][profile_id]
    backend = snp["qemu"]["memory_backend"]
    guest = snp["qemu"]["guest"]
    return [
        (
            f"memory-backend-memfd,id={backend['id']},size={profile['memory']},"
            f"share={bool_qemu(backend['share'])},prealloc={bool_qemu(backend['prealloc'])}"
        ),
        (
            f"sev-snp-guest,id={guest['id']},cbitpos={guest['cbitpos']},"
            f"reduced-phys-bits={guest['reduced_phys_bits']},"
            f"kernel-hashes={on_off_qemu(guest['kernel_hashes'])}"
        ),
    ]


def resolved_configuration(
    staging: Path, profiles: dict[str, Any], tee: str, profile_id: str,
    cpu_model: str | None = None,
) -> dict[str, Any]:
    cmdline = (staging / "cmdline").read_text().strip()
    profile = resolved_profile(profiles, profile_id, tee, cpu_model)
    if tee == "tdx":
        tdx = profiles["tdx"]
        qemu = tdx["qemu"]
        return {
            **profile,
            "acpi_distribution": tdx["acpi_distribution"],
            "qemu_source_version": tdx["qemu_source_version"],
            "mode": "direct",
            "firmware": "firmware/OVMF.inteltdx.fd",
            "kernel": "vmlinuz",
            "initrd": None,
            "cmdline": cmdline,
            "disk": "podvm.raw",
            "qemu": {
                "machine": qemu["runtime_machine"],
                "cpu": qemu["cpu"],
                "accel": qemu["accel"],
                "objects": qemu["runtime_objects"],
                "netdevs": qemu["netdevs"],
                "devices": qemu["runtime_devices"],
            },
            "measurement_note": (
                "ACPI generation uses a null block backend for the root disk and a null "
                "console backend, preserving their device topology. "
                "The ACPI dumper omits the tdx-guest object and confidential-guest-support "
                "property so it can run on a non-TDX KVM host. It also substitutes a hubport "
                "network backend because the measurement tool's minimal QEMU build omits "
                "libslirp, and disables the virtio-net option ROM because that build omits "
                "pc-bios. The runtime still uses user networking and its normal option ROM. "
                "These substitutions leave the measured device topology unchanged."
            ),
        }
    snp = profiles["sev"]
    qemu = snp["qemu"]
    return {
        **profile,
        "mode": "direct",
        "firmware": "firmware/AMDSEV.fd",
        "kernel": "vmlinuz",
        "initrd": None,
        "cmdline": cmdline,
        "disk": "podvm.raw",
        "qemu": {
            "machine": qemu["machine"],
            "cpu": profile["vcpu_type"],
            "objects": snp_runtime_objects(profiles, profile_id),
            "netdevs": qemu["netdevs"],
            "devices": qemu["runtime_devices"],
        },
    }


def measure(
    args: argparse.Namespace, config: dict[str, Any], profiles: dict[str, Any]
) -> None:
    staging = args.staging_dir.resolve()
    validate_staging(staging)
    launch = staging / "launch"
    validate_build_inputs(staging, config)
    if launch.exists():
        shutil.rmtree(launch)
    launch.mkdir()
    measurements = {}
    for profile_id in sorted(profiles["profiles"]):
        profile_dir = launch / "tdx" / profile_id
        metadata = profile_dir / "metadata.json"
        dump_json(metadata, tdx_metadata(staging, profiles, profile_id))
        first_output = profile_dir / "raw-1.json"
        second_output = profile_dir / "raw-2.json"
        first = run_tdx(metadata, profiles["tdx"], True, first_output, config=config)
        second = run_tdx(metadata, profiles["tdx"], False, second_output, config=config)
        if first != second:
            raise PodVMError(f"TDX profile {profile_id} produced nondeterministic measurements")
        first_output.unlink()
        second_output.unlink()
        measurements[profile_id] = {"tdx": first, "sev": {}}
        for model in sorted(snp_settings(profiles, profile_id)["vcpu_types"]):
            profile = resolved_profile(profiles, profile_id, "sev", model)
            configuration = resolved_configuration(staging, profiles, "sev", profile_id, model)
            dump_json(launch / "sev" / profile_id / f"{model}.json", configuration)
            first = run_snp(staging, profile)
            second = run_snp(staging, profile)
            if first != second:
                raise PodVMError(
                    f"SEV-SNP profile {profile_id}/{model} produced nondeterministic measurements"
                )
            measurements[profile_id]["sev"][model] = first
    dump_json(
        args.raw_measurements,
        {
            "fingerprint": measurement_fingerprint(staging, config, profiles),
            "profiles": measurements,
            "tools": {
                "tdx_measure": tdx_tool_provenance(config),
                "sev_snp_measure": config["sources"]["sev_snp_measure"],
            },
        },
    )
    log(f"measurements written to {args.raw_measurements}")


def validate_staging(staging: Path) -> None:
    required = (
        "podvm.raw",
        "vmlinuz",
        "kernel.config",
        "kernel_verity_params",
        "kernel_params",
        "cmdline",
        "firmware/OVMF.inteltdx.fd",
        "firmware/AMDSEV.fd",
        "inputs.json",
    )
    for relative in required:
        path = staging / relative
        if not path.is_file() or path.stat().st_size == 0:
            raise PodVMError(f"staging tree is missing {relative}")
    expected = kata_cmdline((staging / "kernel_verity_params").read_text())
    if (staging / "cmdline").read_text().strip() != expected:
        raise PodVMError("staged command line does not match Kata verity parameters")
    if (staging / "kernel_params").read_text().strip() != ADDITIONAL_KERNEL_PARAMS:
        raise PodVMError("additional kernel parameters do not match the measured command line")
    if (staging / "initrd.img").exists():
        raise PodVMError("obsolete initrd in raw disk staging tree")


def smoke_config() -> str:
    return '''[hypervisor.qemu]
path = "/opt/kata/bin/qemu-system-x86_64"
kernel = "/podvm/vmlinuz"
image = "/podvm/podvm.raw"
initrd = ""
rootfs_type = "ext4"
machine_type = "q35"
enable_debug = true
default_vcpus = 2
default_maxvcpus = 2
default_memory = 2048
default_bridges = 1
block_device_driver = "virtio-scsi"
disable_image_nvdimm = true
disable_guest_selinux = true
shared_fs = "virtio-fs"
virtio_fs_daemon = "/opt/kata/libexec/virtiofsd"
valid_virtio_fs_daemon_paths = ["/opt/kata/libexec/virtiofsd"]
virtio_fs_cache = "auto"
virtio_fs_extra_args = ["--thread-pool-size=1"]
enable_annotations = ["kernel", "image", "kernel_verity_params", "kernel_params", "default_vcpus", "default_max_vcpus", "default_memory"]
[agent.kata]
launch_process_timeout = 6
[runtime]
enable_debug = true
internetworking_model = "none"
disable_new_netns = true
static_sandbox_resource_mgmt = true
'''


def smoke(args: argparse.Namespace, config: dict[str, Any], profiles: dict[str, Any]) -> None:
    staging = args.staging_dir.resolve()
    validate_staging(staging)
    validate_build_inputs(staging, config)
    require_tool("docker")
    require_tool("oras")
    if not all(os.access(path, os.R_OK | os.W_OK) for path in ("/dev/kvm", "/dev/vhost-vsock")):
        raise PodVMError("Kata smoke requires accessible /dev/kvm and /dev/vhost-vsock")
    # Keep fixtures in the shared workspace so ARC's Docker sidecar can mount them.
    temporary = Path(tempfile.mkdtemp(prefix=".smoke-", dir=staging.parent))
    docker_name = "podvm-smoke-" + temporary.name.removeprefix(".smoke-")
    try:
        smoke_image = "podvm-smoke:" + config["sources"]["kata_containers"]["revision"][:12]
        run(["docker", "build", "--build-arg", f"BUILDER={config['build_inputs']['ubuntu_container']}",
             "-f", str(ROOT / "assets/smoke.Dockerfile"), "-t", smoke_image, str(ROOT / "assets")])
        tools = temporary / "tools"
        for name in ("runtime", "qemu", "virtiofsd"):
            pull_oci(config["oci"][name], temporary / name)
            extract_archive(only_archive(temporary / name), tools)
        for binary in ("bin/containerd-shim-kata-v2", "bin/qemu-system-x86_64", "libexec/virtiofsd"):
            if not (tools / "opt/kata" / binary).is_file():
                raise PodVMError(f"pinned runtime payload missing {binary}")
        fixture = temporary / "fixture"
        rootfs = fixture / "rootfs"
        rootfs.mkdir(parents=True)
        pause_name = docker_name + "-pause"
        run(["docker", "create", "--name", pause_name, oci_digest_ref(config["oci"]["pause"])])
        try:
            run(["docker", "export", "--output", str(temporary / "pause.tar"), pause_name])
            extract_archive(temporary / "pause.tar", rootfs)
        finally:
            run(["docker", "rm", "-f", pause_name])
        profile = profiles["profiles"][sorted(profiles["profiles"])[0]]
        annotations = kata_annotations(staging, profile, "snp", "/podvm")
        annotations.pop("io.katacontainers.config.hypervisor.firmware")
        # containerd creates its own bundle, so the exported rootfs must use
        # an absolute path inside the smoke container.
        # Kata's OCI conversion dereferences Linux.Resources unconditionally,
        # even when the container has no resource limits.
        spec = {"ociVersion": "1.0.2", "root": {"path": "/work/fixture/rootfs", "readonly": True},
            "process": {"terminal": False, "user": {"uid": 0, "gid": 0},
                "args": ["/pause", "-v"], "env": ["PATH=/bin"], "cwd": "/"},
            "hostname": "podvm-smoke", "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"}],
            "linux": {"resources": {},
                "namespaces": [{"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}]},
            "annotations": annotations}
        (temporary / "configuration.toml").write_text(smoke_config())
        for bad_hash in (False, True):
            (temporary / "runtime.log").write_text("")
            (temporary / "syslog.log").write_text("")
            if bad_hash:
                params = annotations["io.katacontainers.config.hypervisor.kernel_verity_params"]
                root_hash = verity_fields(params)["root_hash"]
                replacement = ("0" if root_hash[0] != "0" else "1") + root_hash[1:]
                annotations["io.katacontainers.config.hypervisor.kernel_verity_params"] = params.replace(root_hash, replacement)
            dump_json(fixture / "config.json", spec)
            command = ["docker", "run", "--rm", "--name", docker_name, "--privileged",
                "-v", f"{tools / 'opt/kata'}:/opt/kata:ro", "-v", f"{staging}:/podvm:ro",
                "-v", f"{temporary}:/work", smoke_image,
                "ctr", "--address", "/run/podvm-containerd/containerd.sock", "--namespace", "podvm-smoke",
                "run", "--rm", "--runtime", "io.containerd.kata.v2",
                "--runtime-config-path", "/work/configuration.toml", "--config", "/work/fixture/config.json", "podvm-smoke"]
            result = None
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout)
            except subprocess.TimeoutExpired:
                pass
            finally:
                subprocess.run(["docker", "rm", "-f", docker_name], capture_output=True, check=False)
            output = (result.stdout + result.stderr) if result else "timed out"
            for log_name in ("runtime.log", "syslog.log"):
                runtime_log = temporary / log_name
                if runtime_log.exists():
                    output += runtime_log.read_text(errors="replace")
            (temporary / ("bad-hash.log" if bad_hash else "container.log")).write_text(output)
            if not bad_hash and (result is None or result.returncode or "pause version 3.9" not in output):
                raise PodVMError("Kata failed to execute the pause container through its agent:\n" + output[-6000:])
            if bad_hash and result is not None and result.returncode == 0:
                raise PodVMError("Kata unexpectedly executed a container with an invalid verity root hash")
            if bad_hash and not re.search(r"corrupt|verification failed|unable to mount root|kernel panic", output, re.I):
                raise PodVMError("negative smoke failed without evidence of verity/root-mount rejection:\n" + output[-6000:])
        log("Kata agent executed the pinned container; invalid verity hash rejected")
    finally:
        # The Docker container owns all VM/virtiofsd processes and their runtime state.
        subprocess.run(["docker", "rm", "-f", docker_name], capture_output=True, check=False)
        shutil.rmtree(temporary, ignore_errors=True)


def render_launch_script(profiles: dict[str, Any]) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "usage() {",
        '    echo "usage: $0 tdx <profile-id> | sev-snp <profile-id> <cpu-model>" >&2',
        "    exit 2",
        "}",
        "",
        "[[ $# -ge 2 && $# -le 3 ]] || usage",
        '[[ ( "$1" == tdx && $# -eq 2 ) || ( "$1" == sev-snp && $# -eq 3 ) ]] || usage',
        'selection="$1/$2"',
        'if [[ $# -eq 3 ]]; then selection+="/$3"; fi',
        'base_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)',
        'cmdline=$(<"${base_dir}/cmdline")',
        "profile_args=()",
        "",
        'case "${selection}" in',
    ]

    def append_argument(flag: str, value: str) -> None:
        quoted = shlex.quote(value)
        if quoted == value:
            quoted = f"'{value}'"
        lines.append(f"        {flag} {quoted}")

    for profile_id in sorted(profiles["profiles"]):
        profile = resolved_profile(profiles, profile_id, "tdx")
        qemu = profiles["tdx"]["qemu"]
        lines.extend([f"    tdx/{profile_id})", "      profile_args=("])
        for value in qemu["runtime_objects"]:
            append_argument("-object", value)
        append_argument("-machine", qemu["runtime_machine"])
        append_argument("-cpu", qemu["cpu"])
        append_argument("-smp", str(profile["cpus"]))
        append_argument("-m", profile["memory"])
        lines.append('        -bios "${base_dir}/firmware/OVMF.inteltdx.fd"')
        for value in qemu["netdevs"]:
            append_argument("-netdev", value)
        for value in qemu["runtime_devices"]:
            append_argument("-device", value)
        lines.extend(["      )", "      ;;"])

    for profile_id in sorted(profiles["profiles"]):
        for model in sorted(snp_settings(profiles, profile_id)["vcpu_types"]):
            profile = resolved_profile(profiles, profile_id, "sev", model)
            qemu = profiles["sev"]["qemu"]
            lines.extend([f"    sev-snp/{profile_id}/{model})", "      profile_args=("])
            for value in snp_runtime_objects(profiles, profile_id):
                append_argument("-object", value)
            append_argument("-machine", qemu["machine"])
            append_argument("-cpu", profile["vcpu_type"])
            append_argument("-smp", str(profile["cpus"]))
            append_argument("-m", profile["memory"])
            lines.append('        -bios "${base_dir}/firmware/AMDSEV.fd"')
            for value in qemu["netdevs"]:
                append_argument("-netdev", value)
            for value in qemu["runtime_devices"]:
                append_argument("-device", value)
            lines.extend(["      )", "      ;;"])

    lines.extend(
        [
            "    *) usage ;;",
            "esac",
            "",
            "exec qemu-system-x86_64 \\",
            "    -enable-kvm -display none -serial none -monitor none -no-reboot -nodefaults \\",
            '    -chardev stdio,id=charconsole0,signal=off \\',
            '    -kernel "${base_dir}/vmlinuz" \\',
            '    -append "${cmdline}" \\',
            '    -drive "file=${base_dir}/podvm.raw,if=none,id=root,format=raw,readonly=on" \\',
            '    "${profile_args[@]}"',
            "",
        ]
    )
    return "\n".join(lines)


def member_manifest(bundle_root: Path, config: dict[str, Any]) -> dict[str, Any]:
    files = {}
    for path in sorted(bundle_root.rglob("*")):
        if path.is_file() and path.name != "MANIFEST.json":
            relative = path.relative_to(bundle_root).as_posix()
            files[relative] = {"sha256": sha256(path), "size": path.stat().st_size}
    return {
        "platform": config["platform"],
        "build_inputs": config["build_inputs"],
        "sources": config["sources"],
        "oci": config["oci"],
        "files": files,
    }


def make_tar_zst(source: Path, output: Path) -> None:
    require_tool("tar")
    require_tool("zstd")
    output.parent.mkdir(parents=True, exist_ok=True)
    tar_cmd = [
        "tar",
        "--sort=name",
        "--mtime=@0",
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        "-C",
        str(source.parent),
        "-cf",
        "-",
        source.name,
    ]
    zstd_cmd = ["zstd", "-19", "-T0", "-q", "-o", str(output)]
    log("+ " + " ".join(tar_cmd) + " | " + " ".join(zstd_cmd))
    with subprocess.Popen(tar_cmd, stdout=subprocess.PIPE) as tar_process:
        assert tar_process.stdout is not None
        zstd_process = subprocess.run(zstd_cmd, stdin=tar_process.stdout, check=False)
        tar_process.stdout.close()
        tar_status = tar_process.wait()
    if tar_status or zstd_process.returncode:
        raise PodVMError("deterministic tar.zst creation failed")


def git_revision(value: str | None) -> str:
    revision = value or os.environ.get("GITHUB_SHA", "")
    if not revision:
        try:
            revision = capture(["git", "rev-parse", "HEAD"], cwd=ROOT)
        except PodVMError:
            revision = ""
    if not HEX40.fullmatch(revision):
        raise PodVMError("release source revision must be a full 40-character commit SHA")
    return revision


def validate_resolved_configuration(
    tee: str, profile_id: str, configuration: Any
) -> dict[str, Any]:
    common = {"cpus", "memory", "mode", "firmware", "kernel", "initrd", "cmdline", "disk", "qemu"}
    if tee == "tdx":
        expected = common | {
            "acpi_distribution",
            "qemu_source_version",
            "measurement_note",
        }
    else:
        expected = common | {"vcpu_type", "vmm_type", "guest_features"}
    configuration = require_exact_keys(
        configuration, expected, f"measurements.profiles.{profile_id}.{tee}.configuration"
    )
    validate_profile_dimensions(profile_id, configuration, f"measurements.profiles.{tee}")
    if configuration["mode"] != "direct":
        raise PodVMError(f"measurements.json profile {tee}/{profile_id} is not direct boot")
    if configuration["initrd"] is not None:
        raise PodVMError("raw PodVM boot must not use an initrd")
    for name in ("firmware", "kernel", "cmdline", "disk"):
        if not isinstance(configuration[name], str) or not configuration[name]:
            raise PodVMError(f"measurements.json profile {tee}/{profile_id} has invalid {name}")
    qemu_expected = {"machine", "cpu", "objects", "netdevs", "devices"}
    if tee == "tdx":
        qemu_expected.add("accel")
    qemu = require_exact_keys(
        configuration["qemu"], qemu_expected, f"measurements.profiles.{profile_id}.{tee}.qemu"
    )
    for name in ("machine", "cpu", "accel") if tee == "tdx" else ("machine", "cpu"):
        if not isinstance(qemu[name], str) or not qemu[name]:
            raise PodVMError(f"measurements.json profile {tee}/{profile_id} has invalid qemu.{name}")
    for name in ("objects", "netdevs", "devices"):
        require_string_list(qemu[name], f"measurements.profiles.{profile_id}.{tee}.qemu.{name}")
    if tee == "tdx":
        if configuration["cpus"] > 255:
            raise PodVMError(f"measurements.json profile {profile_id} exceeds the TDX vCPU limit")
        for name in ("acpi_distribution", "qemu_source_version", "measurement_note"):
            if not isinstance(configuration[name], str) or not configuration[name]:
                raise PodVMError(f"measurements.json profile {profile_id} has invalid {name}")
    else:
        if not isinstance(configuration["vcpu_type"], str) or configuration["vcpu_type"] not in SNP_VCPU_TYPES:
            raise PodVMError(f"measurements.json profile {profile_id} has unsupported vcpu_type")
        if configuration["vmm_type"] != "QEMU":
            raise PodVMError(f"measurements.json profile {profile_id} has unsupported vmm_type")
        features = configuration["guest_features"]
        if not isinstance(features, str) or not GUEST_FEATURES.fullmatch(features):
            raise PodVMError(f"measurements.json profile {profile_id} has invalid guest_features")
        if qemu["cpu"] != configuration["vcpu_type"]:
            raise PodVMError(f"measurements.json profile {profile_id} CPU model is inconsistent")
    return configuration


def validate_measurements(document: dict[str, Any]) -> None:
    required_top = {"schema", "release", "artifact", "inputs", "profiles"}
    if set(document) != required_top:
        raise PodVMError("measurements.json has an invalid top-level shape")
    if not document["schema"].startswith("https://raw.githubusercontent.com/"):
        raise PodVMError("measurements.json schema must use an immutable GitHub source URL")
    artifact = document["artifact"]
    if not re.fullmatch(r"[0-9a-f]{64}", artifact.get("sha256", "")):
        raise PodVMError("measurements.json artifact SHA-256 is invalid")
    catalog = document.get("profiles")
    if not isinstance(catalog, dict) or not catalog:
        raise PodVMError("measurements.json must contain at least one profile")
    for profile_id, profile in catalog.items():
        if not isinstance(profile_id, str) or not PROFILE_ID.fullmatch(profile_id):
            raise PodVMError(f"measurements.json contains an invalid profile ID: {profile_id!r}")
        require_exact_keys(profile, {"tdx", "sev"}, f"measurements.profiles.{profile_id}")
        if not isinstance(profile["sev"], dict) or not profile["sev"]:
            raise PodVMError(f"measurements.json profile {profile_id} must contain SNP models")
        entries = [("tdx", None, profile["tdx"])] + [
            ("sev", model, entry) for model, entry in profile["sev"].items()
        ]
        shared_dimensions = None
        for tee, model, entry in entries:
            label = f"measurements.profiles.{profile_id}.{tee}" + (f".{model}" if model else "")
            require_exact_keys(entry, {"configuration", "measurement"}, label)
            configuration = validate_resolved_configuration(tee, profile_id, entry["configuration"])
            dimensions = (configuration["cpus"], configuration["memory"])
            if shared_dimensions is None:
                shared_dimensions = dimensions
            elif dimensions != shared_dimensions:
                raise PodVMError(f"measurements.json profile {profile_id} has inconsistent CPU/memory")
            if tee == "sev" and model != configuration["vcpu_type"]:
                raise PodVMError(f"{label} CPU model key is inconsistent")
            if tee == "tdx":
                registers = require_exact_keys(
                    entry["measurement"], {"mr_td", "rtmr_0", "rtmr_1", "rtmr_2"}, label
                )
                values = registers.values()
            else:
                values = [entry["measurement"]]
            if any(not isinstance(value, str) or not HEX384.fullmatch(value) for value in values):
                raise PodVMError(f"{label} has invalid measurement values")


def validate_profile_coverage(
    catalog: Any, profiles: dict[str, Any], label: str
) -> None:
    if not isinstance(catalog, dict) or set(catalog) != set(profiles["profiles"]):
        raise PodVMError(f"{label} do not exactly match configured profiles")
    for profile_id, entry in catalog.items():
        require_exact_keys(entry, {"tdx", "sev"}, f"{label}.{profile_id}")
        expected_models = set(snp_settings(profiles, profile_id)["vcpu_types"])
        if not isinstance(entry["sev"], dict) or set(entry["sev"]) != expected_models:
            raise PodVMError(f"{label}.{profile_id}.sev do not exactly match endorsed models")


def validate_raw_measurements(
    raw: dict[str, Any], config: dict[str, Any], profiles: dict[str, Any]
) -> None:
    require_exact_keys(raw, {"profiles", "tools", "fingerprint"}, "raw measurements")
    expected_tools = {
        "tdx_measure": tdx_tool_provenance(config),
        "sev_snp_measure": config["sources"]["sev_snp_measure"],
    }
    if raw["tools"] != expected_tools:
        raise PodVMError("raw measurement tool provenance does not match versions.yaml")
    validate_profile_coverage(raw["profiles"], profiles, "raw measurements")
    if not isinstance(raw["fingerprint"], str) or not re.fullmatch(r"[0-9a-f]{64}", raw["fingerprint"]):
        raise PodVMError("raw measurement input fingerprint is invalid")
    for profile_id, entry in raw["profiles"].items():
        registers = require_exact_keys(
            entry["tdx"], {"mr_td", "rtmr_0", "rtmr_1", "rtmr_2"}, f"raw.{profile_id}.tdx"
        )
        for name, value in registers.items():
            measurement_value(value, f"{profile_id}.{name}")
        for model, value in entry["sev"].items():
            measurement_value(value, f"{profile_id}.{model}.snp_launch_measurement")


def package(
    args: argparse.Namespace, config: dict[str, Any], profiles: dict[str, Any]
) -> None:
    staging = args.staging_dir.resolve()
    validate_staging(staging)
    raw = load_json(args.raw_measurements)
    validate_build_inputs(staging, config)
    validate_raw_measurements(raw, config, profiles)
    if raw["fingerprint"] != measurement_fingerprint(staging, config, profiles):
        raise PodVMError("stale measurements: staged assets or launch inputs changed; remeasure")
    dist = args.dist_dir.resolve()
    safe_clean(dist, args.workspace)
    safe_version = re.sub(r"[^A-Za-z0-9._-]", "_", args.release_version)
    if not safe_version:
        raise PodVMError("release version is empty")
    bundle_name = f"podvm-ubuntu-24.04-x86_64-{safe_version}.tar.zst"
    bundle_root = dist / "bundle" / "podvm"
    shutil.copytree(staging, bundle_root)
    write_kata_examples(bundle_root, profiles)
    smoke_log = bundle_root / "smoke-serial.log"
    if smoke_log.exists():
        smoke_log.unlink()
    launcher = bundle_root / "launch-podvm.sh"
    launcher.write_text(render_launch_script(profiles))
    launcher.chmod(0o755)
    dump_json(bundle_root / "launch-profiles.json", profiles)
    shutil.copytree(ROOT / "LICENSES", bundle_root / "LICENSES")
    (bundle_root / "schemas").mkdir()
    shutil.copy2(
        ROOT / "schemas" / "measurements.schema.json",
        bundle_root / "schemas" / "measurements.schema.json",
    )
    shutil.copy2(
        ROOT / "schemas" / "launch-profiles.schema.json",
        bundle_root / "schemas" / "launch-profiles.schema.json",
    )
    dump_json(bundle_root / "MANIFEST.json", member_manifest(bundle_root, config))
    bundle = dist / bundle_name
    make_tar_zst(bundle_root, bundle)

    revision = git_revision(args.source_revision)
    repository = args.source_repository or os.environ.get("GITHUB_REPOSITORY", "local/podvm")
    catalog = {}
    for profile_id in sorted(profiles["profiles"]):
        catalog[profile_id] = {
            "tdx": {
                "configuration": resolved_configuration(staging, profiles, "tdx", profile_id),
                "measurement": raw["profiles"][profile_id]["tdx"],
            },
            "sev": {
                model: {
                    "configuration": resolved_configuration(staging, profiles, "sev", profile_id, model),
                    "measurement": raw["profiles"][profile_id]["sev"][model],
                }
                for model in sorted(snp_settings(profiles, profile_id)["vcpu_types"])
            },
        }
    measurements = {
        "schema": (
            f"https://raw.githubusercontent.com/{repository}/{revision}/"
            "schemas/measurements.schema.json"
        ),
        "release": {
            "version": args.release_version,
            "source_repository": repository,
            "source_revision": revision,
        },
        "artifact": {"name": bundle_name, "sha256": sha256(bundle), "media_type": "application/zstd"},
        "inputs": {
            "platform": config["platform"],
            "build_inputs": config["build_inputs"],
            "sources": config["sources"],
            "oci": config["oci"],
            "local_assets": local_asset_hashes(),
            "measurement_tools": raw["tools"],
            "measurement_fingerprint": raw["fingerprint"],
        },
        "profiles": catalog,
    }
    validate_measurements(measurements)
    dump_json(dist / "measurements.json", measurements)
    sums = [
        f"{sha256(bundle)}  {bundle.name}",
        f"{sha256(dist / 'measurements.json')}  measurements.json",
    ]
    (dist / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    shutil.rmtree(dist / "bundle")
    validate_release(dist, profiles)
    log(f"release assets written to {dist}")


def validate_release(dist: Path, profiles: dict[str, Any] | None = None) -> None:
    assets = sorted(path.name for path in dist.iterdir() if path.is_file())
    bundles = [name for name in assets if name.endswith(".tar.zst")]
    if len(bundles) != 1 or set(assets) != {bundles[0], "measurements.json", "SHA256SUMS"}:
        raise PodVMError(f"release must contain exactly three assets, found {assets}")
    measurements = load_json(dist / "measurements.json")
    validate_measurements(measurements)
    if profiles is not None:
        validate_profile_coverage(measurements["profiles"], profiles, "release measurements")
        for profile_id, entry in measurements["profiles"].items():
            for tee, model, record in [("tdx", None, entry["tdx"])] + [
                ("sev", model, record) for model, record in entry["sev"].items()
            ]:
                expected = resolved_profile(profiles, profile_id, tee, model)
                if any(record["configuration"][key] != value for key, value in expected.items()):
                    raise PodVMError(f"release profile {profile_id}/{tee}/{model} differs from configuration")
    if measurements["artifact"]["name"] != bundles[0]:
        raise PodVMError("bundle filename differs from measurements.json")
    if sha256(dist / bundles[0]) != measurements["artifact"]["sha256"]:
        raise PodVMError("bundle checksum differs from measurements.json")
    expected_lines = {
        f"{sha256(dist / bundles[0])}  {bundles[0]}",
        f"{sha256(dist / 'measurements.json')}  measurements.json",
    }
    actual_lines = set((dist / "SHA256SUMS").read_text().splitlines())
    if actual_lines != expected_lines:
        raise PodVMError("SHA256SUMS content is invalid")


def command_verify(
    args: argparse.Namespace, config: dict[str, Any], profiles: dict[str, Any]
) -> None:
    validate_lock(config)
    validate_profiles(profiles)
    if not args.offline:
        verify_oci(config, provenance=not args.skip_provenance)
    log("dependency lock verified")


def command_validate(
    args: argparse.Namespace, config: dict[str, Any], profiles: dict[str, Any]
) -> None:
    validate_lock(config)
    validate_profiles(profiles)
    if args.staging_dir:
        validate_staging(args.staging_dir.resolve())
    if args.dist_dir:
        validate_release(args.dist_dir.resolve(), profiles)
    log("validation passed")


def command_all(
    args: argparse.Namespace, config: dict[str, Any], profiles: dict[str, Any]
) -> None:
    build(args, config, profiles)
    smoke(args, config, profiles)
    install_tools(args, config, profiles)
    measure(args, config, profiles)
    package(args, config, profiles)


def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    common.add_argument("--profiles", type=Path, default=DEFAULT_PROFILES)
    common.add_argument("--workspace", type=Path, default=ROOT)
    cli = argparse.ArgumentParser(description=__doc__)
    sub = cli.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", parents=[common])
    verify.add_argument("--offline", action="store_true")
    verify.add_argument("--skip-provenance", action="store_true")
    sub.add_parser("tools", parents=[common])

    build_parser = sub.add_parser("build", parents=[common])
    build_parser.add_argument("--work-dir", type=Path, default=ROOT / ".work" / "build")
    build_parser.add_argument("--staging-dir", type=Path, default=ROOT / "build" / "staging")

    smoke_parser = sub.add_parser("smoke", parents=[common])
    smoke_parser.add_argument("--staging-dir", type=Path, default=ROOT / "build" / "staging")
    smoke_parser.add_argument("--timeout", type=int, default=180)

    measure_parser = sub.add_parser("measure", parents=[common])
    measure_parser.add_argument("--staging-dir", type=Path, default=ROOT / "build" / "staging")
    measure_parser.add_argument(
        "--raw-measurements", type=Path, default=ROOT / "build" / "measurements.raw.json"
    )

    package_parser = sub.add_parser("package", parents=[common])
    package_parser.add_argument("--staging-dir", type=Path, default=ROOT / "build" / "staging")
    package_parser.add_argument(
        "--raw-measurements", type=Path, default=ROOT / "build" / "measurements.raw.json"
    )
    package_parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist")
    package_parser.add_argument("--release-version", required=True)
    package_parser.add_argument("--source-revision")
    package_parser.add_argument("--source-repository")

    validate_parser = sub.add_parser("validate", parents=[common])
    validate_parser.add_argument("--staging-dir", type=Path)
    validate_parser.add_argument("--dist-dir", type=Path)

    all_parser = sub.add_parser("all", parents=[common])
    all_parser.add_argument("--work-dir", type=Path, default=ROOT / ".work" / "build")
    all_parser.add_argument("--staging-dir", type=Path, default=ROOT / "build" / "staging")
    all_parser.add_argument("--timeout", type=int, default=180)
    all_parser.add_argument(
        "--raw-measurements", type=Path, default=ROOT / "build" / "measurements.raw.json"
    )
    all_parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist")
    all_parser.add_argument("--release-version", required=True)
    all_parser.add_argument("--source-revision")
    all_parser.add_argument("--source-repository")
    return cli


def main() -> int:
    args = parser().parse_args()
    try:
        config = load_yaml(args.config)
        profiles = load_yaml(args.profiles)
        validate_lock(config)
        validate_profiles(profiles)
        commands = {
            "verify": command_verify,
            "build": build,
            "tools": install_tools,
            "smoke": smoke,
            "measure": measure,
            "package": package,
            "validate": command_validate,
            "all": command_all,
        }
        commands[args.command](args, config, profiles)
        return 0
    except PodVMError as exc:
        print(f"podvm: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

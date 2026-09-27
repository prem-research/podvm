#!/usr/bin/env python3
"""Build, measure, validate, and package a dual-TEE CoCo PodVM."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "versions.yaml"
DEFAULT_PROFILE = ROOT / "config" / "launch-profile.json"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX384 = re.compile(r"^[0-9a-f]{96}$")
REQUIRED_GUEST_FILES = (
    "usr/local/bin/kata-agent",
    "usr/local/bin/agent-protocol-forwarder",
    "usr/local/bin/attestation-agent",
    "usr/local/bin/confidential-data-hub",
    "usr/local/bin/api-server-rest",
    "usr/local/bin/process-user-data",
)


class PodVMError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"podvm: {message}", file=sys.stderr, flush=True)


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
    if config.get("schema_version") != 1:
        raise PodVMError("versions.yaml schema_version must be 1")
    platform = config.get("platform", {})
    if (platform.get("architecture"), platform.get("distribution"), platform.get("release")) != (
        "x86_64",
        "ubuntu",
        "24.04",
    ):
        raise PodVMError("only the locked Ubuntu 24.04 x86_64 platform is supported")
    build_inputs = config.get("build_inputs", {})
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
    }
    if set(config.get("oci", {})) != required_oci:
        raise PodVMError("versions.yaml OCI input set is incomplete or contains unknown inputs")
    for name, item in config["oci"].items():
        if not DIGEST.fullmatch(item.get("digest", "")):
            raise PodVMError(f"oci.{name}.digest must be a sha256 digest")
        if not item.get("repository") or not item.get("tag"):
            raise PodVMError(f"oci.{name} requires repository and tag")
        source_revision = item.get("source_revision")
        if source_revision is not None and not HEX40.fullmatch(source_revision):
            raise PodVMError(f"oci.{name}.source_revision must be a full commit SHA")
    tdx = config.get("measurement", {}).get("tdx", {})
    snp = config.get("measurement", {}).get("sev_snp", {})
    if tdx.get("cpus") != 2 or tdx.get("memory") != "8G":
        raise PodVMError("TDX measurement profile must use two vCPUs and 8G")
    if (snp.get("cpus"), snp.get("vcpu_type"), snp.get("guest_features")) != (
        2,
        "EPYC-v4",
        "0x1",
    ):
        raise PodVMError("SEV-SNP measurement profile does not match the release contract")
    profile = load_json(DEFAULT_PROFILE)
    if profile.get("schema_version") != 1:
        raise PodVMError("launch profile schema_version must be 1")
    if profile["tdx"]["devices"][:3] != profile["sev_snp"]["devices"][:3]:
        raise PodVMError("TDX and SEV-SNP disk/network/serial device order must match")
    if profile["tdx"]["runtime_devices"] != profile["sev_snp"]["runtime_devices"]:
        raise PodVMError("TDX and SEV-SNP runtime device order must match")
    if profile["tdx"].get("netdevs") != profile["sev_snp"].get("netdevs"):
        raise PodVMError("TDX and SEV-SNP runtime network backends must match")
    if profile["tdx"].get("acpi_netdevs") != ["hubport,id=network0,hubid=0"]:
        raise PodVMError("TDX ACPI generation must use the release QEMU hubport backend")
    acpi_devices = [device.replace(",romfile=", "") for device in profile["tdx"].get("acpi_devices", [])]
    if acpi_devices != profile["tdx"]["devices"]:
        raise PodVMError("TDX ACPI devices must match runtime devices except for disabled option ROMs")


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
        if provenance and item.get("source_repository"):
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


def extract_uki(build_dir: Path, staging: Path) -> None:
    ukis = [p for p in build_dir.rglob("*.efi") if p.is_file()]
    preferred = [p for p in ukis if "system" in p.name.lower()]
    candidates = preferred or ukis
    if len(candidates) != 1:
        raise PodVMError(f"expected one exported UKI, found {[str(p) for p in candidates]}")
    uki = candidates[0]
    outputs = {".linux": "vmlinuz", ".initrd": "initrd.img", ".cmdline": "cmdline.raw"}
    for section, output in outputs.items():
        run(["objcopy", f"--dump-section", f"{section}={staging / output}", str(uki)])
    raw = (staging / "cmdline.raw").read_bytes().rstrip(b"\0\n")
    (staging / "cmdline.raw").unlink()
    try:
        cmdline = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise PodVMError("UKI .cmdline section is not UTF-8") from exc
    if "roothash=" not in cmdline:
        raise PodVMError("UKI command line does not bind the root filesystem with roothash=")
    (staging / "cmdline").write_text(cmdline + "\n")
    for name in ("vmlinuz", "initrd.img"):
        if (staging / name).stat().st_size == 0:
            raise PodVMError(f"UKI section produced an empty {name}")


def build(args: argparse.Namespace, config: dict[str, Any]) -> None:
    for tool in ("git", "docker", "oras", "qemu-img", "objcopy", "tar"):
        require_tool(tool)
    verify_oci(config, provenance=True)
    work = args.work_dir.resolve()
    staging = args.staging_dir.resolve()
    safe_clean(work, args.workspace)
    safe_clean(staging, args.workspace)
    caa = work / "cloud-api-adaptor"
    clone_exact(config["sources"]["cloud_api_adaptor"], caa)
    patch_caa(caa, config)
    podvm = caa / "src" / "cloud-api-adaptor" / "podvm"
    env = {
        "ARCH": "x86_64",
        "TEE_PLATFORM": "tdx",
        "VERIFY_PROVENANCE": "yes",
        "MKOSI_VERSION": config["sources"]["mkosi"]["revision"],
    }
    run(["make", "podvm-binaries"], cwd=podvm, env=env)
    install_dual_attester(podvm, config, work / "oci")
    run(["make", "image"], cwd=podvm, env=env)

    built = podvm / "build"
    qcow_candidates = list(built.glob("*.qcow2"))
    if len(qcow_candidates) != 1:
        raise PodVMError(f"expected one qcow2 image, found {len(qcow_candidates)}")
    shutil.copy2(qcow_candidates[0], staging / "podvm.qcow2")
    run(["qemu-img", "check", "-f", "qcow2", str(staging / "podvm.qcow2")])
    extract_uki(built, staging)
    install_firmware(staging, config, work / "oci")
    dump_json(
        staging / "inputs.json",
        {
            "platform": config["platform"],
            "build_inputs": config["build_inputs"],
            "sources": config["sources"],
            "oci": config["oci"],
        },
    )
    verify_oci(config, provenance=False)
    log(f"PodVM staged at {staging}")


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


def tdx_metadata(staging: Path, config: dict[str, Any]) -> dict[str, Any]:
    profile = load_json(DEFAULT_PROFILE)["tdx"]
    return {
        "boot_config": {
            "cpus": config["measurement"]["tdx"]["cpus"],
            "memory": config["measurement"]["tdx"]["memory"],
            "bios": "../firmware/OVMF.inteltdx.fd",
            "acpi_tables": "acpi_tables.bin",
            "rsdp": None,
            "table_loader": None,
            "boot_order": None,
            "path_boot_xxxx": None,
            "qemu": {
                "machine": profile["machine"],
                "cpu": profile["cpu"],
                "accel": profile["accel"],
                "globals": [],
                "objects": profile["objects"],
                "netdevs": profile["acpi_netdevs"],
                "devices": profile["acpi_devices"],
                "fw_cfg": [],
            },
        },
        "direct": {
            "kernel": "../vmlinuz",
            "initrd": "../initrd.img",
            "cmdline": (staging / "cmdline").read_text().strip(),
        },
    }


def run_tdx(staging: Path, config: dict[str, Any], create_acpi: bool, output: Path) -> dict[str, str]:
    tool = os.environ.get("TDX_MEASURE", "tdx-measure")
    require_tool(tool)
    metadata = staging / "launch" / "tdx.json"
    command = [tool, str(metadata), "--json-file", str(output)]
    if create_acpi:
        tdx = config["measurement"]["tdx"]
        command.extend(["--create-acpi-tables", tdx["acpi_distribution"], tdx["qemu_source_version"]])
    run(command)
    raw = load_json(output)
    return {
        "mr_td": measurement_value(raw.get("mrtd"), "mr_td"),
        "rtmr_0": measurement_value(raw.get("rtmr0"), "rtmr_0"),
        "rtmr_1": measurement_value(raw.get("rtmr1"), "rtmr_1"),
        "rtmr_2": measurement_value(raw.get("rtmr2"), "rtmr_2"),
    }


def run_snp(staging: Path, config: dict[str, Any]) -> str:
    tool = os.environ.get("SEV_SNP_MEASURE", "sev-snp-measure")
    require_tool(tool)
    profile = config["measurement"]["sev_snp"]
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
            f"--initrd={staging / 'initrd.img'}",
            f"--append={(staging / 'cmdline').read_text().strip()}",
            f"--guest-features={profile['guest_features']}",
            "--output-format=hex",
        ]
    )
    matches = re.findall(r"(?<![0-9a-fA-F])([0-9a-fA-F]{96})(?![0-9a-fA-F])", output)
    if len(matches) != 1:
        raise PodVMError(f"could not parse SEV-SNP measurement from: {output}")
    return measurement_value(matches[0], "snp_launch_measurement")


def measure(args: argparse.Namespace, config: dict[str, Any]) -> None:
    staging = args.staging_dir.resolve()
    validate_staging(staging)
    launch = staging / "launch"
    launch.mkdir(exist_ok=True)
    dump_json(launch / "tdx.json", tdx_metadata(staging, config))
    snp_profile = {
        **config["measurement"]["sev_snp"],
        **load_json(DEFAULT_PROFILE)["sev_snp"],
        "firmware": "firmware/AMDSEV.fd",
        "kernel": "vmlinuz",
        "initrd": "initrd.img",
        "cmdline_file": "cmdline",
        "disk": "podvm.qcow2",
    }
    dump_json(launch / "sev-snp.json", snp_profile)

    first_tdx = run_tdx(staging, config, True, launch / "tdx-raw-1.json")
    second_tdx = run_tdx(staging, config, False, launch / "tdx-raw-2.json")
    first_snp = run_snp(staging, config)
    second_snp = run_snp(staging, config)
    if first_tdx != second_tdx or first_snp != second_snp:
        raise PodVMError("measurement tools produced nondeterministic results")
    for temporary in (launch / "tdx-raw-1.json", launch / "tdx-raw-2.json"):
        temporary.unlink()
    dump_json(
        args.raw_measurements,
        {
            "tdx": first_tdx,
            "sev_snp": first_snp,
            "tools": {
                "tdx_measure": config["sources"]["tdx_measure"],
                "sev_snp_measure": config["sources"]["sev_snp_measure"],
            },
        },
    )
    log(f"measurements written to {args.raw_measurements}")


def validate_staging(staging: Path) -> None:
    required = (
        "podvm.qcow2",
        "vmlinuz",
        "initrd.img",
        "cmdline",
        "firmware/OVMF.inteltdx.fd",
        "firmware/AMDSEV.fd",
        "inputs.json",
    )
    for relative in required:
        path = staging / relative
        if not path.is_file() or path.stat().st_size == 0:
            raise PodVMError(f"staging tree is missing {relative}")
    if "roothash=" not in (staging / "cmdline").read_text():
        raise PodVMError("staged command line is not bound to the dm-verity root hash")


def smoke(args: argparse.Namespace, config: dict[str, Any]) -> None:
    del config
    staging = args.staging_dir.resolve()
    validate_staging(staging)
    qemu = require_tool("qemu-system-x86_64")
    serial = staging / "smoke-serial.log"
    accel = "kvm" if Path("/dev/kvm").exists() else "tcg"
    command = [
        qemu,
        "-machine",
        f"q35,accel={accel}",
        "-cpu",
        "host" if accel == "kvm" else "max",
        "-smp",
        "2",
        "-m",
        "2048",
        "-nographic",
        "-no-reboot",
        "-kernel",
        str(staging / "vmlinuz"),
        "-initrd",
        str(staging / "initrd.img"),
        "-append",
        (staging / "cmdline").read_text().strip(),
        "-drive",
        f"file={staging / 'podvm.qcow2'},if=none,id=root,format=qcow2,readonly=on",
        "-device",
        "virtio-scsi-pci,id=scsi0",
        "-device",
        "scsi-hd,drive=root,bus=scsi0.0",
        "-serial",
        f"file:{serial}",
        "-monitor",
        "none",
    ]
    log("+ " + " ".join(command))
    process = subprocess.Popen(command)
    deadline = time.monotonic() + args.timeout
    markers = ("Reached target", "Startup finished", "Welcome to Ubuntu")
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            text = serial.read_text(errors="replace") if serial.exists() else ""
            if any(marker in text for marker in markers):
                log("direct-boot smoke test reached systemd")
                return
            time.sleep(2)
        text = serial.read_text(errors="replace") if serial.exists() else ""
        raise PodVMError("direct-boot smoke test did not reach systemd\n" + text[-4000:])
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def member_manifest(bundle_root: Path, config: dict[str, Any]) -> dict[str, Any]:
    files = {}
    for path in sorted(bundle_root.rglob("*")):
        if path.is_file() and path.name != "MANIFEST.json":
            relative = path.relative_to(bundle_root).as_posix()
            files[relative] = {"sha256": sha256(path), "size": path.stat().st_size}
    return {
        "schema_version": 1,
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


def validate_measurements(document: dict[str, Any]) -> None:
    required_top = {"schema", "schema_version", "release", "artifact", "inputs", "profiles", "rvps"}
    if set(document) != required_top or document.get("schema_version") != 1:
        raise PodVMError("measurements.json has an invalid top-level shape")
    if not document["schema"].startswith("https://raw.githubusercontent.com/"):
        raise PodVMError("measurements.json schema must use an immutable GitHub source URL")
    artifact = document["artifact"]
    if not re.fullmatch(r"[0-9a-f]{64}", artifact.get("sha256", "")):
        raise PodVMError("measurements.json artifact SHA-256 is invalid")
    tdx = document["profiles"]["tdx"]["measurement"]
    expected = {"mr_td", "rtmr_0", "rtmr_1", "rtmr_2"}
    if set(tdx) != expected or any(not HEX384.fullmatch(value) for value in tdx.values()):
        raise PodVMError("measurements.json contains invalid TDX registers")
    snp = document["profiles"]["sev_snp"]["measurement"]
    if not HEX384.fullmatch(snp):
        raise PodVMError("measurements.json contains an invalid SEV-SNP launch measurement")
    rvps = document["rvps"]["reference_values"]
    expected_rvps = {**{name: [value] for name, value in tdx.items()}, "snp_launch_measurement": [snp]}
    if rvps != expected_rvps:
        raise PodVMError("Trustee/RVPS mapping does not match the profile measurements")


def package(args: argparse.Namespace, config: dict[str, Any]) -> None:
    staging = args.staging_dir.resolve()
    validate_staging(staging)
    raw = load_json(args.raw_measurements)
    for value in raw.get("tdx", {}).values():
        measurement_value(value, "TDX measurement")
    measurement_value(raw.get("sev_snp"), "SEV-SNP measurement")
    dist = args.dist_dir.resolve()
    safe_clean(dist, args.workspace)
    safe_version = re.sub(r"[^A-Za-z0-9._-]", "_", args.release_version)
    if not safe_version:
        raise PodVMError("release version is empty")
    bundle_name = f"podvm-ubuntu-24.04-x86_64-{safe_version}.tar.zst"
    bundle_root = dist / "bundle" / "podvm"
    shutil.copytree(staging, bundle_root)
    smoke_log = bundle_root / "smoke-serial.log"
    if smoke_log.exists():
        smoke_log.unlink()
    shutil.copy2(ROOT / "assets" / "launch-podvm.sh", bundle_root / "launch-podvm.sh")
    (bundle_root / "launch-podvm.sh").chmod(0o755)
    shutil.copytree(ROOT / "LICENSES", bundle_root / "LICENSES")
    (bundle_root / "schemas").mkdir()
    shutil.copy2(
        ROOT / "schemas" / "measurements.schema.json",
        bundle_root / "schemas" / "measurements.schema.json",
    )
    dump_json(bundle_root / "MANIFEST.json", member_manifest(bundle_root, config))
    bundle = dist / bundle_name
    make_tar_zst(bundle_root, bundle)

    revision = git_revision(args.source_revision)
    repository = args.source_repository or os.environ.get("GITHUB_REPOSITORY", "local/podvm")
    tdx_boot = {
        **config["measurement"]["tdx"],
        **load_json(DEFAULT_PROFILE)["tdx"],
        "mode": "direct",
        "measurement_note": (
            "The ACPI dumper omits the tdx-guest object and confidential-guest-support property "
            "so it can run on a non-TDX KVM host. It also substitutes a hubport network backend "
            "because the measurement tool's minimal QEMU build omits libslirp, and disables the "
            "virtio-net option ROM because that build omits pc-bios. The runtime still uses user "
            "networking and its normal option ROM. These substitutions leave the measured device "
            "topology unchanged."
        ),
        "firmware": "firmware/OVMF.inteltdx.fd",
        "kernel": "vmlinuz",
        "initrd": "initrd.img",
        "cmdline": (staging / "cmdline").read_text().strip(),
        "disk": "podvm.qcow2",
    }
    snp_boot = {
        **config["measurement"]["sev_snp"],
        **load_json(DEFAULT_PROFILE)["sev_snp"],
        "mode": "direct",
        "firmware": "firmware/AMDSEV.fd",
        "kernel": "vmlinuz",
        "initrd": "initrd.img",
        "cmdline": (staging / "cmdline").read_text().strip(),
        "disk": "podvm.qcow2",
    }
    measurements = {
        "schema": (
            f"https://raw.githubusercontent.com/{repository}/{revision}/"
            "schemas/measurements.schema.json"
        ),
        "schema_version": 1,
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
        },
        "profiles": {
            "tdx": {"boot": tdx_boot, "measurement": raw["tdx"]},
            "sev_snp": {"boot": snp_boot, "measurement": raw["sev_snp"]},
        },
        "rvps": {
            "format": "Trustee reference-value claim map",
            "reference_values": {
                **{name: [value] for name, value in raw["tdx"].items()},
                "snp_launch_measurement": [raw["sev_snp"]],
            },
        },
    }
    validate_measurements(measurements)
    dump_json(dist / "measurements.json", measurements)
    sums = [
        f"{sha256(bundle)}  {bundle.name}",
        f"{sha256(dist / 'measurements.json')}  measurements.json",
    ]
    (dist / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    shutil.rmtree(dist / "bundle")
    validate_release(dist)
    log(f"release assets written to {dist}")


def validate_release(dist: Path) -> None:
    assets = sorted(path.name for path in dist.iterdir() if path.is_file())
    bundles = [name for name in assets if name.endswith(".tar.zst")]
    if len(bundles) != 1 or set(assets) != {bundles[0], "measurements.json", "SHA256SUMS"}:
        raise PodVMError(f"release must contain exactly three assets, found {assets}")
    measurements = load_json(dist / "measurements.json")
    validate_measurements(measurements)
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


def command_verify(args: argparse.Namespace, config: dict[str, Any]) -> None:
    validate_lock(config)
    if not args.offline:
        verify_oci(config, provenance=not args.skip_provenance)
    log("dependency lock verified")


def command_validate(args: argparse.Namespace, config: dict[str, Any]) -> None:
    validate_lock(config)
    if args.staging_dir:
        validate_staging(args.staging_dir.resolve())
    if args.dist_dir:
        validate_release(args.dist_dir.resolve())
    log("validation passed")


def command_all(args: argparse.Namespace, config: dict[str, Any]) -> None:
    build(args, config)
    smoke(args, config)
    measure(args, config)
    package(args, config)


def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    common.add_argument("--workspace", type=Path, default=ROOT)
    cli = argparse.ArgumentParser(description=__doc__)
    sub = cli.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", parents=[common])
    verify.add_argument("--offline", action="store_true")
    verify.add_argument("--skip-provenance", action="store_true")

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
        config = load_json(args.config)
        validate_lock(config)
        commands = {
            "verify": command_verify,
            "build": build,
            "smoke": smoke,
            "measure": measure,
            "package": package,
            "validate": command_validate,
            "all": command_all,
        }
        commands[args.command](args, config)
        return 0
    except PodVMError as exc:
        print(f"podvm: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

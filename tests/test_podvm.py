import argparse
import copy
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("podvm", ROOT / "podvm.py")
podvm = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(podvm)


class PodVMTests(unittest.TestCase):
    def setUp(self):
        self.config = podvm.load_yaml(ROOT / "versions.yaml")
        self.profiles = podvm.load_yaml(ROOT / "config" / "launch-profiles.yaml")

    @staticmethod
    def tdx_measurement(value: str) -> dict[str, str]:
        return {name: value for name in ("mr_td", "rtmr_0", "rtmr_1", "rtmr_2")}

    def fake_tdx(self, metadata, tdx, create_acpi, output, config=None):
        output.write_text("{}")
        return self.tdx_measurement("ab" * 48)

    def raw_measurements(self, profiles=None, staging=None):
        profiles = self.profiles if profiles is None else profiles
        value = "ab" * 48
        return {
            "fingerprint": podvm.measurement_fingerprint(staging, self.config, profiles) if staging else "0" * 64,
            "profiles": {
                profile_id: {
                    "tdx": self.tdx_measurement(value),
                    "sev": {
                        model: value
                        for model in podvm.snp_settings(profiles, profile_id)["vcpu_types"]
                    },
                }
                for profile_id in profiles["profiles"]
            },
            "tools": {
                name: podvm.tdx_tool_provenance(self.config) if name == "tdx_measure" else self.config["sources"][name]
                for name in ("tdx_measure", "sev_snp_measure")
            },
        }

    def measurement_document(self, artifact_sha: str, bundle_name: str) -> dict:
        value = "ab" * 48
        common = {
            "cpus": 2,
            "memory": "8G",
            "mode": "direct",
            "kernel": "vmlinuz",
            "initrd": None,
            "cmdline": "console=ttyS0",
            "disk": "podvm.raw",
        }
        return {
            "schema": (
                "https://raw.githubusercontent.com/owner/repo/"
                + "1" * 40
                + "/schemas/measurements.schema.json"
            ),
            "release": {
                "version": "v1",
                "source_repository": "owner/repo",
                "source_revision": "1" * 40,
            },
            "artifact": {
                "name": bundle_name,
                "sha256": artifact_sha,
                "media_type": "application/zstd",
            },
            "inputs": {},
            "profiles": {
                "2vcpu-8g": {
                    "tdx": {
                        "configuration": {
                            **common,
                            "firmware": "firmware/OVMF.inteltdx.fd",
                            "acpi_distribution": "ubuntu:26.04",
                            "qemu_source_version": "qemu-version",
                            "qemu": {
                                "machine": "q35",
                                "cpu": "host",
                                "accel": "kvm",
                                "objects": [],
                                "netdevs": [],
                                "devices": [],
                            },
                            "measurement_note": "test",
                        },
                        "measurement": self.tdx_measurement(value),
                    },
                    "sev": {
                        model: {
                            "configuration": {
                                **common,
                                "firmware": "firmware/AMDSEV.fd",
                                "vcpu_type": model,
                                "vmm_type": "QEMU",
                                "guest_features": "0x1",
                                "qemu": {
                                    "machine": "q35",
                                    "cpu": model,
                                    "objects": [],
                                    "netdevs": [],
                                    "devices": [],
                                },
                            },
                            "measurement": value,
                        }
                        for model in ("EPYC-v4", "EPYC-Milan-v2", "EPYC-Genoa-v1", "EPYC-Turin")
                    },
                }
            },
        }

    @staticmethod
    def create_staging(root: Path) -> Path:
        staging = root / "build" / "staging"
        (staging / "firmware").mkdir(parents=True)
        for relative in (
            "podvm.raw", "vmlinuz", "kernel.config", "kernel_params",
            "firmware/OVMF.inteltdx.fd", "firmware/AMDSEV.fd", "inputs.json",
        ):
            (staging / relative).write_bytes(relative.encode())
        verity = "root_hash=" + "ab" * 32 + ",salt=" + "cd" * 32 + ",data_blocks=128,data_block_size=4096,hash_block_size=4096"
        (staging / "kernel_verity_params").write_text(verity + "\n")
        (staging / "cmdline").write_text(podvm.kata_cmdline(verity) + "\n")
        (staging / "kernel_params").write_text(podvm.ADDITIONAL_KERNEL_PARAMS + "\n")
        config = podvm.load_yaml(podvm.DEFAULT_CONFIG)
        inputs = {key: config[key] for key in ("platform", "build_inputs", "sources", "oci")}
        inputs["local_assets"] = podvm.local_asset_hashes()
        podvm.dump_json(staging / "inputs.json", inputs)
        return staging

    def test_lockfile_and_launch_profiles(self):
        podvm.validate_lock(self.config)
        podvm.validate_profiles(self.profiles)
        self.assertEqual(set(self.profiles["profiles"]), {"2vcpu-8g"})
        self.assertEqual(
            self.profiles["sev"]["defaults"]["vcpu_types"],
            ["EPYC-v4", "EPYC-Milan-v2", "EPYC-Genoa-v1", "EPYC-Turin"],
        )

    def test_yaml_preserves_quoted_hex_versions_and_booleans(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.yaml"
            path.write_text('version: "24.04"\nguest_features: "0x1"\nshare: true\n')
            self.assertEqual(
                podvm.load_yaml(path),
                {"version": "24.04", "guest_features": "0x1", "share": True},
            )
        self.assertEqual(self.config["platform"]["release"], "24.04")

    def test_yaml_rejects_invalid_ambiguous_and_unsafe_documents(self):
        invalid = (
            "", "[]", "key: [", "key: 1\nkey: 2",
            "profiles:\n  same:\n    cpus: 2\n    cpus: 4",
            "1: value", "[]: value",
            "key: !!python/object/apply:os.system [false]",
            "key: 1\n---\nkey: 2",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.yaml"
            for content in invalid:
                with self.subTest(content=content):
                    path.write_text(content)
                    with self.assertRaises(podvm.PodVMError):
                        podvm.load_yaml(path)

    def test_profiles_reject_bad_dimensions(self):
        invalid = (
            ("bad id", 2, "8G"), ("valid", 0, "8G"),
            ("valid", True, "8G"), ("valid", 256, "8G"),
            ("valid", 2, "8GB"), ("valid", 2, "0G"),
        )
        for profile_id, cpus, memory in invalid:
            with self.subTest(profile_id=profile_id, cpus=cpus, memory=memory):
                profiles = copy.deepcopy(self.profiles)
                profiles["profiles"] = {profile_id: {"cpus": cpus, "memory": memory}}
                with self.assertRaises(podvm.PodVMError):
                    podvm.validate_profiles(profiles)

    def test_profiles_reject_invalid_defaults_and_overrides(self):
        invalid = (
            {"vcpu_types": []},
            {"vcpu_types": ["EPYC-Turin", "EPYC-Turin"]},
            {"vcpu_types": ["EPYC-Future"]},
            {"vcpu_types": [1]},
            {"guest_features": 1},
            {"guest_features": "0xAB"},
            {"vmm_type": "ec2"},
            {"cpus": 4},
            None,
        )
        for settings in invalid:
            for defaults in (False, True):
                with self.subTest(settings=settings, defaults=defaults):
                    profiles = copy.deepcopy(self.profiles)
                    if defaults:
                        if isinstance(settings, dict):
                            profiles["sev"]["defaults"].update(settings)
                        else:
                            profiles["sev"]["defaults"] = settings
                    else:
                        profiles["profiles"]["2vcpu-8g"]["sev"] = settings
                    with self.assertRaises(podvm.PodVMError):
                        podvm.validate_profiles(profiles)

    def test_profiles_require_complete_defaults_and_nonempty_catalog(self):
        profiles = copy.deepcopy(self.profiles)
        del profiles["sev"]["defaults"]["guest_features"]
        with self.assertRaises(podvm.PodVMError):
            podvm.validate_profiles(profiles)
        profiles = copy.deepcopy(self.profiles)
        profiles["profiles"] = {}
        with self.assertRaises(podvm.PodVMError):
            podvm.validate_profiles(profiles)

    def test_overrides_replace_model_list_and_inherit_other_defaults(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["profiles"]["2vcpu-8g"]["sev"] = {"vcpu_types": ["EPYC-Turin"]}
        podvm.validate_profiles(profiles)
        self.assertEqual(
            podvm.resolved_profile(profiles, "2vcpu-8g", "sev", "EPYC-Turin"),
            {"cpus": 2, "memory": "8G", "vcpu_type": "EPYC-Turin",
             "vmm_type": "QEMU", "guest_features": "0x1"},
        )
        with self.assertRaises(podvm.PodVMError):
            podvm.resolved_profile(profiles, "2vcpu-8g", "sev", "EPYC-Milan-v2")
        profiles["profiles"]["2vcpu-8g"]["sev"] = {"guest_features": "0x21"}
        podvm.validate_profiles(profiles)
        for model in profiles["sev"]["defaults"]["vcpu_types"]:
            self.assertEqual(
                podvm.resolved_profile(profiles, "2vcpu-8g", "sev", model)["guest_features"],
                "0x21",
            )
        self.assertEqual(profiles["sev"]["defaults"]["guest_features"], "0x1")

    def test_previous_config_format_is_rejected(self):
        with self.assertRaises(podvm.PodVMError):
            podvm.validate_profiles({"tdx": {}, "sev_snp": {}})

    def test_measurement_encoding(self):
        raw = list(range(48))
        self.assertEqual(podvm.measurement_value(raw, "test"), bytes(raw).hex())
        with self.assertRaises(podvm.PodVMError):
            podvm.measurement_value("00" * 47, "test")

    def test_tdx_acpi_uses_network_backend_supported_by_release_qemu(self):
        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary)
            (staging / "cmdline").write_text("console=ttyS0\n")
            metadata = podvm.tdx_metadata(staging, self.profiles, "2vcpu-8g")
        boot = metadata["boot_config"]
        self.assertEqual((boot["cpus"], boot["memory"]), (2, "8G"))
        self.assertEqual(boot["bios"], "../../../firmware/OVMF.inteltdx.fd")
        self.assertEqual(boot["qemu"]["netdevs"], ["hubport,id=network0,hubid=0"])
        self.assertIn(
            "virtio-net-pci,netdev=network0,disable-modern=false,romfile=",
            boot["qemu"]["devices"],
        )
        qemu = self.profiles["tdx"]["qemu"]
        self.assertEqual(qemu["netdevs"], ["user,id=network0"])
        self.assertNotIn("romfile=", " ".join(qemu["runtime_devices"]))

    def test_measurements_keep_complete_records_with_identical_digests(self):
        document = self.measurement_document("2" * 64, "podvm-ubuntu-24.04-x86_64-v1.tar.zst")
        duplicate = copy.deepcopy(document["profiles"]["2vcpu-8g"])
        duplicate["tdx"]["configuration"]["memory"] = "64G"
        for entry in duplicate["sev"].values():
            entry["configuration"]["memory"] = "64G"
        document["profiles"]["2vcpu-64g"] = duplicate
        podvm.validate_measurements(document)
        self.assertEqual(len(document["profiles"]["2vcpu-8g"]["sev"]), 4)

    def test_measurements_reject_invalid_shapes_models_and_dimensions(self):
        valid = self.measurement_document("2" * 64, "podvm-ubuntu-24.04-x86_64-v1.tar.zst")
        for mutation in (
            lambda p: p.pop("tdx"),
            lambda p: p.update(extra={}),
            lambda p: p.update(sev={}),
            lambda p: p["tdx"]["measurement"].pop("rtmr_2"),
            lambda p: p["tdx"].update(measurement={"mr_td": "a" * 96}),
            lambda p: p["tdx"]["measurement"].update(mr_td="bad"),
            lambda p: p["sev"]["EPYC-Turin"].update(measurement="bad"),
            lambda p: p["sev"]["EPYC-Turin"]["configuration"].update(memory="64G"),
            lambda p: p["sev"]["EPYC-Turin"]["configuration"].update(cpus=4),
            lambda p: p["sev"]["EPYC-Turin"]["configuration"].update(vcpu_type="EPYC-Milan-v2"),
            lambda p: p["sev"]["EPYC-Turin"]["configuration"]["qemu"].update(cpu="EPYC-Milan-v2"),
            lambda p: p["sev"].update(unknown=p["sev"].pop("EPYC-Turin")),
        ):
            with self.subTest(mutation=mutation):
                document = copy.deepcopy(valid)
                mutation(document["profiles"]["2vcpu-8g"])
                with self.assertRaises(podvm.PodVMError):
                    podvm.validate_measurements(document)
        for catalog in ({}, {"tdx": {}, "sev_snp": {}}):
            document = copy.deepcopy(valid)
            document["profiles"] = catalog
            with self.assertRaises(podvm.PodVMError):
                podvm.validate_measurements(document)

    def test_launcher_executes_resolved_profiles_and_models(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["profiles"]["32vcpu-64g"] = {"cpus": 32, "memory": "64G"}
        profiles["profiles"]["turin-only"] = {
            "cpus": 4, "memory": "16G", "sev": {"vcpu_types": ["EPYC-Turin"]},
        }
        podvm.validate_profiles(profiles)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "cmdline").write_text("console=ttyS0\n")
            launcher = root / "launch-podvm.sh"
            launcher.write_text(podvm.render_launch_script(profiles))
            qemu = root / "qemu-system-x86_64"
            qemu.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$@"\n')
            qemu.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}"}
            selections = [(["tdx", "32vcpu-64g"], "host,pmu=off")]
            selections += [
                (["sev-snp", "32vcpu-64g", model], model)
                for model in ("EPYC-v4", "EPYC-Milan-v2", "EPYC-Genoa-v1", "EPYC-Turin")
            ]
            for selection, cpu in selections:
                with self.subTest(selection=selection):
                    result = subprocess.run(
                        ["bash", str(launcher), *selection], env=env,
                        capture_output=True, text=True, check=True,
                    )
                    args = result.stdout.splitlines()
                    self.assertEqual(args[args.index("-cpu") + 1], cpu)
                    self.assertEqual(args[args.index("-smp") + 1], "32")
                    self.assertEqual(args[args.index("-m") + 1], "64G")
                    self.assertNotIn("-initrd", args)
                    self.assertIn("format=raw", args[args.index("-drive") + 1])
                    self.assertIn("virtio-blk-pci,drive=root,disable-modern=false", args)
                    if selection[0] == "sev-snp":
                        self.assertIn(
                            "memory-backend-memfd,id=ram1,size=64G,share=true,prealloc=false",
                            args,
                        )
            invalid = (
                [], ["tdx"], ["tdx", "unknown"],
                ["tdx", "2vcpu-8g", "EPYC-Turin"], ["sev-snp", "2vcpu-8g"],
                ["sev-snp", "2vcpu-8g", "unknown"],
                ["sev-snp", "turin-only", "EPYC-Milan-v2"],
                ["sev-snp", "2vcpu-8g", "EPYC-Turin", "extra"],
                ["sev", "2vcpu-8g", "EPYC-Turin"],
            )
            for selection in invalid:
                with self.subTest(invalid=selection):
                    result = subprocess.run(
                        ["bash", str(launcher), *selection], env=env,
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("usage:", result.stderr)

    def test_measure_processes_every_profile_and_model_twice(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["profiles"]["32vcpu-64g"] = {"cpus": 32, "memory": "64G"}
        value = "ab" * 48
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = self.create_staging(root)
            raw = root / "measurements.raw.json"
            args = argparse.Namespace(staging_dir=staging, raw_measurements=raw)

            def fake_tdx(metadata, tdx, create_acpi, output, config=None):
                output.write_text("{}")
                return self.tdx_measurement(value)

            with mock.patch.object(podvm, "run_tdx", side_effect=fake_tdx) as tdx_run:
                with mock.patch.object(podvm, "run_snp", return_value=value) as snp_run:
                    podvm.measure(args, self.config, profiles)

            self.assertEqual(tdx_run.call_count, 4)
            self.assertEqual(snp_run.call_count, 16)
            self.assertEqual(
                [call.args[2] for call in tdx_run.call_args_list],
                [True, False, True, False],
            )
            result = podvm.load_json(raw)
            self.assertEqual(result, self.raw_measurements(profiles, staging))
            podvm.validate_raw_measurements(result, self.config, profiles)
            metadata = podvm.load_json(staging / "launch" / "tdx" / "32vcpu-64g" / "metadata.json")
            self.assertEqual(metadata["boot_config"]["cpus"], 32)
            self.assertEqual(metadata["boot_config"]["memory"], "64G")
            for model in ("EPYC-v4", "EPYC-Milan-v2", "EPYC-Genoa-v1", "EPYC-Turin"):
                launch = podvm.load_json(staging / "launch" / "sev" / "32vcpu-64g" / f"{model}.json")
                self.assertEqual(launch["qemu"]["cpu"], model)
                self.assertIn("size=64G", launch["qemu"]["objects"][0])
            measured = [call.args[1] for call in snp_run.call_args_list]
            for cpus, memory in ((2, "8G"), (32, "64G")):
                for model in ("EPYC-v4", "EPYC-Milan-v2", "EPYC-Genoa-v1", "EPYC-Turin"):
                    self.assertEqual(
                        measured.count({
                            "cpus": cpus, "memory": memory, "vcpu_type": model,
                            "vmm_type": "QEMU", "guest_features": "0x1",
                        }), 2,
                    )

    def test_measure_uses_profile_overrides(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["profiles"]["2vcpu-8g"]["sev"] = {
            "vcpu_types": ["EPYC-Turin"], "guest_features": "0x21",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = self.create_staging(root)
            args = argparse.Namespace(staging_dir=staging, raw_measurements=root / "raw.json")
            with mock.patch.object(podvm, "run_tdx", side_effect=self.fake_tdx):
                with mock.patch.object(podvm, "run_snp", return_value="ab" * 48) as snp:
                    podvm.measure(args, self.config, profiles)
            self.assertEqual(snp.call_count, 2)
            self.assertEqual(snp.call_args.args[1]["guest_features"], "0x21")
            self.assertEqual(set(podvm.load_json(args.raw_measurements)["profiles"]["2vcpu-8g"]["sev"]), {"EPYC-Turin"})

    def test_measure_rejects_nondeterminism_in_either_tee(self):
        for tee in ("tdx", "sev"):
            with self.subTest(tee=tee), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                staging = self.create_staging(root)
                args = argparse.Namespace(staging_dir=staging, raw_measurements=root / "raw.json")
                tdx_values = [self.tdx_measurement("ab" * 48)] * 2
                snp_values = ["ab" * 48] * 8
                if tee == "tdx":
                    tdx_values[1] = self.tdx_measurement("cd" * 48)
                else:
                    snp_values[1] = "cd" * 48
                def fake_tdx(metadata, tdx, create_acpi, output, config=None):
                    output.write_text("{}")
                    return tdx_values.pop(0)

                with mock.patch.object(podvm, "run_tdx", side_effect=fake_tdx):
                    with mock.patch.object(podvm, "run_snp", side_effect=snp_values):
                        with self.assertRaisesRegex(podvm.PodVMError, "nondeterministic"):
                            podvm.measure(args, self.config, self.profiles)
                self.assertFalse(args.raw_measurements.exists())

    def test_snp_command_passes_resolved_cpu_and_guest_features(self):
        profile = podvm.resolved_profile(self.profiles, "2vcpu-8g", "sev", "EPYC-Turin")
        with tempfile.TemporaryDirectory() as temporary:
            staging = self.create_staging(Path(temporary))
            with mock.patch.object(podvm, "require_tool"):
                with mock.patch.object(podvm, "capture", return_value="ab" * 48) as capture:
                    self.assertEqual(podvm.run_snp(staging, profile), "ab" * 48)
            command = capture.call_args.args[0]
            self.assertFalse(any(arg.startswith("--initrd") for arg in command))
            for argument in ("--vcpus=2", "--vcpu-type=EPYC-Turin", "--vmm-type=QEMU", "--guest-features=0x1"):
                self.assertIn(argument, command)

    def test_raw_guest_boot_contract_and_annotations(self):
        with tempfile.TemporaryDirectory() as temporary:
            staging = self.create_staging(Path(temporary))
            podvm.validate_staging(staging)
            cmdline = (staging / "cmdline").read_text()
            self.assertIn("verity 1 /dev/vda1 /dev/vda2 4096 4096 128 0 sha256", cmdline)
            self.assertIn("dm-verity,,,ro,0 1024", cmdline)
            self.assertEqual(cmdline.count("root=/dev/dm-0"), 1)
            annotations = podvm.kata_annotations(staging, {"cpus": 2, "memory": "8G"}, "snp", "/opt/podvm")
            prefix = "io.katacontainers.config.hypervisor."
            self.assertEqual(annotations[prefix + "default_memory"], "8192")
            self.assertEqual(annotations[prefix + "image"], "/opt/podvm/podvm.raw")
            self.assertNotIn(prefix + "initrd", annotations)
            self.assertNotIn("root=", annotations[prefix + "kernel_params"])
            metadata = podvm.tdx_metadata(staging, self.profiles, "2vcpu-8g")
            self.assertIsNone(metadata["direct"]["initrd"])
            (staging / "initrd.img").write_bytes(b"old initrd")
            with self.assertRaisesRegex(podvm.PodVMError, "obsolete initrd"):
                podvm.validate_staging(staging)

    def test_verity_rejects_incomplete_duplicate_and_invalid_fields(self):
        valid = "root_hash=" + "ab" * 32 + ",salt=cd,data_blocks=128,data_block_size=4096,hash_block_size=4096"
        for value in (valid + ",salt=ef", valid.replace("data_blocks=128", "data_blocks=0"),
                      valid.replace("data_block_size=4096", "data_block_size=513"),
                      valid.replace("root_hash=" + "ab" * 32, "root_hash=bad"),
                      valid.replace(",salt=cd", "")):
            with self.subTest(value=value), self.assertRaises(podvm.PodVMError):
                podvm.verity_fields(value)

    def test_package_rejects_assets_changed_after_measurement(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            staging = self.create_staging(workspace)
            raw = workspace / "raw.json"
            podvm.dump_json(raw, self.raw_measurements(staging=staging))
            args = argparse.Namespace(staging_dir=staging, raw_measurements=raw,
                dist_dir=workspace / "dist", workspace=workspace, release_version="dev",
                source_revision="1" * 40, source_repository="owner/repo")
            (staging / "podvm.raw").write_bytes(b"changed disk")
            with self.assertRaisesRegex(podvm.PodVMError, "stale measurements"):
                podvm.package(args, self.config, self.profiles)
            self.assertFalse(args.dist_dir.exists())

    def test_local_guest_agent_starts_without_peerpod_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kata = root / "kata"
            (kata / "src/agent").mkdir(parents=True)
            (kata / "src/agent/kata-agent.service.in").write_text(
                "[Unit]\nWants=kata-containers.target\n[Service]\nExecStart=@BINDIR@/@AGENT_NAME@\n")
            (kata / "src/agent/kata-containers.target").write_text(
                "[Unit]\nRequires=basic.target tmp.mount kata-agent.service\n")
            podvm_dir = root / "podvm"
            tree = podvm_dir / "resources/binaries-tree"
            units = tree / "etc/systemd/system"
            units.mkdir(parents=True)
            (units / "kata-agent.path").write_text("PathExists=/run/peerpod/userdata\n")
            (tree / "usr/local/bin").mkdir(parents=True)
            (tree / "usr/local/bin/agent-protocol-forwarder").write_text("obsolete")
            (tree / "etc/kata-opa").mkdir(parents=True)
            podvm.install_local_guest(podvm_dir, kata)
            self.assertFalse((units / "kata-agent.path").exists())
            self.assertFalse((tree / "usr/local/bin/agent-protocol-forwarder").exists())
            self.assertIn("vsock://-1:1024", (tree / "etc/agent-config.toml").read_text())
            agent = (units / "kata-agent.service").read_text()
            self.assertNotIn("confidential-data-hub", agent)
            for unit in units.glob("*"):
                self.assertNotIn("/run/peerpod", unit.read_text())
                self.assertNotIn("NetworkNamespacePath", unit.read_text())

    def test_raw_measurements_require_exact_coverage_and_provenance(self):
        valid = self.raw_measurements()
        podvm.validate_raw_measurements(valid, self.config, self.profiles)
        for mutation in (
            lambda r: r["profiles"].pop("2vcpu-8g"),
            lambda r: r["profiles"].update(extra=r["profiles"]["2vcpu-8g"]),
            lambda r: r["profiles"]["2vcpu-8g"].pop("tdx"),
            lambda r: r["profiles"]["2vcpu-8g"].update(extra={}),
            lambda r: r["profiles"]["2vcpu-8g"]["sev"].pop("EPYC-Turin"),
            lambda r: r["profiles"]["2vcpu-8g"]["sev"].update({"EPYC-Rome-v3": "ab" * 48}),
            lambda r: r["profiles"]["2vcpu-8g"]["tdx"].pop("rtmr_2"),
            lambda r: r["profiles"]["2vcpu-8g"]["sev"].update({"EPYC-Turin": "bad"}),
            lambda r: r["tools"].update(sev_snp_measure={}),
        ):
            with self.subTest(mutation=mutation):
                raw = copy.deepcopy(valid)
                mutation(raw)
                with self.assertRaises(podvm.PodVMError):
                    podvm.validate_raw_measurements(raw, self.config, self.profiles)
        with self.assertRaises(podvm.PodVMError):
            podvm.validate_raw_measurements({"tdx": {}, "sev_snp": {}, "tools": {}}, self.config, self.profiles)

    @staticmethod
    def write_release_document(dist, document):
        measurements = dist / "measurements.json"
        measurements.write_text(json.dumps(document))
        bundle = dist / document["artifact"]["name"]
        (dist / "SHA256SUMS").write_text(
            f"{podvm.sha256(bundle)}  {bundle.name}\n"
            f"{podvm.sha256(measurements)}  measurements.json\n"
        )

    def test_release_validates_model_coverage_dimensions_and_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            bundle = dist / "podvm-ubuntu-24.04-x86_64-v1.tar.zst"
            bundle.write_bytes(b"bundle")
            valid = self.measurement_document(podvm.sha256(bundle), bundle.name)
            self.write_release_document(dist, valid)
            podvm.validate_release(dist, self.profiles)
            for mutation in (
                lambda d: d["profiles"]["2vcpu-8g"]["sev"].pop("EPYC-Turin"),
                lambda d: d["profiles"].update(extra=copy.deepcopy(d["profiles"]["2vcpu-8g"])),
                lambda d: d["profiles"]["2vcpu-8g"]["sev"]["EPYC-Turin"]["configuration"].update(guest_features="0x21"),
            ):
                document = copy.deepcopy(valid)
                mutation(document)
                self.write_release_document(dist, document)
                with self.assertRaises(podvm.PodVMError):
                    podvm.validate_release(dist, self.profiles)
            document = copy.deepcopy(valid)
            document["profiles"]["2vcpu-8g"]["tdx"]["configuration"]["cpus"] = 4
            for entry in document["profiles"]["2vcpu-8g"]["sev"].values():
                entry["configuration"]["cpus"] = 4
            podvm.validate_measurements(document)
            self.write_release_document(dist, document)
            with self.assertRaises(podvm.PodVMError):
                podvm.validate_release(dist, self.profiles)
            self.write_release_document(dist, valid)
            (dist / "unexpected.txt").write_text("no")
            with self.assertRaises(podvm.PodVMError):
                podvm.validate_release(dist)

    @unittest.skipUnless(shutil.which("zstd") and shutil.which("tar"), "tar and zstd are required")
    def test_package_creates_exact_release_contract(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["profiles"]["turin-only"] = {
            "cpus": 4, "memory": "16G", "sev": {"vcpu_types": ["EPYC-Turin"]},
        }
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            staging = self.create_staging(workspace)
            raw = workspace / "measurements.raw.json"
            raw.write_text(json.dumps(self.raw_measurements(profiles, staging)))
            args = argparse.Namespace(
                staging_dir=staging, raw_measurements=raw,
                dist_dir=workspace / "dist", workspace=workspace,
                release_version="v1.2.3", source_revision="1" * 40,
                source_repository="owner/repo",
            )
            podvm.package(args, self.config, profiles)
            podvm.validate_release(workspace / "dist", profiles)
            document = podvm.load_json(workspace / "dist" / "measurements.json")
            self.assertEqual(set(document["profiles"]), {"2vcpu-8g", "turin-only"})
            shared = document["profiles"]["2vcpu-8g"]
            self.assertEqual(set(shared), {"tdx", "sev"})
            self.assertEqual(set(shared["sev"]), {"EPYC-v4", "EPYC-Milan-v2", "EPYC-Genoa-v1", "EPYC-Turin"})
            self.assertEqual(set(document["profiles"]["turin-only"]["sev"]), {"EPYC-Turin"})
            for profile_id, entry in document["profiles"].items():
                expected = profiles["profiles"][profile_id]
                for record in [entry["tdx"], *entry["sev"].values()]:
                    self.assertEqual(record["configuration"]["cpus"], expected["cpus"])
                    self.assertEqual(record["configuration"]["memory"], expected["memory"])
            bundle = workspace / "dist" / "podvm-ubuntu-24.04-x86_64-v1.2.3.tar.zst"
            members = set(podvm.capture(["tar", "--zstd", "-tf", str(bundle)]).splitlines())
            for member in ("launch-podvm.sh", "launch-profiles.json",
                           "schemas/launch-profiles.schema.json", "schemas/measurements.schema.json"):
                self.assertIn(f"podvm/{member}", members)
            bundled = json.loads(podvm.capture(["tar", "--zstd", "-xOf", str(bundle), "podvm/launch-profiles.json"]))
            self.assertEqual(bundled, profiles)
            checksums = subprocess.run(
                ["sha256sum", "--check", "SHA256SUMS"], cwd=workspace / "dist",
                capture_output=True, text=True, check=True,
            )
            self.assertIn("measurements.json: OK", checksums.stdout)


if __name__ == "__main__":
    unittest.main()

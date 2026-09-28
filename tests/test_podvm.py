import argparse
import copy
import importlib.util
import json
import shutil
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
        self.config = podvm.load_json(ROOT / "versions.yaml")
        self.profiles = podvm.load_json(ROOT / "config" / "launch-profiles.json")

    @staticmethod
    def tdx_measurement(value: str) -> dict[str, str]:
        return {name: value for name in ("mr_td", "rtmr_0", "rtmr_1", "rtmr_2")}

    def measurement_document(self, artifact_sha: str, bundle_name: str) -> dict:
        value = "ab" * 48
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
                "tdx": {
                    "2vcpu-8g": {
                        "configuration": {
                            "cpus": 2,
                            "memory": "8G",
                            "acpi_distribution": "ubuntu:26.04",
                            "qemu_source_version": "qemu-version",
                            "mode": "direct",
                            "firmware": "firmware/OVMF.inteltdx.fd",
                            "kernel": "vmlinuz",
                            "initrd": "initrd.img",
                            "cmdline": "console=ttyS0",
                            "disk": "podvm.qcow2",
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
                    }
                },
                "sev_snp": {
                    "epyc-v4-2vcpu-8g": {
                        "configuration": {
                            "cpus": 2,
                            "memory": "8G",
                            "vcpu_type": "EPYC-v4",
                            "vmm_type": "QEMU",
                            "guest_features": "0x1",
                            "mode": "direct",
                            "firmware": "firmware/AMDSEV.fd",
                            "kernel": "vmlinuz",
                            "initrd": "initrd.img",
                            "cmdline": "console=ttyS0",
                            "disk": "podvm.qcow2",
                            "qemu": {
                                "machine": "q35",
                                "cpu": "EPYC-v4",
                                "objects": [],
                                "netdevs": [],
                                "devices": [],
                            },
                        },
                        "measurement": value,
                    }
                },
            },
        }

    @staticmethod
    def create_staging(root: Path) -> Path:
        staging = root / "build" / "staging"
        (staging / "firmware").mkdir(parents=True)
        for relative in (
            "podvm.qcow2",
            "vmlinuz",
            "initrd.img",
            "firmware/OVMF.inteltdx.fd",
            "firmware/AMDSEV.fd",
            "inputs.json",
        ):
            (staging / relative).write_bytes(relative.encode())
        (staging / "cmdline").write_text("console=ttyS0 roothash=0123456789abcdef\n")
        return staging

    def test_lockfile_and_launch_profiles(self):
        podvm.validate_lock(self.config)
        podvm.validate_profiles(self.profiles)

    def test_profile_validation_rejects_bad_dimensions_and_cpu_type(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["tdx"]["profiles"]["bad id"] = {"cpus": 0, "memory": "8GB"}
        with self.assertRaises(podvm.PodVMError):
            podvm.validate_profiles(profiles)

        profiles = copy.deepcopy(self.profiles)
        profiles["sev_snp"]["profiles"]["future-cpu"] = {
            "cpus": 4,
            "memory": "16G",
            "vcpu_type": "EPYC-Future",
            "vmm_type": "QEMU",
            "guest_features": "0x1",
        }
        with self.assertRaises(podvm.PodVMError):
            podvm.validate_profiles(profiles)

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
        self.assertEqual(
            metadata["boot_config"]["qemu"]["netdevs"],
            ["hubport,id=network0,hubid=0"],
        )
        self.assertIn(
            "virtio-net-pci,netdev=network0,disable-modern=false,romfile=",
            metadata["boot_config"]["qemu"]["devices"],
        )
        qemu = self.profiles["tdx"]["qemu"]
        self.assertEqual(qemu["netdevs"], ["user,id=network0"])
        self.assertIn(
            "virtio-net-pci,netdev=network0,disable-modern=false",
            qemu["runtime_devices"],
        )
        self.assertNotIn("romfile=", " ".join(qemu["runtime_devices"]))

    def test_measurements_keep_complete_profile_records(self):
        document = self.measurement_document("2" * 64, "podvm-ubuntu-24.04-x86_64-v1.tar.zst")
        same_value = document["profiles"]["sev_snp"]["epyc-v4-2vcpu-8g"]["measurement"]
        duplicate = copy.deepcopy(document["profiles"]["sev_snp"]["epyc-v4-2vcpu-8g"])
        duplicate["configuration"]["memory"] = "64G"
        document["profiles"]["sev_snp"]["epyc-v4-2vcpu-64g"] = {
            "configuration": duplicate["configuration"],
            "measurement": same_value,
        }
        podvm.validate_measurements(document)

        del document["profiles"]["tdx"]["2vcpu-8g"]["measurement"]["rtmr_2"]
        with self.assertRaises(podvm.PodVMError):
            podvm.validate_measurements(document)

    def test_launcher_is_generated_from_profiles(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["tdx"]["profiles"]["32vcpu-64g"] = {"cpus": 32, "memory": "64G"}
        profiles["sev_snp"]["profiles"]["milan-32vcpu-64g"] = {
            "cpus": 32,
            "memory": "64G",
            "vcpu_type": "EPYC-Milan-v2",
            "vmm_type": "QEMU",
            "guest_features": "0x1",
        }
        podvm.validate_profiles(profiles)
        launcher = podvm.render_launch_script(profiles)
        self.assertIn("tdx/32vcpu-64g)", launcher)
        self.assertIn("sev-snp/milan-32vcpu-64g)", launcher)
        self.assertIn("-smp '32'", launcher)
        self.assertIn("-m '64G'", launcher)
        self.assertIn("-cpu 'EPYC-Milan-v2'", launcher)
        self.assertIn("size=64G", launcher)
        self.assertIn("[[ $# -eq 2 ]] || usage", launcher)

    def test_measure_processes_every_profile_twice(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["tdx"]["profiles"]["32vcpu-64g"] = {"cpus": 32, "memory": "64G"}
        profiles["sev_snp"]["profiles"]["milan-32vcpu-64g"] = {
            "cpus": 32,
            "memory": "64G",
            "vcpu_type": "EPYC-Milan-v2",
            "vmm_type": "QEMU",
            "guest_features": "0x1",
        }
        value = "ab" * 48
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = self.create_staging(root)
            raw = root / "measurements.raw.json"
            args = argparse.Namespace(staging_dir=staging, raw_measurements=raw)

            def fake_tdx(metadata, tdx, create_acpi, output):
                del metadata, tdx, create_acpi
                output.write_text("{}")
                return self.tdx_measurement(value)

            with mock.patch.object(podvm, "run_tdx", side_effect=fake_tdx) as tdx_run:
                with mock.patch.object(podvm, "run_snp", return_value=value) as snp_run:
                    podvm.measure(args, self.config, profiles)

            self.assertEqual(tdx_run.call_count, 4)
            self.assertEqual(snp_run.call_count, 4)
            result = podvm.load_json(raw)
            self.assertEqual(set(result["tdx"]), {"2vcpu-8g", "32vcpu-64g"})
            self.assertEqual(
                set(result["sev_snp"]), {"epyc-v4-2vcpu-8g", "milan-32vcpu-64g"}
            )
            metadata = podvm.load_json(staging / "launch" / "tdx" / "32vcpu-64g" / "metadata.json")
            self.assertEqual(metadata["boot_config"]["cpus"], 32)
            self.assertEqual(metadata["boot_config"]["memory"], "64G")
            snp_launch = podvm.load_json(
                staging / "launch" / "sev-snp" / "milan-32vcpu-64g.json"
            )
            self.assertEqual(snp_launch["qemu"]["cpu"], "EPYC-Milan-v2")
            self.assertIn("size=64G", snp_launch["qemu"]["objects"][0])

    def test_raw_measurements_must_cover_exact_profile_set(self):
        value = "ab" * 48
        raw = {
            "tdx": {"2vcpu-8g": self.tdx_measurement(value)},
            "sev_snp": {"epyc-v4-2vcpu-8g": value},
            "tools": {
                "tdx_measure": self.config["sources"]["tdx_measure"],
                "sev_snp_measure": self.config["sources"]["sev_snp_measure"],
            },
        }
        podvm.validate_raw_measurements(raw, self.config, self.profiles)
        raw["tdx"]["unconfigured"] = self.tdx_measurement(value)
        with self.assertRaises(podvm.PodVMError):
            podvm.validate_raw_measurements(raw, self.config, self.profiles)

    def test_release_validator_rejects_extra_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            bundle = dist / "podvm-ubuntu-24.04-x86_64-v1.tar.zst"
            bundle.write_bytes(b"bundle")
            document = self.measurement_document(podvm.sha256(bundle), bundle.name)
            measurements = dist / "measurements.json"
            measurements.write_text(json.dumps(document))
            (dist / "SHA256SUMS").write_text(
                f"{podvm.sha256(bundle)}  {bundle.name}\n"
                f"{podvm.sha256(measurements)}  measurements.json\n"
            )
            podvm.validate_release(dist)
            (dist / "unexpected.txt").write_text("no")
            with self.assertRaises(podvm.PodVMError):
                podvm.validate_release(dist)

    @unittest.skipUnless(shutil.which("zstd") and shutil.which("tar"), "tar and zstd are required")
    def test_package_creates_exact_release_contract(self):
        value = "ab" * 48
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            staging = self.create_staging(workspace)
            raw = workspace / "measurements.raw.json"
            raw.write_text(
                json.dumps(
                    {
                        "tdx": {"2vcpu-8g": self.tdx_measurement(value)},
                        "sev_snp": {"epyc-v4-2vcpu-8g": value},
                        "tools": {
                            "tdx_measure": self.config["sources"]["tdx_measure"],
                            "sev_snp_measure": self.config["sources"]["sev_snp_measure"],
                        },
                    }
                )
            )
            args = argparse.Namespace(
                staging_dir=staging,
                raw_measurements=raw,
                dist_dir=workspace / "dist",
                workspace=workspace,
                release_version="v1.2.3",
                source_revision="1" * 40,
                source_repository="owner/repo",
            )
            podvm.package(args, self.config, self.profiles)
            podvm.validate_release(workspace / "dist")
            document = podvm.load_json(workspace / "dist" / "measurements.json")
            self.assertNotIn("schema_version", document)
            self.assertNotIn("rvps", document)
            self.assertEqual(set(document["profiles"]["tdx"]), {"2vcpu-8g"})
            self.assertEqual(set(document["profiles"]["sev_snp"]), {"epyc-v4-2vcpu-8g"})
            bundle = workspace / "dist" / "podvm-ubuntu-24.04-x86_64-v1.2.3.tar.zst"
            members = set(podvm.capture(["tar", "--zstd", "-tf", str(bundle)]).splitlines())
            self.assertIn("podvm/launch-podvm.sh", members)
            self.assertIn("podvm/launch-profiles.json", members)
            self.assertIn("podvm/schemas/launch-profiles.schema.json", members)


if __name__ == "__main__":
    unittest.main()

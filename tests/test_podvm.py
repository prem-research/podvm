import importlib.util
import json
import argparse
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("podvm", ROOT / "podvm.py")
podvm = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(podvm)


class PodVMTests(unittest.TestCase):
    def setUp(self):
        self.config = podvm.load_json(ROOT / "versions.yaml")

    def test_lockfile_and_launch_profile(self):
        podvm.validate_lock(self.config)

    def test_measurement_encoding(self):
        raw = list(range(48))
        self.assertEqual(podvm.measurement_value(raw, "test"), bytes(raw).hex())
        with self.assertRaises(podvm.PodVMError):
            podvm.measurement_value("00" * 47, "test")

    def test_tdx_acpi_uses_network_backend_supported_by_release_qemu(self):
        with tempfile.TemporaryDirectory() as temporary:
            staging = Path(temporary)
            (staging / "cmdline").write_text("console=ttyS0\n")
            metadata = podvm.tdx_metadata(staging, self.config)
        self.assertEqual(
            metadata["boot_config"]["qemu"]["netdevs"],
            ["hubport,id=network0,hubid=0"],
        )
        self.assertIn(
            "virtio-net-pci,netdev=network0,disable-modern=false,romfile=",
            metadata["boot_config"]["qemu"]["devices"],
        )
        profile = podvm.load_json(ROOT / "config" / "launch-profile.json")["tdx"]
        self.assertEqual(profile["netdevs"], ["user,id=network0"])
        self.assertIn(
            "virtio-net-pci,netdev=network0,disable-modern=false",
            profile["devices"],
        )
        self.assertNotIn("romfile=", " ".join(profile["devices"]))

    def test_rvps_mapping_must_match_profiles(self):
        value = "ab" * 48
        tdx = {name: value for name in ("mr_td", "rtmr_0", "rtmr_1", "rtmr_2")}
        document = {
            "schema": "https://raw.githubusercontent.com/owner/repo/" + "1" * 40 + "/schemas/measurements.schema.json",
            "schema_version": 1,
            "release": {
                "version": "v1",
                "source_repository": "owner/repo",
                "source_revision": "1" * 40,
            },
            "artifact": {
                "name": "podvm-ubuntu-24.04-x86_64-v1.tar.zst",
                "sha256": "2" * 64,
                "media_type": "application/zstd",
            },
            "inputs": {},
            "profiles": {
                "tdx": {"boot": {}, "measurement": tdx},
                "sev_snp": {"boot": {}, "measurement": value},
            },
            "rvps": {
                "reference_values": {
                    **{name: [item] for name, item in tdx.items()},
                    "snp_launch_measurement": [value],
                }
            },
        }
        podvm.validate_measurements(document)
        document["rvps"]["reference_values"]["mr_td"] = ["cd" * 48]
        with self.assertRaises(podvm.PodVMError):
            podvm.validate_measurements(document)

    def test_release_validator_rejects_extra_assets(self):
        value = "ab" * 48
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            bundle = dist / "podvm-ubuntu-24.04-x86_64-v1.tar.zst"
            bundle.write_bytes(b"bundle")
            tdx = {name: value for name in ("mr_td", "rtmr_0", "rtmr_1", "rtmr_2")}
            document = {
                "schema": "https://raw.githubusercontent.com/owner/repo/" + "1" * 40 + "/schemas/measurements.schema.json",
                "schema_version": 1,
                "release": {
                    "version": "v1",
                    "source_repository": "owner/repo",
                    "source_revision": "1" * 40,
                },
                "artifact": {
                    "name": bundle.name,
                    "sha256": podvm.sha256(bundle),
                    "media_type": "application/zstd",
                },
                "inputs": {},
                "profiles": {
                    "tdx": {"boot": {}, "measurement": tdx},
                    "sev_snp": {"boot": {}, "measurement": value},
                },
                "rvps": {
                    "reference_values": {
                        **{name: [item] for name, item in tdx.items()},
                        "snp_launch_measurement": [value],
                    }
                },
            }
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
            staging = workspace / "build" / "staging"
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
            raw = workspace / "measurements.raw.json"
            raw.write_text(
                json.dumps(
                    {
                        "tdx": {
                            name: value for name in ("mr_td", "rtmr_0", "rtmr_1", "rtmr_2")
                        },
                        "sev_snp": value,
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
            podvm.package(args, self.config)
            podvm.validate_release(workspace / "dist")


if __name__ == "__main__":
    unittest.main()

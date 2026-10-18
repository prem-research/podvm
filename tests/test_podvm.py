import argparse
import base64
import copy
import gzip
import importlib.util
import json
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 remains supported by the build CLI.
    tomllib = None
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
        self.all_profiles = podvm.load_yaml(podvm.DEFAULT_PROFILES)
        self.profiles = podvm.select_profiles(self.all_profiles, "cpu")

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
            "variant": "cpu",
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
            "artifacts": {"cpu": {
                "name": bundle_name,
                "sha256": artifact_sha,
                "media_type": "application/zstd",
            }},
            "inputs": {"cpu": podvm.catalog_inputs(self.config, self.profiles, "cpu", "0" * 64)},
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
    def create_staging(root: Path, version="dev", revision="1" * 40) -> Path:
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
        inputs = podvm.locked_inputs(config)
        inputs["local_assets"] = podvm.local_asset_hashes()
        inputs["guest_identity"] = podvm.guest_identity(version, revision)
        podvm.dump_json(staging / "inputs.json", inputs)
        return staging

    @unittest.skipUnless(sys.platform == "linux", "requires GNU sed in the Linux image builder")
    def test_guest_identity_embedded_by_postinst_preserves_ubuntu_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            postinst = root / "mkosi.images/system/mkosi.postinst"
            postinst.parent.mkdir(parents=True)
            postinst.write_text(
                '#!/usr/bin/env bash\nset -eu\n{\n'
                '  echo "IMAGE_ID=\\"podvm\\""\n'
                '  echo "IMAGE_VERSION=\\"${IMAGE_VERSION-v0.0.0}\\""\n'
                '  echo "VARIANT_ID=\\"${VARIANT_ID}\\""\n'
                '} >> "${BUILDROOT}/etc/os-release"\n'
                'touch "${BUILDROOT}/postinst-ran"\n'
            )
            rootfs = root / "rootfs"
            (rootfs / "etc").mkdir(parents=True)
            os_release = rootfs / "etc/os-release"
            ubuntu = 'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n'
            os_release.write_text(ubuntu + 'IMAGE_ID=old\nIMAGE_VERSION="upstream-dirty"\n'
                                  'PODVM_SOURCE_REVISION="old"\n')
            identity = podvm.guest_identity("v1.2.3-rc1+build.2", "a" * 40)
            podvm.configure_guest_identity(root, identity)
            subprocess.run(["bash", str(postinst)], check=True, env={
                **os.environ, "BUILDROOT": str(rootfs), "VARIANT_ID": "production",
                "IMAGE_VERSION": "upstream-dirty",
            })
            podvm.validate_guest_identity(rootfs, identity)
            self.assertTrue(os_release.read_text().startswith(ubuntu))
            self.assertIn('VARIANT_ID="production"', os_release.read_text())
            self.assertTrue((rootfs / "postinst-ran").exists())
            for key, value in identity.items():
                self.assertEqual(os_release.read_text().count(f'{key}="{value}"'), 1)
            with self.assertRaisesRegex(podvm.PodVMError, "pinned CAA os-release"):
                podvm.configure_guest_identity(root, identity)

    def test_guest_identity_rejects_invalid_versions_and_revisions(self):
        for version in ("", "release/v1", "v1\nIMAGE_ID=evil", 'v1"', "$(id)", "v1 space", "-v1"):
            with self.subTest(version=version), self.assertRaises(podvm.PodVMError):
                podvm.guest_identity(version, "1" * 40)
        for revision in ("", "1234567", "z" * 40, "1" * 40 + "\n"):
            with self.subTest(revision=revision), self.assertRaises(podvm.PodVMError):
                podvm.guest_identity("dev", revision)
        for version in ("dev", "v1.2.3", "pr-123-abcdef123456", "manual-abcdef123456"):
            self.assertEqual(podvm.guest_identity(version, "1" * 40)["IMAGE_VERSION"], version)

    def test_guest_identity_validation_rejects_missing_duplicate_and_wrong_fields(self):
        identity = podvm.guest_identity("v1.2.3", "1" * 40)
        valid = "\n".join(f'{key}="{value}"' for key, value in identity.items()) + "\n"
        with tempfile.TemporaryDirectory() as temporary:
            rootfs = Path(temporary)
            (rootfs / "etc").mkdir()
            with self.assertRaisesRegex(podvm.PodVMError, "missing /etc/os-release"):
                podvm.validate_guest_identity(rootfs, identity)
            for content in (
                valid.replace('IMAGE_ID="podvm"\n', ""),
                valid + 'IMAGE_VERSION="v1.2.3"\n',
                valid.replace("v1.2.3", "v1.2.4"),
                valid.replace("1" * 40, "2" * 40),
                valid.replace('IMAGE_ID="podvm"', 'IMAGE_ID="unterminated'),
            ):
                (rootfs / "etc/os-release").write_text(content)
                with self.subTest(content=content), self.assertRaises(podvm.PodVMError):
                    podvm.validate_guest_identity(rootfs, identity)

    def test_build_cli_identity_defaults_and_overrides(self):
        args = podvm.parser().parse_args(["build"])
        self.assertEqual(args.release_version, "dev")
        self.assertIsNone(args.source_revision)
        args = podvm.parser().parse_args([
            "build", "--release-version", "v1.2.3", "--source-revision", "1" * 40,
        ])
        self.assertEqual(args.release_version, "v1.2.3")
        self.assertEqual(args.source_revision, "1" * 40)

    def test_lockfile_and_launch_profiles(self):
        podvm.validate_lock(self.config)
        podvm.validate_profiles(self.profiles)
        self.assertEqual(set(self.profiles["profiles"]), {"2vcpu-8g"})
        self.assertEqual(
            self.profiles["sev"]["defaults"]["vcpu_types"],
            ["EPYC-v4", "EPYC-Milan-v2", "EPYC-Genoa-v1", "EPYC-Turin"],
        )

    @unittest.skipIf(tomllib is None, "TOML parsing needs Python 3.11+")
    def test_model_initdata_preserves_structured_config_and_policy(self):
        models = [{"modelid": "org/model@revision", "mount_path": "/models/example",
                   "info": "ab" * 32 + "_4096_01234567-89ab-cdef-0123-456789abcdef"}]
        policy = 'package agent_policy\ndefault CreateContainerRequest := false\n'
        encoded = podvm.encode_model_initdata(models, policy)
        decoded = tomllib.loads(gzip.decompress(base64.b64decode(encoded)).decode())
        self.assertEqual(json.loads(decoded["data"]["model-mounts.json"]), models)
        self.assertEqual(decoded["data"]["policy.rego"], policy)
        self.assertEqual(podvm.encode_model_initdata(models, policy), encoded)

    def test_modelwrap_origin_mismatch_prevents_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            output = work / "model-components"
            output.mkdir()
            source = self.config["sources"]["modelwrap"]
            podvm.dump_json(output / "modelwrap.info", {
                "Version": source["tag"], "Origin": {"Hash": "0" * 40, "URL": source["repository"]}
            })
            with mock.patch.object(podvm, "model_builder", return_value="builder"), \
                    mock.patch.object(podvm, "run"):
                with self.assertRaisesRegex(podvm.PodVMError, "module origin"):
                    podvm.build_model_components(work / "kata", work / "tree", self.config, work)
            self.assertFalse((work / "tree").exists())

    def test_model_smoke_timeout_cannot_pass_as_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "fixture").mkdir()
            staging = self.create_staging(work)
            fixtures = [{"modelid": "org/model@revision", "mount_path": "/models/example0",
                         "input_path": "/work/input.mpk",
                         "info": "ab" * 32 + "_4096_01234567-89ab-cdef-0123-456789abcdef"}]
            base = {"mounts": [], "process": {"args": []}}
            with mock.patch.object(podvm, "build_model_smoke_fixtures", return_value=fixtures), \
                    mock.patch.object(podvm, "save_smoke_diagnostics", return_value=("model mount helper mount failed", "details")), \
                    mock.patch.object(podvm, "stop_smoke_container"), \
                    mock.patch.object(podvm.subprocess, "run") as run:
                success = subprocess.CompletedProcess("docker", 0, "MODEL_MOUNTS_OK", "")
                run.side_effect = [success, success, subprocess.TimeoutExpired("docker", 1)]
                with self.assertRaisesRegex(podvm.PodVMError, "models-writable-input did not reject creation promptly"):
                    podvm.smoke_model_mounts(work, work, staging, self.config,
                        self.profiles["profiles"]["2vcpu-8g"], base, "image", "container", work / "logs", 1)

    def test_only_smoke_runtime_can_use_digest_only_provenance(self):
        for name in ("kernel", "kata_agent", "qemu", "pause"):
            with self.subTest(name=name):
                config = copy.deepcopy(self.config)
                config["oci"][name]["provenance"] = "digest-only-smoke"
                with self.assertRaisesRegex(podvm.PodVMError, "cannot bypass"):
                    podvm.validate_lock(config)
        config = copy.deepcopy(self.config)
        del config["oci"]["kernel"]["source_repository"]
        with self.assertRaisesRegex(podvm.PodVMError, "source provenance metadata"):
            podvm.validate_lock(config)

    def test_registry_verification_skips_attestation_only_for_smoke_runtime(self):
        digests = {podvm.oci_tag_ref(item): item["digest"] for item in self.config["oci"].values()}
        with mock.patch.object(podvm, "smoke_model_mounts"), \
                     mock.patch.object(podvm, "smoke_metadata"), \
                     mock.patch.object(podvm, "smoke_logs"), \
                     mock.patch.object(podvm, "require_tool"), \
             mock.patch.object(podvm, "capture", side_effect=lambda command: digests[command[2]]), \
             mock.patch.object(podvm, "verify_attestation") as verify:
            podvm.verify_oci(self.config, provenance=True)
        verified = {call.args[0] for call in verify.call_args_list}
        self.assertEqual(verified, set(self.config["oci"]) - {"runtime", "pause", "nvidia_kernel", "nvidia_rootfs"})
        # Missing attestations on runtime remain fatal when the exception is absent.
        runtime = dict(self.config["oci"]["runtime"])
        runtime.pop("provenance")
        with mock.patch.object(podvm, "smoke_model_mounts"), \
                     mock.patch.object(podvm, "smoke_metadata"), \
                     mock.patch.object(podvm, "smoke_logs"), \
                     mock.patch.object(podvm, "require_tool"), \
             mock.patch.object(podvm, "capture", return_value='{"manifests": []}'):
            with self.assertRaisesRegex(podvm.PodVMError, "no Sigstore attestation referrer"):
                podvm.verify_attestation("runtime", runtime)

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

    def test_smoke_uses_shim_and_requires_verity_rejection(self):
        for memory, negative_output, negative_code, expected_error in (
            ("8G", "dm-verity: data block corrupted", 1, None),
            ("4096M", "dm-verity: data block corrupted", None, None),
            ("8G", "connection refused", 1, "without evidence"),
            ("4096M", "pause.c v3.9-", 0, "unexpectedly executed"),
        ):
            with self.subTest(memory=memory, negative_output=negative_output), tempfile.TemporaryDirectory() as temporary:
                staging = self.create_staging(Path(temporary))
                profiles = copy.deepcopy(self.profiles)
                profiles["profiles"][sorted(profiles["profiles"])[0]]["memory"] = memory
                specs = []
                commands = []

                def fake_extract(archive, destination):
                    if destination.name == "tools":
                        # Only the shim is available, as required by modern Kata.
                        for binary in ("bin/containerd-shim-kata-v2", "bin/qemu-system-x86_64"):
                            path = destination / "opt/kata" / binary
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.touch()

                def fake_subprocess(command, **kwargs):
                    if command[:2] == ["docker", "run"] and "--entrypoint" not in command:
                        commands.append(command)
                        work_mount = next(value for value in command if value.endswith(":/work"))
                        work = Path(work_mount.removesuffix(":/work"))
                        specs.append(podvm.load_json(work / "fixture/config.json"))
                        # Guest boot evidence arrives in the daemon's log.
                        (work / "runtime.log").write_text(negative_output if len(specs) == 2 else "")
                        syslog = work / "syslog.log"
                        self.assertTrue(syslog.stat().st_mode & 0o200)
                        # Reproduce syslogd replacing the log with one that the
                        # caller can read but cannot truncate for the next run.
                        syslog.chmod(0o444)
                        if len(specs) == 2 and negative_code is None:
                            raise subprocess.TimeoutExpired(command, kwargs["timeout"],
                                output=b"partial container output\n", stderr=b"partial error\n")
                        return subprocess.CompletedProcess(
                            command, negative_code if len(specs) == 2 else 0,
                            stdout="" if len(specs) == 2 else "pause.c v3.9-\n", stderr="")
                    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

                args = argparse.Namespace(staging_dir=staging, timeout=180)
                with mock.patch.object(podvm, "smoke_model_mounts"), \
                     mock.patch.object(podvm, "smoke_metadata"), \
                     mock.patch.object(podvm, "smoke_logs"), \
                     mock.patch.object(podvm, "require_tool"), \
                     mock.patch.object(podvm.os, "access", return_value=True), \
                     mock.patch.object(podvm, "run"), \
                     mock.patch.object(podvm, "pull_oci"), \
                     mock.patch.object(podvm, "only_archive", return_value=Path("payload.tar")), \
                     mock.patch.object(podvm, "extract_archive", side_effect=fake_extract), \
                     mock.patch.object(podvm.subprocess, "run", side_effect=fake_subprocess):
                    if expected_error:
                        with self.assertRaisesRegex(podvm.PodVMError, expected_error):
                            podvm.smoke(args, self.config, profiles)
                    else:
                        podvm.smoke(args, self.config, profiles)
                self.assertEqual(len(specs), 2)
                self.assertEqual(specs[0]["root"]["path"], "/run/podvm-smoke-rootfs")
                self.assertEqual(specs[0]["process"]["args"], ["/pause", "-v"])
                for spec in specs:
                    # An omitted/null resources field causes Kata's OCI
                    # ContainerConfig conversion to panic before guest boot.
                    self.assertIsInstance(spec["linux"].get("resources"), dict)
                    self.assertIn({"type": "network", "path": "/run/netns/podvm-smoke"},
                                  spec["linux"]["namespaces"])
                annotation = "io.katacontainers.config.hypervisor.kernel_verity_params"
                self.assertNotEqual(specs[0]["annotations"][annotation], specs[1]["annotations"][annotation])
                for command in commands:
                    self.assertEqual(command[command.index("--shm-size") + 1], memory)
                    ctr = command[command.index("ctr"):]
                    self.assertEqual(ctr[ctr.index("--runtime") + 1], "io.containerd.kata.v2")
                    self.assertEqual(ctr[ctr.index("--runtime-config-path") + 1], "/work/configuration.toml")
                    self.assertEqual(ctr[ctr.index("--config") + 1], "/work/fixture/config.json")
                    self.assertEqual(ctr[ctr.index("--address") + 1], "/run/podvm-containerd/containerd.sock")
                    self.assertIn("--rm", ctr)
                self.assertFalse(list(staging.parent.glob(".smoke-*")))
                runs = list((staging.parent / "smoke-logs").iterdir())
                self.assertEqual(len(runs), 1)
                for attempt in ("valid-hash", "bad-hash"):
                    saved = runs[0] / attempt
                    self.assertTrue((saved / "configuration.toml").is_file())
                    configuration = (saved / "configuration.toml").read_text()
                    hypervisor = configuration.split("[agent.kata]")[0]
                    runtime = configuration.split("[runtime]")[1]
                    self.assertIn("disable_block_device_use = false\n", hypervisor)
                    self.assertIn("shared_fs = \"none\"\n", hypervisor)
                    self.assertIn("create_container_timeout = 60\n", runtime)
                    # Kata rejects disabled network namespaces with tcfilter;
                    # the guest needs this namespace for authenticated time.
                    self.assertIn('internetworking_model = "tcfilter"\n', runtime)
                    self.assertIn("disable_new_netns = false\n", runtime)
                    self.assertTrue((saved / "config.json").is_file())
                    self.assertTrue((saved / "combined.log").is_file())
                if negative_code is None:
                    saved = runs[0] / "bad-hash"
                    self.assertEqual((saved / "stdout.log").read_text(), "partial container output\n")
                    self.assertEqual((saved / "stderr.log").read_text(), "partial error\n")
                    self.assertIn("timed out", (saved / "combined.log").read_text())

    def test_smoke_requires_correct_pause_version_on_stdout_and_zero_exit(self):
        for stdout, runtime_log, returncode in (
            ("pause.c v3.8-\n", "", 0),
            ("pause.c v3.90-\n", "", 0),
            ("", 'level=debug msg="pause.c v3.9-; pause version 3.9"\n', 0),
            ("pause.c v3.9-\n", "", 1),
        ):
            with self.subTest(stdout=stdout, returncode=returncode), tempfile.TemporaryDirectory() as temporary:
                staging = self.create_staging(Path(temporary))
                attempts = []

                def fake_extract(archive, destination):
                    if destination.name == "tools":
                        for binary in ("bin/containerd-shim-kata-v2", "bin/qemu-system-x86_64"):
                            path = destination / "opt/kata" / binary
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.touch()

                def fake_subprocess(command, **kwargs):
                    if command[:2] == ["docker", "run"] and "--entrypoint" not in command:
                        attempts.append(command)
                        work_mount = next(value for value in command if value.endswith(":/work"))
                        work = Path(work_mount.removesuffix(":/work"))
                        (work / "runtime.log").write_text(runtime_log)
                        return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")
                    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

                args = argparse.Namespace(staging_dir=staging, timeout=180)
                with mock.patch.object(podvm, "smoke_model_mounts"), \
                     mock.patch.object(podvm, "smoke_metadata"), \
                     mock.patch.object(podvm, "smoke_logs"), \
                     mock.patch.object(podvm, "require_tool"), \
                     mock.patch.object(podvm.os, "access", return_value=True), \
                     mock.patch.object(podvm, "run"), \
                     mock.patch.object(podvm, "pull_oci"), \
                     mock.patch.object(podvm, "only_archive", return_value=Path("payload.tar")), \
                     mock.patch.object(podvm, "extract_archive", side_effect=fake_extract), \
                     mock.patch.object(podvm.subprocess, "run", side_effect=fake_subprocess):
                    with self.assertRaisesRegex(podvm.PodVMError, "failed to execute the pause container"):
                        podvm.smoke(args, self.config, self.profiles)
                self.assertEqual(len(attempts), 1)
                self.assertFalse(list(staging.parent.glob(".smoke-*")))
                run_logs = next((staging.parent / "smoke-logs").iterdir())
                self.assertEqual((run_logs / "valid-hash/stdout.log").read_text(), stdout)
                self.assertFalse((run_logs / "bad-hash").exists())

    def test_smoke_diagnostics_preserve_boot_failure_before_cleanup_noise(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / "work"
            work.mkdir()
            failure = 'kata-agent.service: Failed at step EXEC spawning /usr/local/bin/kata-agent: No such file'
            boot = 'level=debug msg="reading guest console" vmconsole=' + json.dumps(failure) + '\n'
            runtime = boot + 'level=info msg="Stopping Sandbox"\n' * 400
            (work / "runtime.log").write_text(runtime)
            (work / "syslog.log").write_text(boot * 2 + 'syslog cleanup\n' * 400)
            saved = Path(temporary) / "logs"
            output, detail = podvm.save_smoke_diagnostics(work, saved, "partial stdout\n", "partial stderr\n", True)
            shutil.rmtree(work)
            self.assertEqual((saved / "runtime.log").read_text(), runtime)
            self.assertEqual((saved / "guest-console.log").read_text(), failure + '\n')
            self.assertIn(failure, detail)
            self.assertIn("partial stdout", detail)
            self.assertIn("partial stderr", detail)
            self.assertIn("timed out", detail)
            self.assertIn(str(saved), detail)
            self.assertEqual((saved / "combined.log").read_text(), output)

    def test_smoke_diagnostics_fall_back_to_syslog_console(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "syslog.log").write_text('msg="reading guest console" vmconsole="Kernel panic: root mount failed"\n')
            saved = work / "logs"
            _, detail = podvm.save_smoke_diagnostics(work, saved, "", "", False)
            self.assertIn("Kernel panic: root mount failed", detail)
            self.assertEqual((saved / "guest-console.log").read_text(), "Kernel panic: root mount failed\n")

    def test_smoke_diagnostics_show_hypervisor_failure_before_vsock_timeout(self):
        failure = ('level=error msg="error: kvm run failed Bad address" '
                   'qemuPid=77 source=virtcontainers/hypervisor subsystem=qemu\n')
        for source in ("runtime.log", "syslog.log"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                log = failure + 'level=info msg="Stopping Sandbox"\n' * 400
                (work / source).write_text(log)
                saved = work / "logs"
                _, detail = podvm.save_smoke_diagnostics(
                    work, saved, "", "timed out connecting to vsock 2940119365:1024", False)
                self.assertIn("Hypervisor errors:\n" + failure, detail)
                self.assertIn("No guest console output captured.", detail)
                self.assertNotIn("Bad address", detail.split("Runtime log tail:\n")[1])
                self.assertEqual((saved / source).read_text(), log)

    @staticmethod
    def add_metadata_assets(rootfs, variant="cpu"):
        for name in ("etc/cdi/podvm-metadata.yaml", "etc/agent-config.toml"):
            if variant == "nvidia" and name == "etc/agent-config.toml":
                continue
            path = rootfs / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / "assets/guest" / name, path)
        agent = rootfs / ("usr/libexec/podvm/kata-agent" if variant == "nvidia" else "usr/local/bin/kata-agent")
        agent.parent.mkdir(parents=True, exist_ok=True)
        agent.write_bytes(b"\x7fELFfixture")
        agent.chmod(0o755)
        if variant == "nvidia":
            launcher = rootfs / "usr/bin/kata-agent"
            launcher.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / "assets/nvidia-kata-agent", launcher)
        if variant == "cpu":
            unit = rootfs / "etc/systemd/system/kata-agent.service"
            unit.parent.mkdir(parents=True, exist_ok=True)
            unit.write_text("[Unit]\nRequires=var.mount\nAfter=var.mount\n[Service]\n"
                            "ExecStart=/usr/local/bin/kata-agent --config /etc/agent-config.toml\n")

    @staticmethod
    def add_time_assets(rootfs, variant="cpu"):
        for name in podvm.TIME_ASSETS + (("etc/systemd/system/podvm-time-sync.service",) if variant == "cpu" else ()):
            path = rootfs / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / "assets/guest" / name, path)
        for name in podvm.TIME_BINARIES + ("usr/bin/dash",):
            path = rootfs / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\x7fELFfixture")
            path.chmod(0o755)
        (rootfs / "etc/passwd").write_text("root:x:0:0::/root:/bin/sh\n_chrony:x:101:101::/var/lib/chrony:/usr/sbin/nologin\n")
        (rootfs / "etc/group").write_text("root:x:0:\n_chrony:x:101:\n")
        ca = rootfs / "etc/ssl/certs/ca-certificates.crt"
        ca.parent.mkdir(parents=True, exist_ok=True)
        ca.write_text("fixture")
        if variant == "cpu":
            (rootfs / "etc/systemd/system/kata-containers.target").write_text("[Unit]\nWants=podvm-time-sync.service\n")

    @staticmethod
    def add_guest_executables(rootfs):
        for name in podvm.REQUIRED_GUEST_FILES + ("usr/sbin/veritysetup", "usr/sbin/dmsetup", "usr/bin/mount"):
            path = rootfs / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture")
            path.chmod(0o755)
        PodVMTests.add_metadata_assets(rootfs)
        PodVMTests.add_time_assets(rootfs)

    def test_model_payload_requires_executable_helper_and_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            rootfs = Path(temporary)
            systemd = rootfs / "usr/lib/systemd/systemd"
            systemd.parent.mkdir(parents=True)
            systemd.write_text("fixture")
            systemd.chmod(0o755)
            (rootfs / "sbin").mkdir()
            (rootfs / "sbin/init").symlink_to("../usr/lib/systemd/systemd")
            (rootfs / "etc").mkdir()
            (rootfs / "etc/resolv.conf").touch()
            self.add_guest_executables(rootfs)
            podvm.validate_rootfs(rootfs)
            (rootfs / "usr/local/bin/podvm-model-mount").chmod(0o644)
            with self.assertRaisesRegex(podvm.PodVMError, "podvm-model-mount"):
                podvm.validate_rootfs(rootfs)

    def test_rootfs_requires_init_provider_and_accepts_ubuntu_merged_usr(self):
        with tempfile.TemporaryDirectory() as temporary:
            rootfs = Path(temporary)
            (rootfs / "etc").mkdir()
            (rootfs / "etc/resolv.conf").touch()
            systemd = rootfs / "usr/lib/systemd/systemd"
            systemd.parent.mkdir(parents=True)
            systemd.write_text("systemd fixture")
            systemd.chmod(0o755)
            # Installing systemd alone reproduces the reported rootfs failure.
            with self.assertRaisesRegex(podvm.PodVMError, "install systemd-sysv"):
                podvm.validate_rootfs(rootfs)

            (rootfs / "usr/sbin").mkdir()
            (rootfs / "sbin").symlink_to("usr/sbin")
            (rootfs / "usr/sbin/init").symlink_to("../lib/systemd/systemd")
            self.add_guest_executables(rootfs)
            podvm.validate_rootfs(rootfs)
            systemd.chmod(0o644)
            with self.assertRaisesRegex(podvm.PodVMError, "executable"):
                podvm.validate_rootfs(rootfs)

    def test_rootfs_requires_regular_dns_mount_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            rootfs = Path(temporary)
            systemd = rootfs / "usr/lib/systemd/systemd"
            systemd.parent.mkdir(parents=True)
            systemd.write_text("systemd fixture")
            systemd.chmod(0o755)
            (rootfs / "sbin").mkdir()
            (rootfs / "sbin/init").symlink_to("../usr/lib/systemd/systemd")
            (rootfs / "etc").mkdir()
            resolver = rootfs / "etc/resolv.conf"
            with self.assertRaisesRegex(podvm.PodVMError, "regular /etc/resolv.conf"):
                podvm.validate_rootfs(rootfs)
            # Reproduce the CAA stub link with resolved absent at guest boot.
            resolver.symlink_to("../run/systemd/resolve/stub-resolv.conf")
            with self.assertRaisesRegex(podvm.PodVMError, "regular /etc/resolv.conf"):
                podvm.validate_rootfs(rootfs)
            # Even a link that resolves at build time must not reach the image.
            stub = rootfs / "run/systemd/resolve/stub-resolv.conf"
            stub.parent.mkdir(parents=True)
            stub.write_text("nameserver 127.0.0.53\n")
            with self.assertRaisesRegex(podvm.PodVMError, "regular /etc/resolv.conf"):
                podvm.validate_rootfs(rootfs)
            resolver.unlink()
            resolver.touch()
            self.add_guest_executables(rootfs)
            podvm.validate_rootfs(rootfs)

    def test_image_builder_shares_device_nodes_and_sets_output_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rootfs, staging = root / "rootfs", root / "staging"
            staging.mkdir()
            verity = "root_hash=" + "ab" * 32 + ",salt=cd,data_blocks=128,data_block_size=4096,hash_block_size=4096"
            def fake_run(command, **kwargs):
                if command[:2] == ["docker", "run"]:
                    (staging / "root_hash_local.txt").write_text(verity)
                return subprocess.CompletedProcess(command, 0, stdout="chronyd 4.5 (+NTS)")
            with mock.patch.object(podvm, "validate_rootfs"), \
                 mock.patch.object(podvm, "run", side_effect=fake_run) as run:
                podvm.build_raw_image(rootfs, root / "kata", staging, self.config)
            command = run.call_args.args[0]
            self.assertIn("/dev:/dev", command)
            self.assertIn(f"USER={os.getuid()}", command)
            self.assertIn(f"GROUP={os.getgid()}", command)
            self.assertEqual((staging / "kernel_verity_params").read_text(), verity)

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

    def test_package_rejects_relabeling_guest_without_rebuilding(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            staging = self.create_staging(workspace, version="v1.2.3")
            raw = workspace / "raw.json"
            podvm.dump_json(raw, self.raw_measurements(staging=staging))
            dist = workspace / "dist"
            dist.mkdir()
            sentinel = dist / "existing-release"
            sentinel.write_text("preserve")
            for version, revision in (("v1.2.4", "1" * 40), ("v1.2.3", "2" * 40)):
                args = argparse.Namespace(staging_dir=staging, raw_measurements=raw,
                    dist_dir=dist, workspace=workspace, release_version=version,
                    source_revision=revision, source_repository="owner/repo")
                with self.subTest(version=version, revision=revision), \
                     self.assertRaisesRegex(podvm.PodVMError, "does not match the guest image"):
                    podvm.package(args, self.config, self.profiles)
                self.assertEqual(sentinel.read_text(), "preserve")

    def test_build_inputs_require_guest_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            staging = self.create_staging(Path(temporary))
            inputs = podvm.load_json(staging / "inputs.json")
            for identity in (None, {}, {**inputs["guest_identity"], "IMAGE_ID": "upstream"}):
                changed = {**inputs, "guest_identity": identity}
                if identity is None:
                    del changed["guest_identity"]
                podvm.dump_json(staging / "inputs.json", changed)
                with self.subTest(identity=identity), self.assertRaises(podvm.PodVMError):
                    podvm.validate_build_inputs(staging, self.config)

    def test_build_provenance_and_measurements_ignore_python_bytecode(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            assets = workspace / "assets"
            assets.mkdir()
            source = assets / "helper.py"
            source.write_text("VALUE = 1\n")
            with mock.patch.object(podvm, "ROOT", workspace):
                staging = self.create_staging(workspace)
                clean = podvm.local_asset_hashes()
                fingerprint = podvm.measurement_fingerprint(staging, self.config, self.profiles)
                # Tests import asset helpers in the build job. Other jobs
                # start with a fresh checkout and no interpreter caches.
                py_compile.compile(str(source), doraise=True)
                py_compile.compile(str(source), cfile=str(assets / "helper.pyc"), doraise=True)
                py_compile.compile(str(source), cfile=str(assets / "helper.pyo"), doraise=True)
                self.assertEqual(podvm.local_asset_hashes(), clean)
                podvm.validate_build_inputs(staging, self.config)
                self.assertEqual(podvm.measurement_fingerprint(staging, self.config, self.profiles), fingerprint)
                # Also cover building after tests and measuring in a clean job.
                staging = self.create_staging(workspace / "tested-build")
                fingerprint = podvm.measurement_fingerprint(staging, self.config, self.profiles)
                shutil.rmtree(assets / "__pycache__")
                (assets / "helper.pyc").unlink()
                (assets / "helper.pyo").unlink()
                podvm.validate_build_inputs(staging, self.config)
                self.assertEqual(podvm.measurement_fingerprint(staging, self.config, self.profiles), fingerprint)
                source.write_text("VALUE = 2\n")
                with self.assertRaisesRegex(podvm.PodVMError, "staged build provenance"):
                    podvm.validate_build_inputs(staging, self.config)
                self.assertNotEqual(podvm.measurement_fingerprint(staging, self.config, self.profiles), fingerprint)

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
            self.assertIn("After=var.mount\n", agent)
            self.assertIn("Requires=var.mount\n", agent)
            self.assertNotIn("ExecStartPre=", agent)
            self.assertIn("ExecStart=/usr/local/bin/kata-agent --config /etc/agent-config.toml\n", agent)
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
        bundle = dist / document["artifacts"]["cpu"]["name"]
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

    @unittest.skipUnless(sys.platform == "linux", "requires GNU tar on Linux")
    @unittest.skipUnless(shutil.which("zstd") and shutil.which("tar"), "tar and zstd are required")
    def test_cpu_package_and_assembly_create_exact_release_contract(self):
        profiles = copy.deepcopy(self.profiles)
        profiles["profiles"]["turin-only"] = {
            "cpus": 4, "memory": "16G", "sev": {"vcpu_types": ["EPYC-Turin"]},
        }
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            staging = self.create_staging(workspace, version="v1.2.3")
            raw = workspace / "measurements.raw.json"
            raw.write_text(json.dumps(self.raw_measurements(profiles, staging)))
            args = argparse.Namespace(
                staging_dir=staging, raw_measurements=raw,
                dist_dir=workspace / "package", workspace=workspace,
                release_version="v1.2.3", source_revision="1" * 40,
                source_repository="owner/repo",
            )
            podvm.package(args, self.config, profiles)
            podvm.validate_package(args.dist_dir, self.config, profiles)
            podvm.assemble(argparse.Namespace(package_dir=[args.dist_dir], dist_dir=workspace / "dist",
                workspace=workspace), self.config, profiles)
            podvm.validate_release(workspace / "dist", profiles, self.config)
            document = podvm.load_json(workspace / "dist" / "measurements.json")
            self.assertEqual(document["release"], {
                "version": "v1.2.3", "source_revision": "1" * 40, "source_repository": "owner/repo",
            })
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
                           "schemas/launch-profiles.schema.json", "schemas/measurements.schema.json",
                           "schemas/model-mounts.schema.json", "kata/model-mounts.example.toml"):
                self.assertIn(f"podvm/{member}", members)
            bundled = json.loads(podvm.capture(["tar", "--zstd", "-xOf", str(bundle), "podvm/launch-profiles.json"]))
            self.assertEqual(bundled, profiles)
            inputs = json.loads(podvm.capture(["tar", "--zstd", "-xOf", str(bundle), "podvm/inputs.json"]))
            self.assertEqual(inputs["guest_identity"], podvm.guest_identity("v1.2.3", "1" * 40))
            checksums = subprocess.run(
                ["sha256sum", "--check", "SHA256SUMS"], cwd=workspace / "dist",
                capture_output=True, text=True, check=True,
            )
            self.assertIn("measurements.json: OK", checksums.stdout)

    @staticmethod
    def create_nvidia_staging(root: Path) -> Path:
        staging = PodVMTests.create_staging(root)
        verity = (staging / "kernel_verity_params").read_text()
        (staging / "cmdline").write_text(podvm.kata_cmdline(verity, "nvidia") + "\n")
        (staging / "kernel.version").write_text("6.18.35-nvidia-gpu\n")
        (staging / "kernel.build-version").write_text("pinned\n")
        inputs = podvm.load_json(staging / "inputs.json")
        inputs["variant"] = "nvidia"
        inputs["oci"] = podvm.locked_inputs(podvm.load_yaml(podvm.DEFAULT_CONFIG), "nvidia")["oci"]
        inputs["local_assets"] = podvm.local_asset_hashes("nvidia")
        podvm.dump_json(staging / "inputs.json", inputs)
        return staging

    def test_nvidia_profiles_and_examples_require_complete_layouts(self):
        profiles = podvm.select_profiles(self.all_profiles, "nvidia")
        podvm.validate_profiles(profiles)
        self.assertEqual(set(profiles["profiles"]), {
            "h100-pcie-1-96g", "h200-pcie-1-96g", "h100-hgx-8-768g", "h100-pcie-nvlink-8-768g", "h200-hgx-8-768g",
            "b200-hgx-8-768g", "b300-hgx-8-768g"})
        for change in (
            {"count": 4}, {"nvswitch_count": 0}, {"platform": "pcie"}, {"platform": "pcie-nvlink"},
        ):
            invalid = copy.deepcopy(profiles)
            invalid["profiles"]["h100-hgx-8-768g"]["gpu"].update(change)
            with self.assertRaises(podvm.PodVMError):
                podvm.validate_profiles(invalid)
        with tempfile.TemporaryDirectory() as temporary:
            staging = self.create_nvidia_staging(Path(temporary))
            cmdline = (staging / "cmdline").read_text()
            self.assertTrue(cmdline.strip().endswith(
                "selinux=0 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service "
                "systemd.mask=systemd-networkd.socket scsi_mod.scan=none agent.launch_process_timeout=15 "
                "pci=realloc pci=nocrs pci=assign-busses cgroup_no_v1=all "
                "systemd.unified_cgroup_hierarchy=1 agent.visible_cdi_devices=true"))
            podvm.write_kata_examples(staging, profiles, "nvidia")
            single = podvm.load_yaml(staging / "kata/pod-snp-h100-pcie-1-96g.yaml")
            hgx = podvm.load_yaml(staging / "kata/pod-tdx-h100-hgx-8-768g.yaml")
            self.assertEqual(single["spec"]["runtimeClassName"], "kata-qemu-nvidia-gpu-snp")
            self.assertEqual(single["spec"]["containers"][0]["resources"]["limits"], {"nvidia.com/pgpu": 1})
            self.assertEqual(hgx["spec"]["containers"][0]["resources"]["limits"],
                             {"nvidia.com/pgpu": 8, "nvidia.com/nvswitch": 4})
            nvlink = podvm.load_yaml(staging / "kata/pod-tdx-h100-pcie-nvlink-8-768g.yaml")
            self.assertEqual(nvlink["spec"]["containers"][0]["resources"]["limits"], {"nvidia.com/pgpu": 8})
            self.assertIn("model-specific", (staging / "kata/README.md").read_text())
            self.assertIn('kernel_params = "pci=realloc pci=nocrs pci=assign-busses"\n',
                          (staging / "kata/configuration.toml.fragment").read_text())

    def test_variant_defaults_and_cpu_provenance_are_isolated(self):
        cpu = argparse.Namespace(command="package", variant="cpu", profiles=None, work_dir=None,
            staging_dir=None, raw_measurements=None, dist_dir=None)
        gpu = argparse.Namespace(command="package", variant="nvidia", profiles=None, work_dir=None,
            staging_dir=None, raw_measurements=None, dist_dir=None)
        podvm.configure_variant_paths(cpu)
        podvm.configure_variant_paths(gpu)
        self.assertEqual(cpu.profiles, podvm.DEFAULT_PROFILES)
        self.assertEqual(gpu.profiles, podvm.DEFAULT_PROFILES)
        for name in ("work_dir", "staging_dir", "raw_measurements", "dist_dir"):
            self.assertNotEqual(getattr(cpu, name), getattr(gpu, name))
        self.assertNotIn(cpu.work_dir, gpu.work_dir.parents)
        staging_only = argparse.Namespace(command="validate", variant="nvidia", profiles=None,
            staging_dir=Path("build/staging-nvidia"), dist_dir=None)
        podvm.configure_variant_paths(staging_only)
        self.assertTrue(staging_only.validate_staging)
        self.assertFalse(staging_only.validate_dist)
        with tempfile.TemporaryDirectory() as temporary:
            staging = self.create_staging(Path(temporary))
            original = podvm.measurement_fingerprint(staging, self.config, self.profiles)
            changed = copy.deepcopy(self.config)
            changed["oci"]["nvidia_rootfs"]["digest"] = "sha256:" + "0" * 64
            podvm.validate_build_inputs(staging, changed)
            self.assertEqual(podvm.measurement_fingerprint(staging, changed, self.profiles), original)

    def test_nvidia_rootfs_requires_nvrc_cdi_attestation_and_matching_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            rootfs = Path(temporary)
            executables = (
                "bin/NVRC-x86_64-unknown-linux-musl", "usr/bin/kata-agent",
                "usr/local/bin/podvm-model-mount", "usr/local/bin/attestation-agent",
                "usr/local/bin/confidential-data-hub", "usr/local/bin/api-server-rest",
                "bin/nvidia-ctk", "bin/nvidia-cdi-hook", "bin/nvidia-smi",
                "bin/nvidia-persistenced", "bin/nv-fabricmanager", "sbin/nvlsm",
                "usr/sbin/veritysetup", "usr/sbin/dmsetup", "bin/mount",
            )
            for name in executables:
                path = rootfs / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"binary")
                path.chmod(0o755)
            (rootfs / "sbin/init").symlink_to("/bin/NVRC-x86_64-unknown-linux-musl")
            for name in ("run/cdi", "lib/firmware/nvidia", "lib/modules/6.18.35-nvidia-gpu/kernel"):
                (rootfs / name).mkdir(parents=True)
            (rootfs / "etc").mkdir(exist_ok=True)
            (rootfs / "etc/resolv.conf").write_text("nameserver 1.1.1.1\n")
            (rootfs / "etc/modelwrap-build.json").write_text("{}\n")
            (rootfs / "etc/kata-opa").mkdir()
            (rootfs / "etc/kata-opa/default-policy.rego").write_text("package agent_policy\n")
            (rootfs / "lib/x86_64-linux-gnu").mkdir(parents=True)
            (rootfs / "lib/x86_64-linux-gnu/libnvat.so").write_bytes(b"library")
            (rootfs / "lib/modules/6.18.35-nvidia-gpu/kernel/nvidia.ko").write_bytes(b"module")
            self.add_metadata_assets(rootfs, "nvidia")
            self.add_time_assets(rootfs, "nvidia")
            with mock.patch.object(podvm, "capture", return_value="6.18.35-nvidia-gpu SMP mod_unload"):
                podvm.validate_rootfs(rootfs, "nvidia", "6.18.35-nvidia-gpu")
            with mock.patch.object(podvm, "capture", return_value="other-version SMP mod_unload"):
                with self.assertRaisesRegex(podvm.PodVMError, "vermagic"):
                    podvm.validate_rootfs(rootfs, "nvidia", "6.18.35-nvidia-gpu")
            (rootfs / "bin/nvidia-ctk").unlink()
            with self.assertRaisesRegex(podvm.PodVMError, "nvidia-ctk"):
                podvm.validate_rootfs(rootfs, "nvidia", "6.18.35-nvidia-gpu")

    def test_nvidia_kernel_selects_kernel_archive_when_modules_are_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pulled = root / "oci/kernel"
            pulled.mkdir(parents=True)
            kernel = pulled / "kata-static-kernel-nvidia-gpu.tar.zst"
            kernel.write_bytes(b"kernel")
            (pulled / "kata-static-kernel-nvidia-gpu-modules.tar.zst").write_bytes(b"modules")
            with mock.patch.object(podvm, "pull_oci"), mock.patch.object(
                    podvm, "extract_archive", side_effect=RuntimeError("selected")) as extract:
                with self.assertRaisesRegex(RuntimeError, "selected"):
                    podvm.install_kernel(root, self.config, root / "oci", "nvidia")
            extract.assert_called_once_with(kernel, root / "oci/kernel-unpacked")

    def test_nvidia_measurements_omit_unqualified_tdx_and_detect_staleness(self):
        profiles = podvm.select_profiles(self.all_profiles, "nvidia")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = self.create_nvidia_staging(root)
            raw_path = root / "measurements-nvidia.raw.json"
            args = argparse.Namespace(variant="nvidia", staging_dir=staging, raw_measurements=raw_path)
            with mock.patch.object(podvm, "run_tdx") as tdx, mock.patch.object(
                    podvm, "run_snp", return_value="ab" * 48) as snp:
                podvm.measure(args, self.config, profiles)
            tdx.assert_not_called()
            self.assertEqual(snp.call_count, 2 * sum(len(podvm.snp_settings(profiles, p)["vcpu_types"])
                                                      for p in profiles["profiles"]))
            raw = podvm.load_json(raw_path)
            podvm.validate_raw_measurements(raw, self.config, profiles, "nvidia")
            self.assertTrue(all(set(entry) == {"sev"} for entry in raw["profiles"].values()))
            candidates = podvm.load_json(root / "tdx-candidates-nvidia.json")
            self.assertTrue(all(entry["status"] == "missing-hardware-layout"
                                for entry in candidates["profiles"].values()))
            (staging / "cmdline").write_text("changed\n")
            self.assertNotEqual(raw["fingerprint"], podvm.measurement_fingerprint(staging, self.config, profiles, "nvidia"))

    def test_complete_tdx_topology_is_passed_to_tool_but_stays_unqualified(self):
        profiles = podvm.select_profiles(self.all_profiles, "nvidia")
        profiles["profiles"]["h100-pcie-1-96g"]["tdx_topology"] = {
            "numa": ["node,nodeid=0,cpus=0-3,memdev=mem0"],
            "objects": ["memory-backend-ram,id=mem0,size=16G"],
            "bridges": ["pcie-root-port,id=rp0,bus=pcie.0,addr=0x2"],
            "endpoints": ["vfio-pci,host=0000:01:00.0,bus=rp0"],
            "synthetic_devices": ["pci-testdev,bus=rp0"],
            "qemu_globals": ["q35-pcihost.pci-hole64-size=256G"],
            "fw_cfg": ["name=opt/podvm/PciMmio32,string=512M"],
            "mmio_apertures": {"below_4g": "512M", "above_4g": "256G"},
        }
        podvm.validate_profiles(profiles)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = self.create_nvidia_staging(root)
            calls = []
            def fake_tdx(metadata, tdx, create_acpi, output, config=None):
                calls.append(create_acpi)
                output.write_text("{}")
                return self.tdx_measurement("ab" * 48)
            with mock.patch.object(podvm, "run_tdx", side_effect=fake_tdx):
                candidate = podvm.tdx_gpu_candidate(staging, self.config, profiles,
                                                     "h100-pcie-1-96g", staging / "launch")
            self.assertEqual(calls, [True, False])
            self.assertEqual(candidate["status"], "unqualified-prediction")
            self.assertEqual(candidate["measurement"], self.tdx_measurement("ab" * 48))
            qemu = candidate["inputs"]["tool_metadata"]["boot_config"]["qemu"]
            self.assertEqual(qemu["numa"], profiles["profiles"]["h100-pcie-1-96g"]["tdx_topology"]["numa"])
            self.assertIn("pci-testdev,bus=rp0", qemu["devices"])

    @unittest.skipUnless(sys.platform == "linux", "requires GNU tar on Linux")
    @unittest.skipUnless(shutil.which("zstd") and shutil.which("tar"), "tar and zstd are required")
    def test_nvidia_package_and_assembly_have_snp_only_catalog(self):
        profiles = podvm.select_profiles(self.all_profiles, "nvidia")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staging = self.create_nvidia_staging(root)
            raw = {
                "variant": "nvidia",
                "fingerprint": podvm.measurement_fingerprint(staging, self.config, profiles, "nvidia"),
                "profiles": {name: {"sev": {model: "ab" * 48 for model in
                    podvm.snp_settings(profiles, name)["vcpu_types"]}}
                    for name in profiles["profiles"]},
                "tools": {"tdx_measure": podvm.tdx_tool_provenance(self.config),
                          "sev_snp_measure": self.config["sources"]["sev_snp_measure"]},
            }
            raw_path = root / "raw.json"
            podvm.dump_json(raw_path, raw)
            args = argparse.Namespace(variant="nvidia", staging_dir=staging,
                raw_measurements=raw_path, dist_dir=root / "package", workspace=root,
                release_version="dev", source_revision="1" * 40, source_repository="owner/repo")
            podvm.package(args, self.config, profiles)
            podvm.validate_package(args.dist_dir, self.config, profiles)
            dist = root / "dist"
            podvm.assemble(argparse.Namespace(package_dir=[args.dist_dir], dist_dir=dist,
                workspace=root), self.config, profiles)
            podvm.validate_release(dist, profiles, self.config)
            catalog = podvm.load_json(dist / "measurements.json")
            self.assertEqual(set(catalog["artifacts"]), {"nvidia"})
            self.assertTrue(all(set(entry) == {"gpu", "sev"} for entry in catalog["profiles"].values()))
            self.assertEqual(set(p.name for p in dist.iterdir()), {
                "podvm-nvidia-ubuntu-24.04-x86_64-dev.tar.zst", "measurements.json", "SHA256SUMS"})
            with mock.patch.object(podvm, "make_tar_zst"):
                (staging / "podvm.raw").write_bytes(b"changed")
                with self.assertRaisesRegex(podvm.PodVMError, "stale measurements"):
                    podvm.package(args, self.config, profiles)


if __name__ == "__main__":
    unittest.main()

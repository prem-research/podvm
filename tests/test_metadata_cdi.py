import base64
import gzip
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_podvm

podvm = test_podvm.podvm
ROOT = test_podvm.ROOT


class MetadataCDITests(unittest.TestCase):
    def test_spec_contract(self):
        spec = podvm.load_yaml(ROOT / "assets/guest/etc/cdi/podvm-metadata.yaml")
        self.assertEqual(spec["cdiVersion"], "0.6.0")
        self.assertEqual(spec["kind"], "podvm.local/metadata")
        self.assertEqual([device["name"] for device in spec["devices"]], ["all"])
        mounts = spec["devices"][0]["containerEdits"]["mounts"]
        self.assertEqual([(m["hostPath"], m["containerPath"]) for m in mounts], [
            ("/etc/os-release", "/run/podvm/os-release"),
            ("/run/confidential-containers/initdata/initdata.toml", "/run/podvm/initdata.toml")])
        for mount in mounts:
            self.assertEqual(mount["type"], "bind")
            self.assertEqual(mount["options"], ["bind", "ro", "nosuid", "nodev", "noexec"])

    def test_both_variants_require_static_metadata_and_an_executable_agent_binary(self):
        for variant in ("cpu", "nvidia"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                rootfs = Path(temporary)
                test_podvm.PodVMTests.add_metadata_assets(rootfs, variant)
                # In particular, the NVIDIA fixture has no shell or coreutils.
                podvm.validate_metadata_cdi(rootfs, variant)
                agent_path = "usr/libexec/podvm/kata-agent" if variant == "nvidia" else "usr/local/bin/kata-agent"
                names = ["etc/cdi/podvm-metadata.yaml", agent_path]
                if variant == "cpu":
                    names += ["etc/agent-config.toml", "etc/systemd/system/kata-agent.service"]
                else:
                    names += ["usr/bin/kata-agent"]
                for name in names:
                    path = rootfs / name
                    original, mode = path.read_bytes(), path.stat().st_mode
                    with self.subTest(path=name, problem="missing"):
                        path.unlink()
                        with self.assertRaises(podvm.PodVMError):
                            podvm.validate_metadata_cdi(rootfs, variant)
                    path.write_bytes(b"stale")
                    with self.subTest(path=name, problem="stale"), self.assertRaises(podvm.PodVMError):
                        podvm.validate_metadata_cdi(rootfs, variant)
                    path.write_bytes(original)
                    path.chmod(mode)
                agent = rootfs / agent_path
                agent.chmod(0o644)
                with self.assertRaisesRegex(podvm.PodVMError, "missing executable"):
                    podvm.validate_metadata_cdi(rootfs, variant)
                agent.chmod(0o755)
                agent.write_bytes(b"#!/bin/sh\nexec /usr/local/bin/kata-agent\n")
                with self.assertRaisesRegex(podvm.PodVMError, "real ELF binary"):
                    podvm.validate_metadata_cdi(rootfs, variant)
                agent.write_bytes(b"\x7fELFfixture")
                definition = rootfs / "etc/cdi/podvm-metadata.yaml"
                definition.chmod(0o666)
                with self.assertRaisesRegex(podvm.PodVMError, "mode 0644"):
                    podvm.validate_metadata_cdi(rootfs, variant)
                definition.chmod(0o644)
                podvm.validate_metadata_cdi(rootfs, variant)

    def test_nvidia_overlay_installs_launcher_and_scans_the_private_agent(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            rootfs = work / "rootfs"
            tree = work / "podvm/resources/binaries-tree"
            for name in ("usr/local/bin/kata-agent", "usr/local/bin/podvm-model-mount", "etc/modelwrap-build.json"):
                path = tree / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"\x7fELFtest")
                path.chmod(0o755)
            definition = "etc/cdi/podvm-metadata.yaml"
            (tree / definition).parent.mkdir(parents=True)
            shutil.copy2(ROOT / "assets/guest" / definition, tree / definition)
            for name in ("etc/kata-opa/default-policy.rego", "etc/os-release", "usr/sbin/veritysetup",
                         "usr/sbin/dmsetup", "usr/bin/mount"):
                path = rootfs / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture")
            test_podvm.PodVMTests.add_time_assets(rootfs, "nvidia")
            with mock.patch.object(podvm, "capture", return_value="") as readelf:
                overlay = podvm.prepare_nvidia_overlay(work / "podvm", rootfs, work)
            scanned = [str(call.args[0][-1]) for call in readelf.call_args_list]
            self.assertIn(str(overlay / "usr/libexec/podvm/kata-agent"), scanned)
            self.assertNotIn(str(overlay / "usr/bin/kata-agent"), scanned)
            self.assertEqual((overlay / "usr/libexec/podvm/kata-agent").read_bytes(),
                             (tree / "usr/local/bin/kata-agent").read_bytes())
            self.assertEqual((overlay / "usr/bin/kata-agent").read_bytes(),
                             (ROOT / "assets/nvidia-kata-agent").read_bytes())
            self.assertEqual((overlay / definition).read_bytes(), (tree / definition).read_bytes())
            for name in ("usr/local/bin/kata-agent", "usr/local/bin/podvm-install-cdi",
                         "etc/agent-config.toml", "var/run/cdi/podvm-metadata.yaml"):
                self.assertFalse((overlay / name).exists(), name)

    def test_selector_flows_through_cmdline_staging_annotations_and_opt_in_example(self):
        fixtures = test_podvm.PodVMTests()
        fixtures.setUp()
        for variant in ("cpu", "nvidia"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                staging = (fixtures.create_nvidia_staging if variant == "nvidia" else fixtures.create_staging)(Path(temporary))
                profiles = podvm.select_profiles(fixtures.all_profiles, variant)
                podvm.validate_staging(staging, variant)
                self.assertIn("agent.visible_cdi_devices=true", (staging / "cmdline").read_text())
                podvm.write_kata_examples(staging, profiles, variant)
                for path in (staging / "kata").glob("pod-*.yaml"):
                    doc = podvm.load_yaml(path)
                    self.assertNotIn("env", doc["spec"]["containers"][0])
                    self.assertIn("agent.visible_cdi_devices=true", doc["metadata"]["annotations"][
                        "io.katacontainers.config.hypervisor.kernel_params"])
                example = podvm.load_yaml(staging / "kata/metadata-container.example.yaml")
                self.assertEqual(example["env"][0]["value"], "podvm.local/metadata=all")
                assets = podvm.local_asset_hashes(variant)
                for name in ("assets/guest/etc/cdi/podvm-metadata.yaml",
                             "assets/patches/kata-static-cdi.patch"):
                    self.assertIn(name, assets)

    def test_smoke_requires_missing_source_rejection_without_application_execution(self):
        fixtures = test_podvm.PodVMTests()
        fixtures.setUp()
        evidence = "rootfs mount /run/confidential-containers/initdata/initdata.toml: No such file or directory"
        for outcome, expected_error in (
            (subprocess.CompletedProcess("docker", 1, "", evidence), None),
            (subprocess.CompletedProcess("docker", 0, "", evidence), "before execution"),
            (subprocess.CompletedProcess("docker", 1, "METADATA_APPLICATION_STARTED", evidence), "before execution"),
            (subprocess.CompletedProcess("docker", 1, "", "connection refused"), "mount evidence"),
            (subprocess.TimeoutExpired("docker", 1, stderr=evidence.encode()), "before execution"),
        ):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                staging = fixtures.create_staging(work)
                (work / "fixture").mkdir()
                specs = []
                initdata = b'# exact\r\nalgorithm = "sha384"\r\nversion="0.1.0"\r\n[data]\r\n'
                def run(*args, **kwargs):
                    specs.append(podvm.load_json(work / "fixture/config.json"))
                    if len(specs) < 4:
                        return subprocess.CompletedProcess("docker", 0, "METADATA_APPLICATION_STARTED\nMETADATA_CDI_OK\n", "")
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome
                with mock.patch.object(podvm, "build_metadata_smoke_fixture", return_value=initdata), \
                     mock.patch.object(podvm, "stop_smoke_container"), \
                     mock.patch.object(podvm.subprocess, "run", side_effect=run):
                    args = (work, work, staging, fixtures.config, fixtures.profiles["profiles"]["2vcpu-8g"],
                            {"process": {"args": [], "env": []}}, "image", "container", work / "logs", 1)
                    if expected_error:
                        with self.assertRaisesRegex(podvm.PodVMError, expected_error):
                            podvm.smoke_metadata(*args)
                    else:
                        podvm.smoke_metadata(*args)
                self.assertEqual(len(specs), 4)
                for index, spec in enumerate(specs):
                    encoded = spec["annotations"].get("io.katacontainers.config.hypervisor.cc_init_data")
                    self.assertEqual(bool(encoded), index < 2)
                    if encoded:
                        self.assertEqual(gzip.decompress(base64.b64decode(encoded)), initdata)
                    self.assertEqual(spec["process"]["env"],
                                     ["VISIBLE_CDI_DEVICES=podvm.local/metadata=all"]
                                     if index in (0, 3) else [])


if __name__ == "__main__":
    unittest.main()

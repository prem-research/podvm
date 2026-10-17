import base64
import gzip
import os
import shutil
import stat
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
        spec = podvm.load_yaml(ROOT / "assets/guest/usr/share/podvm/cdi/metadata.yaml")
        self.assertEqual(spec["cdiVersion"], "0.6.0")
        self.assertEqual(spec["kind"], "podvm.local/metadata")
        self.assertEqual([device["name"] for device in spec["devices"]], ["0"])
        mounts = spec["devices"][0]["containerEdits"]["mounts"]
        self.assertEqual([(m["hostPath"], m["containerPath"]) for m in mounts], [
            ("/etc/os-release", "/run/podvm/os-release"),
            ("/run/confidential-containers/initdata/initdata.toml", "/run/podvm/initdata.toml")])
        for mount in mounts:
            self.assertEqual(mount["type"], "bind")
            self.assertEqual(mount["options"], ["bind", "ro", "nosuid", "nodev", "noexec"])

    def installer_fixture(self, work):
        # Relocate only fixed guest paths. Production has no path/env overrides.
        source = work / "metadata.yaml"
        shutil.copy2(ROOT / "assets/guest/usr/share/podvm/cdi/metadata.yaml", source)
        runtime = work / "runtime/cdi"
        installer = work / "install"
        text = (ROOT / "assets/guest/usr/local/bin/podvm-install-cdi").read_text()
        installer.write_text(text.replace("/var/run/cdi", str(runtime)).replace(
            "/usr/share/podvm/cdi/metadata.yaml", str(source)))
        installer.chmod(0o755)
        env = dict(os.environ)
        if os.geteuid() != 0:
            # Non-root unit tests exercise filesystem operations while recording
            # the ownership request. Root runs additionally verify actual uid/gid.
            shim = work / "bin"
            shim.mkdir()
            chown = shim / "chown"
            chown.write_text('#!/bin/sh\n[ "$1" = "0:0" ] || exit 1\n')
            chown.chmod(0o755)
            env["PATH"] = str(shim) + ":" + env["PATH"]
        return installer, source, runtime, env

    def test_installer_empty_repeat_and_nvidia_preservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            installer, source, runtime, env = self.installer_fixture(Path(temporary))
            for repeat in range(2):
                subprocess.run([installer], env=env, check=True)
                target = runtime / "podvm-metadata.yaml"
                self.assertEqual(target.read_bytes(), source.read_bytes())
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
                if os.geteuid() == 0:
                    self.assertEqual((target.stat().st_uid, target.stat().st_gid), (0, 0))
                if repeat == 0:
                    (runtime / "nvidia.yaml").write_text("keep NVIDIA devices")
                self.assertEqual((runtime / "nvidia.yaml").read_text(), "keep NVIDIA devices")
                self.assertEqual(sorted(p.name for p in runtime.iterdir()), ["nvidia.yaml", "podvm-metadata.yaml"])

    def test_installer_failure_preserves_previous_spec_and_cleans_temporary(self):
        for failure in ("source", "chown", "chmod", "mv", "mkdir"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                installer, source, runtime, env = self.installer_fixture(work)
                subprocess.run([installer], env=env, check=True)
                old = (runtime / "podvm-metadata.yaml").read_bytes()
                if failure == "source":
                    source.unlink()
                else:
                    shim = work / "fail-bin"
                    shim.mkdir()
                    command = shim / failure
                    command.write_text("#!/bin/sh\nexit 42\n")
                    command.chmod(0o755)
                    env["PATH"] = str(shim) + ":" + env["PATH"]
                result = subprocess.run([installer], env=env, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((runtime / "podvm-metadata.yaml").read_bytes(), old)
                self.assertEqual([p.name for p in runtime.iterdir()], ["podvm-metadata.yaml"])

    def test_launcher_forwards_arguments_environment_exit_and_stops_on_failure(self):
        for installation_status in (0, 42):
            with self.subTest(status=installation_status), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                install = work / "install"
                install.write_text(f"#!/bin/sh\nexit {installation_status}\n")
                install.chmod(0o755)
                agent = work / "agent"
                agent.write_text('#!/bin/sh\nprintf "%s\\n" "$NVRC_TEST" "$@"\nexit 37\n')
                agent.chmod(0o755)
                launcher = work / "launcher"
                launcher.write_text((ROOT / "assets/nvidia-kata-agent").read_text().replace(
                    "/usr/local/bin/podvm-install-cdi", str(install)).replace(
                    "/usr/local/bin/kata-agent", str(agent)))
                launcher.chmod(0o755)
                result = subprocess.run([launcher, "--flag", "space value", "", "*"],
                                        env={**os.environ, "NVRC_TEST": "preserved"}, capture_output=True, text=True)
                self.assertEqual(result.returncode, installation_status or 37)
                self.assertEqual(result.stdout, "" if installation_status else "preserved\n--flag\nspace value\n\n*\n")

    def test_both_variants_reject_missing_stale_or_nonexecutable_metadata_components(self):
        for variant in ("cpu", "nvidia"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                rootfs = Path(temporary)
                (rootfs / "usr/bin").mkdir(parents=True)
                test_podvm.PodVMTests.add_metadata_assets(rootfs, variant)
                podvm.validate_metadata_cdi(rootfs, variant)
                names = ["usr/share/podvm/cdi/metadata.yaml", "usr/local/bin/podvm-install-cdi",
                         "usr/local/bin/kata-agent"]
                names += ["usr/bin/kata-agent"] if variant == "nvidia" else [
                    "etc/agent-config.toml", "etc/systemd/system/kata-agent.service"]
                for name in names:
                    path = rootfs / name
                    original = path.read_bytes()
                    path.write_bytes(b"stale")
                    with self.subTest(path=name), self.assertRaises(podvm.PodVMError):
                        podvm.validate_metadata_cdi(rootfs, variant)
                    path.write_bytes(original)
                installer = rootfs / "usr/local/bin/podvm-install-cdi"
                installer.chmod(0o644)
                with self.assertRaisesRegex(podvm.PodVMError, "not executable"):
                    podvm.validate_metadata_cdi(rootfs, variant)

    def test_nvidia_overlay_keeps_launcher_separate_and_scans_real_agent(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            rootfs = work / "rootfs"
            tree = work / "podvm/resources/binaries-tree"
            for name in ("usr/local/bin/kata-agent", "usr/local/bin/podvm-model-mount", "etc/modelwrap-build.json"):
                path = tree / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"\x7fELFtest")
                path.chmod(0o755)
            for name in ("usr/share/podvm/cdi/metadata.yaml", "usr/local/bin/podvm-install-cdi"):
                path = tree / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / "assets/guest" / name, path)
            for name in ("etc/kata-opa/default-policy.rego", "etc/os-release", "usr/sbin/veritysetup",
                         "usr/sbin/dmsetup", "usr/bin/mount"):
                path = rootfs / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture")
            with mock.patch.object(podvm, "capture", return_value="") as readelf:
                overlay = podvm.prepare_nvidia_overlay(work / "podvm", rootfs, work)
            scanned = [str(call.args[0][-1]) for call in readelf.call_args_list]
            self.assertIn(str(overlay / "usr/local/bin/kata-agent"), scanned)
            self.assertNotIn(str(overlay / "usr/bin/kata-agent"), scanned)
            self.assertEqual((overlay / "usr/bin/kata-agent").read_bytes(), (ROOT / "assets/nvidia-kata-agent").read_bytes())
            self.assertEqual((overlay / "usr/share/podvm/cdi/metadata.yaml").read_bytes(),
                             (tree / "usr/share/podvm/cdi/metadata.yaml").read_bytes())
            self.assertFalse((overlay / "etc/agent-config.toml").exists())

    def test_selector_flows_through_cmdline_staging_annotations_and_opt_in_example(self):
        fixtures = test_podvm.PodVMTests()
        fixtures.setUp()
        for variant in ("cpu", "nvidia"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                staging = (fixtures.create_nvidia_staging if variant == "nvidia" else fixtures.create_staging)(Path(temporary))
                profiles = podvm.load_yaml(podvm.NVIDIA_PROFILES) if variant == "nvidia" else fixtures.profiles
                podvm.validate_staging(staging, variant)
                self.assertIn("agent.visible_cdi_devices=true", (staging / "cmdline").read_text())
                podvm.write_kata_examples(staging, profiles)
                for path in (staging / "kata").glob("pod-*.yaml"):
                    doc = podvm.load_yaml(path)
                    self.assertNotIn("env", doc["spec"]["containers"][0])
                    self.assertIn("agent.visible_cdi_devices=true", doc["metadata"]["annotations"][
                        "io.katacontainers.config.hypervisor.kernel_params"])
                example = podvm.load_yaml(staging / "kata/metadata-container.example.yaml")
                self.assertEqual(example["env"][0]["value"], "podvm.local/metadata=0")
                assets = podvm.local_asset_hashes(variant)
                for name in ("assets/guest/usr/share/podvm/cdi/metadata.yaml",
                             "assets/guest/usr/local/bin/podvm-install-cdi", "assets/nvidia-kata-agent"):
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
                    self.assertEqual(bool(spec["process"]["env"]), index in (0, 3))


if __name__ == "__main__":
    unittest.main()

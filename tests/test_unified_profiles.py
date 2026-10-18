import argparse
import copy
from contextlib import nullcontext
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from jsonschema import Draft202012Validator, ValidationError

import test_podvm as fixtures


podvm = fixtures.podvm


class UnifiedProfilesTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = fixtures.PodVMTests()
        self.fixtures.setUp()
        self.config = self.fixtures.config
        self.profiles = self.fixtures.all_profiles
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.dist = self.root / "dist"

    def schema(self, name):
        schema = podvm.load_json(podvm.ROOT / "schemas" / f"{name}.schema.json")
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(schema)

    def create_package(self, variant, *, real_archive=False, profiles=None):
        profiles = self.profiles if profiles is None else profiles
        create = (self.fixtures.create_nvidia_staging if variant == "nvidia"
                  else self.fixtures.create_staging)
        staging = create(self.root / variant)
        args = argparse.Namespace(variant=variant, staging_dir=staging,
            raw_measurements=self.root / variant / "raw.json", workspace=self.root,
            dist_dir=self.root / "build/packages" / variant, release_version="dev",
            source_revision="1" * 40, source_repository="owner/repo")
        with mock.patch.object(podvm, "run_tdx", side_effect=self.fixtures.fake_tdx), \
                mock.patch.object(podvm, "run_snp", return_value="ab" * 48):
            podvm.measure(args, self.config, profiles)
        archive = nullcontext() if real_archive else mock.patch.object(podvm, "make_tar_zst",
            side_effect=lambda source, output: output.write_bytes(f"bundle {variant}".encode()))
        with archive:
            podvm.package(args, self.config, profiles)
        return args.dist_dir

    def assemble(self, directories, profiles=None):
        args = argparse.Namespace(package_dir=directories, dist_dir=self.dist, workspace=self.root)
        podvm.assemble(args, self.config, self.profiles if profiles is None else profiles)
        return podvm.load_json(self.dist / "measurements.json")

    def test_shared_config_and_schema_accept_both_variants(self):
        podvm.validate_profiles(self.profiles)
        self.schema("launch-profiles").validate(self.profiles)
        self.assertEqual(set(self.profiles), {"tdx", "sev", "profiles"})
        self.assertEqual(len(self.profiles["profiles"]), 8)
        self.assertEqual(podvm.profile_variants(self.profiles), {"cpu", "nvidia"})
        for variant, count in (("cpu", 1), ("nvidia", 7)):
            selected = podvm.select_profiles(self.profiles, variant)
            self.assertEqual(len(selected["profiles"]), count)
            self.schema("launch-profiles").validate(selected)

    def test_shared_config_rejects_legacy_variant_and_invalid_gpu_fields(self):
        for mutation in (
            lambda p: p.update(variant="nvidia"),
            lambda p: p["profiles"]["2vcpu-8g"].update(variant="cpu"),
            lambda p: p["profiles"]["h100-pcie-1-96g"].update(gpu=None),
            lambda p: p["profiles"]["2vcpu-8g"].update(tdx_topology={}),
        ):
            profiles = copy.deepcopy(self.profiles)
            mutation(profiles)
            with self.subTest(profiles=profiles["profiles"]):
                with self.assertRaises(podvm.PodVMError):
                    podvm.validate_profiles(profiles)
                with self.assertRaises(ValidationError):
                    self.schema("launch-profiles").validate(profiles)

    def test_json_rejects_duplicate_profile_keys(self):
        source = self.root / "catalog-part.json"
        source.write_text('{"profiles": {"same": {}, "same": {}}}')
        with self.assertRaisesRegex(podvm.PodVMError, "duplicate JSON key"):
            podvm.load_json(source)

    def test_empty_variant_selection_fails_before_running_tools(self):
        gpu_only = podvm.select_profiles(self.profiles, "nvidia")
        for function in (podvm.build, podvm.measure, podvm.package, podvm.smoke):
            with self.subTest(command=function.__name__), mock.patch.object(podvm, "run") as run:
                with self.assertRaisesRegex(podvm.PodVMError, "no launch profiles"):
                    function(argparse.Namespace(variant="cpu"), self.config, gpu_only)
                run.assert_not_called()

    def test_cli_defaults_share_profiles_and_separate_packages(self):
        for variant in ("cpu", "nvidia"):
            args = podvm.parser().parse_args(["package", "--variant", variant, "--release-version", "dev"])
            podvm.configure_variant_paths(args)
            self.assertEqual(args.profiles, podvm.DEFAULT_PROFILES)
            self.assertEqual(args.dist_dir, podvm.ROOT / "build/packages" / variant)
            args = podvm.parser().parse_args(["validate", "--variant", variant, "--dist-dir", "dist"])
            podvm.configure_variant_paths(args)
            self.assertFalse(args.validate_staging)
            self.assertTrue(args.validate_dist)

    def test_fingerprints_isolate_profiles_and_bind_shared_settings(self):
        cpu = self.fixtures.create_staging(self.root / "cpu")
        gpu = self.fixtures.create_nvidia_staging(self.root / "nvidia")
        original = {v: podvm.measurement_fingerprint(s, self.config, self.profiles, v)
                    for v, s in (("cpu", cpu), ("nvidia", gpu))}
        changed = copy.deepcopy(self.profiles)
        changed["profiles"]["h100-pcie-1-96g"]["sev"] = {"vcpu_types": ["EPYC-Turin"]}
        self.assertEqual(original["cpu"], podvm.measurement_fingerprint(cpu, self.config, changed))
        self.assertNotEqual(original["nvidia"], podvm.measurement_fingerprint(gpu, self.config, changed, "nvidia"))
        changed = copy.deepcopy(self.profiles)
        changed["sev"]["defaults"]["guest_features"] = "0x21"
        for variant, staging in (("cpu", cpu), ("nvidia", gpu)):
            self.assertNotEqual(original[variant], podvm.measurement_fingerprint(staging, self.config, changed, variant))

    @unittest.skipUnless(sys.platform == "linux", "requires GNU tar on Linux")
    @unittest.skipUnless(shutil.which("tar") and shutil.which("zstd"), "tar and zstd are required")
    def test_mixed_release_has_all_profiles_and_correct_bundled_selections(self):
        directories = [self.create_package(v, real_archive=True) for v in ("cpu", "nvidia")]
        document = self.assemble(directories)
        self.schema("measurements").validate(document)
        podvm.validate_release(self.dist, self.profiles, self.config)
        self.assertEqual(set(document["profiles"]), set(self.profiles["profiles"]))
        self.assertEqual(set(document["artifacts"]), {"cpu", "nvidia"})
        self.assertEqual(set(document["inputs"]), {"cpu", "nvidia"})
        self.assertEqual(set(p.name for p in self.dist.iterdir()), {
            "podvm-ubuntu-24.04-x86_64-dev.tar.zst",
            "podvm-nvidia-ubuntu-24.04-x86_64-dev.tar.zst", "measurements.json", "SHA256SUMS"})
        bundled_cmdlines = {}
        for variant in ("cpu", "nvidia"):
            bundle = self.dist / document["artifacts"][variant]["name"]
            bundled_cmdlines[variant] = podvm.capture([
                "tar", "--zstd", "-xOf", str(bundle), "podvm/cmdline"]).strip()
            bundled = podvm.json.loads(podvm.capture([
                "tar", "--zstd", "-xOf", str(bundle), "podvm/launch-profiles.json"]))
            self.assertEqual(bundled, podvm.select_profiles(self.profiles, variant))
            members = podvm.capture(["tar", "--zstd", "-tf", str(bundle)]).splitlines()
            examples = {Path(name).name for name in members if "/kata/pod-" in name}
            self.assertEqual(examples, {f"pod-{tee}-{name}.yaml"
                for name in bundled["profiles"] for tee in ("tdx", "snp")})
        for name, record in document["profiles"].items():
            if "gpu" in self.profiles["profiles"][name]:
                self.assertEqual(set(record), {"gpu", "sev"})
                variant = "nvidia"
            else:
                self.assertEqual(set(record), {"tdx", "sev"})
                variant = "cpu"
            for model, measurement in record["sev"].items():
                with self.subTest(profile=name, model=model):
                    self.assertEqual(measurement["configuration"]["cmdline"],
                                     bundled_cmdlines[variant])
        first = {p.name: p.read_bytes() for p in self.dist.iterdir()}
        self.assemble(list(reversed(directories)))
        self.assertEqual(first, {p.name: p.read_bytes() for p in self.dist.iterdir()})

    def test_single_variant_catalogs_use_the_same_schema(self):
        for variant in ("cpu", "nvidia"):
            with self.subTest(variant=variant):
                profiles = podvm.select_profiles(self.profiles, variant)
                directory = self.create_package(variant, profiles=profiles)
                document = self.assemble([directory], profiles)
                self.schema("measurements").validate(document)
                self.assertEqual(set(document["artifacts"]), {variant})
                self.assertEqual(len(list(self.dist.iterdir())), 3)

    def test_assembly_discovers_configured_packages_from_cli(self):
        self.create_package("cpu")
        self.create_package("nvidia")
        config_path = self.root / "profiles.yaml"
        config_path.write_text(podvm.yaml.safe_dump(self.profiles))
        (self.root / "assets").symlink_to(podvm.ROOT / "assets", target_is_directory=True)
        with mock.patch.object(podvm, "ROOT", self.root), mock.patch("sys.argv", [
                "podvm.py", "assemble", "--profiles", str(config_path), "--workspace", str(self.root)]):
            self.assertEqual(podvm.main(), 0)
        podvm.validate_release(self.dist, self.profiles, self.config)

    def test_assembly_rejects_missing_duplicate_and_unexpected_variants(self):
        cpu, gpu = self.create_package("cpu"), self.create_package("nvidia")
        cases = (([cpu], self.profiles), ([cpu, gpu, cpu], self.profiles),
                 ([cpu, gpu], podvm.select_profiles(self.profiles, "cpu")))
        for directories, profiles in cases:
            with self.subTest(directories=directories), self.assertRaises(podvm.PodVMError):
                self.assemble(directories, profiles)
        self.assertFalse(self.dist.exists())

    def test_failed_assembly_preserves_existing_release(self):
        cpu, gpu = self.create_package("cpu"), self.create_package("nvidia")
        self.assemble([cpu, gpu])
        previous = {p.name: p.read_bytes() for p in self.dist.iterdir()}
        part_path = gpu / "catalog-part.json"
        valid = podvm.load_json(part_path)
        mutations = (
            lambda d: d["release"].update(version="different"),
            lambda d: d["release"].update(source_revision="2" * 40),
            lambda d: d.update(schema="https://example.com/schema.json"),
            lambda d: d["profiles"].pop("h100-pcie-1-96g"),
            lambda d: d["profiles"].update(extra=copy.deepcopy(d["profiles"]["h100-pcie-1-96g"])),
            lambda d: d["profiles"]["h100-pcie-1-96g"]["sev"].pop("EPYC-Turin"),
            lambda d: d["profiles"]["h100-pcie-1-96g"].update(tdx={}),
            lambda d: d["inputs"]["nvidia"].update(launch_profiles_sha256="0" * 64),
            lambda d: d["inputs"]["nvidia"].update(measurement_tools={}),
            lambda d: d["artifacts"]["nvidia"].update(sha256="0" * 64),
            lambda d: d["artifacts"]["nvidia"].update(name="../outside.tar.zst"),
        )
        for mutation in mutations:
            document = copy.deepcopy(valid)
            mutation(document)
            podvm.dump_json(part_path, document)
            with self.subTest(mutation=mutation), self.assertRaises(podvm.PodVMError):
                self.assemble([cpu, gpu])
            self.assertEqual(previous, {p.name: p.read_bytes() for p in self.dist.iterdir()})
        podvm.dump_json(part_path, valid)
        bundle = gpu / valid["artifacts"]["nvidia"]["name"]
        bundle.write_bytes(b"changed archive")
        with self.assertRaisesRegex(podvm.PodVMError, "bundle checksum"):
            self.assemble([cpu, gpu])
        self.assertEqual(previous, {p.name: p.read_bytes() for p in self.dist.iterdir()})

    def test_assembly_rejects_valid_but_different_release_identities(self):
        cpu, gpu = self.create_package("cpu"), self.create_package("nvidia")
        part_path = gpu / "catalog-part.json"
        document = podvm.load_json(part_path)
        artifact = document["artifacts"]["nvidia"]
        old = gpu / artifact["name"]
        document["release"]["version"] = "other"
        artifact["name"] = artifact["name"].replace("-dev.", "-other.")
        old.rename(gpu / artifact["name"])
        podvm.dump_json(part_path, document)
        with self.assertRaisesRegex(podvm.PodVMError, "release identities"):
            self.assemble([cpu, gpu])

    def test_assembly_rejects_stale_shared_defaults_and_profile_overrides(self):
        directories = [self.create_package(v) for v in ("cpu", "nvidia")]
        for mutation in (
            lambda p: p["sev"]["defaults"].update(guest_features="0x21"),
            lambda p: p["profiles"]["h100-pcie-1-96g"].update(sev={"vcpu_types": ["EPYC-Turin"]}),
            lambda p: p["tdx"].update(acpi_distribution="changed"),
        ):
            changed = copy.deepcopy(self.profiles)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaises(podvm.PodVMError):
                self.assemble(directories, changed)

    def test_copy_and_rename_failures_preserve_existing_release(self):
        directories = [self.create_package(v) for v in ("cpu", "nvidia")]
        self.assemble(directories)
        previous = {p.name: p.read_bytes() for p in self.dist.iterdir()}
        with mock.patch.object(podvm.shutil, "copy2", side_effect=OSError("copy failed")):
            with self.assertRaisesRegex(OSError, "copy failed"):
                self.assemble(directories)
        original_rename = Path.rename
        def rename(source, destination):
            if source.name == "release" and source.parent.name.startswith(".podvm-assemble-"):
                raise OSError("rename failed")
            return original_rename(source, destination)
        with mock.patch.object(Path, "rename", rename):
            with self.assertRaisesRegex(OSError, "rename failed"):
                self.assemble(directories)
        self.assertEqual(previous, {p.name: p.read_bytes() for p in self.dist.iterdir()})

    def test_failed_restore_retains_backup_for_recovery(self):
        directories = [self.create_package(v) for v in ("cpu", "nvidia")]
        self.assemble(directories)
        previous = {p.name: p.read_bytes() for p in self.dist.iterdir()}
        original_rename = Path.rename
        def rename(source, destination):
            if source.name in ("release", "previous"):
                raise OSError("rename failed")
            return original_rename(source, destination)
        with mock.patch.object(Path, "rename", rename):
            with self.assertRaisesRegex(podvm.PodVMError, "previous output retained"):
                self.assemble(directories)
        backup, = self.root.glob(".podvm-assemble-*/previous")
        self.assertEqual(previous, {p.name: p.read_bytes() for p in backup.iterdir()})

    def test_catalog_schema_and_validator_reject_inconsistent_variant_maps(self):
        directories = [self.create_package(v) for v in ("cpu", "nvidia")]
        valid = self.assemble(directories)
        for mutation in (
            lambda d: d["artifacts"].pop("nvidia"),
            lambda d: d["inputs"].pop("cpu"),
            lambda d: d["artifacts"].update(other=d["artifacts"]["cpu"]),
            lambda d: d.update(variant="nvidia"),
            lambda d: d["profiles"]["h100-pcie-1-96g"].update(tdx=d["profiles"]["2vcpu-8g"]["tdx"]),
        ):
            document = copy.deepcopy(valid)
            mutation(document)
            with self.subTest(mutation=mutation):
                with self.assertRaises(podvm.PodVMError):
                    podvm.validate_measurements(document)
                with self.assertRaises(ValidationError):
                    self.schema("measurements").validate(document)


if __name__ == "__main__":
    unittest.main()

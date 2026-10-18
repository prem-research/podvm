import base64
import gzip
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_podvm

podvm = test_podvm.podvm
ROOT = test_podvm.ROOT


def workload_output(stdout_lines=podvm.LOG_SMOKE_LINES, done=True):
    stdout = "".join(f"LOG_SMOKE_STDOUT {i:06d} ...\n" for i in range(stdout_lines))
    stderr = "".join(f"LOG_SMOKE_STDERR {i:06d} ...\n" for i in range(podvm.LOG_SMOKE_LINES))
    return stdout + ("LOG_SMOKE_DONE\n" if done else ""), stderr


class LogSmokeTests(unittest.TestCase):
    def test_policy_denies_only_log_reads(self):
        denied = podvm.log_smoke_policy(False)
        self.assertIn("default ReadStreamRequest := false\n", denied)
        self.assertNotIn("default ReadStreamRequest := true\n", denied)
        self.assertIn("default CreateContainerRequest := true\n", denied)
        self.assertEqual(denied.count(":= false"), 1)
        allowed = podvm.log_smoke_policy(True)
        self.assertNotIn(":= false", allowed)

    def test_agent_build_applies_the_log_drain_patch(self):
        patch = (ROOT / "assets/patches/kata-log-drain.patch").read_text()
        # Redacting a read to empty data is what makes the shim stop draining.
        self.assertIn("-            response.clear_data();", patch)
        self.assertNotIn("+            response.clear_data();", patch)
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(podvm, "run") as run, mock.patch.object(podvm.shutil, "copy2"):
            podvm.patch_agent(Path(temporary))
        applied = [Path(call.args[0][-1]).name for call in run.call_args_list]
        self.assertEqual(applied[-1], "kata-log-drain.patch")
        self.assertIn("assets/patches/kata-log-drain.patch", podvm.local_asset_hashes())
        self.assertIn("assets/log-smoke.go", podvm.local_asset_hashes())

    def test_smoke_requires_complete_output_when_allowed_and_silent_exit_when_denied(self):
        fixtures = test_podvm.PodVMTests()
        fixtures.setUp()
        complete = subprocess.CompletedProcess("docker", 0, *workload_output())
        for denied, expected_error in (
            (subprocess.CompletedProcess("docker", 0, "", ""), None),
            (subprocess.TimeoutExpired("docker", 1), "stalled"),
            (subprocess.CompletedProcess("docker", 1, "", ""), "logs-denied failed"),
            (subprocess.CompletedProcess("docker", 0, "LOG_SMOKE_STDOUT 000000\n", ""), "leaked"),
            (subprocess.CompletedProcess("docker", 0, "", "LOG_SMOKE_STDERR 000000\n"), "leaked"),
        ):
            with self.subTest(denied=denied), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                staging = fixtures.create_staging(work)
                (work / "fixture").mkdir()
                specs = []

                def run(*args, **kwargs):
                    specs.append(podvm.load_json(work / "fixture/config.json"))
                    outcome = complete if len(specs) == 1 else denied
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome
                with mock.patch.object(podvm, "build_log_smoke_fixture"), \
                     mock.patch.object(podvm, "stop_smoke_container"), \
                     mock.patch.object(podvm.subprocess, "run", side_effect=run):
                    args = (work, work, staging, fixtures.config, fixtures.profiles["profiles"]["2vcpu-8g"],
                            {"process": {"args": [], "env": []}}, "image", "container", work / "logs", 1)
                    if expected_error:
                        with self.assertRaisesRegex(podvm.PodVMError, expected_error):
                            podvm.smoke_logs(*args)
                    else:
                        podvm.smoke_logs(*args)
                self.assertEqual(len(specs), 2)
                for spec, logs_allowed in zip(specs, (True, False)):
                    self.assertEqual(spec["process"]["args"], ["/log-smoke"])
                    initdata = gzip.decompress(base64.b64decode(
                        spec["annotations"]["io.katacontainers.config.hypervisor.cc_init_data"])).decode()
                    self.assertIn(f"default ReadStreamRequest := {'true' if logs_allowed else 'false'}", initdata)

    def test_smoke_rejects_incomplete_output_when_allowed(self):
        fixtures = test_podvm.PodVMTests()
        fixtures.setUp()
        for stdout, stderr in (workload_output(stdout_lines=1024), workload_output(done=False)):
            with self.subTest(lines=stdout.count("\n")), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                staging = fixtures.create_staging(work)
                (work / "fixture").mkdir()
                with mock.patch.object(podvm, "build_log_smoke_fixture"), \
                     mock.patch.object(podvm, "stop_smoke_container"), \
                     mock.patch.object(podvm.subprocess, "run",
                                       return_value=subprocess.CompletedProcess("docker", 0, stdout, stderr)):
                    with self.assertRaisesRegex(podvm.PodVMError, "logs-allowed did not deliver"):
                        podvm.smoke_logs(work, work, staging, fixtures.config,
                                         fixtures.profiles["profiles"]["2vcpu-8g"],
                                         {"process": {"args": [], "env": []}}, "image", "container",
                                         work / "logs", 1)


if __name__ == "__main__":
    unittest.main()

import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest

import test_podvm

ROOT = test_podvm.ROOT
podvm = test_podvm.podvm


class TimeSyncTests(unittest.TestCase):
    def wait_until(self, predicate):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail("time synchronization process did not reach the expected state")

    def test_supervisor_gates_readiness_and_restarts_without_stepping(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            daemon = work / "chronyd"
            daemon.write_text('''#!/usr/bin/env python3
import json, os, signal, sys
with open(os.environ['TEST_WORK'] + '/starts', 'a') as stream:
    stream.write(json.dumps({'pid': os.getpid(), 'args': sys.argv[1:]}) + '\\n')
signal.pause()
''')
            client = work / "chronyc"
            client.write_text('''#!/usr/bin/env python3
import os, sys
from pathlib import Path
work = Path(os.environ['TEST_WORK'])
if 'waitsync' in sys.argv:
    sys.exit(0 if (work / 'authenticated').exists() else 1)
if 'makestep' in sys.argv:
    sys.exit(0 if (work / 'disable-steps').exists() else 1)
sys.exit(1)
''')
            daemon.chmod(0o755)
            client.chmod(0o755)
            script = (ROOT / "assets/guest/usr/local/bin/podvm-time-sync").read_text()
            script = script.replace("/run/", str(work) + "/")
            script = script.replace("/usr/sbin/chronyd", str(daemon)).replace("/usr/bin/chronyc", str(client))
            script = script.replace("-o 0 -g 0", f"-o {os.getuid()} -g {os.getgid()}")
            script = script.replace("-o _chrony -g _chrony", f"-o {os.getuid()} -g {os.getgid()}")
            process = subprocess.Popen(["sh", "-c", script], start_new_session=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                env={**os.environ, "TEST_WORK": str(work)})
            try:
                starts = work / "starts"
                ready = work / "podvm-time/ready"
                self.wait_until(starts.exists)
                self.assertFalse(ready.exists())
                (work / "authenticated").touch()
                # Synchronization alone must not publish before stepping is disabled.
                time.sleep(1.2)
                self.assertFalse(ready.exists())
                (work / "disable-steps").touch()
                self.wait_until(ready.exists)
                self.assertEqual((ready.parent.stat().st_mode & 0o777), 0o700)
                entries = lambda: [json.loads(line) for line in starts.read_text().splitlines()]
                first = entries()[0]
                self.assertNotIn("-R", first["args"])
                (work / "authenticated").unlink()
                os.kill(first["pid"], signal.SIGKILL)
                self.wait_until(lambda: len(entries()) >= 2)
                self.assertIn("-R", entries()[1]["args"])
                self.assertTrue(ready.exists(), "later loss of sync must not revoke initial admission")
            finally:
                os.killpg(process.pid, signal.SIGTERM)
                process.communicate(timeout=5)

    def test_nvidia_launcher_preserves_agent_pid_arguments_and_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            agent = work / "agent"
            agent.write_text('''#!/usr/bin/env python3
import json, os, sys
print(json.dumps([os.getpid(), sys.argv[1:], os.environ['TEST_ATTESTER']]))
''')
            helper = work / "helper"
            helper.write_text("#!/bin/sh\n: > \"$TEST_WORK/helper-started\"\n")
            agent.chmod(0o755)
            helper.chmod(0o755)
            script = work / "launcher"
            script.write_text((ROOT / "assets/nvidia-kata-agent").read_text()
                .replace("/usr/libexec/podvm/kata-agent", str(agent))
                .replace("/usr/local/bin/podvm-time-sync", str(helper)))
            for arguments in (["--version"], ["--config", "path with spaces"]):
                process = subprocess.Popen(["sh", str(script), *arguments], text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={**os.environ, "TEST_ATTESTER": "nvidia", "TEST_WORK": str(work)})
                output, error = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, error)
                self.assertEqual(json.loads(output), [process.pid, arguments, "nvidia"])
                if arguments == ["--version"]:
                    self.assertFalse((work / "helper-started").exists())
                else:
                    self.wait_until((work / "helper-started").exists)

    def test_both_images_require_identical_configuration_and_boot_scoped_state(self):
        for variant in ("cpu", "nvidia"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                rootfs = Path(temporary)
                test_podvm.PodVMTests.add_time_assets(rootfs, variant)
                podvm.validate_time_sync(rootfs, variant)
                config = rootfs / "etc/chrony/chrony.conf"
                original = config.read_bytes()
                config.write_text("server attacker.example iburst\n")
                with self.assertRaises(podvm.PodVMError):
                    podvm.validate_time_sync(rootfs, variant)
                config.write_bytes(original)
                ready = rootfs / "run/podvm-time/ready"
                ready.parent.mkdir(parents=True)
                ready.touch()
                with self.assertRaisesRegex(podvm.PodVMError, "readiness state"):
                    podvm.validate_time_sync(rootfs, variant)

    def test_nvidia_account_merge_preserves_users_and_rejects_id_conflicts(self):
        source = (ROOT / "assets/compose-nvidia-rootfs.sh").read_text()
        merge = source.split("# Merge the daemon account", 1)[1]
        merge = merge[merge.index("for database"):].split("# Keep upstream", 1)[0]
        for existing, succeeds in (("root:x:0:0::/:/bin/sh\n", True),
                                  ("other:x:101:101::/:/bin/sh\n", False),
                                  ("_chrony:x:102:102::/:/bin/sh\n", False)):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                overlay, output = work / "overlay", work / "output"
                for directory in (overlay, output):
                    (directory / "etc").mkdir(parents=True)
                (overlay / "etc/passwd").write_text("_chrony:x:101:101::/:/bin/false\n")
                (overlay / "etc/group").write_text("_chrony:x:101:\n")
                (output / "etc/passwd").write_text(existing)
                (output / "etc/group").write_text("root:x:0:\n")
                script = merge.replace("/overlay/", str(overlay) + "/").replace("/output/", str(output) + "/")
                result = subprocess.run(["bash", "-ec", "error() { echo \"$*\" >&2; }\n" + script],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                if succeeds:
                    self.assertEqual((output / "etc/passwd").read_text(),
                                     existing + (overlay / "etc/passwd").read_text())


if __name__ == "__main__":
    unittest.main()

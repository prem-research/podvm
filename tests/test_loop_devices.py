import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


HELPER = Path(__file__).resolve().parents[1] / "assets/image-builder-loop.sh"


class LoopDeviceTests(unittest.TestCase):
    def run_helper(self, sysfs, node, kind, stubs=""):
        script = (
            "set -euo pipefail\n"
            "error(){ echo \"$*\" >&2; }\n"
            f"source {shlex.quote(str(HELPER))}\n"
            + stubs + "\n"
            + "ensure_loop_node " + " ".join(shlex.quote(str(arg)) for arg in (sysfs, node, kind))
        )
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True)

    def test_missing_driver_fails_before_creating_nodes(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_helper(Path(temporary) / "missing", "/dev/loop-control", "c",
                                     'mknod(){ echo "unexpected mknod"; }')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Docker host must provide the loop driver", result.stderr)
            self.assertEqual(result.stdout, "")

    def test_partition_node_uses_kernel_numbers(self):
        with tempfile.TemporaryDirectory() as temporary:
            sysfs = Path(temporary) / "loop17p2"
            sysfs.mkdir()
            (sysfs / "dev").write_text("259:37\n")
            node = Path(temporary) / "node"
            result = self.run_helper(sysfs, node, "b", 'mknod(){ printf "%s\\n" "$@"; }')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["-m", "0600", str(node), "b", "259", "37"])

    def test_existing_correct_node_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            sysfs = Path(temporary)
            (sysfs / "dev").write_text("1:3\n")
            result = self.run_helper(sysfs, "/dev/null", "c",
                                     'rm(){ echo "unexpected rm"; }; mknod(){ echo "unexpected mknod"; }')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")

    def test_non_device_path_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            sysfs = Path(temporary)
            (sysfs / "dev").write_text("7:17\n")
            node = sysfs / "ordinary-file"
            node.write_text("preserve me")
            result = self.run_helper(sysfs, node, "b")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing to replace non-device path", result.stderr)
            self.assertEqual(node.read_text(), "preserve me")

    def test_stale_device_numbers_are_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            sysfs = Path(temporary)
            (sysfs / "dev").write_text("259:37\n")
            # Stub mutations: exercise replacement without modifying /dev/null.
            result = self.run_helper(sysfs, "/dev/null", "b",
                'rm(){ echo "remove $*"; }; mknod(){ echo "create $*"; }')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(),
                ["remove -f /dev/null", "create -m 0600 /dev/null b 259 37"])

    def test_concurrent_creation_accepts_matching_node(self):
        with tempfile.TemporaryDirectory() as temporary:
            sysfs = Path(temporary)
            (sysfs / "dev").write_text("1:3\n")
            node = sysfs / "node"
            result = self.run_helper(sysfs, node, "c",
                'mknod(){ ln -s /dev/null "$3"; return 1; }')
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_creation_rejects_wrong_node(self):
        with tempfile.TemporaryDirectory() as temporary:
            sysfs = Path(temporary)
            (sysfs / "dev").write_text("259:37\n")
            node = sysfs / "node"
            result = self.run_helper(sysfs, node, "b",
                'mknod(){ ln -s /dev/null "$3"; return 1; }')
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()

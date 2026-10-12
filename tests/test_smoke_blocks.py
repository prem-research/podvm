import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location('smoke_blocks', Path(__file__).resolve().parents[1] / 'assets/smoke-blocks.py')
blocks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(blocks)


class SmokeBlockOwnershipTests(unittest.TestCase):
    def test_cleanup_detaches_only_owned_backing_and_retains_failures(self):
        for current_inode, detach_fails in [(111, False), (222, False), (111, True)]:
            with self.subTest(current_inode=current_inode, detach_fails=detach_fails), tempfile.TemporaryDirectory() as temporary:
                journal = Path(temporary) / 'ownership.json'
                record = {'device': '/dev/test-block', 'inode': 111, 'dev': '7:4'}
                journal.write_text(json.dumps([record]))
                calls = []

                def command(*args):
                    calls.append(args)
                    if args[1] == '--json':
                        return json.dumps({'loopdevices': [{'name': record['device'], 'back-ino': current_inode, 'back-maj:min': '7:4'}]})
                    if detach_fails:
                        raise subprocess.CalledProcessError(1, args)
                    return ''

                with mock.patch.object(blocks, 'JOURNAL', journal), mock.patch.object(blocks, 'ROOTFS', Path(temporary)), mock.patch.object(blocks, 'command', side_effect=command):
                    if detach_fails:
                        with self.assertRaisesRegex(RuntimeError, 'could not release'):
                            blocks.cleanup()
                    else:
                        blocks.cleanup()
                detaches = [call for call in calls if call[1] == '--detach']
                self.assertEqual(len(detaches), int(current_inode == 111))
                self.assertEqual(json.loads(journal.read_text()), [record] if detach_fails else [])

    def test_cleanup_is_idempotent_when_device_is_already_gone(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / 'ownership.json'
            journal.write_text(json.dumps([{'device': '/dev/test-block', 'inode': 111, 'dev': '7:4'}]))
            with mock.patch.object(blocks, 'JOURNAL', journal), mock.patch.object(blocks, 'ROOTFS', Path(temporary)), mock.patch.object(blocks, 'command', return_value='{"loopdevices": []}') as command:
                blocks.cleanup()
                blocks.cleanup()
            self.assertEqual(json.loads(journal.read_text()), [])
            self.assertFalse(any(call.args[1] == '--detach' for call in command.call_args_list))

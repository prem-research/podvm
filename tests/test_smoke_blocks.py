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
    def test_setup_allows_writable_rootfs_backend_and_keeps_models_readonly(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            fixture = work / 'fixture'
            (fixture / 'rootfs').mkdir(parents=True)
            model = work / 'model-fixtures/model.mpk'
            model.parent.mkdir()
            model.write_bytes(b'model fixture')
            root_mount = work / 'mounted-rootfs'
            journal = work / 'ownership.json'
            request = {
                'root': {'path': str(root_mount), 'readonly': True},
                'mounts': [{'destination': '/models/example', 'type': 'bind',
                            'source': str(model), 'options': ['rbind', 'rprivate', 'ro']}],
            }
            for name in ('config.json', 'model-subset.json'):
                (fixture / name).write_text(json.dumps(request))
            root_image = str(fixture / 'rootfs.img')

            def command(*args):
                if args[0] == 'losetup':
                    if args[-1] == root_image:
                        # Reproduce the pinned Kata rootfs backend's writable
                        # open failing when the harness attaches it read-only.
                        if '--read-only' in args:
                            raise PermissionError('The device is not writable')
                        return '/dev/test-rootfs'
                    self.assertEqual(args[-1], str(model))
                    self.assertIn('--read-only', args)
                    return '/dev/test-model'
                return ''

            with mock.patch.object(blocks, 'WORK', work), \
                    mock.patch.object(blocks, 'JOURNAL', journal), \
                    mock.patch.object(blocks, 'ROOTFS', root_mount), \
                    mock.patch.object(blocks, 'command', side_effect=command) as run:
                blocks.setup()

            run.assert_any_call('mkfs.ext4', '-q', '-F', '-O', '^has_journal', '-E',
                                'lazy_itable_init=0', '-d', str(fixture / 'rootfs'), root_image)
            run.assert_any_call('sync', '-f', str(root_mount))
            run.assert_any_call('mount', '-o', 'ro', '/dev/test-rootfs', str(root_mount))
            self.assertEqual(sum(call.args[0] == 'losetup' for call in run.call_args_list), 2)
            for name in ('config.json', 'model-subset.json'):
                actual = json.loads((fixture / name).read_text())
                self.assertEqual(actual['root'], request['root'])
                self.assertEqual(actual['mounts'][0]['source'], '/dev/test-model')
                self.assertEqual(actual['mounts'][0]['options'], request['mounts'][0]['options'])
            records = json.loads(journal.read_text())
            self.assertEqual([r['device'] for r in records], ['/dev/test-rootfs', '/dev/test-model'])
            for record, path in zip(records, (Path(root_image), model)):
                self.assertEqual(record['inode'], path.stat().st_ino)

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

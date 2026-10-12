import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace


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

            def attach(path, *, read_only):
                if path == root_image:
                    # The pinned Kata rootfs backend opens the device writable.
                    self.assertFalse(read_only)
                    return '/dev/test-rootfs'
                self.assertEqual(path, str(model))
                self.assertTrue(read_only)
                return '/dev/test-model'

            with mock.patch.object(blocks, 'WORK', work), \
                    mock.patch.object(blocks, 'JOURNAL', journal), \
                    mock.patch.object(blocks, 'ROOTFS', root_mount), \
                    mock.patch.object(blocks, 'attach_loop', side_effect=attach) as allocate, \
                    mock.patch.object(blocks, 'command', return_value='') as run:
                blocks.setup()

            run.assert_any_call('mkfs.ext4', '-q', '-F', '-O', '^has_journal', '-E',
                                'lazy_itable_init=0', '-d', str(fixture / 'rootfs'), root_image)
            run.assert_any_call('sync', '-f', str(root_mount))
            run.assert_any_call('mount', '-o', 'ro', '/dev/test-rootfs', str(root_mount))
            self.assertEqual(allocate.call_count, 2)
            for name in ('config.json', 'model-subset.json'):
                actual = json.loads((fixture / name).read_text())
                self.assertEqual(actual['root'], request['root'])
                self.assertEqual(actual['mounts'][0]['source'], '/dev/test-model')
                self.assertEqual(actual['mounts'][0]['options'], request['mounts'][0]['options'])
            records = json.loads(journal.read_text())
            self.assertEqual([r['device'] for r in records], ['/dev/test-rootfs', '/dev/test-model'])
            for record, path in zip(records, (Path(root_image), model)):
                self.assertEqual(record['inode'], path.stat().st_ino)

    def test_attachment_creates_selected_node_before_opening_it(self):
        nodes = set()

        def ensure(node, sysfs, kind):
            nodes.add(str(node))

        def command(*args):
            if args == ('losetup', '--find'):
                self.assertIn('/dev/loop-control', nodes)
                return '/dev/loop17'
            if args[0] == 'losetup':
                # Reproduce CI: the file exists, but opening a selected loop
                # device without its node gives ENOENT in a private /dev.
                if '/dev/loop17' not in nodes:
                    raise FileNotFoundError('/dev/loop17')
                self.assertEqual(args, ('losetup', '--show', '--read-only', '/dev/loop17', '/model.mpk'))
                return '/dev/loop17'
            self.fail(f'unexpected command: {args}')

        with mock.patch.object(blocks, 'ensure_device', side_effect=ensure) as create, \
                mock.patch.object(blocks, 'command', side_effect=command):
            self.assertEqual(blocks.attach_loop('/model.mpk', read_only=True), '/dev/loop17')
        create.assert_any_call(Path('/dev/loop17'), Path('/sys/class/block/loop17'), stat.S_IFBLK)

    def test_node_creation_uses_sysfs_and_refuses_conflicting_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            sysfs = Path(temporary)
            (sysfs / 'dev').write_text('7:17\n')
            node = sysfs / 'node'
            for kind, devno, accepted in [
                (stat.S_IFBLK, os.makedev(7, 17), True),
                (stat.S_IFCHR, os.makedev(7, 17), False),
                (stat.S_IFBLK, os.makedev(7, 18), False),
                (stat.S_IFREG, 0, False),
                (stat.S_IFLNK, 0, False),
            ]:
                with self.subTest(kind=kind, devno=devno), \
                        mock.patch.object(blocks.os, 'mknod', side_effect=FileExistsError) as create, \
                        mock.patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=kind | 0o600, st_rdev=devno)):
                    if accepted:
                        blocks.ensure_device(node, sysfs, stat.S_IFBLK)
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'refusing mismatched'):
                            blocks.ensure_device(node, sysfs, stat.S_IFBLK)
                    create.assert_called_once_with(node, stat.S_IFBLK | 0o600, os.makedev(7, 17))

    def test_concurrent_allocation_retries_without_detaching_foreign_device(self):
        with tempfile.TemporaryDirectory() as temporary:
            sysfs = Path(temporary)
            backing = sysfs / 'loop17/loop/backing_file'
            backing.parent.mkdir(parents=True)
            backing.write_text('/another-build/image')
            failure = subprocess.CalledProcessError(1, 'losetup')
            with mock.patch.object(blocks, 'SYS_BLOCK', sysfs), \
                    mock.patch.object(blocks, 'ensure_device'), \
                    mock.patch.object(blocks, 'command', side_effect=['/dev/loop17', failure, '/dev/loop18', '/dev/loop18']) as command:
                self.assertEqual(blocks.attach_loop('/model.mpk', read_only=True), '/dev/loop18')
            self.assertFalse(any('--detach' in call.args for call in command.call_args_list))

    def test_attachment_errors_propagate_and_retries_are_bounded(self):
        for claimed in (False, True):
            with self.subTest(claimed=claimed), tempfile.TemporaryDirectory() as temporary:
                sysfs = Path(temporary)
                if claimed:
                    backing = sysfs / 'loop17/loop/backing_file'
                    backing.parent.mkdir(parents=True)
                    backing.write_text('/another-build/image')
                failure = subprocess.CalledProcessError(1, 'losetup')
                with mock.patch.object(blocks, 'SYS_BLOCK', sysfs), \
                        mock.patch.object(blocks, 'ensure_device'), \
                        mock.patch.object(blocks, 'command', side_effect=['/dev/loop17', failure] * 8) as command:
                    with self.assertRaises(RuntimeError if claimed else subprocess.CalledProcessError):
                        blocks.attach_loop('/model.mpk', read_only=True)
                    self.assertEqual(command.call_count, 16 if claimed else 2)

    def test_cleanup_detaches_only_owned_backing_and_retains_failures(self):
        for current_inode, detach_fails in [(111, False), (222, False), (111, True)]:
            with self.subTest(current_inode=current_inode, detach_fails=detach_fails), tempfile.TemporaryDirectory() as temporary:
                journal = Path(temporary) / 'ownership.json'
                sysfs = Path(temporary) / 'sysfs'
                (sysfs / 'loop17').mkdir(parents=True)
                (sysfs / 'loop17/dev').write_text('7:17\n')
                record = {'device': '/dev/loop17', 'inode': 111, 'dev': '7:4'}
                journal.write_text(json.dumps([record]))
                calls = []

                def command(*args):
                    calls.append(args)
                    if args[1] == '--json':
                        return json.dumps({'loopdevices': [{'name': record['device'], 'back-ino': current_inode, 'back-maj:min': '7:4'}]})
                    if detach_fails:
                        raise subprocess.CalledProcessError(1, args)
                    return ''

                with mock.patch.object(blocks, 'JOURNAL', journal), \
                        mock.patch.object(blocks, 'ROOTFS', Path(temporary)), \
                        mock.patch.object(blocks, 'SYS_BLOCK', sysfs), \
                        mock.patch.object(blocks, 'ensure_device') as create, \
                        mock.patch.object(blocks, 'command', side_effect=command):
                    if detach_fails:
                        with self.assertRaisesRegex(RuntimeError, 'could not release'):
                            blocks.cleanup()
                    else:
                        blocks.cleanup()
                create.assert_called_once_with(Path(record['device']), sysfs / 'loop17', stat.S_IFBLK)
                detaches = [call for call in calls if call[1] == '--detach']
                self.assertEqual(len(detaches), int(current_inode == 111))
                self.assertEqual(json.loads(journal.read_text()), [record] if detach_fails else [])

    def test_cleanup_is_idempotent_when_device_is_already_gone(self):
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / 'ownership.json'
            journal.write_text(json.dumps([{'device': '/dev/loop17', 'inode': 111, 'dev': '7:4'}]))
            with mock.patch.object(blocks, 'JOURNAL', journal), \
                    mock.patch.object(blocks, 'ROOTFS', Path(temporary)), \
                    mock.patch.object(blocks, 'SYS_BLOCK', Path(temporary) / 'missing'), \
                    mock.patch.object(blocks, 'command') as command:
                blocks.cleanup()
                blocks.cleanup()
            self.assertEqual(json.loads(journal.read_text()), [])
            self.assertFalse(any(call.args[1] == '--detach' for call in command.call_args_list))

    def test_cleanup_node_failure_keeps_ownership_for_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / 'loop17').mkdir()
            (work / 'loop17/dev').write_text('7:17\n')
            journal = work / 'ownership.json'
            records = [{'device': '/dev/loop17', 'inode': 111, 'dev': '7:4'}]
            journal.write_text(json.dumps(records))
            with mock.patch.object(blocks, 'JOURNAL', journal), \
                    mock.patch.object(blocks, 'ROOTFS', work), \
                    mock.patch.object(blocks, 'SYS_BLOCK', work), \
                    mock.patch.object(blocks, 'ensure_device', side_effect=PermissionError('mknod denied')), \
                    mock.patch.object(blocks, 'command') as command:
                with self.assertRaisesRegex(RuntimeError, 'could not release owned test devices'):
                    blocks.cleanup()
            self.assertEqual(json.loads(journal.read_text()), records)
            command.assert_not_called()

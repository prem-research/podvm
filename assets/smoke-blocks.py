#!/usr/bin/python3
"""Owned block attachments for the isolated Docker smoke runner."""
import json
import os
from pathlib import Path
import subprocess
import sys

WORK = Path('/work')
JOURNAL = WORK / 'block-devices.json'
ROOTFS = Path('/run/podvm-smoke-rootfs')


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def save(records):
    temporary = JOURNAL.with_suffix('.tmp')
    temporary.write_text(json.dumps(records))
    temporary.replace(JOURNAL)


def cleanup():
    if not JOURNAL.exists():
        return
    records = json.loads(JOURNAL.read_text())
    if ROOTFS.is_mount():
        command('umount', str(ROOTFS))
    remaining = []
    failures = []
    for record in reversed(records):
        # Loop numbers may have been reused. Check kernel backing identity
        # before detaching the exact device this harness originally allocated.
        output = json.loads(command('losetup', '--json', '--output', 'NAME,BACK-INO,BACK-MAJ:MIN'))
        matches = [d for d in output['loopdevices'] if d['name'] == record['device']]
        if not matches:
            continue
        current = matches[0]
        if (int(current['back-ino']), current['back-maj:min']) != (record['inode'], record['dev']):
            continue
        try:
            command('losetup', '--detach', record['device'])
        except subprocess.CalledProcessError as error:
            remaining.append(record)
            failures.append(error)
    save(list(reversed(remaining)))
    if failures:
        raise RuntimeError(f'could not release owned test devices: {failures}')


def setup():
    if JOURNAL.exists() and json.loads(JOURNAL.read_text()):
        raise RuntimeError('existing smoke block ownership; cleanup required')
    records = []
    save(records)
    devices = {}

    def attach(path, *, read_only=True):
        if path not in devices:
            st = os.stat(path)
            args = ['losetup', '--find', '--show']
            if read_only:
                args.append('--read-only')
            device = command(*args, path)
            records.append({'device': device, 'inode': st.st_ino,
                            'dev': f'{os.major(st.st_dev)}:{os.minor(st.st_dev)}'})
            save(records)
            devices[path] = device
        return devices[path]

    image = str(WORK / 'fixture/rootfs.img')
    with open(image, 'wb') as stream:
        stream.truncate(64 * 1024 * 1024)
    # The test rootfs has no persistent journal to initialize or replay while
    # it is mounted on the host and then opened by the guest kernel.
    command('mkfs.ext4', '-q', '-F', '-O', '^has_journal', '-E',
            'lazy_itable_init=0', '-d', str(WORK / 'fixture/rootfs'), image)
    ROOTFS.mkdir(mode=0o700, exist_ok=True)
    # Kata's pinned rootfs plugDevice path leaves DeviceInfo.ReadOnly false,
    # so QEMU opens its backend writable even for an OCI read-only rootfs.
    # This disposable test image must permit that open; keep the host mount
    # and OCI root read-only, and all model device attachments read-only.
    command('mount', '-o', 'ro', attach(image, read_only=False), str(ROOTFS))
    command('sync', '-f', str(ROOTFS))
    for path in (WORK / 'fixture').glob('*.json'):
        spec = json.loads(path.read_text())
        for mount in spec.get('mounts', []):
            source = mount.get('source', '')
            if source.startswith(f'{WORK}/model-fixtures/') and Path(source).is_file():
                mount['source'] = attach(source)
        path.write_text(json.dumps(spec))


if __name__ == '__main__':
    {'setup': setup, 'cleanup': cleanup}[sys.argv[1]]()

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'assets/model-lifecycle-smoke.sh'


class ModelLifecycleTests(unittest.TestCase):
    def run_lifecycle(self, *, init_exit=0, stuck=False):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            # Run the actual orchestration with a delayed shim teardown. The
            # stub models ctr's exit-before-delete behavior from the CI trace.
            (work / 'ctr').write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
work = Path(os.environ['TEST_WORK'])
path = work / 'calls.json'
calls = json.loads(path.read_text()) if path.exists() else []
args = sys.argv[5:]  # --address SOCKET --namespace NAMESPACE
calls.append(args)
path.write_text(json.dumps(calls))
if args[0] == 'run':
    cid = args[-1]
    if cid == 'podvm-model-init':
        if '--detach' not in args:
            print('MODEL_MOUNTS_OK')
            sys.exit('ctr: failed to delete task: Container not ready or stopped, impossible to delete')
        assert '--rm' not in args
        log = Path(args[args.index('--log-uri') + 1].removeprefix('file://'))
        with log.open('a') as output:
            output.write('MODEL_MOUNTS_OK\\n')
    elif args[args.index('--config') + 1].endswith('model-bad.json'):
        sys.exit('model mount helper mount failed')
elif args[:2] == ['tasks', 'rm']:
    attempts = sum(c == args for c in calls)
    if attempts <= 2 or os.environ['TEST_STUCK'] == '1':
        sys.exit('ctr: failed to delete task: Container not ready or stopped, impossible to delete')
    if args[-1] == 'podvm-model-init' and os.environ['TEST_INIT_EXIT'] != '0':
        # ctr tasks rm warns but returns zero for a nonzero task exit.
        print('task podvm-model-init exit with non-zero exit code ' + os.environ['TEST_INIT_EXIT'], file=sys.stderr)
elif args[:2] == ['tasks', 'exec']:
    print('MODEL_MOUNTS_OK')
''')
            (work / 'ctr').chmod(0o755)
            # Keep the bounded retry test fast without changing its limit.
            (work / 'sleep').write_text('#!/bin/sh\nexit 0\n')
            (work / 'sleep').chmod(0o755)
            # The two block transports reuse the workspace, and Kata's file
            # log driver appends. A prior init's output must not count again.
            (work / 'model-init.log').write_text('MODEL_MOUNTS_OK\n')
            script = work / 'lifecycle.sh'
            script.write_text(SCRIPT.read_text().replace('/work/', str(work) + '/'))
            result = subprocess.run(['sh', str(script)], text=True, capture_output=True,
                                    timeout=15, env={**os.environ, 'PATH': str(work) + ':' + os.environ['PATH'],
                                        'TEST_WORK': str(work), 'TEST_INIT_EXIT': str(init_exit),
                                        'TEST_STUCK': str(int(stuck))})
            calls = json.loads((work / 'calls.json').read_text())
            return result, calls

    def test_completed_init_waits_for_teardown_before_consumers(self):
        result, calls = self.run_lifecycle()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('MODEL_MOUNTS_OK'), 8)
        self.assertIn('MODEL_LIFECYCLE_OK', result.stdout)
        self.assertEqual(calls.count(['tasks', 'rm', 'podvm-model-init']), 3)
        removed = calls.index(['containers', 'rm', 'podvm-model-init'])
        consumer = next(i for i, c in enumerate(calls) if c[0] == 'run' and c[-1] == 'podvm-model-app')
        self.assertLess(removed, consumer)

    def test_nonzero_init_exit_rejects_lifecycle_even_with_success_output(self):
        result, calls = self.run_lifecycle(init_exit=42)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('non-zero exit code 42', result.stderr)
        self.assertNotIn('MODEL_LIFECYCLE_OK', result.stdout)
        self.assertFalse(any(c[0] == 'run' and c[-1] == 'podvm-model-app' for c in calls))

    def test_teardown_retry_is_bounded(self):
        result, calls = self.run_lifecycle(stuck=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Container not ready or stopped', result.stderr)
        self.assertEqual(calls.count(['tasks', 'rm', 'podvm-model-init']), 100)
        self.assertNotIn('MODEL_LIFECYCLE_OK', result.stdout)

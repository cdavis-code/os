"""Check the SDK invocation contract without starting privileged containers."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RunnerContract(unittest.TestCase):
    def test_sdk_uses_loopback_hostname_and_host_artifact_owner(self):
        # k5test uses socket.gethostname() as its KDC address. The guest only
        # has the base-image hosts file, not Docker's generated hosts entry.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / '.pnp-kerberos'
            shutil.copytree(ROOT, scripts, ignore=shutil.ignore_patterns('out', '__pycache__'))
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            binaries = root / 'bin'
            binaries.mkdir()
            commands = {
                'uname': '#!/bin/sh\ncase "$1" in -m) echo x86_64;; -s) echo Linux;; esac\n',
                'cosign': '#!/bin/sh\necho "{}"\n',
                'timeout': '#!/bin/sh\nshift\nexec "$@"\n',
                'docker': '''#!/usr/bin/env python3
import sys
args = sys.argv[1:]
if args[0] == 'run':
    if '--hostname' not in args or args[args.index('--hostname') + 1] != 'localhost':
        print('KDC hostname is absent from guest hosts file', file=sys.stderr)
        sys.exit(42)
    for name, value in [('HOST_UID', __import__('os').getuid()), ('HOST_GID', __import__('os').getgid())]:
        if name + '=' + str(value) not in args:
            print('Missing caller artifact ownership', file=sys.stderr)
            sys.exit(43)
''',
            }
            for name, content in commands.items():
                path = binaries / name
                path.write_text(content)
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ['PATH'], COSIGN=str(binaries / 'cosign'))
            result = subprocess.run(['bash', str(scripts / 'build.sh'), '--arch', 'x86_64', '--recipe', 'krb5.yaml', '--output', '.pnp-kerberos/out/x86_64', '--inputs-lock', str(scripts / 'tools.lock.json'), '--discover-inputs'], cwd=root, env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


class DiagnosticArtifacts(unittest.TestCase):
    def test_collector_keeps_test_logs_but_excludes_cache_and_private_keys(self):
        script = ROOT / 'collect-diagnostics.sh'
        self.assertTrue(script.exists(), 'diagnostic collector is missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, workspace = root / 'output', root / 'workspace'
            (output / 'cache').mkdir(parents=True)
            (output / 'cache' / 'private.rsa').write_text('never publish')
            (output / 'sdk-keys').mkdir()
            (output / 'sdk-keys' / 'vendor.pub').write_text('public vendor key')
            (workspace / 'src' / 'tests').mkdir(parents=True)
            (workspace / 'src' / 'tests' / 'testlog').write_text('synthetic KDC failure')
            (workspace / 'src' / 'tests' / 'test.keytab').write_text('never publish')
            (output / 'build.log').write_text('failed build')
            (output / 'sdk-apk-installed.txt').write_text('public SDK package inventory')
            subprocess.run(['bash', str(script), str(output), str(workspace)], check=True)
            published = output / 'publish'
            self.assertEqual((published / 'test-logs' / 'src' / 'tests' / 'testlog').read_text(), 'synthetic KDC failure')
            self.assertEqual((published / 'build.log').read_text(), 'failed build')
            self.assertEqual((published / 'sdk-apk-installed.txt').read_text(), 'public SDK package inventory')
            self.assertEqual((published / 'sdk-keys' / 'vendor.pub').read_text(), 'public vendor key')
            self.assertFalse((published / 'cache').exists())
            self.assertFalse(list(published.rglob('*.rsa')))
            self.assertFalse(list(published.rglob('*.keytab')))
            self.assertTrue(all(path.stat().st_mode & 0o004 for path in published.rglob('*') if path.is_file()))


if __name__ == '__main__':
    unittest.main()

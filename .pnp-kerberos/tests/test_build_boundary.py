"""Exercise the public-input gate before any package build can start."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PublicBuildBoundary(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.snapshot = self.root / "inputs.json"
        self.snapshot.write_text('{"packages":[]}\n')
        self.lock = {
            "schema_version": 1,
            "upstream_base": "c84b5e5b04c806831acca635e55479c38f741c78",
            "source": {
                "repository": "https://github.com/krb5/krb5.git",
                "commit": "f5bee90a501da6c351b3db46c1ae837b033a714c",
            },
            "sdk": "ghcr.io/wolfi-dev/sdk@sha256:5637faa2c4c4b402f392cf49dcbc161a392a91a5cea69ce0edf0f998f2e88b59",
            "runner": "bubblewrap",
            "repositories": ["https://apk.cgr.dev/chainguard"],
            "captured_inputs": {
                "aarch64": {
                    "path": "inputs.json",
                    "sha256": hashlib.sha256(self.snapshot.read_bytes()).hexdigest(),
                }
            },
        }

    def run_gate(self, arch="aarch64", discovery=False):
        path = self.root / "lock.json"
        path.write_text(json.dumps(self.lock))
        command = [sys.executable, str(ROOT / "source_lock.py"), str(path), arch]
        if discovery:
            command.append("--discovery")
        return subprocess.run(command, text=True, capture_output=True, check=False)

    def test_captured_public_inputs_are_accepted(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("captured", result.stdout)

    def test_private_repository_is_refused(self):
        self.lock["repositories"].append("https://apk.cgr.dev/chainguard-private/")
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("REFUSED", result.stderr)

    def test_tool_without_an_immutable_digest_is_refused(self):
        self.lock["sdk"] = "ghcr.io/wolfi-dev/sdk:latest"
        self.assertEqual(self.run_gate().returncode, 1)

    def test_unsupported_architecture_is_refused(self):
        self.assertEqual(self.run_gate("ppc64le").returncode, 1)

    def test_missing_capture_cannot_be_an_accepted_rebuild(self):
        self.lock["captured_inputs"] = {}
        self.assertEqual(self.run_gate().returncode, 1)

    def test_explicit_discovery_is_labeled_ineligible(self):
        self.lock["captured_inputs"] = {}
        result = self.run_gate(discovery=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ineligible", result.stdout)

    def test_changed_input_snapshot_is_refused(self):
        self.snapshot.write_text('{"packages":["substituted"]}\n')
        self.assertEqual(self.run_gate().returncode, 1)

    def test_input_path_cannot_escape_the_capture_directory(self):
        self.lock["captured_inputs"]["aarch64"]["path"] = "../inputs.json"
        self.assertEqual(self.run_gate().returncode, 1)

    def test_qemu_cannot_restore_the_private_kernel_path(self):
        self.lock["runner"] = "qemu"
        self.assertEqual(self.run_gate().returncode, 1)


if __name__ == "__main__":
    unittest.main()

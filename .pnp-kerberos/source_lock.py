#!/usr/bin/env python3
"""Check pinned public build inputs before invoking the SDK (not package acceptance)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


PUBLIC_REPOSITORIES = {
    "https://apk.cgr.dev/chainguard",
    "https://packages.wolfi.dev/os",
}


def validate(lock, arch, root, discovery=False):
    if arch not in {"aarch64", "x86_64"}:
        raise ValueError("unsupported architecture")
    if lock.get("schema_version") != 1 or lock.get("runner") != "bubblewrap":
        raise ValueError("only the reviewed bubblewrap build boundary is supported")
    if not re.fullmatch(r"[a-f0-9]{40}", lock.get("upstream_base", "")):
        raise ValueError("missing exact upstream commit")
    source = lock.get("source", {})
    if source.get("repository") != "https://github.com/krb5/krb5.git" or not re.fullmatch(
            r"[a-f0-9]{40}", source.get("commit", "")):
        raise ValueError("missing pinned public Kerberos source")
    if not re.fullmatch(r"ghcr\.io/wolfi-dev/sdk@sha256:[a-f0-9]{64}", lock.get("sdk", "")):
        raise ValueError("SDK requires its exact public digest")
    repositories = lock.get("repositories")
    if not isinstance(repositories, list) or not repositories or any(
            url not in PUBLIC_REPOSITORIES for url in repositories):
        raise ValueError("unreviewed or private repository")
    capture = lock.get("captured_inputs", {}).get(arch)
    if capture is None and discovery:
        return {"sdk": lock["sdk"], "mode": "discovery: ineligible for acceptance"}
    if not isinstance(capture, dict):
        raise ValueError("accepted rebuild requires captured inputs for this architecture")
    path = Path(capture.get("path", ""))
    if not path.parts or path.is_absolute() or ".." in path.parts:
        raise ValueError("capture path must remain within the lock directory")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError("captured input snapshot is absent or escapes its directory")
    expected = capture.get("sha256", "")
    if not re.fullmatch(r"[a-f0-9]{64}", expected) or hashlib.sha256(
            resolved.read_bytes()).hexdigest() != expected:
        raise ValueError("captured input snapshot hash mismatch")
    return {"sdk": lock["sdk"], "mode": "captured input identity checked; full verification still required"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("arch")
    parser.add_argument("--discovery", action="store_true")
    args = parser.parse_args()
    try:
        result = validate(json.loads(args.lock.read_text()), args.arch, args.lock.parent, args.discovery)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

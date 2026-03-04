#!/usr/bin/env python3
"""Generate module_manifests.json for production mode.

Scans the modules directory, computes SHA-256 hashes for each .py file,
and writes a manifest file that bond_server.py uses for integrity verification.

Usage:
    python scripts/generate_manifests.py [--modules-dir modules] [--output modules/module_manifests.json]
"""

import argparse
import hashlib
import json
import os
import sys


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Generate Bond module manifests")
    parser.add_argument(
        "--modules-dir", default="modules",
        help="Path to modules directory (default: modules)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Output path (default: <modules-dir>/module_manifests.json)",
    )
    args = parser.parse_args()

    modules_dir = os.path.abspath(args.modules_dir)
    output = args.output or os.path.join(modules_dir, "module_manifests.json")

    if not os.path.isdir(modules_dir):
        print(f"Error: modules directory not found: {modules_dir}", file=sys.stderr)
        sys.exit(1)

    manifests = []
    for fname in sorted(os.listdir(modules_dir)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        fpath = os.path.join(modules_dir, fname)
        if not os.path.isfile(fpath):
            continue
        module_id = fname[:-3]  # strip .py
        sha = sha256_file(fpath)
        manifests.append({
            "module_id": module_id,
            "file_path": fname,
            "sha256_hash": sha,
            "allowed": True,
            "max_safety_level": "HIGH",
        })
        print(f"  {module_id}: {sha[:16]}...")

    result = {"manifests": manifests}
    with open(output, "w") as f:
        json.dump(result, f, indent=2)
        f.write("\n")

    print(f"\nWrote {len(manifests)} module manifest(s) to {output}")


if __name__ == "__main__":
    main()

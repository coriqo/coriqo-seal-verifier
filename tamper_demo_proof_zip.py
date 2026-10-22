#!/usr/bin/env python3
"""Live tamper demo for a Trust Repair proof zip.

    python tamper_demo_proof_zip.py coriqo_package_<id>_proof.zip

1. Verifies the zip as downloaded (expected: pass).
2. Makes a COPY, changes one character of snapshot.json, verifies the copy
   (expected: fail, the package no longer matches its signed seal).
3. Makes a second COPY, changes one character in a bundle event chain,
   verifies it (expected: fail, the bundle's file hash no longer matches).

The zip you pass in is only read. All edits happen in a temporary directory
that is deleted at the end. Needs Python 3 and the 'cryptography' package,
same as verify_proof.py. Exits 0 only if the original passed AND both
tampered copies failed.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

CMD = ["--bundle-dir", "bundle", "--snapshot", "snapshot.json", "--trust-repair"]


def _extract(zip_path: Path, dest: Path) -> None:
    dest.mkdir()
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if name.startswith("/") or ".." in Path(name).parts:
                raise SystemExit(f"refusing unsafe path in zip: {name}")
        zf.extractall(dest)


def _verify(folder: Path) -> int:
    proc = subprocess.run([sys.executable, "-I", str(folder / "verify_proof.py"), *CMD],
                          cwd=folder, capture_output=True, text=True)
    tail = [ln for ln in (proc.stdout + proc.stderr).strip().splitlines() if ln.strip()][-3:]
    print("    " + "\n    ".join(tail))
    return proc.returncode


def _flip(path: Path) -> None:
    data = bytearray(path.read_bytes())
    i = next((n for n, b in enumerate(data) if chr(b).isalpha()), 0)
    data[i] = ord("X") if data[i] != ord("X") else ord("Y")
    path.write_bytes(bytes(data))


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    src = Path(sys.argv[1]).resolve()
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        print("1. The proof zip as downloaded")
        _extract(src, root / "original")
        rc = _verify(root / "original")
        print(f"   exit {rc} (expected 0)")
        ok &= rc == 0

        print("2. A copy with one character of snapshot.json changed")
        _extract(src, root / "snap")
        _flip(root / "snap" / "snapshot.json")
        rc = _verify(root / "snap")
        print(f"   exit {rc} (expected non-zero)")
        ok &= rc != 0

        print("3. A copy with one character of a bundle event chain changed")
        _extract(src, root / "chain")
        events = sorted((root / "chain" / "bundle" / "events").glob("*.jsonl"))
        if not events:
            print("   no event chain in the bundle; cannot run this step")
            ok = False
        else:
            _flip(events[0])
            rc = _verify(root / "chain")
            print(f"   exit {rc} (expected non-zero)")
            ok &= rc != 0
    print("\nDEMO " + ("OK: the original verified and both edits were caught." if ok else "UNEXPECTED RESULT."))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

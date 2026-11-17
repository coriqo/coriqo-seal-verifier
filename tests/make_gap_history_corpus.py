"""Writes the six sealed-gap-history bundles in testdata/gap_history/ (SPEC.md section 8.5).

Signed with a throwaway Ed25519 key derived from a fixed phrase, so the files
are the same on every run and the key is public on purpose: nothing real is
signed with it. Every check other than the gap history passes in each bundle.

    python tests/make_gap_history_corpus.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_gap_history as gh  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "testdata" / "gap_history"
HOURS = {"max_open_gap_hours": 24}


def _use_fixed_key() -> None:
    gh._PRIV = ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"coriqo gap history test bundles: a public throwaway key").digest())
    gh._PEM = gh._PRIV.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def bundles() -> dict:
    _use_fixed_key()
    out = {"pass": gh.build(gh.good_events(), [gh.OPEN], policy=HOURS)}
    tampered = gh.build(gh.good_events(), [gh.OPEN], policy=HOURS)
    tampered["gap_events"][1]["reason"] = "x"
    out["tampered"] = tampered
    deleted = gh.build(gh.good_events(), [gh.OPEN], policy=HOURS)
    del deleted["gap_events"][0]
    out["deleted"] = deleted
    out["forged_closed"] = gh.build([gh.event("dev-1", 7, 8, "closed", "2026-11-17T07:00:00Z")], [])
    out["overage"] = gh.build(gh.good_events(), [gh.OPEN], policy={"max_open_gap_hours": 4})
    out["absent"] = gh.build([], [], with_block=False)
    return out


if __name__ == "__main__":
    for name, cert in bundles().items():
        (OUT / f"{name}.json").write_text(json.dumps(cert, indent=1) + "\n")
    print(f"wrote {len(bundles())} bundles to {OUT}")

"""
--bundle-dir's public head log check (SPEC.md §14.4): each of the tenant's
head-log entries that the signed head covers must carry an RFC 6962 inclusion
proof against that head; entries issued after the head are "not yet
checkable", never a pass.

Written against SPEC.md, not Coriqo's source — same "second implementation"
discipline as make_corpus.py. The log, the head and the proofs below are
built here from RFC 6962 §2.1's definitions (MTH and PATH), so a disagreement
with verify_proof.py is evidence one of the two misreads the spec.

The log has 7 entries from two tenants; the signed head covers the first 6.
Tenant A owns seq 1, 3, 5 (covered) and seq 6 (after the head). 6 and 7 are
not powers of two, so the RFC 6962 promotion rule is exercised.

Run:  python -m pytest tests/ -q
"""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof  # noqa: E402

TESTDATA = Path(__file__).resolve().parent.parent / "testdata"
FIXTURE = TESTDATA / "tenant_bundle"

HEAD_SEED = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
HEAD_KEY_ID = "head-log-test-key"
GENESIS = "0" * 64
TENANT_A = "tenant-a-opaque-id"
TENANT_B = "tenant-b-opaque-id"


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# RFC 6962 §2.1 -------------------------------------------------------------

def _mth(d: list[bytes]) -> bytes:
    if len(d) == 1:
        return _sha(b"\x00" + d[0])
    k = 1
    while k * 2 < len(d):
        k *= 2
    return _sha(b"\x01" + _mth(d[:k]) + _mth(d[k:]))


def _path(m: int, d: list[bytes]) -> list[bytes]:
    if len(d) == 1:
        return []
    k = 1
    while k * 2 < len(d):
        k *= 2
    if m < k:
        return _path(m, d[:k]) + [_mth(d[k:])]
    return _path(m - k, d[k:]) + [_mth(d[:k])]


# A 7-entry log, head over the first 6 -------------------------------------

def _build_log(checkpoint_ids_a: list[str] | None = None):
    owners = [TENANT_B, TENANT_A, TENANT_B, TENANT_A, TENANT_B, TENANT_A, TENANT_A]
    ids_a = list(checkpoint_ids_a or ["cp-a-1", "cp-a-3", "cp-a-5", "cp-a-6"])
    entries, prev = [], GENESIS
    for seq, owner in enumerate(owners):
        cid = ids_a.pop(0) if owner == TENANT_A else f"cp-b-{seq}"
        fields = {
            "seq": seq, "tenant_id": owner,
            "subject_hash": hashlib.sha256(b"org_default").hexdigest(),
            "checkpoint_id": cid, "sth_hash": hashlib.sha256(f"sth-{seq}".encode()).hexdigest(),
            "tree_size": seq + 3, "issued_at": f"2026-09-22T10:00:0{seq}+00:00",
            "prev_entry_hash": prev,
        }
        fields["entry_hash"] = hashlib.sha256(_canonical(fields)).hexdigest()
        prev = fields["entry_hash"]
        entries.append(fields)

    tree_size = 6
    leaves = [bytes.fromhex(e["entry_hash"]) for e in entries[:tree_size]]
    root = _mth(leaves).hex()
    key = Ed25519PrivateKey.from_private_bytes(HEAD_SEED)
    body = {"tree_size": tree_size, "root_hash": root, "tree_version": 2}
    head = {
        "tree_size": tree_size, "root_hash": root, "issued_at": "2026-09-22T11:00:00+00:00",
        "key_id": HEAD_KEY_ID, "signature_hex": key.sign(_canonical(body)).hex(),
        "rekor_uuid": None, "anchor_status": "pending",
    }
    tenant_entries = []
    for e in entries:
        if e["tenant_id"] != TENANT_A:
            continue
        e = dict(e)
        e["inclusion_proof"] = (
            {"leaf_index": e["seq"], "tree_size": tree_size,
             "proof_path": [h.hex() for h in _path(e["seq"], leaves)]}
            if e["seq"] < tree_size else None
        )
        tenant_entries.append(e)
    pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    return tenant_entries, head, pem


@pytest.fixture
def keyring(tmp_path) -> str:
    _, _, pem = _build_log()
    d = tmp_path / "head_keyring"
    d.mkdir()
    (d / f"{HEAD_KEY_ID}.pem").write_text(pem)
    return str(d)


def _by_seq(entries, seq):
    return next(e for e in entries if e["seq"] == seq)


# check_bundle_head_log -----------------------------------------------------

def test_valid_proofs_pass_and_the_entry_after_the_head_is_pending(keyring):
    entries, head, _ = _build_log()
    r = verify_proof.check_bundle_head_log(entries, head, keyring_path=keyring)
    assert r["failures"] == []
    assert r["sig_ok"] and "verifies" in r["sig_detail"]
    assert [e["seq"] for e in r["verified"]] == [1, 3, 5]
    assert [e["seq"] for e in r["pending"]] == [6]


def test_tampered_entry_field_fails_the_rehash():
    entries, head, _ = _build_log()
    _by_seq(entries, 3)["sth_hash"] = "f" * 64
    r = verify_proof.check_bundle_head_log(entries, head)
    assert [(cid, why) for cid, why in r["failures"]] == [
        ("cp-a-3", "entry fields do not re-hash to its entry_hash")]
    assert [e["seq"] for e in r["verified"]] == [1, 5]


def test_tampered_leaf_with_consistent_entry_hash_fails_the_proof():
    """A forger who edits a field AND recomputes entry_hash gets past the
    re-hash, but the leaf no longer matches what the signed root covers."""
    entries, head, _ = _build_log()
    e = _by_seq(entries, 1)
    e["sth_hash"] = "e" * 64
    e["entry_hash"] = verify_proof.head_log_entry_hash(e)
    r = verify_proof.check_bundle_head_log(entries, head)
    assert r["failures"] == [("cp-a-1", "inclusion proof does not reproduce the signed head's root_hash")]


def test_tampered_path_fails():
    entries, head, _ = _build_log()
    path = _by_seq(entries, 5)["inclusion_proof"]["proof_path"]
    path[0] = ("0" if path[0][0] != "0" else "1") + path[0][1:]
    r = verify_proof.check_bundle_head_log(entries, head)
    assert r["failures"] == [("cp-a-5", "inclusion proof does not reproduce the signed head's root_hash")]


def test_proof_claiming_a_different_leaf_index_fails():
    entries, head, _ = _build_log()
    _by_seq(entries, 3)["inclusion_proof"]["leaf_index"] = 2
    r = verify_proof.check_bundle_head_log(entries, head)
    assert len(r["failures"]) == 1
    cid, why = r["failures"][0]
    assert cid == "cp-a-3" and "not leaf 3 of 6" in why


def test_another_entrys_valid_proof_does_not_verify_this_entry():
    """Swap in seq 1's (valid) path, relabelled as seq 3's — the index is
    right on paper, but the path was built for a different leaf."""
    entries, head, _ = _build_log()
    _by_seq(entries, 3)["inclusion_proof"]["proof_path"] = list(
        _by_seq(entries, 1)["inclusion_proof"]["proof_path"])
    r = verify_proof.check_bundle_head_log(entries, head)
    assert r["failures"] == [("cp-a-3", "inclusion proof does not reproduce the signed head's root_hash")]


def test_covered_entry_without_a_proof_fails():
    entries, head, _ = _build_log()
    _by_seq(entries, 5)["inclusion_proof"] = None
    r = verify_proof.check_bundle_head_log(entries, head)
    assert len(r["failures"]) == 1 and "no inclusion proof" in r["failures"][0][1]


def test_beyond_head_is_pending_even_with_a_proof_attached():
    """An entry at seq >= tree_size is never a pass, whatever it carries."""
    entries, head, _ = _build_log()
    _by_seq(entries, 6)["inclusion_proof"] = copy.deepcopy(_by_seq(entries, 5)["inclusion_proof"])
    r = verify_proof.check_bundle_head_log(entries, head)
    assert [e["seq"] for e in r["pending"]] == [6]
    assert 6 not in [e["seq"] for e in r["verified"]]
    assert r["failures"] == []


def test_forged_head_signature_fails_under_a_pinned_key(keyring):
    entries, head, _ = _build_log()
    head["signature_hex"] = "00" * 64
    r = verify_proof.check_bundle_head_log(entries, head, keyring_path=keyring)
    assert not r["sig_ok"] and "does NOT verify" in r["sig_detail"]


# --bundle-dir end to end ---------------------------------------------------

def _bundle_with_head_log(tmp_path, *, head_covers: bool = True) -> Path:
    dest = tmp_path / "bundle"
    shutil.copytree(FIXTURE, dest)
    on_disk = sorted(p.stem for p in (dest / "checkpoints").glob("*.json"))
    # Give tenant A's first entries the bundle's real checkpoint ids.
    ids = on_disk + [f"cp-a-extra-{i}" for i in range(4 - len(on_disk))]
    entries, head, _ = _build_log(ids)
    if not head_covers:
        entries = [dict(e, inclusion_proof=None) for e in entries]
        head = dict(head, tree_size=0)
    (dest / "head_log").mkdir()
    (dest / "head_log" / "entries.jsonl").write_text(
        "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries))
    (dest / "head_log" / "head.json").write_text(json.dumps(head))
    return dest


def test_bundle_dir_passes_public_log_agrees(tmp_path, capsys, keyring):
    bundle = _bundle_with_head_log(tmp_path)
    verify_proof.run_bundle_dir(str(bundle), keyring_path=keyring)
    out = capsys.readouterr().out
    assert "[PASS] public log agrees" in out
    assert "3 entries are included under the signed log head" in out
    assert "not yet checkable" in out and "cp-a-extra" in out.split("not yet checkable")[1]
    assert "[FAIL] public log agrees" not in out


def test_bundle_dir_all_after_head_is_not_checked_not_passed(tmp_path, capsys):
    bundle = _bundle_with_head_log(tmp_path, head_covers=False)
    verify_proof.run_bundle_dir(str(bundle))
    out = capsys.readouterr().out
    assert "not yet checkable" in out
    assert "public log agrees" not in out


def test_bundle_dir_checkpoint_missing_from_log_still_fails(tmp_path, capsys):
    bundle = _bundle_with_head_log(tmp_path)
    lines = (bundle / "head_log" / "entries.jsonl").read_text().splitlines()
    on_disk = sorted(p.stem for p in (bundle / "checkpoints").glob("*.json"))
    kept = [ln for ln in lines if json.loads(ln)["checkpoint_id"] not in on_disk]
    (bundle / "head_log" / "entries.jsonl").write_text("\n".join(kept) + "\n")
    rc = verify_proof.run_bundle_dir(str(bundle))
    out = capsys.readouterr().out
    assert "NOT IN PUBLIC LOG" in out
    assert rc != verify_proof.EXIT_OK


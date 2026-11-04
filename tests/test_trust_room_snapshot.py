"""--trust-room (DA-4b): a frozen Trust Room page, checked offline. A good file passes with the
organization's key and the witness key pinned; a changed page fails; a witness that is not pinned is
UNVERIFIED, never witnessed; a file with no checkpoint yet exits 2."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof  # noqa: E402

PAGE = {"detail": "aggregate", "period": {"days": 90}, "sections": ["agents"],
        "agents": [{"agent_id": "a1", "name": "Payments agent", "status": "active"}]}
SNAP_ID = "11111111-2222-3333-4444-555555555555"
WITNESS_ID = "witness-lindqvist-audit"


def _pem_pub(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _leaf(event_hash: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(event_hash)).digest()


def _access_row(seq, subject, fingerprint, prev="0" * 64):
    row = {"seq": seq, "subject_ref": subject, "actor_id": "u1", "actor_label": "alice", "actor_type": "human",
           "accessed_at": "2026-10-30T10:00:00+00:00", "access_kind": "export", "seal_reason": "trust_room_freeze",
           "record_count": 1, "query_fingerprint": fingerprint, "declared_purpose_id": None, "prev_hash": prev}
    row["event_hash"] = verify_proof.access_event_hash_of(row)
    return row


@pytest.fixture()
def world(tmp_path):
    org, witness = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    page_sha = verify_proof.trust_room_page_sha256(PAGE)
    other = _access_row(0, "tenant", None)
    mine = _access_row(0, f"trust_room_snapshot:{SNAP_ID}", page_sha)
    # Two leaves, mine is index 1: root = H(0x01 || leaf0 || leaf1), proof path = [leaf0].
    root = hashlib.sha256(b"\x01" + _leaf(other["event_hash"]) + _leaf(mine["event_hash"])).digest().hex()
    sth = {"subject": "org_default", "issued_at": "2026-10-30T11:00:00+00:00", "length": 0, "head_hash": "0" * 64,
           "merkle_root": "00" * 32, "tree_size": 0, "key_id": "org-key-1", "tree_version": 2,
           "access_log": {"ordinal_watermark": 2, "tree_size": 2, "merkle_root": root}}
    msg = verify_proof._canonical_bytes(sth)
    proof = {"checkpoint_id": "cp1", "event_id": "ev-mine", "leaf_tree": "access_log", "leaf_index": 1, "tree_size": 2,
             "merkle_root": root, "leaf_input": mine["event_hash"], "proof_path": [_leaf(other["event_hash"]).hex()],
             "access_event": {"event_id": "ev-mine", **{k: v for k, v in mine.items() if k != "event_hash"}},
             "checkpoint_signature": org.sign(msg).hex(), "key_id": "org-key-1", "public_key_pem": _pem_pub(org),
             "issued_at": sth["issued_at"], "subject": sth["subject"], "spec_version": "1.0", "sth_body": sth,
             "cosignatures": [{"witness_key_id": WITNESS_ID, "witness_label": "Lindqvist Audit",
                               "signature_hex": witness.sign(msg).hex(), "signed_at": "2026-10-30T12:00:00+00:00",
                               "witness_relationship": "independent", "revoked": False}]}
    bundle = {"kind": verify_proof.TRUST_ROOM_KIND, "spec_version": "1.0",
              "room": {"room_id": "r1", "name": "Sponsor bank Q4", "issued_to": "Sponsor Bank NA"},
              "snapshot": {"snapshot_id": SNAP_ID, "frozen_at": "2026-10-30T10:00:00+00:00", "frozen_by": "alice",
                           "page_sha256": page_sha, "page": PAGE, "access_event_id": "ev-mine",
                           "access_event_hash": mine["event_hash"], "subject_ref": f"trust_room_snapshot:{SNAP_ID}"},
              "proof": proof, "proof_pending": None}
    (tmp_path / "org.pem").write_text(_pem_pub(org))
    (tmp_path / "witness.pem").write_text(_pem_pub(witness))
    return bundle, tmp_path


def _run(bundle, tmp_path, *, witness=True, org=True, extra=None):
    f = tmp_path / "snap.json"
    f.write_text(json.dumps(bundle))
    return verify_proof.run_trust_room(
        str(f), str(tmp_path / "org.pem") if org else None, None, None,
        str(tmp_path / "witness.pem") if witness else None, extra)


def test_good_bundle_passes_with_the_witness_pinned(world, capsys):
    bundle, tmp = world
    assert _run(bundle, tmp) == verify_proof.EXIT_OK
    out = capsys.readouterr().out
    assert "TRUST ROOM PAGE: VERIFIED" in out and "page matches its sha256" in out
    # Pinned and valid, but independence is not established unless the reader says so.
    assert "INDEPENDENTLY WITNESSED" not in out


def test_independence_needs_the_reader_to_declare_it(world, capsys):
    bundle, tmp = world
    assert _run(bundle, tmp, extra=[WITNESS_ID]) == verify_proof.EXIT_OK
    assert "INDEPENDENTLY WITNESSED" in capsys.readouterr().out


def test_unpinned_witness_is_unverified_not_witnessed(world, capsys):
    bundle, tmp = world
    assert _run(bundle, tmp, witness=False) == verify_proof.EXIT_OK
    out = capsys.readouterr().out
    assert "UNVERIFIED" in out and "INDEPENDENTLY WITNESSED" not in out and "SELF-WITNESSED" not in out


def test_changed_page_fails(world, capsys):
    bundle, tmp = world
    bundle = copy.deepcopy(bundle)
    bundle["snapshot"]["page"]["agents"][0]["status"] = "revoked"
    assert _run(bundle, tmp) == verify_proof.EXIT_TAMPER
    out = capsys.readouterr().out
    assert "[FAIL] page matches its sha256" in out and "FAILED" in out


def test_page_and_hash_changed_together_fails_on_the_sealed_read(world, capsys):
    bundle, tmp = world
    bundle = copy.deepcopy(bundle)
    bundle["snapshot"]["page"]["agents"][0]["status"] = "revoked"
    bundle["snapshot"]["page_sha256"] = verify_proof.trust_room_page_sha256(bundle["snapshot"]["page"])
    assert _run(bundle, tmp) == verify_proof.EXIT_TAMPER
    assert "[FAIL] sealed read carries this page's hash" in capsys.readouterr().out


def test_wrong_checkpoint_key_fails(world, capsys):
    bundle, tmp = world
    (tmp / "org.pem").write_text(_pem_pub(Ed25519PrivateKey.generate()))
    assert _run(bundle, tmp) == verify_proof.EXIT_TAMPER


def test_tampered_cosignature_fails_under_a_pinned_witness_key(world):
    bundle, tmp = world
    bundle = copy.deepcopy(bundle)
    sig = bundle["proof"]["cosignatures"][0]["signature_hex"]
    bundle["proof"]["cosignatures"][0]["signature_hex"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    assert _run(bundle, tmp) == verify_proof.EXIT_TAMPER


def test_no_checkpoint_yet_exits_unsealed(world, capsys):
    bundle, tmp = world
    bundle = copy.deepcopy(bundle)
    bundle["proof"], bundle["proof_pending"] = None, "No checkpoint covers this version yet."
    assert _run(bundle, tmp) == verify_proof.EXIT_UNSEALED
    assert "NOT YET SEALED" in capsys.readouterr().out


def test_other_file_kinds_are_malformed(tmp_path, capsys):
    f = tmp_path / "x.json"
    f.write_text(json.dumps({"kind": "something_else"}))
    assert verify_proof.run_trust_room(str(f)) == verify_proof.EXIT_MALFORMED
    f.write_text(json.dumps({"kind": verify_proof.TRUST_ROOM_KIND, "snapshot": {"page": "nope"}}))
    assert verify_proof.run_trust_room(str(f)) == verify_proof.EXIT_MALFORMED
    assert "MALFORMED" in capsys.readouterr().out


def test_cli_flag_runs_the_mode(world, monkeypatch):
    bundle, tmp = world
    f = tmp / "snap.json"
    f.write_text(json.dumps(bundle))
    monkeypatch.setattr(sys, "argv", ["verify_proof.py", "--trust-room", str(f), "--pubkey", str(tmp / "org.pem"),
                                      "--witness-pubkey", str(tmp / "witness.pem")])
    with pytest.raises(SystemExit) as e:
        verify_proof.main()
    assert e.value.code == 0

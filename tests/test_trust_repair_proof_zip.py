"""The single Trust Repair proof zip Coriqo exports: unzip it, run the
shipped verifier on it as an examiner would, then tamper with copies and expect a failure.

Run:  python -m pytest seal-verifier/tests/test_trust_repair_proof_zip.py -q
"""
from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(ROOT))
import make_tenant_bundle_fixture as mk  # noqa: E402
import verify_proof as vp  # noqa: E402
from api.domains.packages.proof_zip import PROOF_COMMAND, assemble_proof_zip  # noqa: E402

V = "ver-remediation"
FID = "finding-1"
KEY = Ed25519PrivateKey.from_private_bytes(mk.SEED)
PUB = KEY.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
WHEN = "2026-09-08T00:00:00+00:00"


def _events():
    specs = [
        ("finding_status_changed", {"finding_id": FID, "from": "open", "to": "in_remediation"}),
        ("finding_status_changed", {"finding_id": FID, "from": "in_remediation", "to": "resolved",
                                    "retest_execution_id": "run-9", "retest_result": "pass"}),
    ]
    rows, prev = [], "0" * 64
    for i, (action, notes) in enumerate(specs):
        r = {"event_id": f"ev{i}", "version_id": V, "ordinal": i + 1, "seq": i, "actor": "system",
             "actor_type": "system", "action": action, "from_status": "approved", "to_status": "approved",
             "notes": json.dumps(notes, sort_keys=True, separators=(",", ":")), "prev_hash": prev,
             "content_hash_verifiable": True, "oversight": None, "created_at": WHEN}
        r["event_hash"] = vp._event_hash_of(r)
        rows.append(r)
        prev = r["event_hash"]
    return rows


def _snapshot(rows) -> bytes:
    snap = {"remediation_status": {"articles": [{"number": 1, "finding_id": FID, "finding": {
        "status": "resolved", "occurrence_count": 1, "repeats": [],
        "retest": {"execution_id": "run-9", "result": "pass", "evidence_verified": True},
        "closure": {"basis": "retest_verified", "strength": "independent", "label": "x"},
        "sealed_steps": [{"to": "in_remediation", "ref": f"ev0:{rows[0]['event_hash']}"},
                         {"to": "resolved", "ref": f"ev1:{rows[1]['event_hash']}"}]}}]}}
    return mk.canonical_bytes(snap)


def _checkpoint(cp_id, subject, rows, attestation=None):
    root = mk.merkle_root([bytes.fromhex(r["event_hash"]) for r in rows])
    sth = {"subject": subject, "issued_at": WHEN, "length": len(rows), "head_hash": rows[-1]["event_hash"],
           "merkle_root": root, "tree_size": len(rows), "key_id": mk.KEY_ID, "ordering_version": 2,
           "ordinal_watermark": rows[-1]["ordinal"], "tree_version": 2}
    if attestation:
        sth["package_attestation"] = attestation
    sig = mk.sign(sth, KEY)
    cp = {"checkpoint_id": cp_id, "subject": subject, "issued_at": WHEN, "length": sth["length"],
          "head_hash": sth["head_hash"], "key_id": mk.KEY_ID, "signature_hex": sig, "trigger": "manual",
          "issued_by": "test", "created_at": WHEN, "merkle_root": root, "tree_size": sth["tree_size"],
          "version_id": None, "continuity": None, "cohort_rollup": None, "ordering_version": 2,
          "ordinal_watermark": sth["ordinal_watermark"], "reproducible": True, "tree_version": 2,
          "anchor_status": None, "rekor_uuid": None, "rekor_log_index": None, "anchored_at": None,
          "anchor_attempts": 0, "anchor_last_attempt_at": None, "cosign_status": "no_cosign",
          "cosignatures": [], "quarantine": None, "custom_field_values": {}}
    if attestation:
        cp["package_attestation"] = attestation
    cert = {"statement": {
        "certificate_version": "1.0", "subject": subject, "issued_at": WHEN,
        "period": {"from": WHEN, "to": WHEN},
        "checkpoint_window": {"from": WHEN, "to": WHEN, "requested_from": None, "requested_to": None},
        "checkpoint_count": 1,
        "checkpoints": [{"checkpoint_id": cp_id, "issued_at": WHEN, "length": sth["length"],
                         "head_hash": sth["head_hash"], "merkle_root": root, "tree_size": sth["tree_size"],
                         "key_id": mk.KEY_ID, "signature_hex": sig, "sth_body": sth}],
        "linkage": [], "linkage_unbroken": True, "linkage_status": "not_applicable", "links_proven": 0,
        "linkage_problems": [], "excluded_v1_checkpoints": [], "excluded_checkpoints": [],
        "coverage": {"sealed_event_count": sth["length"], "events_added_in_period": 0,
                     "obligations_in_period": {}, "obligations_closing": {}},
        "coverage_gaps": [], "gap_summary": {"total": 0, "normal_cadence": 0, "exceeds_policy": 0},
        "claim": "Single sealed checkpoint.", "succession": []},
        "signature_hex": None, "key_id": mk.KEY_ID,
        "public_keys": {mk.KEY_ID: {"pem": PUB, "revoked": False, "detail": None}},
        "cosignatures": {}, "anchors": {}}
    cert["signature_hex"] = mk.sign(cert["statement"], KEY)
    return cp, cert


def _bundle(rows, snapshot_bytes) -> bytes:
    att = {"package_id": "p1", "snapshot_sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
           "package_event_hash": "1" * 64, "approval_head_hash": "2" * 64}
    cp1, cert1 = _checkpoint("cp-org", "org_default", rows)
    cp2, cert2 = _checkpoint("cp-pkg", "package:p1", rows, att)
    files = {
        "checkpoints/cp-org.json": json.dumps(cp1), "checkpoints/cp-pkg.json": json.dumps(cp2),
        f"events/{V}.jsonl": "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows),
        "keys/keys.json": json.dumps({"keys": [{"key_id": mk.KEY_ID, "public_key_pem": PUB,
                                                "revoked": False, "detail": None}], "succession": []}),
        "audit_log.jsonl": "", "documents/manifest.json": "[]",
        "verify_proof.py": (ROOT / "seal-verifier" / "verify_proof.py").read_bytes(),
        "SPEC.md": (ROOT / "seal-verifier" / "SPEC.md").read_bytes(),
        "README.txt": "fixture",
    }
    files = {k: v.encode() if isinstance(v, str) else v for k, v in files.items()}
    manifest = {"format": "tenant_bundle_v1", "tenant": "t_test", "generated_at": WHEN,
                "subjects": ["org_default", "package:p1"],
                "counts": {"checkpoints": 2, "events": len(rows), "keys": 1, "audit_log_rows": 0,
                           "documents": 0, "events_not_content_verifiable_total": 0,
                           "events_not_content_verifiable_by_version": {}},
                "files": {k: mk.sha256_hex(v) for k, v in files.items()},
                "continuity_certificates": {"org_default": cert1, "package:p1": cert2},
                "uncertified_subjects": []}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        for k, v in files.items():
            zf.writestr(k, v)
    return buf.getvalue()


def _proof_zip() -> bytes:
    rows = _events()
    snap = _snapshot(rows)
    return assemble_proof_zip(
        package_id="p1", snapshot_bytes=snap, bundle_zip_bytes=_bundle(rows, snap),
        verifier_py=(ROOT / "seal-verifier" / "verify_proof.py").read_bytes(),
        spec_md=(ROOT / "seal-verifier" / "SPEC.md").read_bytes())


def _unzip(data: bytes, dest: Path) -> Path:
    dest.mkdir()
    zipfile.ZipFile(io.BytesIO(data)).extractall(dest)
    return dest


def _run(folder: Path):
    args = PROOF_COMMAND.split()[2:]
    return subprocess.run([sys.executable, "-I", "verify_proof.py", *args], cwd=folder,
                          capture_output=True, text=True)


def test_zip_has_the_promised_files():
    z = zipfile.ZipFile(io.BytesIO(_proof_zip()))
    assert {"snapshot.json", "verify_proof.py", "SPEC.md", "README.txt", "bundle/manifest.json"} <= set(z.namelist())
    assert PROOF_COMMAND in z.read("README.txt").decode()


def test_unzipped_proof_verifies_with_the_shipped_verifier(tmp_path):
    proc = _run(_unzip(_proof_zip(), tmp_path / "ok"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "TRUST REPAIR CLAIMS: VERIFIED" in proc.stdout


def test_tampered_snapshot_fails(tmp_path):
    folder = _unzip(_proof_zip(), tmp_path / "t1")
    p = folder / "snapshot.json"
    p.write_bytes(p.read_bytes().replace(b"retest_verified", b"management_signoff"))
    proc = _run(folder)
    assert proc.returncode != 0, proc.stdout


def test_tampered_event_chain_fails(tmp_path):
    folder = _unzip(_proof_zip(), tmp_path / "t2")
    p = folder / "bundle" / "events" / f"{V}.jsonl"
    text = p.read_text()
    assert "run-9" in text
    p.write_text(text.replace("run-9", "run-8", 1))
    proc = _run(folder)
    assert proc.returncode != 0, proc.stdout


def test_demo_script_catches_both_edits_and_leaves_the_original(tmp_path):
    z = tmp_path / "p.zip"
    z.write_bytes(_proof_zip())
    before = z.read_bytes()
    proc = subprocess.run([sys.executable, str(ROOT / "seal-verifier" / "tamper_demo_proof_zip.py"), str(z)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert z.read_bytes() == before

#!/usr/bin/env python3
"""
Regenerate the tenant record bundle fixture in ../testdata/tenant_bundle/
(SPEC.md §13, W1-D).

Written against SPEC.md rather than against Coriqo's source — same
"second implementation" discipline as make_corpus.py, so a disagreement
between this script and verify_proof.py's --bundle-dir mode is evidence the
spec is wrong or incomplete, not a bug this script quietly works around.

Two model-version chains, 5 and 13 events — deliberately non-power-of-two
counts (SPEC.md §11's reasoning applies here too: at a power-of-two size the
duplicating and RFC 6962 tree constructions can coincide and the fixture
would distinguish nothing) — sealed together under one org-wide checkpoint
whose 18-leaf tree spans both chains in ordinal order, and one continuity
certificate over that single checkpoint.

    python tests/make_tenant_bundle_fixture.py
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

TESTDATA = Path(__file__).resolve().parent.parent / "testdata"
OUT_DIR = TESTDATA / "tenant_bundle"

SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
KEY_ID = "test-key-2026"
GENESIS = "0" * 64
SUBJECT = "org_default"
TENANT_SLUG = "fixture_bank"

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- event chain, matching verify_proof.py's _event_hash_of ----------------

def build_chain(version_id: str, raw: list[dict], ordinal_start: int) -> list[dict]:
    chain = []
    prev = GENESIS
    for i, item in enumerate(raw):
        hashable = {
            "seq": i, "actor": item["actor"], "action": item["action"],
            "model_version_id": version_id, "from_status": item["from_status"],
            "to_status": item["to_status"], "notes": item.get("notes"),
            "prev_hash": prev,
        }
        event_hash = sha256_hex(canonical_bytes(hashable))
        chain.append({
            "event_id": f"{version_id}-ev{i}",
            "version_id": version_id,
            "ordinal": ordinal_start + i,
            "seq": i,
            "actor": item["actor"],
            "actor_type": "human",
            "action": item["action"],
            "from_status": item["from_status"],
            "to_status": item["to_status"],
            "notes": item.get("notes"),
            "prev_hash": prev,
            "event_hash": event_hash,
            "content_hash_verifiable": True,
            "oversight": None,
            "created_at": f"2026-0{1 + (ordinal_start + i) % 9}-01T00:00:00+00:00",
        })
        prev = event_hash
    return chain


# --- Merkle tree, RFC 6962 (tree_version 2), same construction as make_corpus.py ---

def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def build_levels(leaves: list[bytes]) -> list[list[bytes]]:
    if not leaves:
        return [[hashlib.sha256(b"").digest()]]
    current = [leaf_hash(d) for d in leaves]
    levels = [current]
    while len(current) > 1:
        nxt = [node_hash(current[i], current[i + 1]) for i in range(0, len(current) - 1, 2)]
        if len(current) % 2:
            nxt.append(current[-1])
        current = nxt
        levels.append(current)
    return levels


def merkle_root(leaves: list[bytes]) -> str:
    return build_levels(leaves)[-1][0].hex()


def sign(body: dict, key: Ed25519PrivateKey) -> str:
    return key.sign(canonical_bytes(body)).hex()


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "checkpoints").mkdir(exist_ok=True)
    (OUT_DIR / "events").mkdir(exist_ok=True)
    (OUT_DIR / "keys").mkdir(exist_ok=True)
    (OUT_DIR / "documents").mkdir(exist_ok=True)

    key = Ed25519PrivateKey.from_private_bytes(SEED)
    pub_pem = key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()

    alpha_raw = [
        {"actor": "alice", "action": "submit", "from_status": None, "to_status": "submitted", "notes": "initial submission"},
        {"actor": "alice", "action": "assign_reviewer", "from_status": "submitted", "to_status": "in_review", "notes": "assigned to bob"},
        {"actor": "bob", "action": "review", "from_status": "in_review", "to_status": "reviewed", "notes": "no findings"},
        {"actor": "carla", "action": "approve", "from_status": "reviewed", "to_status": "approved", "notes": "approved for production"},
        {"actor": "carla", "action": "publish", "from_status": "approved", "to_status": "published", "notes": None},
    ]
    beta_raw = [
        {"actor": "dan", "action": "submit", "from_status": None, "to_status": "submitted", "notes": f"submission {i}"}
        if i == 0 else
        {"actor": "dan", "action": "update", "from_status": "submitted", "to_status": "submitted", "notes": f"revision {i}"}
        for i in range(13)
    ]

    alpha = build_chain("fixture-version-alpha", alpha_raw, ordinal_start=0)
    beta = build_chain("fixture-version-beta", beta_raw, ordinal_start=len(alpha))
    all_events = alpha + beta  # ordinal order across the whole tenant
    assert len(all_events) == 18, "fixture must stay non-power-of-two (5 + 13 = 18)"

    # One row modelling a real production shape (found against a live
    # tenant, not hypothetical): a seeded/legacy event whose stored
    # event_hash was never produced by compute_governance_event_hash and so
    # cannot be re-derived, even though the row's own prev_hash chain
    # linkage is completely sound. `notes` is edited AFTER event_hash was
    # computed above specifically so recomputation would disagree — the
    # point is to prove the disclosed path (content_hash_verifiable=False,
    # chain linkage still checked) is exercised, not to compute a
    # "correct" legacy hash formula that does not exist here.
    beta[-1]["content_hash_verifiable"] = False
    beta[-1]["notes"] = "legacy seeded note — event_hash predates the current formula"

    leaves = [bytes.fromhex(e["event_hash"]) for e in all_events]
    root = merkle_root(leaves)

    checkpoint_id = "cp-fixture-0001"
    sth_body = {
        "subject": SUBJECT,
        "issued_at": "2026-09-08T00:00:00+00:00",
        "length": len(all_events),
        "head_hash": all_events[-1]["event_hash"],
        "merkle_root": root,
        "tree_size": len(all_events),
        "key_id": KEY_ID,
        "ordering_version": 2,
        "ordinal_watermark": all_events[-1]["ordinal"],
        "tree_version": 2,
    }
    signature_hex = sign(sth_body, key)

    checkpoint_file = {
        "checkpoint_id": checkpoint_id,
        "subject": SUBJECT,
        "issued_at": sth_body["issued_at"],
        "length": sth_body["length"],
        "head_hash": sth_body["head_hash"],
        "key_id": KEY_ID,
        "signature_hex": signature_hex,
        "trigger": "manual",
        "issued_by": "fixture-generator",
        "created_at": sth_body["issued_at"],
        "merkle_root": root,
        "tree_size": sth_body["tree_size"],
        "version_id": None,
        "continuity": None,
        "cohort_rollup": None,
        "ordering_version": 2,
        "ordinal_watermark": sth_body["ordinal_watermark"],
        "reproducible": True,
        "tree_version": 2,
        "anchor_status": None,
        "rekor_uuid": None,
        "rekor_log_index": None,
        "anchored_at": None,
        "anchor_attempts": 0,
        "anchor_last_attempt_at": None,
        "cosign_status": "no_cosign",
        "cosignatures": [],
        "quarantine": None,
        "custom_field_values": {},
    }

    certificate = {
        "statement": {
            "certificate_version": "1.0",
            "subject": SUBJECT,
            "issued_at": "2026-09-08T00:05:00+00:00",
            "period": {"from": alpha[0]["created_at"], "to": beta[-1]["created_at"]},
            "checkpoint_window": {
                "from": sth_body["issued_at"], "to": sth_body["issued_at"],
                "requested_from": None, "requested_to": None,
            },
            "checkpoint_count": 1,
            "checkpoints": [{
                "checkpoint_id": checkpoint_id,
                "issued_at": sth_body["issued_at"],
                "length": sth_body["length"],
                "head_hash": sth_body["head_hash"],
                "merkle_root": root,
                "tree_size": sth_body["tree_size"],
                "key_id": KEY_ID,
                "signature_hex": signature_hex,
                "sth_body": sth_body,
            }],
            "linkage": [],
            "linkage_unbroken": True,
            "linkage_status": "not_applicable",
            "links_proven": 0,
            "linkage_problems": [],
            "excluded_v1_checkpoints": [],
            "excluded_checkpoints": [],
            "coverage": {
                "sealed_event_count": sth_body["length"],
                "events_added_in_period": 0,
                "obligations_in_period": {},
                "obligations_closing": {},
            },
            "coverage_gaps": [],
            "gap_summary": {"total": 0, "normal_cadence": 0, "exceeds_policy": 0},
            "claim": (
                f"Single sealed checkpoint covering {sth_body['length']} events across "
                "two model versions — its contents are examiner-verifiable; a second "
                "checkpoint is needed before cross-seal linkage can be demonstrated."
            ),
            "succession": [],
        },
        "signature_hex": None,  # filled below
        "key_id": KEY_ID,
        "public_keys": {KEY_ID: {"pem": pub_pem, "revoked": False, "detail": None}},
        "cosignatures": {},
        "anchors": {},
        "_verify_with": "python verify_proof.py --bundle-dir .",
        "_how_it_works": "See SPEC.md §9 and §13.",
    }
    certificate["signature_hex"] = sign(certificate["statement"], key)

    # --- write files -----------------------------------------------------
    (OUT_DIR / "checkpoints" / f"{checkpoint_id}.json").write_text(
        json.dumps(checkpoint_file, indent=2), encoding="utf-8")

    for version_id, chain in (("fixture-version-alpha", alpha), ("fixture-version-beta", beta)):
        with open(OUT_DIR / "events" / f"{version_id}.jsonl", "w", encoding="utf-8") as fh:
            for ev in chain:
                fh.write(json.dumps(ev, separators=(",", ":")))
                fh.write("\n")

    keys_doc = {
        "keys": [{"key_id": KEY_ID, "public_key_pem": pub_pem, "revoked": False, "detail": None}],
        "succession": [],
    }
    (OUT_DIR / "keys" / "keys.json").write_text(json.dumps(keys_doc, indent=2), encoding="utf-8")

    with open(OUT_DIR / "audit_log.jsonl", "w", encoding="utf-8") as fh:
        for i, row in enumerate([
            {"log_id": f"log-{i}", "seq": i, "actor_id": "alice", "actor_type": "human",
             "action": "MODEL_SUBMITTED", "resource_type": "model_version",
             "resource_id": "fixture-version-alpha", "metadata": None,
             "user_agent": None, "request_id": None, "created_at": "2026-09-01T00:00:00+00:00"}
            for i in range(2)
        ]):
            fh.write(json.dumps(row, separators=(",", ":")))
            fh.write("\n")

    (OUT_DIR / "documents" / "manifest.json").write_text(json.dumps([], indent=2), encoding="utf-8")

    verify_proof_src = (TESTDATA.parent / "verify_proof.py").read_bytes()
    spec_src = (TESTDATA.parent / "SPEC.md").read_bytes()
    (OUT_DIR / "verify_proof.py").write_bytes(verify_proof_src)
    (OUT_DIR / "SPEC.md").write_bytes(spec_src)
    (OUT_DIR / "README.txt").write_text(
        "Fixture tenant record bundle — see seal-verifier/SPEC.md §13.\n"
        "Run: python verify_proof.py --bundle-dir .\n",
        encoding="utf-8",
    )

    files = {}
    for path in sorted(OUT_DIR.rglob("*")):
        if path.is_file():
            rel = path.relative_to(OUT_DIR).as_posix()
            if rel == "manifest.json":
                continue
            files[rel] = sha256_hex(path.read_bytes())

    manifest = {
        "format": "tenant_bundle_v1",
        "tenant": TENANT_SLUG,
        "generated_at": "2026-09-08T00:10:00+00:00",
        "subjects": [SUBJECT],
        "counts": {
            "checkpoints": 1, "events": len(all_events), "keys": 1,
            "audit_log_rows": 2, "documents": 0,
            "events_not_content_verifiable_total": 1,
            "events_not_content_verifiable_by_version": {"fixture-version-beta": 1},
        },
        "files": files,
        "continuity_certificates": {SUBJECT: certificate},
        "uncertified_subjects": [],
    }
    (OUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Wrote fixture bundle to {OUT_DIR}")


if __name__ == "__main__":
    main()

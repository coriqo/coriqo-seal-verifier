#!/usr/bin/env python3
"""
Regenerate the succession-binding tenant bundle fixture in
../testdata/succession_bundle/ (SPEC.md §9.3.5).

Unlike make_tenant_bundle_fixture.py (org_default, no key rotation), this
fixture carries ONE version-scoped chain — subject "version:<id>" — with a
genuine key rotation partway through: a real `key.succession` GovernanceEvent
appended into the chain (mirroring
the Coriqo server, and a
certificate whose `statement.succession` carries the matching signed record.
This is the shape §9.3.5's binding check needs to exercise at all — the
org_default fixture never has a succession record to bind.

7 events (deliberately non-power-of-two, same reasoning as
make_tenant_bundle_fixture.py / SPEC.md §11): 3 signed by the outgoing key,
a `key.succession` event recording the handoff, then 3 more signed
(chained, not re-sealed) under the incoming key's authority — the events
themselves are not signed individually; what changes across the rotation
is which key signs the CHECKPOINT that seals them.

    python tests/make_succession_bundle_fixture.py
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

TESTDATA = Path(__file__).resolve().parent.parent / "testdata"
OUT_DIR = TESTDATA / "succession_bundle"

OUTGOING_SEED = hashlib.sha256(b"m9a-outgoing-key-seed").digest()
INCOMING_SEED = hashlib.sha256(b"m9a-incoming-key-seed").digest()
OUTGOING_KEY_ID = "outgoing-key-2026"
INCOMING_KEY_ID = "incoming-key-2026"
GENESIS = "0" * 64
VERSION_ID = "fixture-version-succession"
SUBJECT = f"version:{VERSION_ID}"
TENANT_SLUG = "fixture_bank"
TENANT_SCHEMA = "t_fixture_bank"


def canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


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

    outgoing_key = Ed25519PrivateKey.from_private_bytes(OUTGOING_SEED)
    incoming_key = Ed25519PrivateKey.from_private_bytes(INCOMING_SEED)
    outgoing_pub_pem = outgoing_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    incoming_pub_pem = incoming_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

    raw = [
        {"actor": "alice", "action": "submit", "from_status": None, "to_status": "submitted", "notes": "initial submission"},
        {"actor": "alice", "action": "assign_reviewer", "from_status": "submitted", "to_status": "in_review", "notes": "assigned to bob"},
        {"actor": "bob", "action": "review", "from_status": "in_review", "to_status": "reviewed", "notes": "no findings"},
        # placeholder for the key.succession event — filled in below, needs
        # the real prior_event_hash, which only exists once the first three
        # events are chained.
        None,
        {"actor": "carla", "action": "approve", "from_status": "reviewed", "to_status": "approved", "notes": "approved for production"},
        {"actor": "carla", "action": "publish", "from_status": "approved", "to_status": "published", "notes": None},
        {"actor": "dan", "action": "annotate", "from_status": "published", "to_status": "published", "notes": "post-publish note"},
    ]

    chain = []
    prev = GENESIS
    effective_at = "2026-09-08T12:00:00+00:00"
    succession_body = None
    succession_signature = None
    for i, item in enumerate(raw):
        if item is None:
            succession_body = {
                "type": "key.succession",
                "tenant_schema": TENANT_SCHEMA,
                "outgoing_key_id": OUTGOING_KEY_ID,
                "incoming_key_id": INCOMING_KEY_ID,
                "effective_at": effective_at,
                "prior_event_hash": prev,
                "reason": "bank_held_custody",
            }
            succession_signature = sign(succession_body, outgoing_key)
            notes = json.dumps({**succession_body, "signature_hex": succession_signature},
                                sort_keys=True, separators=(",", ":"))
            hashable = {
                "seq": i, "actor": "signing_key_custody:confirmed_by:ops",
                "action": "key.succession", "model_version_id": VERSION_ID,
                "from_status": "", "to_status": "", "notes": notes, "prev_hash": prev,
            }
            event_hash = sha256_hex(canonical_bytes(hashable))
            chain.append({
                "event_id": f"{VERSION_ID}-ev{i}", "version_id": VERSION_ID,
                "ordinal": i, "seq": i,
                "actor": "signing_key_custody:confirmed_by:ops", "actor_type": "service",
                "action": "key.succession", "from_status": "", "to_status": "",
                "notes": notes, "prev_hash": prev, "event_hash": event_hash,
                "content_hash_verifiable": True, "oversight": None,
                "created_at": effective_at,
            })
            prev = event_hash
            continue
        hashable = {
            "seq": i, "actor": item["actor"], "action": item["action"],
            "model_version_id": VERSION_ID, "from_status": item["from_status"],
            "to_status": item["to_status"], "notes": item.get("notes"), "prev_hash": prev,
        }
        event_hash = sha256_hex(canonical_bytes(hashable))
        chain.append({
            "event_id": f"{VERSION_ID}-ev{i}", "version_id": VERSION_ID,
            "ordinal": i, "seq": i, "actor": item["actor"], "actor_type": "human",
            "action": item["action"], "from_status": item["from_status"],
            "to_status": item["to_status"], "notes": item.get("notes"),
            "prev_hash": prev, "event_hash": event_hash,
            "content_hash_verifiable": True, "oversight": None,
            "created_at": f"2026-09-0{1 + i}T00:00:00+00:00",
        })
        prev = event_hash

    assert len(chain) == 7, "fixture must stay non-power-of-two (7 events)"

    leaves = [bytes.fromhex(e["event_hash"]) for e in chain]
    root = merkle_root(leaves)

    checkpoint_id = "cp-succession-0001"
    sth_body = {
        "subject": SUBJECT,
        "issued_at": "2026-09-08T12:05:00+00:00",
        "length": len(chain),
        "head_hash": chain[-1]["event_hash"],
        "merkle_root": root,
        "tree_size": len(chain),
        "key_id": INCOMING_KEY_ID,
        "ordering_version": 2,
        "ordinal_watermark": chain[-1]["ordinal"],
        "tree_version": 2,
    }
    signature_hex = sign(sth_body, incoming_key)

    checkpoint_file = {
        "checkpoint_id": checkpoint_id, "subject": SUBJECT,
        "issued_at": sth_body["issued_at"], "length": sth_body["length"],
        "head_hash": sth_body["head_hash"], "key_id": INCOMING_KEY_ID,
        "signature_hex": signature_hex, "trigger": "manual",
        "issued_by": "fixture-generator", "created_at": sth_body["issued_at"],
        "merkle_root": root, "tree_size": sth_body["tree_size"], "version_id": VERSION_ID,
        "continuity": None, "cohort_rollup": None, "ordering_version": 2,
        "ordinal_watermark": sth_body["ordinal_watermark"], "reproducible": True,
        "tree_version": 2, "anchor_status": None, "rekor_uuid": None,
        "rekor_log_index": None, "anchored_at": None, "anchor_attempts": 0,
        "anchor_last_attempt_at": None, "cosign_status": "no_cosign", "cosignatures": [],
        "quarantine": None, "custom_field_values": {},
    }

    succession_record = {**succession_body, "signature_hex": succession_signature}

    certificate = {
        "statement": {
            "certificate_version": "1.0", "subject": SUBJECT,
            "issued_at": "2026-09-08T12:10:00+00:00",
            "period": {"from": chain[0]["created_at"], "to": chain[-1]["created_at"]},
            "checkpoint_window": {
                "from": sth_body["issued_at"], "to": sth_body["issued_at"],
                "requested_from": None, "requested_to": None,
            },
            "checkpoint_count": 1,
            "checkpoints": [{
                "checkpoint_id": checkpoint_id, "issued_at": sth_body["issued_at"],
                "length": sth_body["length"], "head_hash": sth_body["head_hash"],
                "merkle_root": root, "tree_size": sth_body["tree_size"],
                "key_id": INCOMING_KEY_ID, "signature_hex": signature_hex,
                "sth_body": sth_body,
            }],
            "linkage": [], "linkage_unbroken": True, "linkage_status": "not_applicable",
            "links_proven": 0, "linkage_problems": [], "excluded_v1_checkpoints": [],
            "excluded_checkpoints": [],
            "coverage": {
                "sealed_event_count": sth_body["length"], "events_added_in_period": 0,
                "obligations_in_period": {}, "obligations_closing": {},
            },
            "coverage_gaps": [],
            "gap_summary": {"total": 0, "normal_cadence": 0, "exceeds_policy": 0},
            "claim": (
                f"Single sealed checkpoint covering {sth_body['length']} events, "
                "signed under the incoming key after a bank-held custody rotation."
            ),
            # NOTE: a lone checkpoint means _check_certificate_succession's
            # transition-detection (which only fires between two DIFFERENT
            # checkpoint key_ids) has nothing to compare against a SINGLE
            # checkpoint's key_id — Rule 9.3.1 only fires across a certified
            # RANGE of checkpoints. §9.3.5's binding check does not depend
            # on that: it walks statement.succession directly regardless of
            # how many checkpoints are certified, which is exactly why a
            # single-checkpoint fixture (this one, deliberately simpler than
            # make_tenant_bundle_fixture.py's two-chain one) can still
            # exercise it.
            "succession": [succession_record],
        },
        "signature_hex": None,
        "key_id": INCOMING_KEY_ID,
        "public_keys": {
            OUTGOING_KEY_ID: {"pem": outgoing_pub_pem, "revoked": False, "detail": None},
            INCOMING_KEY_ID: {"pem": incoming_pub_pem, "revoked": False, "detail": None},
        },
        "cosignatures": {}, "anchors": {},
        "_verify_with": "python verify_proof.py --bundle-dir .",
        "_how_it_works": "See SPEC.md §9.3.5 and §13.",
    }
    certificate["signature_hex"] = sign(certificate["statement"], incoming_key)

    (OUT_DIR / "checkpoints" / f"{checkpoint_id}.json").write_text(
        json.dumps(checkpoint_file, indent=2), encoding="utf-8")

    with open(OUT_DIR / "events" / f"{VERSION_ID}.jsonl", "w", encoding="utf-8") as fh:
        for ev in chain:
            fh.write(json.dumps(ev, separators=(",", ":")))
            fh.write("\n")

    keys_doc = {
        "keys": [
            {"key_id": OUTGOING_KEY_ID, "public_key_pem": outgoing_pub_pem, "revoked": False, "detail": None},
            {"key_id": INCOMING_KEY_ID, "public_key_pem": incoming_pub_pem, "revoked": False, "detail": None},
        ],
        "succession": [succession_record],
        "revocations": [],
    }
    (OUT_DIR / "keys" / "keys.json").write_text(json.dumps(keys_doc, indent=2), encoding="utf-8")

    with open(OUT_DIR / "audit_log.jsonl", "w", encoding="utf-8") as fh:
        for i in range(2):
            fh.write(json.dumps({
                "log_id": f"log-{i}", "seq": i, "actor_id": "alice", "actor_type": "human",
                "action": "MODEL_SUBMITTED", "resource_type": "model_version",
                "resource_id": VERSION_ID, "metadata": None, "user_agent": None,
                "request_id": None, "created_at": "2026-09-01T00:00:00+00:00",
            }, separators=(",", ":")))
            fh.write("\n")

    (OUT_DIR / "documents" / "manifest.json").write_text(json.dumps([], indent=2), encoding="utf-8")

    verify_proof_src = (TESTDATA.parent / "verify_proof.py").read_bytes()
    spec_src = (TESTDATA.parent / "SPEC.md").read_bytes()
    (OUT_DIR / "verify_proof.py").write_bytes(verify_proof_src)
    (OUT_DIR / "SPEC.md").write_bytes(spec_src)
    (OUT_DIR / "README.txt").write_text(
        "Fixture tenant record bundle with a real key rotation — see "
        "seal-verifier/SPEC.md §9.3.5 and §13.\n"
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
        "generated_at": "2026-09-08T12:15:00+00:00",
        "subjects": [SUBJECT],
        "counts": {
            "checkpoints": 1, "events": len(chain), "keys": 2,
            "audit_log_rows": 2, "documents": 0,
            "events_not_content_verifiable_total": 0,
            "events_not_content_verifiable_by_version": {},
        },
        "files": files,
        "continuity_certificates": {SUBJECT: certificate},
        "uncertified_subjects": [],
    }
    (OUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Wrote fixture bundle to {OUT_DIR}")


if __name__ == "__main__":
    main()

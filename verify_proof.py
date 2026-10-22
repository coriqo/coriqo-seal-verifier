#!/usr/bin/env python3
"""
Coriqo V1.5 — Offline Attestation Verifier

Verifies Coriqo attestations using only mathematics. No network connection,
no Coriqo account, no Coriqo software, no trust in Coriqo as an institution.

Four modes:

  --proof        an inclusion proof — "was this governance event sealed?"
  --certificate  a Governance Continuity Certificate — "did governance ever
                 stop?" Proves unbroken linkage from checkpoint N to M,
                 reports the obligations covered, and renders every quiet
                 period with its recorded reason. Elapsed time on a
                 hash-linked chain cannot be faked, so this claim cannot be
                 issued retroactively.
  --bundle       a deliverables.zip from GET /api/v1/engagements/{id}/
                 deliverables.zip — a consultant-to-client handover bundle
                 whose manifest.json lists every file's sha256 and, when
                 sealed, is itself bound inside a signed certificate.json.
                 Checks the certificate the same way --certificate does,
                 then walks signature -> manifest hash -> each file's hash,
                 so tampering with a bundled file AND rewriting its sha256
                 in manifest.json still fails: the manifest's own bytes no
                 longer match what the certificate signed.
  INPUT          a single positional file, in place of any of the above
                 flags — this tool auto-detects what it is:
                   *.zip carrying manifest.json — a deliverables bundle;
                     routed to the SAME full check as --bundle. A zip's
                     certificate.json can verify perfectly while its payload
                     files were tampered with and its manifest rewritten to
                     match, so this case is never downgraded to the weaker
                     form below.
                   *.zip without manifest.json, or *.pdf — a certificate.json
                     or proof.json is extracted (from the zip's entries, or a
                     PDF attachment — the latter needs `pypdf`) and verified
                     on its own. The report states plainly that only the
                     extracted object was checked, not the rest of the file.
                   bare JSON — read directly; proof vs. certificate is told
                     apart by shape (a certificate has a top-level
                     "statement" object).
                 Mutually exclusive with --proof/--certificate/--bundle.

Usage
-----
    python tools/verify_proof.py --proof proof.json --pubkey pubkey.pem
    python tools/verify_proof.py --certificate certificate.json
    python tools/verify_proof.py --certificate certificate.json --keyring keys/
    python tools/verify_proof.py --certificate certificate.json --keyring keys.json
    python tools/verify_proof.py --proof proof.json --pubkey pubkey.pem \
        --witness-keyring witness_keys/ --independent-witness audit-firm-2026
    python tools/verify_proof.py --bundle deliverables.zip
    python tools/verify_proof.py --bundle deliverables.zip --pubkey pubkey.pem
    python tools/verify_proof.py deliverables.zip
    python tools/verify_proof.py certificate.json
    python tools/verify_proof.py "engagement package.pdf"

Where:
    proof.json   — the proof bundle downloaded from
                   GET /api/v1/checkpoints/{checkpoint_id}/proof/{event_id}
    pubkey.pem   — the Coriqo Ed25519 public key (published separately,
                   obtainable from GET /api/v1/checkpoints/public-key)
    certificate.json — the bundle from GET /api/v1/checkpoints/certificate.
                   Self-contained: it carries the public key for every
                   key_id it references, so no --pubkey is needed.
    --keyring    — pin MULTIPLE keys at once, one per key_id, instead of the
                   single unnamed key --pubkey pins. Every real chain today is
                   signed by exactly one key_id (coriqo-v1), so --pubkey covers
                   it; --keyring exists ahead of per-tenant signing keys and
                   key rotation, where a certificate can legitimately span more
                   than one key_id. Accepts either:
                     * a directory of "<key_id>.pem" files, one per key, or
                     * a single JSON file mapping key_id -> PEM text.
                   Entries from --keyring and --pubkey are merged; --pubkey's
                   key is used for any key_id --keyring does not name.
    --witness-keyring / --witness-pubkey
                   — the same pinning mechanism, applied to WITNESS keys
                   instead of signing keys. A witness cosignature is checked
                   ONLY against a key you supplied here. There is no fallback
                   to a key carried in the bundle, and this tool never fetches
                   a witness key from Coriqo — a cosignature checked against a
                   key Coriqo handed you at verify time witnesses nothing.
    --independent-witness KEY_ID
                   — repeatable. You assert that this witness key belongs to a
                   third party independent of the organisation whose chain
                   this is. Without it a verified cosignature is reported as
                   SELF-WITNESSED, never as independent: the bundle's own
                   label for a witness is unsigned data, and unsigned data is
                   not enough to upgrade the claim.

Exit codes
----------
--proof and --certificate:
    0  — PASS: all checks passed
    1  — FAIL: one or more checks failed

--bundle and INPUT (a wider table — a script checking $? can tell these apart
without parsing stdout; 1 keeps the same meaning it has in the other two
modes). INPUT uses this table even when it lands on the weaker
extract-and-verify path (a zip without manifest.json, a PDF, or bare JSON),
so exit-code handling never has to change depending on which mode found it:
    0  — PASS: for a deliverables bundle (--bundle, or INPUT routed there),
         the certificate verifies, it binds THIS manifest.json, and every
         present file matches its manifest sha256. For the weaker path, the
         extracted certificate/proof verified — see stdout for the scope
         disclaimer stating what was and was not checked.
    1  — TAMPER: a deliverables bundle's certificate signature/linkage
         failed, OR its manifest hash / a file hash did not match what was
         signed; or, on the weaker path, the extracted certificate/proof
         failed its own checks.
    2  — UNSEALED: a deliverables bundle carries no certificate.json —
         nothing to cryptographically verify (not a tamper finding; see
         manifest.json's own seal.status/seal.reason, printed by this tool)
    3  — MALFORMED: the input would not open or parse as the shape this tool
         expects for its mode — a zip that would not open, a missing/invalid
         manifest.json or certificate.json, JSON that will not parse, a PDF
         with no certificate/proof attachment, or a PDF input when `pypdf`
         is not installed

What is verified
----------------
    1. Merkle inclusion proof:
       leaf_hash = SHA-256(0x00 || bytes.fromhex(leaf_input))
       Walk proof_path under the construction the SIGNED body declares in
       tree_version (absent means 1):
         1 — sibling side by leaf_index parity, path length fixed by tree_size
         2 — RFC 6962 §2.1.1, which pins tree_size inside the walk itself
       Final hash must equal bytes.fromhex(merkle_root)

    2. Ed25519 checkpoint signature:
       The signature in checkpoint_signature must be valid over
       canonical_bytes(sth_body) using the provided public key.
       canonical_bytes = UTF-8 JSON with sorted keys, no extra whitespace.

Both checks are pure cryptography — they prove:
    "The governance event was part of a set of events that Coriqo attested
     to at the time the checkpoint was signed. Neither the event nor the
     set can have been altered after signing."

Key succession (certificate mode only)
------------------------------------------------------------
A certificate's checkpoints can change key_id partway through — a custody
transfer hands signing authority for one chain from one key to another. The
handoff is itself a signed statement: the OUTGOING key signs a record naming
the INCOMING key, so only the party that held the old key can nominate the
new one.

    * No key_id change across the certified range: nothing to check, and the
      report says so plainly.
    * A key_id change WITH a `statement.succession` record that names that
      exact outgoing/incoming key_id pair AND carries a valid Ed25519
      signature under the outgoing key: accepted — see SPEC.md §9.3.
    * A key_id change whose record is missing, names a different pair, or
      carries an absent/invalid signature: FAILS. An unexplained mid-range
      key change is treated as a broken continuity claim, not a benign
      detail, because a verifier that lets it pass silently could be shown a
      certificate stitched together from two unrelated signing keys — or one
      where a party holding only the NEW key appended itself to somebody
      else's sealed history — and call it one continuous chain.

Witness cosignatures (SPEC.md §9.4)
-----------------------------------
A checkpoint may carry cosignatures: independent Ed25519 signatures over the
exact bytes Coriqo's own signature covers. They answer a question the
checkpoint signature cannot — "could Coriqo have authored this history by
itself?" — because Coriqo does not hold the witness's private key.

Four states, reported separately and never collapsed into each other:

    (a) no cosignature in this bundle
    (b) SELF-WITNESSED — a cosignature verifies under a witness key YOU
        pinned, and you have not declared that witness independent
    (c) INDEPENDENTLY WITNESSED — as (b), and you passed
        --independent-witness for that key_id
    (d) UNVERIFIED — a cosignature is present but no key for it was pinned,
        or the bundle reports the witness key as revoked. Reported as
        UNVERIFIED: never as verified, and never as absent.

A cosignature that IS pinned and does not verify is a hard failure.

Two deliberate refusals, both of which make this tool less convenient:

    * The bundle carries no witness public key, and this tool would not use
      one if it did. Pinning is the entire mechanism. A witness key obtained
      from the party being witnessed is not a witness key.
    * "Independent" is never inferred from the bundle. The bundle's
      `witness_relationship` label is unsigned metadata produced by Coriqo;
      honouring it would let the party under scrutiny promote its own
      cosignature to an external audit. The label is shown, and it can only
      ever DOWNGRADE — a witness the bundle itself calls the tenant stays
      self-witnessed even if you declared it independent.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import zipfile
from datetime import timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Exit codes. `--proof` and `--certificate` keep the original 0/1 contract
# (see the module docstring's "Exit codes" section) — this file has shipped
# that contract to examiners already, and neither mode has a third outcome
# to report. `--bundle` has three distinct failure shapes an examiner needs
# to tell apart at a glance (a script checking $? gets this for free without
# parsing stdout), so it uses the wider table below. 1 keeps the same
# meaning it already has in the other two modes — a cryptographic/integrity
# failure — so a caller that just checks "exit code 0" never has to learn
# bundle mode exists.
# ---------------------------------------------------------------------------
EXIT_OK = 0
EXIT_TAMPER = 1        # signature invalid, or a hash link in the chain broke
EXIT_UNSEALED = 2       # no certificate.json — nothing to cryptographically verify
EXIT_MALFORMED = 3      # bundle/manifest/certificate isn't the shape this tool expects


# ---------------------------------------------------------------------------
# RFC 6962 Merkle primitives (copy of attestation/merkle.py — self-contained
# so examiners don't need to install the Coriqo package)
# ---------------------------------------------------------------------------

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


# The release this file belongs to. Each published release is a git tag of
# the same name with a SHA256SUMS file (README, "Check that you have the
# right copy"). Bump it whenever this file or SPEC.md changes.
VERIFIER_VERSION = "2026.10.22.1"

SUPPORTED_TREE_VERSIONS = (1, 2)

# SPEC.md §12.1. The version of SPEC.md this verifier implements. A bundle
# carries the version it was written to in its top-level `spec_version`
# ("MAJOR.MINOR"); absent means "1.0", every bundle issued before the field
# existed. A newer MINOR only adds fields this verifier ignores, so it is
# checked as normal. A different MAJOR may change what a field means, so the
# verifier refuses it rather than return a verdict it cannot stand behind.
SPEC_VERSION = "1.1"
SUPPORTED_SPEC_MAJOR = 1


def spec_version_problem(bundle) -> str | None:
    """None when this verifier can check `bundle`, else the reason it refuses."""
    if not isinstance(bundle, dict) or "spec_version" not in bundle:
        return None
    raw = bundle.get("spec_version")
    parts = raw.split(".") if isinstance(raw, str) else []
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        return (f"spec_version {raw!r} is not MAJOR.MINOR (for example \"1.0\"), "
                "so this verifier cannot tell which rules apply")
    if int(parts[0]) != SUPPORTED_SPEC_MAJOR:
        return (f"this file was written to spec version {raw}, and this verifier "
                f"(v{VERIFIER_VERSION}) implements spec version {SPEC_VERSION}. "
                f"A different major version can change what a field means, so it "
                f"is not checked. Get a verifier that supports spec {parts[0]}.x "
                f"from github.com/coriqo/coriqo-seal-verifier")
    return None


def _refuse_spec_version(bundle) -> bool:
    problem = spec_version_problem(bundle)
    if problem is None:
        return False
    print(f"UNSUPPORTED SPEC VERSION: {problem}.")
    return True


def _verify_inclusion_v1(
    leaf_input_hex: str,
    leaf_index: int,
    tree_size: int,
    proof_path_hex: list[str],
    expected_root_hex: str,
) -> bool:
    """
    Version-1 tree: odd levels pair the last node with itself (SPEC.md §5.2).

    Frozen. Every checkpoint sealed before tree_version 2 was signed against
    this shape and must keep verifying against it.
    """
    # The proof path must be exactly as deep as the declared tree. Without
    # this, tree_size is decorative: the walk below only compares a computed
    # root, so a path of any length that happens to reproduce the signed root
    # would pass while claiming a tree of a different size. The v1 tree
    # duplicates the last node on odd levels, which means a tree of n leaves
    # and one of n+1 leaves whose last leaf repeats share a root -- so the
    # declared size has to be checked, not assumed.
    #
    # This rule applies to v1 ONLY. Under RFC 6962 the path length varies by
    # index, so applying it to a v2 proof rejects honest records.
    expected_depth = 0 if tree_size == 1 else (tree_size - 1).bit_length()
    if len(proof_path_hex) != expected_depth:
        print(f"  [ERROR] proof_path has {len(proof_path_hex)} sibling(s); a v1 tree of "
              f"{tree_size} leaves requires exactly {expected_depth}")
        return False

    computed = _leaf_hash(bytes.fromhex(leaf_input_hex))
    idx = leaf_index

    for sibling_hex in proof_path_hex:
        sibling = bytes.fromhex(sibling_hex)
        if idx % 2 == 0:
            computed = _node_hash(computed, sibling)
        else:
            computed = _node_hash(sibling, computed)
        idx //= 2

    return computed == bytes.fromhex(expected_root_hex)


def _verify_inclusion_v2(
    leaf_input_hex: str,
    leaf_index: int,
    tree_size: int,
    proof_path_hex: list[str],
    expected_root_hex: str,
) -> bool:
    """
    Version-2 tree: RFC 6962 §2.1.1 inclusion-proof verification.

    tree_size is threaded through the walk (fn/sn) instead of being checked
    separately. sn must reach exactly 0 as the path is consumed: a path that is
    too short leaves sn != 0, and one that is too long trips sn == 0 mid-walk.
    So the declared size is verified by the algorithm itself, and no separate
    proof-depth rule is needed here -- nor would a fixed-depth rule be correct,
    because RFC 6962 audit-path length depends on the leaf's index as well as
    the tree size (a 5,161-leaf tree has valid lengths 4, 7, 8, 12 and 13).
    """
    fn = leaf_index
    sn = tree_size - 1
    r = _leaf_hash(bytes.fromhex(leaf_input_hex))

    for sibling_hex in proof_path_hex:
        if sn == 0:
            print(f"  [ERROR] proof_path is longer than a tree of {tree_size} "
                  f"leaves can produce")
            return False
        sibling = bytes.fromhex(sibling_hex)
        if (fn & 1) or fn == sn:
            r = _node_hash(sibling, r)
            if not (fn & 1):
                while fn and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node_hash(r, sibling)
        fn >>= 1
        sn >>= 1

    if sn != 0:
        print(f"  [ERROR] proof_path is shorter than a tree of {tree_size} "
              f"leaves requires")
        return False
    return r == bytes.fromhex(expected_root_hex)


def _rfc6962_root(leaf_hashes: list[bytes]) -> bytes:
    """
    Rebuild an RFC 6962 §2.1 Merkle root from already-hashed leaves (each
    element here is itself the leaf's pre-image, e.g. a head-log
    entry_hash — this function applies the leaf-hash prefix itself, exactly
    as the Coriqo server does).

    Used where the verifier holds every leaf of a tree (a checkpoint's
    exported events). The bundle's head log is NOT such a case: the signed
    head covers every tenant's entries and a bundle carries one tenant's, so
    check_bundle_head_log verifies per-entry inclusion proofs instead.
    """
    if not leaf_hashes:
        return hashlib.sha256(b"").digest()
    current = [_leaf_hash(d) for d in leaf_hashes]
    while len(current) > 1:
        nxt = [_node_hash(current[i], current[i + 1]) for i in range(0, len(current) - 1, 2)]
        if len(current) % 2:
            nxt.append(current[-1])
        current = nxt
    return current[0]


def verify_inclusion(
    leaf_input_hex: str,
    leaf_index: int,
    tree_size: int,
    proof_path_hex: list[str],
    expected_root_hex: str,
    tree_version: int = 1,
) -> bool:
    """
    Verify a Merkle inclusion proof under the declared tree construction.

    leaf_input_hex    — the event_hash hex (the raw bytes hashed into the leaf)
    leaf_index        — position of this leaf in the tree
    tree_size         — total number of leaves
    proof_path_hex    — ordered list of sibling hashes (hex), leaf → root
    expected_root_hex — the Merkle root hex from the checkpoint
    tree_version      — 1 = duplicate-last-node, 2 = RFC 6962 (SPEC.md §5.2).
                        The caller MUST source this from the SIGNED body; a
                        tree_version taken from an unsigned field would let a
                        forger pick whichever construction their hand-built
                        path satisfies.
    """
    if tree_size == 0 or leaf_index < 0 or leaf_index >= tree_size:
        return False
    if tree_version not in SUPPORTED_TREE_VERSIONS:
        print(f"  [ERROR] unknown tree_version {tree_version!r}; this verifier "
              f"implements {SUPPORTED_TREE_VERSIONS}")
        return False

    if tree_version == 2:
        return _verify_inclusion_v2(
            leaf_input_hex, leaf_index, tree_size, proof_path_hex, expected_root_hex)
    return _verify_inclusion_v1(
        leaf_input_hex, leaf_index, tree_size, proof_path_hex, expected_root_hex)


# ---------------------------------------------------------------------------
# Ed25519 signature verification (requires cryptography package)
# ---------------------------------------------------------------------------

def _canonical_bytes(obj: dict) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


ALGORITHM_ED25519 = "ed25519"
ALGORITHM_ES256 = "es256"
SUPPORTED_ALGORITHMS = (ALGORITHM_ED25519, ALGORITHM_ES256)


def verify_signature(
    sth_body: dict,
    signature_hex: str,
    public_key_pem: str,
    algorithm: str = ALGORITHM_ED25519,
) -> bool:
    """
    Verify that signature_hex is a valid signature over
    canonical_bytes(sth_body) using the given PEM public key.

    `algorithm` defaults to ed25519 — SPEC.md 6.1, where ed25519 is spelled by
    the ABSENCE of the field. A caller checking a CHECKPOINT signature must
    pass the value from that checkpoint's own signed body and nowhere else
    (Rule 6.1.1); reading it from an unsigned part of a bundle would let a
    forger select the verification path.

    The default is deliberately NOT "derive it from the key". This function is
    shared by paths that have no signed algorithm declaration of their own --
    witness cosignatures, revocation entries, the global head log -- and those
    are ed25519 by definition today. Deriving from the key would silently
    accept some other algorithm on those paths the moment such a key appeared,
    which is the confusion this field exists to prevent. When witness keys gain
    algorithm agility they must pass their own declared value explicitly.

    Rule 6.1.2: the declared algorithm and the key must AGREE. A mismatch is a
    failure, never a fallback to whatever the key happens to support.
    Rule 6.1.3: an unrecognised algorithm fails closed.
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.exceptions import InvalidSignature

        if algorithm not in SUPPORTED_ALGORITHMS:
            print(f"  [ERROR] Unrecognised signature algorithm {algorithm!r} — "
                  f"this verifier implements {list(SUPPORTED_ALGORITHMS)}. Failing "
                  "closed rather than skipping the signature check.")
            return False

        pub = load_pem_public_key(public_key_pem.encode())
        sig = bytes.fromhex(signature_hex)
        msg = _canonical_bytes(sth_body)

        if algorithm == ALGORITHM_ED25519:
            if not isinstance(pub, Ed25519PublicKey):
                print("  [ERROR] Signed body declares ed25519 (or omits the field, "
                      "which means ed25519) but the pinned public key is not an "
                      "Ed25519 key. Refusing to verify.")
                return False
            pub.verify(sig, msg)
        else:
            if not (isinstance(pub, ec.EllipticCurvePublicKey)
                    and isinstance(pub.curve, ec.SECP256R1)):
                print("  [ERROR] Signed body declares es256 but the pinned public "
                      "key is not an EC P-256 key. Refusing to verify.")
                return False
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception as exc:
        print(f"  [ERROR] Signature check failed with exception: {exc}")
        return False


# ---------------------------------------------------------------------------
# Global head log
# SPEC.md §14
# ---------------------------------------------------------------------------

def check_head_log_proof(
    data: dict,
    *,
    expect_head: str | None = None,
    pubkey_path: str | None = None,
    keyring_path: str | None = None,
) -> tuple[str, str]:
    """
    Verify one head-log entry + inclusion proof, as returned by
    GET /api/v1/public/head-log/entries/{sth_hash} (or the same shape saved
    to a file for --head-log-proof).

    Returns (verdict, detail) where verdict is one of:
      "PASS"        — entry is included under its signed log head, and (if a
                       key was available) the head's signature verifies.
      "FAIL"        — inclusion or signature check failed: this is either a
                       forged entry or a forged proof.
      "NOT CHECKED" — the data does not carry enough to check (no log_head /
                       inclusion_proof yet — SPEC.md §14 requires this be
                       reported distinctly from a pass, never silently as one).

    `expect_head` (the sth_hash a bank told an examiner about) is compared
    against the entry's own sth_hash — this is what lets an examiner confirm
    they were handed the SAME checkpoint the bank named, not a substitute.
    """
    entry = data.get("entry") if isinstance(data.get("entry"), dict) else data
    log_head = data.get("log_head")
    inclusion_proof = data.get("inclusion_proof")

    if expect_head is not None and entry.get("sth_hash") != expect_head:
        return "FAIL", (
            f"entry sth_hash {entry.get('sth_hash')!r} does not match "
            f"--expect-head {expect_head!r} — this is not the checkpoint "
            "the bank named"
        )

    if not log_head or not inclusion_proof:
        return "NOT CHECKED", (
            "entry exists but carries no signed log head / inclusion proof yet "
            "— the periodic head-log seal has not covered it. Not a pass or a "
            "fail."
        )

    proof_path = inclusion_proof.get("proof_path") or []
    ok = verify_inclusion(
        entry["entry_hash"], inclusion_proof["leaf_index"], inclusion_proof["tree_size"],
        proof_path, log_head["root_hash"], tree_version=2,
    )
    if not ok:
        return "FAIL", "inclusion proof does not verify against the signed log head's root_hash"

    pem = None
    if pubkey_path or keyring_path:
        try:
            pinned = _merge_pinned(pubkey_path, keyring_path)
            pem = pinned.get(log_head.get("key_id"))
        except ValueError:
            pem = None
    if pem is None:
        return "PASS", (
            "inclusion proof verifies against the signed log head's root_hash "
            "(head signature not checked — pass --pubkey/--keyring for "
            f"key_id {log_head.get('key_id')!r} to pin it)"
        )

    sig_body = {
        "tree_size": log_head["tree_size"], "root_hash": log_head["root_hash"],
        "tree_version": 2,
    }
    if not verify_signature(sig_body, log_head.get("signature_hex", ""), pem):
        return "FAIL", f"signed log head's own signature does not verify under key_id {log_head.get('key_id')!r}"

    return "PASS", "public log agrees: entry included under a signature-verified log head"


def head_log_entry_hash(entry: dict) -> str:
    """
    Recompute a head-log entry's entry_hash from its fields, exactly as the
    server does:
    sha256 over the canonical JSON of these eight fields. SPEC.md §14.1.
    """
    content = {k: entry.get(k) for k in (
        "seq", "tenant_id", "subject_hash", "checkpoint_id", "sth_hash",
        "tree_size", "issued_at", "prev_entry_hash",
    )}
    return hashlib.sha256(_canonical_bytes(content)).hexdigest()


def check_bundle_head_log(
    entries: list,
    head: dict,
    *,
    pubkey_path: str | None = None,
    keyring_path: str | None = None,
) -> dict:
    """
    SPEC.md §14.4: check a tenant bundle's head_log/entries.jsonl against its
    head_log/head.json.

    The signed head's root covers EVERY tenant's entries and the bundle holds
    only this tenant's, so the root cannot be rebuilt from the bundle. Each
    entry is checked on its own instead:

      - its fields re-hash to its entry_hash (a changed field is caught here);
      - if seq < head.tree_size, it carries an inclusion proof for leaf_index
        == seq and tree_size == head.tree_size, and that proof, walked from
        the RECOMPUTED entry_hash, reproduces head.root_hash (RFC 6962,
        tree_version 2 — the same verify_inclusion as --head-log-proof);
      - if seq >= head.tree_size, the head was signed before the entry
        existed: "pending", reported as not yet checkable, never a pass.

    The head's signature is checked when --pubkey/--keyring pins its key_id,
    as before.

    Returns {"verified": [entry...], "pending": [entry...],
             "failures": [(checkpoint_id, reason)...], "sig_ok": bool,
             "sig_detail": str}.
    """
    tree_size = head.get("tree_size")
    root_hex = head.get("root_hash") or ""
    verified, pending, failures = [], [], []

    for e in sorted(entries, key=lambda x: x.get("seq", -1)):
        cid = e.get("checkpoint_id")
        recomputed = head_log_entry_hash(e)
        if recomputed != e.get("entry_hash"):
            failures.append((cid, "entry fields do not re-hash to its entry_hash"))
            continue
        seq = e.get("seq")
        if not isinstance(seq, int) or not isinstance(tree_size, int):
            failures.append((cid, "seq or head tree_size is not an integer"))
            continue
        if seq >= tree_size:
            pending.append(e)
            continue
        proof = e.get("inclusion_proof")
        if not isinstance(proof, dict):
            failures.append((cid, f"no inclusion proof, but the signed head (tree_size "
                                  f"{tree_size}) covers seq {seq}"))
            continue
        if proof.get("leaf_index") != seq or proof.get("tree_size") != tree_size:
            failures.append((cid, f"inclusion proof is for leaf {proof.get('leaf_index')} of "
                                  f"{proof.get('tree_size')}, not leaf {seq} of {tree_size}"))
            continue
        try:
            ok = verify_inclusion(recomputed, seq, tree_size, proof.get("proof_path") or [],
                                  root_hex, tree_version=2)
        except (ValueError, TypeError):
            ok = False
        if not ok:
            failures.append((cid, "inclusion proof does not reproduce the signed head's root_hash"))
            continue
        verified.append(e)

    sig_ok = True
    sig_detail = "signature not checked (no --keyring/--pubkey for the log head's key_id)"
    if pubkey_path or keyring_path:
        try:
            pinned = _merge_pinned(pubkey_path, keyring_path)
            pem = pinned.get(head.get("key_id"))
        except ValueError:
            pem = None
        if pem:
            sig_body = {"tree_size": tree_size, "root_hash": head.get("root_hash"), "tree_version": 2}
            sig_ok = verify_signature(sig_body, head.get("signature_hex", ""), pem)
            sig_detail = "signed log head's signature verifies" if sig_ok else \
                f"signed log head's signature does NOT verify under key_id {head.get('key_id')!r}"

    return {"verified": verified, "pending": pending, "failures": failures,
            "sig_ok": sig_ok, "sig_detail": sig_detail}


def run_head_log_proof(path: str, expect_head: str | None, pubkey_path: str | None,
                        keyring_path: str | None) -> int:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        print(f"FAIL: {path} is not valid JSON: {exc}")
        return EXIT_MALFORMED

    print("=" * 60)
    print("Coriqo — Global Head Log Proof Verification")
    print("=" * 60)
    print()
    verdict, detail = check_head_log_proof(
        data, expect_head=expect_head, pubkey_path=pubkey_path, keyring_path=keyring_path,
    )
    print(f"  [{verdict}] {detail}")
    print()
    if verdict == "PASS":
        print("RESULT: PUBLIC LOG AGREES ✓")
        return EXIT_OK
    if verdict == "NOT CHECKED":
        print("RESULT: NOT CHECKED — no signed log head covers this entry yet")
        return EXIT_UNSEALED
    print("RESULT: NOT IN PUBLIC LOG ✗")
    return EXIT_TAMPER


# ---------------------------------------------------------------------------
# Public transparency-log anchor (Sigstore Rekor)
# ---------------------------------------------------------------------------

def _print_rekor_anchor(proof: dict) -> None:
    """
    Surface the checkpoint's Sigstore Rekor anchor, if present in the bundle.

    The anchor is INFORMATIONAL — it never affects PASS/FAIL above (those are
    pure offline cryptography). It tells the examiner where the signed tree
    head was published on Rekor, a public append-only transparency log that
    Coriqo does not control, so the checkpoint's existence can be confirmed
    independently of Coriqo. The online lookup is optional and offline-
    tolerant: if Rekor cannot be reached, manual instructions are printed
    instead of failing.
    """
    anchor = proof.get("anchor")
    print("-" * 60)
    print("Public transparency-log anchor (Sigstore Rekor)")
    print("-" * 60)
    if not anchor or not anchor.get("rekor_uuid"):
        status = (anchor or {}).get("status", "not anchored")
        print(f"  No Rekor anchor in this bundle (status: {status}).")
        print("  The offline cryptographic checks above stand on their own;")
        print("  anchoring additionally witnesses the checkpoint on a public")
        print("  log outside Coriqo's control.")
        print()
        return

    uuid = anchor["rekor_uuid"]
    rekor_url = (anchor.get("rekor_url") or "https://rekor.sigstore.dev").rstrip("/")
    print(f"  Anchor status : {anchor.get('status')}")
    print(f"  Rekor UUID    : {uuid}")
    if anchor.get("rekor_log_index") is not None:
        print(f"  Log index     : {anchor['rekor_log_index']}")
    external_time = anchor.get("anchored_at")
    if external_time:
        # This is Rekor's own integratedTime, carried into the bundle at
        # anchor time (the Coriqo server) — external to Coriqo's
        # app clock, which is the whole point of anchoring. It is REPORTED
        # here, not independently verified: this tool does not fetch or
        # check a Rekor inclusion/consistency proof against the value, so
        # a tampered bundle could claim a false one. SPEC.md §10 keeps the
        # PASS/FAIL verdict itself unaffected by this field either way.
        print(f"  External time : {external_time}  (reported by the bundle, not verified — see SPEC.md §10)")
    print(f"  Browse        : https://search.sigstore.dev/?uuid={uuid}")
    print()

    # Optional online confirmation — best-effort, never fails the run.
    entry_url = f"{rekor_url}/api/v1/log/entries/{uuid}"
    fetched = False
    try:
        import urllib.request
        with urllib.request.urlopen(entry_url, timeout=10) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
        entry = data.get(uuid, {})
        print("  [INFO] Rekor entry fetched — the checkpoint IS in the public log.")
        if entry.get("logIndex") is not None:
            print(f"         logIndex={entry['logIndex']} integratedTime={entry.get('integratedTime')}")
        fetched = True
    except Exception as exc:
        print(f"  [INFO] Could not reach Rekor ({type(exc).__name__}) — verify manually:")

    if not fetched:
        print()
        print("  Manual verification (any machine with internet access):")
        print(f"    1. Open https://search.sigstore.dev/?uuid={uuid}")
        print(f"       or: curl {entry_url}")
        print("    2. The entry is a hashedrekord whose artifact SHA-256 equals")
        print("       sha256(canonical_bytes(sth_body)) from this proof bundle,")
        print("       and whose signature/public key match checkpoint_signature")
        print("       and public_key_pem here.")
        print("    3. Rekor is append-only and operated by Sigstore, not Coriqo —")
        print("       a matching entry proves the checkpoint existed no later")
        print("       than its integratedTime and was not rewritten since.")
    print()


# ---------------------------------------------------------------------------
# Keyring loading — pin more than one key_id at once (--keyring)
#
# Every checkpoint sealed by Coriqo today carries key_id "coriqo-v1"; --pubkey
# alone is enough to pin it. This exists ahead of per-tenant signing keys,
# where a single certificate can legitimately reference more than one key_id
# and a single unnamed PEM has nothing to disambiguate against.
# ---------------------------------------------------------------------------

def _verify_tsa_offline(token_b64: str, sth_body: dict, tsa_ca_path: str | None) -> dict:
    """
    Self-contained RFC 3161 TSA token check for the offline verifier — no
    import of Coriqo code, no network. Parses the DER TimeStampResp, confirms its
    messageImprint equals SHA256(canonical sth_body), and checks the CMS
    signature. Reimplemented here (rather than importing
    the Coriqo server) because this script is meant to be runnable with
    only the stdlib plus the packages already imported at the top of this
    file (cryptography) — see the module docstring's "no Coriqo import"
    promise for --bundle-dir/--certificate. Requires pyasn1 + pyasn1_modules
    + rfc3161ng only when a bundle actually carries a tsa_token; a bundle
    with none never imports them.
    """
    import base64

    try:
        import rfc3161ng
        from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
        from pyasn1.type import univ as pyasn1_univ
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding
    except ImportError as exc:
        return {"available": False, "detail": f"rfc3161ng not installed ({exc}) — cannot parse TSA token"}

    try:
        token_der = base64.b64decode(token_b64)
        tsr, substrate = der_decoder.decode(token_der, asn1Spec=rfc3161ng.TimeStampResp())
        if substrate:
            return {"available": False, "detail": "extra data after TimeStampResp"}
        tst = tsr.getComponentByName("timeStampToken")
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "detail": f"could not parse TSA token: {exc}"}

    expected_hash = hashlib.sha256(_canonical_bytes(sth_body)).digest()

    signed_data = tst.getComponentByName("content")
    tstinfo_octets, _ = der_decoder.decode(
        bytes(signed_data["contentInfo"]["content"]), asn1Spec=pyasn1_univ.OctetString(),
    )
    tst_info, _ = der_decoder.decode(bytes(tstinfo_octets), asn1Spec=rfc3161ng.TSTInfo())
    imprint = tst_info.getComponentByName("messageImprint")
    imprint_matches = (
        imprint.getComponentByName("hashAlgorithm").getComponentByPosition(0) == rfc3161ng.id_sha256
        and bytes(imprint.getComponentByName("hashedMessage")) == expected_hash
    )
    gen_time_iso = None
    try:
        gen_time = rfc3161ng.get_timestamp(tst, naive=False)
        if gen_time.tzinfo is None:
            gen_time = gen_time.replace(tzinfo=timezone.utc)
        gen_time_iso = gen_time.astimezone(timezone.utc).isoformat()
    except Exception:  # noqa: BLE001
        pass

    # CMS signature. This is hand-rolled rather than rfc3161ng.check_timestamp because that
    # helper hard-codes RSA/PKCS1v15 and raises a bare TypeError against a
    # real EC-signed TSA response (observed against FreeTSA in practice).
    signature_verified = False
    sig_detail = "no signerInfo"
    ca_verified = None
    try:
        signer_info = signed_data["signerInfos"][0]
        cert_der = der_encoder.encode(signed_data["certificates"][0][0])
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        content = bytes(der_decoder.decode(
            bytes(signed_data["contentInfo"]["content"]), asn1Spec=pyasn1_univ.OctetString(),
        )[0])
        attrs = signer_info["authenticatedAttributes"]
        if len(attrs):
            s = pyasn1_univ.SetOf()
            for i, a in enumerate(attrs):
                s.setComponentByPosition(i, a)
            signed_bytes = der_encoder.encode(s)
        else:
            signed_bytes = content
        signature = bytes(signer_info["encryptedDigest"])
        digest_oid = signer_info["digestAlgorithm"]["algorithm"]
        signer_hash_name = rfc3161ng.oid_to_hash.get(digest_oid, "sha256")
        signer_hash = getattr(hashes, signer_hash_name.upper())()
        public_key = cert.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed_bytes, ec.ECDSA(signer_hash))
        else:
            public_key.verify(signature, signed_bytes, padding.PKCS1v15(), signer_hash)
        signature_verified = True
        sig_detail = ""

        if tsa_ca_path:
            with open(tsa_ca_path, "rb") as fh:
                ca_pem_bytes = fh.read()
            ca_certs = []
            for block in ca_pem_bytes.split(b"-----END CERTIFICATE-----"):
                if b"-----BEGIN CERTIFICATE-----" not in block:
                    continue
                ca_certs.append(x509.load_pem_x509_certificate(
                    block + b"-----END CERTIFICATE-----\n", default_backend()))
            ca_verified = False
            for ca in ca_certs:
                # Issuer name and signature, for RSA and EC CAs alike. A
                # self-hosted TSA (ops/tsa) has an EC P-256 root; a
                # PKCS1v15-only check reported every such token as unpinned.
                try:
                    cert.verify_directly_issued_by(ca)
                    ca_verified = True
                    break
                except Exception:  # noqa: BLE001
                    continue
    except InvalidSignature:
        sig_detail = "CMS signature does not verify"
    except Exception as exc:  # noqa: BLE001
        sig_detail = f"signature check failed: {exc}"

    return {
        "available": True,
        "imprint_matches": imprint_matches,
        "signature_verified": signature_verified,
        "ca_verified": ca_verified,
        "gen_time": gen_time_iso,
        "detail": sig_detail,
    }


def _print_tsa_timestamp(tsa_info: dict | None, sth_body: dict, tsa_ca_path: str | None) -> None:
    """
    Surface a checkpoint's RFC 3161 TSA timestamp, if present — the second
    external time source alongside Rekor (W2-D, SPEC.md §10.2). Same
    posture as _print_rekor_anchor: INFORMATIONAL, never affects PASS/FAIL.
    """
    print("-" * 60)
    print("RFC 3161 Time-Stamp Authority timestamp")
    print("-" * 60)
    if not tsa_info or not tsa_info.get("tsa_token"):
        status = (tsa_info or {}).get("status", "not configured")
        print(f"  No TSA timestamp in this bundle (status: {status}).")
        print("  The offline cryptographic checks above stand on their own;")
        print("  a TSA token additionally corroborates the checkpoint's age")
        print("  from a second party independent of Rekor and of Coriqo.")
        print()
        return

    result = _verify_tsa_offline(tsa_info["tsa_token"], sth_body, tsa_ca_path)
    if not result["available"]:
        print(f"  [WARN] Could not check TSA token: {result['detail']}")
        print()
        return

    print(f"  Message imprint matches sth_body : {'yes' if result['imprint_matches'] else 'NO — MISMATCH'}")
    print(f"  Token signature verifies         : {'yes' if result['signature_verified'] else 'NO'}")
    if tsa_ca_path:
        ca_word = "yes" if result["ca_verified"] else "NO — did not chain to --tsa-ca"
        print(f"  Signing cert chains to --tsa-ca  : {ca_word}")
    else:
        print("  TSA token present, CA not pinned — not verified (pass --tsa-ca <bundle> to check the chain)")
    if result["gen_time"]:
        print(f"  External time (TSA genTime)      : {result['gen_time']}  (reported, verified above if CA pinned — see SPEC.md §10.2)")
    print()


def _load_keyring(path: str, flag: str = "--keyring") -> dict[str, str]:
    """
    Load a keyring from either:
      * a directory containing "<key_id>.pem" files (one key per file, the
        filename stem is the key_id), or
      * a single JSON file mapping key_id -> PEM text.

    Raises ValueError with a message meant to be shown to the user, not a
    traceback, on anything malformed — a keyring the examiner cannot trust
    the shape of is worse than no keyring at all.
    """
    p = Path(path)
    if not p.exists():
        raise ValueError(f"{flag} path does not exist: {path}")

    if p.is_dir():
        keyring: dict[str, str] = {}
        pem_files = sorted(p.glob("*.pem"))
        if not pem_files:
            raise ValueError(f"{flag} directory {path} contains no *.pem files")
        for pem_file in pem_files:
            keyring[pem_file.stem] = pem_file.read_text()
        return keyring

    try:
        data = json.loads(p.read_text())
    except Exception as exc:
        raise ValueError(f"{flag} file {path} is not a directory and not valid JSON: {exc}")
    if not isinstance(data, dict) or not all(isinstance(v, str) for v in data.values()):
        raise ValueError(
            f"{flag} file {path} must be a JSON object mapping key_id -> PEM text"
        )
    return data


def _merge_pinned(pubkey_path: str | None, keyring_path: str | None,
                  pubkey_flag: str = "--pubkey",
                  keyring_flag: str = "--keyring") -> dict[str, str] | None:
    """
    Build the `pinned` dict both run() and run_certificate() key their
    signature checks against: {key_id: pem}, with the special key `None`
    meaning "pin every key_id to this one PEM" (what a bare --pubkey means
    when no --keyring narrows it to specific key_ids).

    Returns None when neither flag was passed — "no pinning, trust the
    bundle's own embedded keys" — which is a materially different, weaker
    trust posture and must stay distinguishable from an empty keyring.
    """
    if pubkey_path is None and keyring_path is None:
        return None
    pinned: dict[str, str] = {}
    if keyring_path is not None:
        pinned.update(_load_keyring(keyring_path, keyring_flag))
    if pubkey_path is not None:
        try:
            pem = Path(pubkey_path).read_text()
        except Exception as exc:
            raise ValueError(f"Cannot read {pubkey_flag} file {pubkey_path}: {exc}")
        # A bare --pubkey with no --keyring pins everything (today's single-key
        # world: key_id lookup falls back to the sole unnamed entry). Combined
        # with --keyring it fills in whichever key_id --keyring did not name,
        # rather than clobbering the keyring's own entries.
        if keyring_path is None:
            pinned[None] = pem
        else:
            pinned.setdefault(None, pem)
    return pinned


# ---------------------------------------------------------------------------
# Witness cosignatures (SPEC.md §9.4)
#
# A cosignature is an Ed25519 signature by a party OTHER than the signer, over
# byte-for-byte the same canonical_bytes(sth_body) the checkpoint signature
# covers. It is the only signature in a bundle that Coriqo could not have
# produced, which is exactly why every rule below is about refusing to let the
# bundle influence how it is judged:
#
#   * the witness public key comes from the operator, never from the bundle
#     and never from Coriqo at verify time (day_one_trust_spec.md I-1: the
#     record must be checkable with Coriqo uncooperative);
#   * "independent" comes from the operator, never from the bundle
#     (I-3: a self-witnessed chain must never present as externally
#     witnessed — it answers "can Coriqo forge my history", not "is Coriqo
#     independently audited");
#   * a cosignature that cannot be checked is reported as UNVERIFIED, which
#     is neither "verified" nor "absent".
#
# An earlier bug is the reason the pinned-and-invalid case is a hard
# failure rather than a warning: an unpinned fallback in --proof mode let a
# self-signed forgery report VERIFIED. There is no fallback here at all.
# ---------------------------------------------------------------------------

COSIGN_NONE = "none"
COSIGN_SELF = "self"
COSIGN_INDEPENDENT = "independent"
COSIGN_UNVERIFIED = "unverified"
COSIGN_INVALID = "invalid"

_COSIGN_HEADLINE = {
    COSIGN_NONE: "NO COSIGNATURE — this checkpoint carries only Coriqo's own signature",
    COSIGN_SELF: "SELF-WITNESSED — cosigned under a witness key you pinned",
    COSIGN_INDEPENDENT: "INDEPENDENTLY WITNESSED — cosigned by a third party you named",
    COSIGN_UNVERIFIED: "UNVERIFIED — a cosignature is present but you pinned no key for it",
    COSIGN_INVALID: "COSIGNATURE INVALID — a pinned witness key does not verify it",
}


def _resolve_witness_key(pinned: dict | None, witness_key_id) -> str | None:
    """
    The pinned PEM for a witness key_id, or None.

    Deliberately has no bundle-fallback branch. `_resolve_bundle_key` has one
    because a proof bundle legitimately carries the SIGNER's key and an
    unpinned run against it is a documented, weaker mode (SPEC.md §9.1). A
    witness key has no such mode: a witness key handed to you by the party
    being witnessed proves nothing, so "not pinned" can only mean "cannot be
    checked".
    """
    if pinned is None or witness_key_id is None:
        return None
    # A bare --witness-pubkey (the unnamed entry) covers every witness_key_id
    # --witness-keyring did not name, exactly as a bare --pubkey does for
    # signing keys. Read it as the assertion it is: "EVERY cosignature in this
    # bundle must verify under this key." On a bundle carrying a second
    # witness you did not expect, that assertion is false and the run fails --
    # which is the intended outcome, not a bug. Name the keys with
    # --witness-keyring when more than one witness is in play.
    return pinned.get(witness_key_id) or pinned.get(None)


def _evaluate_cosignatures(
    sth_body: dict,
    entries,
    pinned: dict | None,
    independent_ids: set,
) -> tuple[str, list[dict], list[str], list[str]]:
    """
    Judge every cosignature attached to one checkpoint.

    Returns (state, rows, failures, notes):
      state    — one of COSIGN_*, the headline for this checkpoint
      rows     — one dict per cosignature, for the printed report
      failures — non-empty means FAIL the run
      notes    — operator-facing warnings that are not failures
    """
    rows: list[dict] = []
    failures: list[str] = []
    notes: list[str] = []

    if entries is None or entries == []:
        return COSIGN_NONE, rows, failures, notes
    if not isinstance(entries, list):
        failures.append(
            "the bundle's `cosignatures` field is present but is not a list; "
            "refusing to guess at its shape")
        return COSIGN_INVALID, rows, failures, notes

    saw_invalid = False
    saw_self = False
    saw_independent = False

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            failures.append(f"cosignature {i} is not an object")
            saw_invalid = True
            continue

        witness_key_id = entry.get("witness_key_id")
        if not isinstance(witness_key_id, str) or not witness_key_id:
            # Refused rather than tolerated. Beyond the shape argument, an
            # unhashable value here (a dict, a list) would raise out of the
            # set/dict lookups below and turn a malformed bundle into a
            # traceback instead of a verdict.
            failures.append(
                f"cosignature {i} has no usable witness_key_id "
                f"({witness_key_id!r}); a cosignature nobody can name is a "
                "cosignature nobody can pin a key for")
            saw_invalid = True
            continue
        claimed = entry.get("witness_relationship")
        declared_independent = witness_key_id in independent_ids
        row = {
            "witness_key_id": witness_key_id,
            "label": entry.get("witness_label") or "",
            "signed_at": entry.get("signed_at"),
            "claimed": claimed,
            "declared_independent": declared_independent,
        }

        # A witness key the bundle itself reports as revoked cannot carry a
        # claim. Unlike SPEC.md rule 9.2.1 this does NOT fail the run: a
        # cosignature is additive, so revoking a witness must not retroactively
        # break every proof bundle ever issued under it. It is downgraded to
        # UNVERIFIED instead, which is the honest reading — the claim is gone,
        # the checkpoint is untouched. Note the asymmetry that makes this safe:
        # `revoked: true` is a downgrade and is honoured; the ABSENCE of the
        # flag is never read as proof that a key is live.
        if entry.get("revoked") is True:
            row["status"] = "revoked"
            row["detail"] = ("the bundle reports this witness key as revoked — the "
                             "cosignature does not count")
            rows.append(row)
            continue

        pem = _resolve_witness_key(pinned, witness_key_id)
        if not pem:
            row["status"] = "unpinned"
            row["detail"] = (
                "no public key for this witness was supplied via --witness-keyring / "
                "--witness-pubkey, so this cosignature CANNOT be checked")
            rows.append(row)
            continue

        # Same message the checkpoint signature covers, by construction.
        if not verify_signature(sth_body, entry.get("signature_hex") or "", pem):
            row["status"] = "invalid"
            row["detail"] = "COSIGNATURE INVALID under the witness key you pinned"
            rows.append(row)
            saw_invalid = True
            failures.append(
                f"witness {witness_key_id!r}: cosignature does not verify under the "
                "pinned witness key. Either the cosignature was altered, or the key "
                "you pinned is not this witness's — with more than one witness, name "
                "each key with --witness-keyring rather than covering them all with "
                "a bare --witness-pubkey")
            continue

        row["status"] = "verified"
        if claimed == "self":
            row["independence"] = COSIGN_SELF
            saw_self = True
            if declared_independent:
                notes.append(
                    f"witness {witness_key_id!r}: you declared this witness independent, "
                    "but the bundle labels it as the organisation itself. Reported as "
                    "SELF-WITNESSED — the weaker of the two claims. Find out which is "
                    "true before relying on either.")
            row["detail"] = "valid, and the bundle labels this witness the organisation itself"
        elif declared_independent:
            row["independence"] = COSIGN_INDEPENDENT
            saw_independent = True
            row["detail"] = ("valid under a key you pinned and declared independent of "
                             "the organisation")
        else:
            row["independence"] = COSIGN_SELF
            saw_self = True
            row["detail"] = (
                "valid, but independence is NOT established — pass "
                f"--independent-witness {witness_key_id} only if you know this key "
                "belongs to a third party")
        rows.append(row)

    if saw_invalid:
        state = COSIGN_INVALID
    elif saw_independent:
        state = COSIGN_INDEPENDENT
    elif saw_self:
        state = COSIGN_SELF
    else:
        state = COSIGN_UNVERIFIED
    return state, rows, failures, notes


def _print_cosign_section(blocks: list[tuple[str, str, list[dict], list[str]]],
                          pinned: dict | None) -> None:
    """
    Render the witness state for each checkpoint. `blocks` is
    (label, state, rows, notes) per checkpoint — a proof bundle passes one.

    Printed for every run, including the no-cosignature case: "nobody has
    cosigned this" is a real answer to a real question and must not be
    silence, the same way the anchor section prints when there is no anchor.
    """
    print("-" * 60)
    print("Witness cosignatures")
    print("-" * 60)
    for label, state, rows, notes in blocks:
        if label:
            print(f"  {label}")
        print(f"  {_COSIGN_HEADLINE[state]}")
        # The headline names the STRONGEST state established on this
        # checkpoint. With more than one witness that is a summary, so the
        # tally follows it -- otherwise a bundle with one independent witness
        # and three unpinnable ones would read as if all four were checked.
        if len(rows) > 1:
            tally: dict[str, int] = {}
            for row in rows:
                tally[row.get("status")] = tally.get(row.get("status"), 0) + 1
            print(f"  {len(rows)} cosignature(s): "
                  + ", ".join(f"{n} {k}" for k, n in sorted(tally.items())))
        for row in rows:
            wid = row.get("witness_key_id")
            name = f" ({row['label']})" if row.get("label") else ""
            print(f"    · {wid}{name}  [{row.get('status')}]")
            print(f"      {row.get('detail')}")
            print(f"      bundle label: witness_relationship={row.get('claimed')!r} "
                  f"(unsigned; never used to upgrade this verdict)"
                  + ("  signed_at=" + str(row["signed_at"]) if row.get("signed_at") else ""))
        for note in notes:
            print(f"    NOTE: {note}")
        print()
    if all(state == COSIGN_NONE for _label, state, _rows, _notes in blocks):
        # Nothing was cosigned, so nothing here is pending. Saying more --
        # least of all the word "unverified" -- would describe a control that
        # is not in play as one that failed.
        print("  Nothing to check. A cosignature is a second signature over the")
        print("  same bytes, made by someone who is not Coriqo; none was offered.")
        print()
        return
    if not pinned:
        # `not pinned` rather than `pinned is None`: an empty keyring (an
        # empty JSON manifest) pinned nothing, and telling the operator their
        # keys were used would be false.
        print("  No witness keys were pinned (--witness-keyring / --witness-pubkey).")
        print("  Any cosignature above is therefore UNVERIFIED. Get the witness's")
        print("  public key from the witness, not from Coriqo, and re-run.")
    else:
        print("  Cosignatures were checked ONLY against the witness keys you supplied.")
        print("  This tool never fetches a witness key from Coriqo at verify time.")
    print("  A cosignature says the witness saw these exact bytes. It does not")
    print("  make the checkpoint more or less valid — that rests on the checks")
    print("  below — and self-witnessing is not third-party audit.")
    print()


def _witness_pinning(witness_pubkey_path: str | None,
                     witness_keyring_path: str | None) -> tuple[dict | None, str | None]:
    """(pinned, error). A malformed witness keyring is an error, not an empty set."""
    if not (witness_pubkey_path or witness_keyring_path):
        return None, None
    try:
        return _merge_pinned(witness_pubkey_path, witness_keyring_path,
                             pubkey_flag="--witness-pubkey",
                             keyring_flag="--witness-keyring"), None
    except ValueError as exc:
        return None, str(exc)


# ---------------------------------------------------------------------------
# Passkey countersignatures (SPEC.md §9.5): `--countersign-keyring PATH`
#
# A person at the bank signed the checkpoint head with their passkey when
# they signed in. The WebAuthn challenge was
#   SHA-256("coriqo-countersign-v1" || "\n" || SHA-256(canonical(sth_body)) || nonce)
# so the assertion is a signature by a key Coriqo never held over this exact
# head. Mirror of the Coriqo server; the two must
# agree byte for byte.
#
# Coriqo stores the passkey public keys, so a key carried in the bundle proves
# only that the bundle is self-consistent. Pin the bank's own copy (the keyring
# it downloaded, or the fingerprints in its "a passkey was added" emails) with
# --countersign-keyring to count a countersignature as the bank's. Like witness
# cosignatures, this check never makes a checkpoint more or less valid; a
# countersignature that is present and does not verify is a hard failure.
# ---------------------------------------------------------------------------

_COUNTERSIGN_DOMAIN = b"coriqo-countersign-v1"
_COUNTERSIGN_KEYRING_PATH: str | None = None  # set from --countersign-keyring

COUNTER_NONE = "none"
COUNTER_PINNED = "pinned"
COUNTER_UNPINNED = "unpinned"
_COUNTER_HEADLINE = {
    COUNTER_NONE: "NO COUNTERSIGNATURE — nobody at the bank countersigned this checkpoint",
    COUNTER_PINNED: "BANK-COUNTERSIGNED — verified under a passkey key you pinned",
    COUNTER_UNPINNED: "COUNTERSIGNED, KEY NOT PINNED — consistent with the key in the bundle, "
                      "which came from Coriqo",
}


def _b64url_decode(value: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _spki_fingerprint(pem: str) -> str:
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_public_key(pem.encode())
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _load_countersign_keyring(path: str) -> dict[str, str]:
    """{fingerprint: PEM} from the JSON file Coriqo's Download keyring gives.
    Keys starting with '_' are notes, not keys. Each PEM must hash to the
    fingerprint it is filed under."""
    try:
        data = json.loads(Path(path).read_text())
    except Exception as exc:
        raise ValueError(f"--countersign-keyring {path} is not readable JSON: {exc}")
    if not isinstance(data, dict):
        raise ValueError(f"--countersign-keyring {path} must be a JSON object of fingerprint -> PEM")
    out: dict[str, str] = {}
    for fp, pem in data.items():
        if str(fp).startswith("_"):
            continue
        if not isinstance(pem, str):
            raise ValueError(f"--countersign-keyring entry {fp!r} is not PEM text")
        try:
            actual = _spki_fingerprint(pem)
        except Exception as exc:
            raise ValueError(f"--countersign-keyring entry {fp!r} is not a public key: {exc}")
        if actual != fp:
            raise ValueError(f"--countersign-keyring entry {fp!r} holds a key whose fingerprint is {actual}")
        out[fp] = pem
    return out


def verify_countersignature(entry: dict, sth_body: dict, public_key_pem: str) -> tuple[bool, str]:
    """(ok, reason) for one countersignature under one public key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    try:
        nonce = bytes.fromhex(entry["nonce"])
        auth_data = _b64url_decode(entry["authenticator_data"])
        client_json = _b64url_decode(entry["client_data_json"])
        signature = _b64url_decode(entry["signature"])
        rp_id = entry["rp_id"]
        algorithm = entry.get("algorithm") or "es256"
    except (KeyError, TypeError, ValueError) as exc:
        return False, f"malformed countersignature: {exc}"
    try:
        client = json.loads(client_json)
    except ValueError:
        return False, "clientDataJSON is not JSON"
    if not isinstance(client, dict):
        return False, "clientDataJSON is not a JSON object"
    if client.get("type") != "webauthn.get":
        return False, f"clientDataJSON type is {client.get('type')!r}, expected 'webauthn.get'"
    head = hashlib.sha256(_canonical_bytes(sth_body)).digest()
    expected = _b64url_encode(hashlib.sha256(_COUNTERSIGN_DOMAIN + b"\n" + head + nonce).digest())
    if client.get("challenge") != expected:
        return False, "the signed challenge is not this checkpoint's head"
    if len(auth_data) < 37:
        return False, "authenticator data is too short"
    if auth_data[:32] != hashlib.sha256(rp_id.encode()).digest():
        return False, f"authenticator data is not for {rp_id!r}"
    if not auth_data[32] & 0x01 or not auth_data[32] & 0x04:
        return False, "the person was not verified on the device (no fingerprint, face or PIN)"
    signed = auth_data + hashlib.sha256(client_json).digest()
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode())
        if algorithm == "es256" and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif algorithm == "ed25519" and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, signed)
        elif algorithm == "rs256" and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False, f"key type does not match algorithm {algorithm!r}"
    except InvalidSignature:
        return False, "signature does not verify under the passkey's public key"
    except ValueError as exc:
        return False, f"unreadable public key: {exc}"
    return True, "verifies"


def _evaluate_countersignatures(sth_body: dict, entries, keyring: dict | None):
    """(state, rows, failures, notes) for one checkpoint's countersignatures."""
    if entries is None or entries == []:
        return COUNTER_NONE, [], [], []
    if not isinstance(entries, list):
        return COUNTER_UNPINNED, [], ["the bundle's `countersignatures` field is not a list"], []
    rows, failures, notes = [], [], []
    pinned_ok = False
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            failures.append(f"countersignature {i} is not an object")
            continue
        fp = entry.get("key_fingerprint")
        signer = entry.get("signer") or "?"
        bundle_pem = entry.get("public_key_pem") or ""
        try:
            bundle_fp = _spki_fingerprint(bundle_pem)
        except Exception:
            failures.append(f"countersignature by {signer}: the key in the bundle is unreadable")
            continue
        if bundle_fp != fp:
            failures.append(f"countersignature by {signer}: key_fingerprint does not match the key in the bundle")
            continue
        if keyring and fp in keyring:
            ok, reason = verify_countersignature(entry, sth_body, keyring[fp])
            status = "BANK-COUNTERSIGNED" if ok else "FAILED"
            pinned_ok = pinned_ok or ok
        else:
            ok, reason = verify_countersignature(entry, sth_body, bundle_pem)
            status = "KEY NOT PINNED" if ok else "FAILED"
            if ok and keyring is not None:
                notes.append(f"{signer}'s key {fp[:23]}… is not in your keyring. If nobody at the bank "
                             "added a passkey after you saved it, ask who did.")
        if not ok:
            failures.append(f"countersignature by {signer}: {reason}")
        rows.append({"signer": signer, "fingerprint": fp, "status": status, "detail": reason,
                     "signed_at": entry.get("signed_at")})
    return (COUNTER_PINNED if pinned_ok else COUNTER_UNPINNED), rows, failures, notes


def _countersign_keyring() -> tuple[dict | None, str | None]:
    if not _COUNTERSIGN_KEYRING_PATH:
        return None, None
    try:
        return _load_countersign_keyring(_COUNTERSIGN_KEYRING_PATH), None
    except ValueError as exc:
        return None, str(exc)


def _print_countersign_section(blocks: list, keyring: dict | None) -> None:
    print("-" * 60)
    print("Bank countersignatures (passkeys)")
    print("-" * 60)
    for label, state, rows, notes in blocks:
        if label:
            print(f"  {label}")
        print(f"  {_COUNTER_HEADLINE[state]}")
        for row in rows:
            print(f"    · {row['signer']}  {row['fingerprint'][:23]}…  [{row['status']}]"
                  + (f"  signed_at={row['signed_at']}" if row.get("signed_at") else ""))
            if row["status"] == "FAILED":
                print(f"      {row['detail']}")
        for note in notes:
            print(f"    NOTE: {note}")
        print()
    if all(state == COUNTER_NONE for _l, state, _r, _n in blocks):
        print("  Nothing to check. Nobody at the bank signed these heads with a passkey.")
        print()
        return
    if keyring is None:
        print("  No --countersign-keyring given, so each countersignature was checked")
        print("  under the key carried in the bundle, which Coriqo supplied. Pass the")
        print("  bank's own keyring file to count them as the bank's.")
    print("  A countersignature says a person at the bank saw this exact head. It")
    print("  does not change the checkpoint's own verdict.")
    print()


def _check_countersignatures(blocks_in: list, results: list, keyring: dict | None,
                             keyring_error: str | None) -> list:
    """Shared by proof and certificate modes. `blocks_in` is [(label, sth, entries)]."""
    if keyring_error is not None:
        results.append(("bank countersignatures", False, keyring_error))
        return []
    blocks, failures, states = [], [], []
    for label, sth_body, entries in blocks_in:
        state, rows, cp_failures, notes = _evaluate_countersignatures(sth_body, entries, keyring)
        blocks.append((label, state, rows, notes))
        states.append(state)
        failures.extend((f"{label}: " if label else "") + f for f in cp_failures)
    if any(s != COUNTER_NONE for s in states):
        results.append(("bank countersignatures", not failures,
                        "; ".join(failures) if failures
                        else "; ".join(_COUNTER_HEADLINE[s] for s in states if s != COUNTER_NONE)[:400]))
    return blocks


# ---------------------------------------------------------------------------
# Main verifier
# ---------------------------------------------------------------------------

def _compliance_coverage_detail(obligations: dict, *, empty_note: str) -> tuple[str, int]:
    """
    Shared by the single-proof and certificate compliance-coverage checks so
    the two paths can't silently diverge in how they report the same
    covered/total/percentage arithmetic. Returns (detail_message, percentage).
    """
    if not obligations:
        return (empty_note, 0)
    # Bundle JSON is attacker-controlled — an obligation value that isn't a
    # real number (a string, a bool, a dict) must count as not-covered, not
    # raise. `isinstance(v, (int, float))` before comparing avoids a
    # TypeError from `v > 0` on a non-numeric truthy value.
    covered = sum(
        1 for v in obligations.values()
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0
    )
    total = len(obligations)
    percentage = (covered * 100) // total if total > 0 else 0
    detail = (
        f"{covered}/{total} obligation types covered ({percentage}%): "
        f"{', '.join(f'{k}={v}' for k, v in sorted(obligations.items()))}"
    )
    return (detail, percentage)


def _check_timestamp_consistency(proof: dict, sth: dict) -> tuple[str, bool, str]:
    """
    Verify that the proof bundle's top-level (unsigned) issued_at agrees with
    the signed body's issued_at. A missing sth_ts is itself a failure, not a
    free pass — an unsigned/absent timestamp on the signed body means there
    is nothing to authenticate the proof bundle's own issued_at claim
    against, and the top-level field can be freely rewritten post-signing
    without invalidating the Ed25519 signature.
    """
    proof_ts = proof.get("issued_at")
    sth_ts = sth.get("issued_at")
    if not sth_ts:
        return (
            "Timestamp consistency",
            False,
            "signed checkpoint body is missing issued_at — cannot verify "
            "timestamp consistency",
        )
    if proof_ts != sth_ts:
        return (
            "Timestamp consistency",
            False,
            f"proof bundle timestamp {proof_ts!r} does not match signed body "
            f"{sth_ts!r}",
        )
    return (
        "Timestamp consistency",
        True,
        f"checkpoint timestamp {sth_ts!r} is consistent with proof bundle",
    )


def run(proof_path: str | None, pubkey_path: str | None, keyring_path: str | None = None,
        witness_keyring_path: str | None = None,
        witness_pubkey_path: str | None = None,
        independent_witnesses: list[str] | None = None,
        proof_data: dict | None = None,
        tsa_ca_path: str | None = None) -> bool:
    """
    Load the proof bundle and public key, run all checks, print report.
    Returns True if all checks pass.

    witness_* pin the keys any COSIGNATURE in the bundle is checked against.
    They are a separate pinned set from pubkey_path/keyring_path on purpose:
    a witness key and a signing key answer different questions, and merging
    them would let a signing key Coriqo published stand in for a witness key
    it must not hold. See _evaluate_cosignatures.

    keyring_path, if given, is looked up by the proof's own key_id (see
    _load_keyring). It takes precedence over pubkey_path for that key_id;
    pubkey_path stays the escape hatch for the common single-key case and
    is used when the keyring does not name the proof's key_id.

    proof_data, when given, is used instead of reading/parsing proof_path —
    the caller (the positional-INPUT auto-detection path) has already
    resolved it out of a zip, PDF, or bare JSON file.
    """
    if proof_data is not None:
        proof = proof_data
    else:
        try:
            proof = json.loads(Path(proof_path).read_text())
        except Exception as exc:
            print(f"FAIL: Cannot load proof file: {exc}")
            return False

    if _refuse_spec_version(proof):
        return False

    print("=" * 60)
    print("Coriqo Merkle Inclusion Proof Verifier")
    print("=" * 60)
    print(f"  Checkpoint ID : {proof.get('checkpoint_id')}")
    print(f"  Event ID      : {proof.get('event_id')}")
    print(f"  Issued at     : {proof.get('issued_at')}")
    print(f"  Subject       : {proof.get('subject')}")
    print(f"  Spec version  : {proof.get('spec_version', '1.0 (not stated)')}")
    print(f"  Leaf index    : {proof.get('leaf_index')} of {proof.get('tree_size')} events")
    print()

    results: list[tuple[str, bool, str]] = []

    # ── Check 0: the proof must describe the checkpoint it is signed under ──
    # The signature covers sth_body and nothing else. Every top-level field
    # here is an unsigned restatement, so the Merkle check below must be
    # anchored to the signed body rather than to the bundle's own headline
    # values. Without this, a forger keeps a genuine sth_body and its genuine
    # signature, swaps in a merkle_root and proof_path for a tree they built
    # themselves, and both remaining checks pass while the bundle claims an
    # event was sealed that never was.
    sth = proof.get("sth_body") or {}
    # SPEC.md 4.5: which signed tree the leaf is proven against. Absent means
    # the governance-event tree (sth_body.merkle_root); "access_log" means the
    # sealed-read log (sth_body.access_log). The label is unsigned, which is
    # safe: both trees are signed, and an access leaf must also re-derive from
    # its own fields (Check 1b) before it counts.
    leaf_tree = proof.get("leaf_tree") or "governance_events"
    binding = []
    if leaf_tree == "access_log":
        signed_tree = sth.get("access_log")
        if signed_tree is None:
            signed_tree = {}
            binding.append("sth_body signs no access_log, so no sealed read can be proven under it")
        else:
            shape = access_log_shape_problem(signed_tree)
            if shape is not None:
                signed_tree = {}
                binding.append(f"sth_body.{shape}")
    elif leaf_tree == "governance_events":
        signed_tree = sth
    else:
        signed_tree = {}
        binding.append(f"unknown leaf_tree {leaf_tree!r}")
    if not binding:
        for field in ("merkle_root", "tree_size"):
            top, signed = proof.get(field), signed_tree.get(field)
            if signed is None:
                binding.append(f"sth_body is missing {field}")
            elif top != signed:
                binding.append(
                    f"{field} in the bundle ({top!r}) disagrees with the signed "
                    f"checkpoint body ({signed!r})")
    results.append((
        "proof fields match the signed checkpoint body",
        not binding,
        "; ".join(binding) if binding
        else "merkle_root and tree_size are the values the signature covers",
    ))

    # ── Check 1: Merkle inclusion proof ─────────────────────────────────
    # Root and size come from the SIGNED body when it carries them, so the
    # check below is against what Coriqo attested, not what the file asserts.
    # tree_version comes from the SIGNED body and nowhere else. Absent means 1
    # (every checkpoint sealed before the RFC 6962 construction). Reading it
    # from the bundle's top level would reintroduce exactly the defect Check 0
    # closes: an unsigned field steering how the signed root is interpreted.
    merkle_ok = not binding and verify_inclusion(
        leaf_input_hex=proof["leaf_input"],
        leaf_index=proof["leaf_index"],
        tree_size=signed_tree.get("tree_size", proof["tree_size"]),
        proof_path_hex=proof["proof_path"],
        expected_root_hex=signed_tree.get("merkle_root", proof["merkle_root"]),
        tree_version=sth.get("tree_version", 1),
    )
    results.append((
        "Merkle inclusion proof",
        merkle_ok,
        "event_hash is proven to be in the Merkle tree" if merkle_ok
        else "PROOF INVALID — event may not be in this checkpoint",
    ))

    # ── Check 1b: a sealed read re-derives from its own fields ───────────
    # SPEC.md 4.5. Required for an access_log proof: without it the bundle
    # proves a hash was sealed, not what read the hash stands for.
    if leaf_tree == "access_log":
        event = proof.get("access_event")
        if not isinstance(event, dict):
            content_ok, content_detail = False, "bundle carries no access_event to re-derive"
        else:
            content_ok = access_event_hash_of(event) == proof.get("leaf_input")
            content_detail = (
                f"{event.get('actor_label')} ({event.get('access_kind')}, "
                f"{event.get('seal_reason')}) on {event.get('subject_ref')} at "
                f"{event.get('accessed_at')}, {event.get('record_count')} record(s)"
                if content_ok else
                "access_event fields do not hash to leaf_input — the read described is not the one sealed"
            )
        results.append(("sealed read re-derives its hash", content_ok, content_detail))

    # ── Check 2: Ed25519 STH signature ──────────────────────────────────
    # Key resolution goes through the exact same pinned-set logic
    # run_certificate() uses (_merge_pinned / _resolve_bundle_key), so both
    # verification modes fail closed identically: if --keyring and/or
    # --pubkey were supplied and neither names this bundle's key_id, refuse
    # to fall back to the key embedded in the bundle rather than silently
    # trusting a self-supplied key. With no pinning requested at all (no
    # --keyring, no --pubkey), the bundle's own embedded key is used — the
    # legitimate unpinned-verification mode. See _resolve_bundle_key's
    # docstring for the reasoning.
    key_id = proof.get("key_id")
    pin_error = None
    pinned = None
    if pubkey_path or keyring_path:
        try:
            pinned = _merge_pinned(pubkey_path, keyring_path)
        except ValueError as exc:
            pin_error = str(exc)

    if pin_error is not None:
        results.append(("Ed25519 checkpoint signature", False, pin_error))
    else:
        # _resolve_bundle_key expects a {"public_keys": {key_id: {...}}}
        # shape (the certificate bundle's own layout); a proof bundle
        # carries a single embedded key at the top level instead, so it is
        # wrapped here to reuse the exact same resolution/refusal logic
        # rather than re-implementing it.
        fake_bundle = {
            "public_keys": {key_id: {"pem": proof.get("public_key_pem") or "", "revoked": False}}
        }
        pub_pem, _revoked, key_detail = _resolve_bundle_key(fake_bundle, key_id, pinned)

        if not pub_pem:
            results.append((
                "Ed25519 checkpoint signature",
                False,
                key_detail or "No public key available — provide --pubkey/--keyring or "
                "ensure the proof bundle contains public_key_pem",
            ))
        else:
            sig_ok = verify_signature(
                sth_body=proof["sth_body"],
                signature_hex=proof["checkpoint_signature"],
                public_key_pem=pub_pem,
                # Rule 6.1.1: from the signed body, nowhere else.
                algorithm=proof["sth_body"].get("algorithm", ALGORITHM_ED25519),
            )
            results.append((
                "Ed25519 checkpoint signature",
                sig_ok,
                f"STH signed by {proof.get('key_id')} — signature valid" if sig_ok
                else "SIGNATURE INVALID — checkpoint may have been tampered with",
            ))

    # ── Check 3: Timestamp backdating ───────────────────────────────────
    results.append(_check_timestamp_consistency(proof, sth))

    # ── Check 4: Compliance coverage ────────────────────────────────────
    # Calculate coverage percentage based on obligations in the checkpoint.
    # For a single proof, we report the obligations from the signed body.
    continuity = sth.get("continuity") or {}
    obligations = continuity.get("obligations") or {}
    coverage_detail, _percentage = _compliance_coverage_detail(
        obligations, empty_note="no obligations recorded in checkpoint",
    )
    results.append((
        "Compliance coverage percentage",
        True,  # Report coverage percentage; it's informational, not a pass/fail
        coverage_detail,
    ))
    # ── Check 5: witness cosignatures ───────────────────────────────────
    # Additive: a checkpoint with no cosignature is complete and this check
    # contributes nothing. A cosignature that IS present and IS pinned must
    # verify, or the run fails.
    witness_pinned, witness_pin_error = _witness_pinning(
        witness_pubkey_path, witness_keyring_path)
    independent_ids = set(independent_witnesses or ())
    if witness_pin_error is not None:
        cosign_state, cosign_rows, cosign_notes = COSIGN_UNVERIFIED, [], []
        results.append(("witness cosignatures", False, witness_pin_error))
    else:
        cosign_state, cosign_rows, cosign_failures, cosign_notes = _evaluate_cosignatures(
            sth, proof.get("cosignatures"), witness_pinned, independent_ids)
        if cosign_state != COSIGN_NONE:
            results.append((
                "witness cosignatures",
                not cosign_failures,
                "; ".join(cosign_failures) if cosign_failures
                else _COSIGN_HEADLINE[cosign_state],
            ))

    # ── Check 6: bank countersignatures (passkeys, SPEC.md §9.5) ─────────
    cs_keyring, cs_keyring_error = _countersign_keyring()
    counter_blocks = _check_countersignatures(
        [("", sth, proof.get("countersignatures"))], results, cs_keyring, cs_keyring_error)

    # ── Check 7: recorded tool calls against the sealed mandate (§19) ────
    # Additive: only a bundle that carries a mandate_check block has one.
    mandate = None
    if proof.get("mandate_check") is not None:
        try:
            mandate = check_mandate_calls(proof["mandate_check"], _merge_pinned(pubkey_path, keyring_path),
                                          outer=_outer_key(proof))
            failed = [f"{n}: {d}" for n, v, d in mandate["lines"] if v == TR_FAILED]
            results.append(("decisions and mandates in mandate_check", not failed,
                            "; ".join(failed) if failed else
                            "every sealed decision and mandate in the file is under a signed checkpoint"))
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            results.append(("decisions and mandates in mandate_check", False,
                            f"the mandate_check block is malformed ({type(exc).__name__}: {exc})"))

    # ── Print results ─────────────────────────────────────────────────────
    all_pass = all(r[1] for r in results)
    if mandate is not None:
        print_mandate_section(mandate)
    _print_rekor_anchor(proof)
    _print_tsa_timestamp(proof.get("tsa"), proof["sth_body"], tsa_ca_path)
    _print_cosign_section([("", cosign_state, cosign_rows, cosign_notes)], witness_pinned)
    if counter_blocks:
        _print_countersign_section(counter_blocks, cs_keyring)
    for name, passed, detail in results:
        tag = "PASS" if passed else "FAIL"
        print(f"  [{tag}] {name}")
        print(f"         {detail}")
        print()

    print("=" * 60)
    if all_pass:
        print("RESULT: VERIFIED ✓")
        print()
        print("  The " + ("sealed read" if leaf_tree == "access_log" else "governance event")
              + " is cryptographically proven to be part of")
        print(f"  checkpoint {proof.get('checkpoint_id')} issued at {proof.get('issued_at')}.")
        print("  This proof was verified without contacting Coriqo's servers.")
        # The banner is about the checkpoint. Say what the witness state is
        # too, so "VERIFIED" is never read as "independently witnessed".
        print(f"  Witness state: {_COSIGN_HEADLINE[cosign_state]}")
        if mandate is not None:
            print(f"  Mandate: {len(mandate['outside'])} of {mandate['calls']} recorded tool calls "
                  "fell outside the sealed mandate"
                  + ("" if mandate["complete"] else " (some decisions were not checked; see above)"))
    else:
        print("RESULT: VERIFICATION FAILED ✗")
        print()
        print("  One or more checks failed. The event may not be part of this")
        print("  checkpoint, or the checkpoint may have been tampered with.")
    print("=" * 60)

    return all_pass


# ---------------------------------------------------------------------------
# Governance Continuity Certificate verifier
# (verifiable_governance_strategy.md §2)
#
# An inclusion proof answers "was this event sealed?". A certificate answers
# "did governance ever stop?" — which is the claim a competitor cannot issue
# retroactively, because elapsed time on a hash-linked chain cannot be faked.
#
# Everything below is pure offline mathematics over the bundle's own bytes:
# no network, no Coriqo import, no keyring directory. The public key for
# every key_id referenced is carried inside the bundle, each flagged with its
# revocation state.
# ---------------------------------------------------------------------------

def _pem_fingerprint(pem: str) -> str:
    """SHA-256 over the PEM's base64 body — stable, and comparable by eye."""
    try:
        body = "".join(
            line.strip() for line in pem.splitlines() if not line.startswith("-----")
        )
        import base64
        return hashlib.sha256(base64.b64decode(body)).hexdigest()
    except Exception:
        return "unavailable"


def _print_key_trust(cert: dict, pinned: dict | None) -> None:
    """
    Show exactly which key each signature was checked against.

    The bundle carries its own public keys so it verifies with no network.
    That is what makes offline verification possible — but it also means the
    bundle alone proves internal consistency, not authorship: anyone can sign
    a fabricated statement with their own key and ship the matching PEM. The
    fingerprints below are what an examiner compares against Coriqo's
    published keyring (GET /api/v1/checkpoints/public-keys) to close that
    gap, or they can pin the key directly with --pubkey.
    """
    print("-" * 60)
    print("Signing keys used for verification")
    print("-" * 60)
    keys = cert.get("public_keys") or {}
    if not keys:
        print("  None in bundle — every signature check below will fail.")
        print()
        return
    any_pinned = False
    for key_id, entry in sorted(keys.items()):
        embedded_pem = (entry or {}).get("pem") or ""
        flag = " [REVOKED]" if (entry or {}).get("revoked") else ""
        # Report what _resolve_bundle_key actually did for THIS key_id, not
        # a single blanket flag for the whole report -- a key_id a partial
        # --keyring doesn't name is not pinned, even when other keys are.
        is_pinned = pinned is not None and (key_id in pinned or None in pinned)
        if is_pinned:
            any_pinned = True
            source = "pinned via --keyring" if key_id in pinned else "pinned via --pubkey"
            # Fingerprint the PEM that was actually used to verify (the
            # pinned one), not the bundle's own embedded copy -- otherwise
            # the fingerprint an examiner compares against Coriqo's
            # published keyring isn't the key that did the verifying.
            fingerprint_pem = pinned.get(key_id) or pinned.get(None) or embedded_pem
        else:
            source = "from bundle (unpinned)"
            fingerprint_pem = embedded_pem
        print(f"  {key_id}{flag}  ({source})")
        print(f"    sha256: {_pem_fingerprint(fingerprint_pem)}")
    print()
    if any_pinned:
        print("  Keys marked \"pinned\" above were checked against the PEM you supplied")
        print("  via --keyring/--pubkey, so a self-signed forgery under those key_ids")
        print("  cannot pass. Any key marked \"from bundle\" was NOT pinned and was")
        print("  checked only against its own embedded copy -- compare its fingerprint")
        print("  against the published keyring separately.")
    else:
        print("  NOTE: keys came from the bundle itself. The checks below prove the")
        print("  certificate is internally consistent and unaltered. To also prove it")
        print("  was issued by Coriqo, compare the fingerprint(s) above against the")
        print("  published keyring, or re-run with --pubkey <key.pem> to pin it.")
    print()


def _resolve_bundle_key(cert: dict, key_id: str, pinned: dict | None = None) -> tuple[str | None, bool, str]:
    """
    Resolve the public key for key_id.

    With --pubkey the supplied PEM(s) win outright: a bundle that names a key
    the examiner did not supply cannot be verified, which is what turns
    "internally consistent" into "issued by the holder of this key".
    """
    if pinned is not None:
        # Revocation still applies when a key is pinned. The bundle's revoked
        # flag is a claim by the issuer that this key must not be trusted;
        # supplying the PEM yourself says "this is the right key", not "ignore
        # the revocation". Dropping it here would make --pubkey a way to
        # silently launder a revoked attestation (key_management.md rule 4).
        bundle_revoked = bool(
            ((cert.get("public_keys") or {}).get(key_id) or {}).get("revoked")
        )
        if key_id in pinned:
            return pinned[key_id], bundle_revoked, "pinned"
        # An unnamed PEM (bare --pubkey, no --keyring naming this key_id)
        # pins any signature not covered by a named --keyring entry.
        if None in pinned:
            return pinned[None], bundle_revoked, "pinned"
        return None, False, (
            f"key_id '{key_id}' was not supplied via --keyring/--pubkey; refusing to "
            "fall back to the key embedded in the bundle"
        )
    entry = (cert.get("public_keys") or {}).get(key_id) or {}
    if not entry:
        return None, False, f"no public key in the bundle for key_id '{key_id}'"
    return entry.get("pem"), bool(entry.get("revoked")), entry.get("detail") or ""


def _revocation_signed_body(entry: dict) -> dict:
    """The entry with `signature_hex` removed — Rule 9.2.4.

    Same construction as `_succession_signed_body`, and for the same reason:
    take the record as-is and drop only the signature, so a field added in a
    later version is covered by the signature rather than silently ignored,
    and an unsigned field cannot be stapled onto a genuine record.
    """
    return {k: v for k, v in entry.items() if k != "signature_hex"}


def _revocation_index(cert: dict, pinned: dict | None = None) -> tuple[dict, list]:
    """
    Read `statement.revocations` and return
    ({key_id: earliest verified effective_at}, [hard failure details]).

    A signed revocation record turns "this key is revoked" from an unsigned
    claim into a dated, checkable one, which is what lets the verifier stop
    punishing a key's entire history for a compromise that happened last
    Tuesday. See SPEC.md §9.2.

    **Earliest, not latest.** If a later record could push a revocation
    forward in time, anyone able to append one could un-revoke the window
    between the two dates and re-validate checkpoints an earlier record had
    already excluded. Taking the minimum means an appended record can only
    ever tighten.

    The signer key is resolved WITHOUT applying the revocation flag. A
    self-revocation is signed by the key being revoked — necessarily, since
    that is the case where no successor exists — so applying the flag here
    would make the only record that can establish a revocation impossible to
    check. The record's own semantics (§9.2: it was signed before the
    revocation took effect) are what carry that weight, not the flag.
    """
    statement = cert.get("statement") or {}
    entries = statement.get("revocations")
    if entries is None:
        return {}, []
    if not isinstance(entries, list):
        # A field an attacker can get ignored is a field an attacker will
        # malform — same posture as §9.4.3 takes for `cosignatures`.
        return {}, ["`revocations` must be a list"]

    index: dict = {}
    failures: list = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            failures.append(f"revocation entry {i} is not an object")
            continue
        if entry.get("type") != "key.revocation":
            # Rule 9.2.5, the same domain separation §9.3.3 requires: without
            # it, a signature the signer made over some other structure that
            # happens to carry `key_id` and `effective_at` could be replayed
            # here as a revocation that party never issued.
            failures.append(
                f"revocation entry {i} has type {entry.get('type')!r}, expected "
                "'key.revocation'"
            )
            continue
        key_id = entry.get("key_id")
        effective_at = entry.get("effective_at")
        signer_id = entry.get("signed_by_key_id")
        if not (key_id and effective_at and signer_id):
            failures.append(
                f"revocation entry {i} is missing key_id, effective_at or signed_by_key_id"
            )
            continue
        pem, _revoked, detail = _resolve_bundle_key(cert, signer_id, pinned)
        if not pem:
            failures.append(
                f"revocation of '{key_id}' names signer '{signer_id}', for which "
                f"{detail or 'no public key is available'}"
            )
            continue
        if not verify_signature(_revocation_signed_body(entry), entry.get("signature_hex", ""),
                                pem):
            failures.append(
                f"revocation of '{key_id}' SIGNATURE INVALID under '{signer_id}'"
            )
            continue
        prior = index.get(key_id)
        if prior is None or effective_at < prior:
            index[key_id] = effective_at
    return index, failures


def _check_certificate_signatures(cert: dict, results: list, pinned: dict | None = None) -> None:
    """The certificate's own signature, then every checkpoint under its OWN key_id."""
    statement = cert.get("statement") or {}
    revoked_from, revocation_failures = _revocation_index(cert, pinned)

    if statement.get("revocations") is not None:
        results.append((
            "key revocation records",
            not revocation_failures,
            "; ".join(revocation_failures) if revocation_failures else (
                f"{len(revoked_from)} signed revocation record(s) verified: "
                + ", ".join(f"{k} from {v}" for k, v in sorted(revoked_from.items()))
            ),
        ))

    def _one(body, sig_hex, key_id, label, issued_at=None):
        pem, revoked, detail = _resolve_bundle_key(cert, key_id, pinned)
        if pem is None and detail:
            return False, detail
        effective_at = revoked_from.get(key_id)
        if effective_at is not None:
            # A signed, dated revocation is present for this key. Only
            # attestations made from `effective_at` onward are refused — the
            # ones made before it were made by a key that was still good, and
            # invalidating them would mean a compromise today retroactively
            # destroyed years of honest evidence, which is both wrong and the
            # opposite of what an append-only record is for.
            #
            # Compared as strings, the same way _check_certificate_timestamp_
            # monotonicity already compares two issued_at values — ISO-8601 UTC
            # sorts lexicographically, which is why §3 requires that shape
            # everywhere rather than an epoch number.
            #
            # The sharp edge, for a second implementer: that holds only while
            # both sides spell the UTC offset the same way. "…T00:00:00+00:00"
            # and "…T00:00:00Z" are the same instant but not the same string,
            # and '+' sorts before 'Z', so a revocation written one way and a
            # checkpoint written the other could tie-break wrongly at exactly
            # equal instants. Coriqo emits "+00:00" on both sides (datetime.
            # isoformat, for the revocation record and for a checkpoint's
            # issued_at alike), so they are consistent in practice — but
            # nothing in the format enforces it and a producer that mixed them
            # would still be within §3 as written. Flagged for a later change, which is
            # where a normalisation rule belongs.
            if issued_at is not None and issued_at < effective_at:
                pass
            else:
                when = f" (issued_at {issued_at})" if issued_at else ""
                return False, (
                    f"KEY REVOKED — '{key_id}' was revoked with effect from "
                    f"{effective_at}. {label}{when} was issued at or after that "
                    "instant and must NOT be trusted, even though its signature may "
                    "be mathematically valid."
                )
        elif revoked:
            # No signed record, only the bundle's unsigned `revoked` flag.
            # Rule 9.2.1 stands unchanged: the flag carries no date, so there
            # is nothing to bound the distrust with, and the whole key is
            # refused. This is the earlier behaviour and remains the default
            # for any bundle that does not carry revocation records.
            return False, (
                f"KEY REVOKED — '{key_id}' has been revoked. {label} must NOT be "
                "trusted even though its signature may be mathematically valid."
            )
        if not pem:
            return False, f"no public key in the bundle for key_id '{key_id}'"
        # Rule 6.1.1: from the signed body, nowhere else. Both bodies reaching
        # _one are signed bodies -- a certificate statement (which has no
        # `algorithm` key, so this yields ed25519, as it did before v3) and a
        # checkpoint's own sth_body (which declares it when not ed25519).
        if verify_signature(body, sig_hex, pem,
                            algorithm=body.get("algorithm", ALGORITHM_ED25519)):
            return True, f"{label} signed by {key_id} — signature valid"
        return False, f"{label} SIGNATURE INVALID under {key_id}"

    results.append(("certificate signature",) + _one(
        statement, cert.get("signature_hex", ""), cert.get("key_id", ""), "certificate",
        # The certificate has no issued_at of its own, so a dated revocation
        # of the CERTIFICATE's key cannot be scoped by time and the whole
        # certificate is refused — the conservative reading, and the right
        # one: a certificate is issued now, over a range, by whoever currently
        # holds the key, so it cannot predate its own signer's revocation.
        issued_at=None,
    ))

    failures = []
    checkpoints = statement.get("checkpoints") or []
    for cp in checkpoints:
        ok, detail = _one(cp.get("sth_body") or {}, cp.get("signature_hex", ""),
                          cp.get("key_id", ""), f"checkpoint {cp.get('checkpoint_id')}",
                          # From the SIGNED body, never the unsigned envelope:
                          # reading issued_at from a top-level field would let a
                          # forger back-date a checkpoint past a revocation by
                          # editing a value no signature covers.
                          issued_at=(cp.get("sth_body") or {}).get("issued_at"))
        if not ok:
            failures.append(detail)
    results.append((
        "checkpoint signatures (each under its recorded key_id)",
        not failures,
        "; ".join(failures) if failures else f"all {len(checkpoints)} checkpoint signatures valid",
    ))


def _check_certificate_linkage(cert: dict, results: list) -> None:
    """
    Unbroken linkage: each checkpoint's sealed head must be a leaf of the
    NEXT checkpoint's Merkle tree, proven against that checkpoint's signed
    root. This is what turns "governance never stopped" into a proof.

    Every value used here comes from the checkpoints' `sth_body` — the bytes
    their signatures actually cover — never from the linkage entry's own
    restatement of them. A linkage entry is unsigned convenience data; a
    proof verified against it would only show the entry is self-consistent,
    which a forger can arrange trivially.

    Completeness is enforced as well: N checkpoints must produce exactly N-1
    links joining consecutive pairs. Otherwise a bundle claiming ten
    checkpoints could ship an empty linkage list and pass vacuously.
    """
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []
    links = statement.get("linkage") or []
    failures = []

    expected = max(0, len(cps) - 1)
    if len(links) != expected:
        failures.append(
            f"expected {expected} link(s) for {len(cps)} checkpoint(s), found {len(links)}")
        links = []

    # The status is inside the signed body, so an issuer cannot relabel a
    # certificate after the fact -- but it must still agree with the evidence
    # actually shipped. A single checkpoint has no consecutive pair and
    # therefore proves nothing about continuity; a bundle claiming `proven`
    # with no links would be asserting exactly the vacuous truth this check
    # exists to catch.
    status = statement.get("linkage_status")
    if status == "proven" and expected == 0:
        failures.append(
            "statement claims linkage 'proven' but a single checkpoint has no "
            "consecutive pair to link")
    if status == "not_applicable" and expected > 0:
        failures.append(
            f"statement claims linkage 'not_applicable' but {len(cps)} checkpoints "
            f"were supplied, which must be linked")
    claimed_proven = statement.get("links_proven")
    if isinstance(claimed_proven, int) and claimed_proven > expected:
        failures.append(
            f"statement claims {claimed_proven} proven link(s) but only {expected} "
            f"are possible for {len(cps)} checkpoint(s)")

    for i, link in enumerate(links):
        earlier, later = cps[i], cps[i + 1]
        label = f"{link.get('from_checkpoint_id')} → {link.get('to_checkpoint_id')}"

        if (link.get("from_checkpoint_id") != earlier.get("checkpoint_id")
                or link.get("to_checkpoint_id") != later.get("checkpoint_id")):
            failures.append(f"link {i} does not join consecutive checkpoints {label}")
            continue

        earlier_body = earlier.get("sth_body") or {}
        later_body = later.get("sth_body") or {}
        sealed_head = earlier_body.get("head_hash")
        earlier_len = earlier_body.get("length")
        root = later_body.get("merkle_root")
        tree_size = later_body.get("tree_size")
        # A link proves the earlier head is a leaf of the LATER tree, so the
        # later checkpoint's construction is the one that applies. Signed body
        # only, and absent means 1.
        later_tree_version = later_body.get("tree_version", 1)

        if link.get("sealed_head") != sealed_head:
            failures.append(f"{label}: sealed_head disagrees with the signed checkpoint body")
            continue
        if link.get("merkle_root") != root or link.get("tree_size") != tree_size:
            failures.append(f"{label}: merkle_root/tree_size disagree with the signed body")
            continue
        if not isinstance(earlier_len, int) or not isinstance(tree_size, int):
            failures.append(f"{label}: signed body is missing length/tree_size")
            continue
        if earlier_len > tree_size:
            failures.append(f"{label}: chain shrank between seals ({earlier_len} → {tree_size})")
            continue
        if earlier_len == 0:
            continue  # empty chain at the earlier seal — nothing to prove
        if later_tree_version not in SUPPORTED_TREE_VERSIONS:
            failures.append(
                f"{label}: signed body declares unknown tree_version "
                f"{later_tree_version!r}")
            continue

        leaf_index = earlier_len - 1
        if link.get("leaf_index") != leaf_index:
            failures.append(f"{label}: leaf_index does not match the signed length")
            continue
        if not link.get("provable"):
            failures.append(f"{label}: {link.get('detail') or 'link not provable'}")
            continue
        if not root or not sealed_head:
            failures.append(f"{label}: signed body is missing merkle_root/head_hash")
            continue

        try:
            ok = verify_inclusion(
                sealed_head, leaf_index, tree_size,
                link.get("proof_path") or [], root,
                tree_version=later_tree_version,
            )
        except ValueError:
            failures.append(f"{label}: malformed hex in the linkage proof")
            continue
        if not ok:
            failures.append(f"{label}: inclusion proof does not reproduce the sealed root")

    if not statement.get("linkage_unbroken", False):
        for problem in statement.get("linkage_problems") or []:
            failures.append(problem)
        if not failures:
            failures.append("certificate does not claim unbroken linkage")

    results.append((
        "chain linkage across the range",
        not failures,
        "; ".join(failures) if failures
        else (f"{len(links)} consecutive checkpoint link(s) proven against the signed "
              "roots — governance was continuous across the certified range"),
    ))


def _check_certificate_coverage(cert: dict, results: list) -> None:
    """
    Recompute every coverage and gap claim from the SIGNED checkpoint bodies.

    The certificate is generated by Coriqo, so its claims are only worth what
    the seals behind them support. This check re-derives them independently;
    if the issuer ever claimed coverage the signatures do not back, it fails.
    """
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []
    coverage = statement.get("coverage") or {}
    problems = []

    if not cps:
        results.append(("coverage matches the sealed events", False, "no checkpoints in the bundle"))
        return

    first_body = cps[0].get("sth_body") or {}
    last_body = cps[-1].get("sth_body") or {}

    if coverage.get("sealed_event_count") != last_body.get("length"):
        problems.append("sealed_event_count does not match the closing checkpoint's signed length")
    expected_added = (last_body.get("length") or 0) - (first_body.get("length") or 0)
    if coverage.get("events_added_in_period") != expected_added:
        problems.append(
            f"events_added_in_period claims {coverage.get('events_added_in_period')}, "
            f"signed lengths give {expected_added}")

    opening = ((first_body.get("continuity") or {}).get("obligations")) or {}
    closing = ((last_body.get("continuity") or {}).get("obligations")) or {}
    for key, claimed in (coverage.get("obligations_in_period") or {}).items():
        o, c = opening.get(key), closing.get(key)
        expected = (c - o) if isinstance(o, int) and isinstance(c, int) else None
        if claimed != expected:
            problems.append(f"obligation '{key}' claims {claimed}, signed bodies give {expected}")

    # The cumulative counts are what a single-checkpoint chain actually
    # displays, so they must be attested too — not merely echoed.
    for key, claimed in (coverage.get("obligations_closing") or {}).items():
        if claimed != closing.get(key):
            problems.append(
                f"cumulative obligation '{key}' claims {claimed}, "
                f"the closing signed body gives {closing.get(key)}")

    # Reported gaps must be a subset of what the closing checkpoint sealed.
    # A certificate may narrow gaps to its window; it may never invent one,
    # and it may never quietly drop one that the seal recorded.
    sealed_gaps = ((last_body.get("continuity") or {}).get("coverage_gaps")) or []
    sealed_keys = {(g.get("from"), g.get("to")) for g in sealed_gaps}
    for gap in statement.get("coverage_gaps") or []:
        if (gap.get("from"), gap.get("to")) not in sealed_keys:
            problems.append(
                f"reported gap {gap.get('from')} → {gap.get('to')} is not in the signed record")

    results.append((
        "coverage matches the sealed events",
        not problems,
        "; ".join(problems) if problems
        else "every coverage and gap claim is backed by a signed checkpoint body",
    ))


# ---------------------------------------------------------------------------
# Key succession (SPEC.md §9.3)
#
# A certificate's checkpoints may span more than one key_id, because signing
# authority for a chain can be handed over — a custody transfer moves an
# engagement from the validator that produced it to the bank that owns it.
#
# The handoff is a signed statement, not a label. `statement.succession` is a
# list of records; each is the canonical body the OUTGOING key signed, plus
# the detached `signature_hex` over it. Verifying it needs nothing beyond
# this bundle: the outgoing key's PEM is already carried in `public_keys` (or
# pinned via --pubkey/--keyring), and the body is canonicalised exactly the
# way every other signature in this format is (§3).
#
# The signed body is the record with `signature_hex` removed — every other
# field it carries is covered. That is deliberate: it means a forger cannot
# staple an unsigned field (an approver name, an earlier date) onto a
# genuine record, and it means a field added to the record in a future
# version is signed automatically rather than silently unchecked.
#
# What this closes: before signature verification, a party holding only the
# INCOMING key could take somebody else's genuine, outgoing-key-signed
# checkpoints, append their own checkpoints under their own key, assert a
# `{outgoing, incoming}` pair, and the whole thing verified. Nothing in the
# bundle required the outgoing party's consent to the handoff. Now it does.
# ---------------------------------------------------------------------------

# Domain separation: the body a key succession signs declares what it is.
# Requiring it stops a signature made by the outgoing key over some *other*
# structure that happens to carry these two field names from being replayed
# here as a handoff the outgoing party never authorised.
SUCCESSION_BODY_TYPE = "key.succession"


def _succession_signed_body(record: dict) -> dict:
    """The bytes the outgoing key signed: the record minus its own signature."""
    return {k: v for k, v in record.items() if k != "signature_hex"}


def _check_certificate_succession(cert: dict, results: list, pinned: dict | None = None) -> None:
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []
    if len(cps) < 2:
        return  # nothing to transition between

    key_ids = [cp.get("key_id") for cp in cps]
    transitions = [
        (i, key_ids[i], key_ids[i + 1])
        for i in range(len(key_ids) - 1)
        if key_ids[i] != key_ids[i + 1]
    ]
    if not transitions:
        results.append((
            "key succession",
            True,
            f"single signing key ({key_ids[0]!r}) throughout — no succession record needed",
        ))
        return

    succession = statement.get("succession")
    records = [r for r in (succession if isinstance(succession, list) else [])
               if isinstance(r, dict)]
    problems = []
    for i, outgoing, incoming in transitions:
        label = (f"{cps[i].get('checkpoint_id')} ({outgoing!r}) → "
                 f"{cps[i + 1].get('checkpoint_id')} ({incoming!r})")
        # A record only explains THIS change if it names this exact pair:
        # `outgoing_key_id` must be the key that signed the checkpoint
        # before the change, `incoming_key_id` the key that signed the one
        # after. A record naming some other pair explains some other
        # handoff, and leaves this one unexplained.
        candidates = [
            r for r in records
            if r.get("outgoing_key_id") == outgoing and r.get("incoming_key_id") == incoming
        ]
        if not candidates:
            problems.append(
                f"{label}: signing key changed with no matching record in "
                "statement.succession — an unexplained key change is not a "
                "provable continuity claim"
            )
            continue

        # Verify under the OUTGOING key. Resolution goes through the same
        # path every other signature in this bundle uses, so --pubkey /
        # --keyring pinning applies here too: a bundle that ships its own
        # "outgoing" key is no more trusted for the handoff than it is for a
        # checkpoint. Revocation is not re-checked here — the outgoing key is
        # by construction a checkpoint's key_id in this range, so
        # _check_certificate_signatures has already failed the certificate
        # loudly if it is revoked.
        pem, _revoked, detail = _resolve_bundle_key(cert, outgoing, pinned)
        if not pem:
            problems.append(f"{label}: {detail or f'no public key available for {outgoing!r}'}")
            continue

        reasons = []
        for r in candidates:
            body = _succession_signed_body(r)
            if body.get("type") != SUCCESSION_BODY_TYPE:
                reasons.append(
                    f"record does not declare type={SUCCESSION_BODY_TYPE!r} — "
                    "an unlabelled body is not a key-succession statement"
                )
                continue
            sig = r.get("signature_hex")
            if not isinstance(sig, str) or not sig:
                reasons.append("record carries no signature_hex")
                continue
            if verify_signature(body, sig, pem):
                break
            reasons.append(f"record's signature does not verify under {outgoing!r}")
        else:
            problems.append(
                f"{label}: {'; '.join(reasons)}. Only the holder of the outgoing "
                "key can hand its chain to a successor, so a record it did not "
                "sign does not authorise this key change."
            )

    if problems:
        results.append(("key succession", False, "; ".join(problems)))
    else:
        results.append((
            "key succession",
            True,
            f"{len(transitions)} key change(s), each authorised by a succession "
            "record naming that exact outgoing/incoming key_id pair and signed "
            "under the outgoing key (see SPEC.md §9.3 for what a succession "
            "record does and does not prove)",
        ))


def _check_certificate_timestamp_monotonicity(cert: dict, results: list) -> None:
    """
    Verify that checkpoint timestamps are non-decreasing in the chain.

    Checkpoints should be ordered chronologically. A record claiming an
    earlier timestamp than a preceding record in the hash chain indicates
    backdating and should be flagged as a failure.
    """
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []

    if len(cps) < 2:
        results.append((
            "Timestamp monotonicity",
            True,
            "single checkpoint — no timestamp ordering to verify",
        ))
        return

    problems = []
    for i in range(1, len(cps)):
        prev_body = cps[i - 1].get("sth_body") or {}
        curr_body = cps[i].get("sth_body") or {}
        prev_ts = prev_body.get("issued_at")
        curr_ts = curr_body.get("issued_at")

        # A missing issued_at on either side is itself a failure, not a free
        # pass — omitting the timestamp on one checkpoint must not let a
        # forger defeat this check the same way a missing sth_ts would have
        # defeated the single-proof _check_timestamp_consistency.
        if not prev_ts or not curr_ts:
            problems.append(
                f"checkpoint {cps[i].get('checkpoint_id')!r} or "
                f"{cps[i-1].get('checkpoint_id')!r} is missing issued_at — "
                f"cannot verify ordering between them"
            )
        elif prev_ts > curr_ts:
            problems.append(
                f"checkpoint {cps[i].get('checkpoint_id')} ({curr_ts!r}) "
                f"backdated relative to {cps[i-1].get('checkpoint_id')} ({prev_ts!r})"
            )

    results.append((
        "Timestamp monotonicity",
        not problems,
        "; ".join(problems) if problems
        else f"{len(cps)} checkpoint timestamps are in non-decreasing order",
    ))


def _check_certificate_compliance_coverage(cert: dict, results: list) -> None:
    """
    Calculate and report compliance coverage percentage based on obligations.

    Counts the number of obligation types with non-zero values in the final
    checkpoint's continuity block and reports coverage as a percentage of
    all tracked obligation types.
    """
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []

    if not cps:
        results.append((
            "Compliance coverage percentage",
            True,
            "no checkpoints — coverage cannot be computed",
        ))
        return

    # Use the closing checkpoint's obligations
    last_body = cps[-1].get("sth_body") or {}
    continuity = last_body.get("continuity") or {}
    obligations = continuity.get("obligations") or {}

    coverage_detail, _percentage = _compliance_coverage_detail(
        obligations, empty_note="no obligations recorded in closing checkpoint",
    )

    results.append((
        "Compliance coverage percentage",
        True,  # Report coverage percentage; it's informational, not a pass/fail
        coverage_detail,
    ))


def _check_certificate_cosignatures(
    cert: dict, results: list, pinned: dict | None, independent_ids: set,
) -> list[tuple[str, str, list[dict], list[str]]]:
    """
    Witness state for EVERY checkpoint in the certified range, kept per
    checkpoint rather than rolled up.

    A range where the first two seals are cosigned and the rest are not is a
    materially different record from one where all of them are, and a single
    aggregated verdict would hide exactly that. day_one_trust_spec.md I-3
    ("a pending control renders as pending") is a per-checkpoint rule.

    `cert["cosignatures"]` is UNSIGNED metadata keyed by checkpoint_id — the
    same trust class as the top-level restatements §7.3 warns about — which
    is why nothing here is taken from it except the raw signature bytes and
    the witness key_id, both of which are then checked against a key the
    operator supplied.
    """
    statement = cert.get("statement") or {}
    cps = statement.get("checkpoints") or []
    by_checkpoint = cert.get("cosignatures")
    if by_checkpoint is not None and not isinstance(by_checkpoint, dict):
        results.append((
            "witness cosignatures",
            False,
            "the bundle's `cosignatures` field is present but is not an object "
            "keyed by checkpoint_id; refusing to guess at its shape",
        ))
        return []

    blocks = []
    failures = []
    states = []
    for cp in cps:
        cp_id = cp.get("checkpoint_id")
        entries = (by_checkpoint or {}).get(cp_id)
        state, rows, cp_failures, notes = _evaluate_cosignatures(
            cp.get("sth_body") or {}, entries, pinned, independent_ids)
        blocks.append((f"checkpoint {cp_id}", state, rows, notes))
        states.append(state)
        failures.extend(f"{cp_id}: {f}" for f in cp_failures)

    if all(s == COSIGN_NONE for s in states):
        return blocks  # nothing cosigned anywhere; no assertion to make
    results.append((
        "witness cosignatures (each checkpoint under its own witness keys)",
        not failures,
        "; ".join(failures) if failures
        else "; ".join(f"{cp.get('checkpoint_id')}: {_COSIGN_HEADLINE[s]}"
                       for cp, s in zip(cps, states)),
    ))
    return blocks


def _print_certificate_anchors(cert: dict) -> None:
    """
    Rekor references for the certified checkpoints. Informational, exactly as
    for a proof bundle (SPEC.md §10): the anchor never moves PASS/FAIL, and a
    verifier that failed because Rekor was unreachable would have made offline
    verification conditional on being online.
    """
    anchors = cert.get("anchors")
    if not isinstance(anchors, dict) or not anchors:
        return
    print("-" * 60)
    print("Public transparency-log anchors (Sigstore Rekor)")
    print("-" * 60)
    external_times = []
    for cp in (cert.get("statement") or {}).get("checkpoints") or []:
        cp_id = cp.get("checkpoint_id")
        anchor = anchors.get(cp_id) or {}
        uuid = anchor.get("rekor_uuid")
        status = anchor.get("status") or "not anchored"
        if not uuid:
            print(f"  {cp_id}: not anchored (status: {status})")
            continue
        print(f"  {cp_id}: {status} — https://search.sigstore.dev/?uuid={uuid}")
        external_time = anchor.get("anchored_at")
        if anchor.get("rekor_log_index") is not None:
            print(f"      log index {anchor['rekor_log_index']}  "
                  f"anchored at {external_time}")
        if external_time:
            external_times.append(external_time)
    print()
    if external_times:
        # Earliest across the group, not latest: the claim a bundle can
        # actually support is "witnessed by an outside log no later than
        # this" — the earliest anchor is the strongest (oldest) fact.
        # Reported straight from the bundle's own anchor metadata, not
        # independently verified against a Rekor inclusion/consistency
        # proof (see the equivalent note in _print_rekor_anchor).
        earliest = min(external_times)
        print(f"  Externally attested since {earliest} (reported, not verified — see SPEC.md §10).")
    print("  Informational only — no check above depends on reaching Rekor.")
    print()


def _print_certificate_tsa_timestamps(cert: dict, tsa_ca_path: str | None) -> None:
    """
    RFC 3161 TSA timestamps for the certified checkpoints (W2-D, SPEC.md
    §10.2). Same informational posture as _print_certificate_anchors.

    A certificate bundle does not ship each checkpoint's full sth_body
    (only the summarised `statement.checkpoints` entries), so the
    messageImprint cross-check --proof mode performs is not repeated here —
    this reports the token's own signature/CA validity and genTime, stated
    plainly, rather than silently reusing a different checkpoint's bytes.
    """
    tsa_map = cert.get("tsa_timestamps")
    if not isinstance(tsa_map, dict) or not tsa_map:
        return
    print("-" * 60)
    print("RFC 3161 Time-Stamp Authority timestamps")
    print("-" * 60)
    gen_times = []
    for cp in (cert.get("statement") or {}).get("checkpoints") or []:
        cp_id = cp.get("checkpoint_id")
        info = tsa_map.get(cp_id) or {}
        token = info.get("tsa_token")
        if not token:
            print(f"  {cp_id}: no TSA timestamp (status: {info.get('status') or 'not configured'})")
            continue
        result = _verify_tsa_offline(token, {}, tsa_ca_path)
        if not result.get("available"):
            print(f"  {cp_id}: [WARN] {result.get('detail')}")
            continue
        ca_word = (
            "not pinned" if not tsa_ca_path
            else ("chains OK" if result["ca_verified"] else "DOES NOT CHAIN")
        )
        print(f"  {cp_id}: signature {'valid' if result['signature_verified'] else 'INVALID'}, "
              f"CA {ca_word}, genTime {result.get('gen_time')} "
              "(messageImprint not re-checked in certificate mode — see --proof)")
        if result["signature_verified"] and result.get("gen_time"):
            gen_times.append(result["gen_time"])
    print()
    if gen_times:
        earliest = min(gen_times)
        print(f"  Earliest TSA-attested time: {earliest} (reported; see SPEC.md §10.2).")
    print("  Informational only — no check above depends on reaching a TSA.")
    print()


def _print_continuity_summary(cert: dict) -> None:
    """
    The human readout. Gaps are shown even when everything passes — silence in
    the chain is meant to be visible and sold, not fought
    (verifiable_governance_strategy.md §7). A quiet fortnight on a small model
    book is ordinary operation, and is labelled as such rather than as a fault.
    """
    statement = cert.get("statement") or {}
    period = statement.get("period") or {}
    coverage = statement.get("coverage") or {}
    summary = statement.get("gap_summary") or {}

    print("-" * 60)
    print("Governance continuity")
    print("-" * 60)
    print(f"  Subject:            {statement.get('subject')}")
    print(f"  Period:             {period.get('from')} → {period.get('to')}")
    print(f"  Checkpoints:        {statement.get('checkpoint_count')}")
    print(f"  Events sealed:      {coverage.get('sealed_event_count')} "
          f"({coverage.get('events_added_in_period')} added in period)")

    obligations = coverage.get("obligations_in_period") or {}
    if obligations:
        rendered = ", ".join(
            f"{k}={v}" for k, v in sorted(obligations.items()) if v is not None
        )
        print(f"  Obligations:        {rendered or 'none recorded in period'}")

    print()
    print(f"  Quiet periods:      {summary.get('total', 0)} "
          f"({summary.get('normal_cadence', 0)} normal cadence, "
          f"{summary.get('exceeds_policy', 0)} beyond policy)")
    for gap in statement.get("coverage_gaps") or []:
        label = "normal cadence" if gap.get("classification") == "normal_cadence" else "BEYOND POLICY"
        reason = gap.get("reason") or "no reason recorded"
        still_open = " (still open)" if gap.get("open_ended") else ""
        print(f"    · {gap.get('days')} days, {gap.get('from')} → {gap.get('to')}{still_open}")
        print(f"      {label} — {reason}")
    if not (statement.get("coverage_gaps") or []):
        print("    · none — no quiet period reached the reporting threshold")

    # Prefer the reasoned list; fall back to the id-only field for certificates
    # issued before it existed. Reporting every exclusion as "no Merkle root"
    # would be wrong for the non-reproducible ones and would read to an examiner
    # as a different, milder problem than the one actually present.
    # Withheld checkpoints are pulled out of this list and reported on their
    # own below. Naming one here as well would describe it twice, and the
    # milder description — "excluded from linkage proofs" — would be the one an
    # examiner read first.
    detailed = [item for item in (statement.get("excluded_checkpoints") or [])
                if not (isinstance(item, dict)
                        and item.get("reason") == REASON_SIGNATURE_NOT_VERIFIABLE)]
    excluded = statement.get("excluded_v1_checkpoints") or []
    if detailed:
        print()
        print(f"  NOTE: {len(detailed)} checkpoint(s) in this range are excluded from")
        print("        linkage proofs:")
        for item in detailed:
            print(f"    · {item.get('checkpoint_id')} ({item.get('issued_at')})")
            print(f"      {item.get('detail') or item.get('reason')}")
    elif excluded:
        print()
        print(f"  NOTE: {len(excluded)} V1 checkpoint(s) in this range carry no Merkle root")
        print("        and are excluded from linkage proofs. Re-issue to upgrade them.")
    print()


# ---------------------------------------------------------------------------
# Checkpoints withheld from the certified range (SPEC.md §8.4)
#
# `excluded_checkpoints` has carried only mild reasons until now. A pre-Merkle
# checkpoint has no root to link against; a non-reproducible one cannot be
# re-derived. Neither says the record is wrong.
#
# `signature_not_verifiable` says exactly that. It means the issuer found a
# checkpoint whose signature does not check out, could not repair it —
# checkpoints are append-only — and dropped it from the certified set under a
# named declaration. Reporting that in the same NOTE, in the same voice, as
# "this one predates Merkle roots" would hand an examiner the milder of two
# very different facts.
#
# Two rules follow, and they pull against each other on purpose:
#
#   * the declaration is reproduced in full, because the reader's real
#     question is what is missing from this range and on whose word;
#   * none of it is verified, and the output says so in those words. The
#     checks below ran over the checkpoints the certificate carries. A
#     withheld checkpoint is not here to check. Collapsing the two is how a
#     removal starts to read as a repair.
#
# One thing here IS checked, because its failure mode is real rather than
# hypothetical: a certificate that lists a checkpoint as withheld while still
# counting it among the certified set has removed it on paper only, and a
# declaration with no declarant is an unattributable deletion wearing the word
# "quarantine". Both are properties of the bundle, so both are decidable
# offline. Whether the removal was warranted is not, and is not claimed.
# ---------------------------------------------------------------------------

REASON_SIGNATURE_NOT_VERIFIABLE = "signature_not_verifiable"

_QUARANTINE_FIELDS = (
    ("declared_by", "Declared by"),
    ("declared_at", "Declared at"),
    ("operator_reason", "Stated reason"),
    ("verification_failure", "Failure recorded"),
)


def _withheld_checkpoints(statement: dict) -> list[dict]:
    """Exclusions dropped from the certified set because their signature fails."""
    return [item for item in (statement.get("excluded_checkpoints") or [])
            if isinstance(item, dict)
            and item.get("reason") == REASON_SIGNATURE_NOT_VERIFIABLE]


def _print_withheld_checkpoints(cert: dict) -> None:
    """The loud half of the disclosure: what was removed, and who removed it."""
    statement = cert.get("statement") or {}
    withheld = _withheld_checkpoints(statement)
    if not withheld:
        return
    certified = {cp.get("checkpoint_id")
                 for cp in (statement.get("checkpoints") or []) if isinstance(cp, dict)}

    print("=" * 60)
    print(f"WITHHELD FROM THE CERTIFIED RANGE — {len(withheld)} checkpoint(s)")
    print("=" * 60)
    print()
    print("  These checkpoints fall inside the period above but were taken out of")
    print("  the certified set: the issuer declares that their signatures do not")
    print("  verify. This verifier checked none of them. What follows is the")
    print("  issuer's own declaration, reproduced so you can see what was removed")
    print("  and on whose authority.")
    print()
    for item in withheld:
        cp_id = item.get("checkpoint_id") or "(no checkpoint_id recorded)"
        print(f"  · {cp_id}  (sealed {item.get('issued_at') or 'date not recorded'})")
        if item.get("detail"):
            print(f"      {item['detail']}")
        quarantine = item.get("quarantine")
        if isinstance(quarantine, dict) and quarantine:
            for key, label in _QUARANTINE_FIELDS:
                print(f"      {label + ':':<18}{quarantine.get(key) or 'not recorded'}")
        else:
            print("      No quarantine record — this removal names nobody.")
        if item.get("checkpoint_id") in certified:
            print("      Still counted among the certified checkpoints as well, which")
            print("      the check below fails on.")
        print()
    print("  A PASS below covers the checkpoints this certificate carries. It says")
    print("  nothing about the ones listed here, and it is not agreement that they")
    print("  were rightly removed. To judge that, compare this list against your own")
    print("  record of what should have been sealed in the period.")
    print()


def _check_certificate_withheld(cert: dict, results: list) -> None:
    """
    Coherence of the withholding, and nothing beyond it.

    Adds no result at all when nothing is withheld, so a certificate without
    quarantines reads exactly as it did before.
    """
    statement = cert.get("statement") or {}
    withheld = _withheld_checkpoints(statement)
    if not withheld:
        return
    certified = {cp.get("checkpoint_id")
                 for cp in (statement.get("checkpoints") or []) if isinstance(cp, dict)}

    problems = []
    for item in withheld:
        cp_id = item.get("checkpoint_id")
        label = cp_id or "(no checkpoint_id)"
        if not cp_id:
            problems.append("an exclusion names no checkpoint_id")
        elif cp_id in certified:
            problems.append(f"{label}: declared withheld but still counted among the "
                            "certified checkpoints")
        quarantine = item.get("quarantine")
        if not isinstance(quarantine, dict) or not quarantine:
            problems.append(f"{label}: declared unverifiable with no quarantine record, "
                            "so the removal names nobody")
            continue
        missing = [key for key, _ in _QUARANTINE_FIELDS if not quarantine.get(key)]
        if missing:
            problems.append(f"{label}: quarantine record is missing {', '.join(missing)}")

    results.append((
        "withheld checkpoints (attributable, and actually out of the certified set)",
        not problems,
        "; ".join(problems) if problems else
        f"{len(withheld)} checkpoint(s) withheld as unverifiable; each names a declarant, "
        "and none of them is counted among the checkpoints checked here. That is the "
        "shape of the declaration, not its truth — whether the removal was warranted is "
        "the issuer's claim, and an offline verifier cannot settle it.",
    ))


def run_certificate(cert_path: str, pubkey_path: str | None = None,
                     keyring_path: str | None = None,
                     witness_keyring_path: str | None = None,
                     witness_pubkey_path: str | None = None,
                     independent_witnesses: list[str] | None = None,
                     tsa_ca_path: str | None = None) -> bool:
    """Verify a Governance Continuity Certificate bundle offline.

    Thin wrapper around `verify_certificate_dict` that loads the certificate
    from a file path. `--bundle` mode (see `run_bundle`) reads a certificate
    out of a zip entry instead of a standalone file, so the actual checking
    logic lives in `verify_certificate_dict` and both callers share it —
    there is exactly one implementation of "is this certificate's signature
    and linkage valid", not two that could drift apart.
    """
    try:
        cert = json.loads(Path(cert_path).read_text())
    except Exception as exc:
        print(f"FAIL: Cannot load certificate file: {exc}")
        return False

    return verify_certificate_dict(cert, pubkey_path, keyring_path,
                                    witness_keyring_path, witness_pubkey_path,
                                    independent_witnesses, tsa_ca_path)


def verify_certificate_dict(cert: dict, pubkey_path: str | None = None,
                             keyring_path: str | None = None,
                             witness_keyring_path: str | None = None,
                             witness_pubkey_path: str | None = None,
                             independent_witnesses: list[str] | None = None,
                             tsa_ca_path: str | None = None) -> bool:
    """Same checks as `run_certificate`, but on an already-loaded dict."""
    if _refuse_spec_version(cert):
        return False
    pinned = None
    if pubkey_path or keyring_path:
        try:
            pinned = _merge_pinned(pubkey_path, keyring_path)
        except ValueError as exc:
            print(f"FAIL: {exc}")
            return False

    statement = cert.get("statement")
    if not isinstance(statement, dict):
        print("FAIL: Not a certificate bundle — no 'statement' object. "
              "For an inclusion proof use --proof instead.")
        return False

    print("=" * 60)
    print("Coriqo — Governance Continuity Certificate Verification")
    print("=" * 60)
    print()

    witness_pinned, witness_pin_error = _witness_pinning(
        witness_pubkey_path, witness_keyring_path)
    if witness_pin_error is not None:
        print(f"FAIL: {witness_pin_error}")
        return False

    _print_continuity_summary(cert)
    _print_withheld_checkpoints(cert)
    _print_certificate_anchors(cert)
    _print_certificate_tsa_timestamps(cert, tsa_ca_path)
    _print_key_trust(cert, pinned)

    results: list[tuple[str, bool, str]] = []
    _check_certificate_signatures(cert, results, pinned)
    _check_certificate_linkage(cert, results)
    _check_certificate_coverage(cert, results)
    _check_certificate_succession(cert, results, pinned)
    _check_certificate_timestamp_monotonicity(cert, results)
    _check_certificate_compliance_coverage(cert, results)
    _check_certificate_withheld(cert, results)
    cosign_blocks = _check_certificate_cosignatures(
        cert, results, witness_pinned, set(independent_witnesses or ()))
    if cosign_blocks:
        _print_cosign_section(cosign_blocks, witness_pinned)
    by_cp = cert.get("countersignatures") or {}
    if not isinstance(by_cp, dict):
        results.append(("bank countersignatures", False,
                        "the bundle's `countersignatures` field is not an object keyed by checkpoint_id"))
    elif by_cp:
        listed = {cp.get("checkpoint_id") for cp in (statement.get("checkpoints") or [])}
        orphans = sorted(str(k) for k in by_cp if k not in listed)
        if orphans:
            # Unsigned metadata for a checkpoint this certificate does not
            # cover: nothing to check it against, and passing it over in
            # silence would let a reader think it was checked.
            results.append(("bank countersignatures", False,
                            "countersignatures are attached to checkpoint(s) not in this certificate: "
                            + ", ".join(orphans)))
        cs_keyring, cs_keyring_error = _countersign_keyring()
        counter_blocks = _check_countersignatures(
            [(f"checkpoint {cp.get('checkpoint_id')}", cp.get("sth_body") or {}, by_cp.get(cp.get("checkpoint_id")))
             for cp in (statement.get("checkpoints") or [])],
            results, cs_keyring, cs_keyring_error)
        if counter_blocks:
            _print_countersign_section(counter_blocks, cs_keyring)

    for name, passed, detail in results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        print(f"         {detail}")
        print()

    all_pass = all(r[1] for r in results)
    withheld = _withheld_checkpoints(statement)
    print("=" * 60)
    if all_pass:
        # Decision: a withholding narrows the verdict's scope. It does not
        # weaken the verdict, and it does not get to be silent.
        #
        # Two easier answers were both wrong. Failing a certificate because it
        # excludes something would punish the issuer for disclosing — naming an
        # unverifiable checkpoint is the honest move, and a verifier that turns
        # disclosure into a FAIL teaches issuers to say nothing instead.
        # Printing the same unqualified "CONTINUITY VERIFIED" as a certificate
        # with nothing withheld is worse: readers take the last line as the
        # answer, and that line would be answering a narrower question than the
        # one they asked.
        #
        # So the verdict stays PASS — the mathematics over the checkpoints that
        # ARE here is sound, and a proof over a smaller set is still a proof —
        # and the headline states its scope. Someone who reads nothing but the
        # last line still learns that checkpoints were removed, and how many.
        if withheld:
            print("RESULT: CONTINUITY VERIFIED OVER A REDUCED RANGE ✓")
            print()
            print(f"  {len(withheld)} checkpoint(s) in this period were withheld as "
                  "unverifiable and")
            print("  are not covered by this result. Each one, and the declaration behind")
            print("  it, is listed under WITHHELD FROM THE CERTIFIED RANGE above.")
        else:
            print("RESULT: CONTINUITY VERIFIED ✓")
        print()
        # A malformed bundle can omit `claim` even though every cryptographic
        # check passed. Printing a bare "None" under a PASS banner reads as a
        # verifier fault rather than a missing field, so say which it is.
        claim = statement.get("claim")
        print(f"  {claim}" if claim else
              "  (the certificate carries no claim text; the checks above still hold)")
        print()
        print("  Verified with mathematics alone — no network access, no Coriqo")
        print("  software, and no trust in Coriqo as an institution.")
    else:
        print("RESULT: CONTINUITY VERIFICATION FAILED ✗")
        print()
        print("  Do not rely on this certificate. One or more checks failed above;")
        print("  a revoked signing key or a broken link between checkpoints means")
        print("  the continuity claim is not supported by the sealed record.")
    print("=" * 60)

    return all_pass


# ---------------------------------------------------------------------------
# --bundle mode: GET /api/v1/engagements/{id}/deliverables.zip
#
# manifest.json (first zip entry) carries a sha256 for every bundled file.
# On its own that proves nothing — anyone who edits a file can edit its
# sha256 in the same manifest. certificate.json (second entry, when the
# bundle is sealed) is a Governance Continuity Certificate whose signed
# `statement.bundle_binding.manifest_sha256` is the hash of manifest.json's
# OWN bytes. The chain this function walks is:
#
#     signature -> statement.bundle_binding.manifest_sha256
#               -> manifest.json bytes -> each file's recorded sha256 -> file bytes
#
# Editing a bundled file breaks its manifest sha256 (link 4). Editing the
# manifest to cover that up changes manifest.json's bytes, which breaks the
# signed manifest_sha256 (link 2). Editing the binding to cover THAT up
# breaks the Ed25519 signature (link 1). None of the three is repairable
# without the signing key — that is the whole point of binding the manifest
# hash inside the signed statement instead of leaving it beside it.
# ---------------------------------------------------------------------------

MANIFEST_ENTRY = "manifest.json"
CERTIFICATE_ENTRY = "certificate.json"


def _check_manifest_binding(cert: dict, manifest_bytes: bytes) -> list[tuple[str, bool, str]]:
    """The link-2 check shared by every container format that binds a
    manifest into a certificate's signed statement: is `manifest_bytes`
    genuinely the thing `statement.bundle_binding.manifest_sha256` commits
    to? Pure — no I/O — so `run_bundle` (zip) and `run_pdf_bundle` (PDF) both
    call this on whatever manifest bytes they extracted, rather than each
    reimplementing the same three sub-checks and risking them drifting apart.
    """
    statement = cert.get("statement") if isinstance(cert.get("statement"), dict) else {}
    binding = statement.get("bundle_binding")
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    results: list[tuple[str, bool, str]] = []

    if not isinstance(binding, dict):
        results.append((
            "certificate binds a manifest",
            False,
            "statement.bundle_binding is missing. This certificate does not seal a "
            "manifest at all (or the binding was stripped after signing) — its "
            "signature was never checked against this manifest.",
        ))
        return results

    bound_hash = binding.get("manifest_sha256")
    if bound_hash == manifest_hash:
        results.append((
            f"{MANIFEST_ENTRY} hash matches the signed binding",
            True,
            f"sha256({MANIFEST_ENTRY}) = {manifest_hash}, equals "
            "statement.bundle_binding.manifest_sha256.",
        ))
    else:
        results.append((
            f"{MANIFEST_ENTRY} hash matches the signed binding",
            False,
            f"sha256({MANIFEST_ENTRY}) = {manifest_hash} but "
            f"statement.bundle_binding.manifest_sha256 = {bound_hash!r}. "
            f"{MANIFEST_ENTRY} was changed after the certificate signed it — the "
            "signature no longer commits to this manifest, whatever its 'files' "
            "hashes say.",
        ))

    exp_name = binding.get("manifest_filename")
    results.append((
        "bundle_binding.manifest_filename matches the entry hashed",
        exp_name == MANIFEST_ENTRY,
        (f"binding names {exp_name!r}, matching {MANIFEST_ENTRY!r}."
         if exp_name == MANIFEST_ENTRY else
         f"statement.bundle_binding.manifest_filename = {exp_name!r}, but the entry "
         f"actually hashed was {MANIFEST_ENTRY!r}."),
    ))

    exp_len = binding.get("manifest_bytes")
    results.append((
        "bundle_binding.manifest_bytes matches the entry length",
        exp_len == len(manifest_bytes),
        (f"{MANIFEST_ENTRY} is {len(manifest_bytes)} bytes, matching the binding."
         if exp_len == len(manifest_bytes) else
         f"{MANIFEST_ENTRY} is {len(manifest_bytes)} bytes but "
         f"statement.bundle_binding.manifest_bytes = {exp_len!r}."),
    ))
    return results


def run_bundle(bundle_path: str, pubkey_path: str | None = None,
                keyring_path: str | None = None,
                witness_keyring_path: str | None = None,
                witness_pubkey_path: str | None = None,
                independent_witnesses: list[str] | None = None) -> int:
    """Verify a deliverables.zip bundle offline. Returns an exit code — see
    the module docstring's "Exit codes" section (EXIT_OK / EXIT_TAMPER /
    EXIT_UNSEALED / EXIT_MALFORMED).

    Never executes anything read from the bundle. manifest.json carries a
    human-readable `seal.verify_command` / `_how_to_check` string for
    examiners without this tool — those are DATA describing what a human
    could type, not instructions this function runs.
    """
    print("=" * 60)
    print("Coriqo — Deliverables Bundle Verification")
    print("=" * 60)
    print()

    try:
        zf = zipfile.ZipFile(bundle_path)
    except (FileNotFoundError, zipfile.BadZipFile, OSError, PermissionError) as exc:
        print(f"FAIL: Cannot open bundle: {exc}")
        return EXIT_MALFORMED

    with zf:
        names = zf.namelist()

        if MANIFEST_ENTRY not in names:
            print(f"FAIL: {MANIFEST_ENTRY} is missing from this bundle — a deliverables "
                  "bundle without a manifest cannot be verified at all.")
            return EXIT_MALFORMED

        manifest_bytes = zf.read(MANIFEST_ENTRY)
        try:
            manifest = json.loads(manifest_bytes)
        except Exception as exc:
            print(f"FAIL: {MANIFEST_ENTRY} is not valid JSON: {exc}")
            return EXIT_MALFORMED

        if not isinstance(manifest, dict):
            print(f"FAIL: {MANIFEST_ENTRY} does not decode to a JSON object.")
            return EXIT_MALFORMED

        seal = manifest.get("seal") if isinstance(manifest.get("seal"), dict) else {}

        if CERTIFICATE_ENTRY not in names:
            # An unsealed bundle is not a tamper failure — it was never
            # signed, so there is nothing here to cryptographically verify.
            # Report exactly what the manifest itself says happened.
            status = seal.get("status", "unknown")
            reason = seal.get("reason") or manifest.get("bundle_note") or (
                "manifest.json does not explain why this bundle is unsealed.")
            print("  [INFO] seal.status")
            print(f"         {status!r}")
            print()
            print(f"UNSEALED: this bundle carries no {CERTIFICATE_ENTRY} — {reason}")
            print()
            print("This is not proof of tampering. It means this bundle was never signed,")
            print("so this tool has nothing to check a signature against. Ask for a sealed")
            print("bundle if you need a verifiable one.")
            print("=" * 60)
            return EXIT_UNSEALED

        cert_bytes = zf.read(CERTIFICATE_ENTRY)
        try:
            cert = json.loads(cert_bytes)
        except Exception as exc:
            print(f"FAIL: {CERTIFICATE_ENTRY} is not valid JSON: {exc}")
            return EXIT_MALFORMED

        entry_names = set(names)

    print(f"manifest.json seal.status : {seal.get('status', 'unknown')!r}")
    print()
    print("-- link 1/3: certificate signature and checkpoint linkage " + "-" * 12)
    print()

    cert_ok = verify_certificate_dict(cert, pubkey_path, keyring_path,
                                       witness_keyring_path, witness_pubkey_path,
                                       independent_witnesses)
    if not cert_ok:
        print()
        print("=" * 60)
        print("RESULT: BUNDLE VERIFICATION FAILED ✗")
        print()
        print("  The certificate's own signature or checkpoint linkage did not verify")
        print("  (see the checks above). This is a problem with the certificate itself —")
        print(f"  it was never checked whether it actually binds this {MANIFEST_ENTRY}, or")
        print("  whether the bundled files match it, because a certificate that fails on")
        print("  its own terms cannot vouch for anything sealed under it.")
        print("=" * 60)
        return EXIT_TAMPER

    print()
    print("-- link 2/3: manifest bound to the signed certificate " + "-" * 12)
    print()

    results = _check_manifest_binding(cert, manifest_bytes)

    for name, passed, detail in results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        print(f"         {detail}")
        print()

    binding_ok = all(r[1] for r in results)

    print("-- link 3/3: every bundled file matches its manifest hash " + "-" * 8)
    print()

    file_results: list[tuple[str, bool, str]] = []
    files = manifest.get("files")
    if not isinstance(files, list):
        file_results.append((
            "manifest.files is present and usable",
            False,
            f"{MANIFEST_ENTRY}['files'] is missing or not a list — nothing to check "
            "bundled files against.",
        ))
    else:
        named: set[str] = set()
        with zipfile.ZipFile(bundle_path) as zf2:
            for row in files:
                if not isinstance(row, dict):
                    continue
                name = row.get("name")
                if not isinstance(name, str):
                    continue
                named.add(name)
                status = row.get("status")
                sha = row.get("sha256")
                if sha is None:
                    # A manifest cannot hash the certificate that signs it —
                    # e.g. certificate.json's own row (see
                    # sha256_omitted_reason). Nothing to compare; skip, don't fail.
                    continue
                if status == "absent":
                    continue
                if name not in entry_names:
                    file_results.append((
                        f"present in the zip: {name}",
                        False,
                        f"manifest lists {name!r} as status={status!r} with a recorded "
                        "sha256, but no such entry exists in this zip.",
                    ))
                    continue
                actual = hashlib.sha256(zf2.read(name)).hexdigest()
                if actual == sha:
                    file_results.append((
                        f"sha256 matches: {name}",
                        True,
                        f"sha256 = {actual}, matches manifest.json.",
                    ))
                else:
                    file_results.append((
                        f"sha256 matches: {name}",
                        False,
                        f"sha256(zip entry) = {actual} but manifest.json records {sha!r} "
                        f"for {name!r}. This file was altered after the manifest was "
                        "written and signed — rewriting the manifest's own sha256 row to "
                        "match does not help, because the manifest's bytes are themselves "
                        "bound to the certificate's signature (link 2/3 above).",
                    ))

        extra = sorted(entry_names - named - {MANIFEST_ENTRY})
        if extra:
            print("  [WARN] zip entries not listed in manifest.json's files:")
            for name in extra:
                print(f"         {name}")
            print("         Not scored as a failure: the certificate's signature commits")
            print("         to manifest.json's bytes, and the manifest never claimed")
            print("         anything about these entries one way or the other — but an")
            print("         examiner should know they are here and unaccounted for.")
            print()

    for name, passed, detail in file_results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        print(f"         {detail}")
        print()

    files_ok = all(r[1] for r in file_results)
    all_pass = binding_ok and files_ok

    print("=" * 60)
    if all_pass:
        print("RESULT: BUNDLE VERIFIED ✓")
        print()
        print(f"  The certificate's signature covers statement.bundle_binding, which")
        print(f"  matches sha256({MANIFEST_ENTRY}) for the {MANIFEST_ENTRY} actually in this")
        print("  zip, and every present file in that manifest matches its recorded")
        print("  sha256. Signature -> manifest -> files, unbroken.")
    else:
        print("RESULT: BUNDLE VERIFICATION FAILED ✗")
        print()
        print("  Do not rely on this bundle. One or more links in the chain below the")
        print("  certificate's own signature failed — see the checks above for which")
        print("  file or field broke it.")
    print("=" * 60)

    return EXIT_OK if all_pass else EXIT_TAMPER


# ---------------------------------------------------------------------------
# Positional INPUT auto-detection (zip / PDF / bare JSON)
#
# Ported from the standalone examiner-facing verifier
# (coriqo-seal-verifier/verify_proof.py's load_bundle_input), which lets an
# examiner pass one file and skip choosing --proof/--certificate/--bundle by
# hand. That copy's extraction pulls certificate.json or proof.json out of a
# zip or PDF and checks ONLY that object — which is exactly wrong for a
# Coriqo deliverables bundle (a zip with manifest.json), because this file's
# --bundle mode exists precisely to catch a payload file tampered with AND
# its manifest.json sha256 row rewritten to match: the extracted-certificate
# check alone would report that bundle VERIFIED.
#
# So routing here adds one rule the standalone copy does not have: a zip
# carrying manifest.json is a deliverables bundle and goes to run_bundle()
# for the full signature -> manifest -> file check, same as --bundle. Only a
# zip WITHOUT manifest.json, a PDF, or bare JSON takes the weaker
# extract-and-verify-only-that-object path — and that path always says so.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Tenant record bundle (SPEC.md §13, W1-D). A directory (not a single JSON
# file, not a deliverables.zip) produced by POST /api/v1/checkpoints/export:
# every checkpoint, the full governance_events leaf set, keys, audit log,
# and a document manifest, anchored under one signed continuity certificate
# embedded in manifest.json. Distinct from run_bundle() above (a
# deliverables.zip's engagement-scoped manifest+certificate.json pair) —
# this checks a whole tenant's chain, not one engagement's deck.
# ---------------------------------------------------------------------------

def _event_hash_of(row: dict) -> str:
    """Recompute event_hash the same way the Coriqo server does
    compute_governance_event_hash does: sha256 of the canonical JSON of
    {seq, actor, action, model_version_id, from_status, to_status, notes,
    prev_hash, [oversight]}. Kept in sync with that function deliberately —
    SPEC.md §12 freezes the event hash field set, so this is not expected to
    drift."""
    import hashlib as _hashlib
    hashable = {
        "seq": row.get("seq"), "actor": row.get("actor"), "action": row.get("action"),
        "model_version_id": row.get("version_id"), "from_status": row.get("from_status"),
        "to_status": row.get("to_status"), "notes": row.get("notes"),
        "prev_hash": row.get("prev_hash"),
    }
    if row.get("oversight") is not None:
        hashable["oversight"] = row["oversight"]
    return _hashlib.sha256(_canonical_bytes(hashable)).hexdigest()


# SPEC.md 4.5. The fields a sealed read's hash commits to, and only these.
# Mirrors how the Coriqo server hashes a read event.
_ACCESS_EVENT_FIELDS = (
    "seq", "subject_ref", "actor_id", "actor_label", "actor_type", "accessed_at",
    "access_kind", "seal_reason", "record_count", "query_fingerprint",
    "declared_purpose_id", "prev_hash",
)


def access_event_hash_of(row: dict) -> str:
    """Recompute a sealed read's event_hash (SPEC.md 4.5): SHA-256 over the
    canonical bytes of exactly _ACCESS_EVENT_FIELDS taken from `row`. Any
    other key on the row (event_id, ordinal, event_hash) is ignored."""
    import hashlib as _hashlib
    return _hashlib.sha256(
        _canonical_bytes({k: row.get(k) for k in _ACCESS_EVENT_FIELDS})
    ).hexdigest()


def check_access_rows(rows: list) -> list:
    """Problems with a sealed-read log (SPEC.md 4.5), [] when sound: every
    row re-derives its hash, ordinals strictly increase, and each subject's
    rows run seq 0,1,2... with each prev_hash equal to the previous
    event_hash (genesis 64 zeros)."""
    problems = []
    last_ordinal = None
    heads: dict = {}
    for row in rows:
        ordinal = row.get("ordinal")
        if last_ordinal is not None and not (isinstance(ordinal, int) and ordinal > last_ordinal):
            problems.append(f"sealed read {row.get('event_id')}: ordinal {ordinal!r} is out of order")
            break
        last_ordinal = ordinal
        event_hash = row.get("event_hash")
        if not isinstance(event_hash, str) or access_event_hash_of(row) != event_hash:
            problems.append(
                f"sealed read {row.get('event_id')}: content does not match its event_hash")
            break
        subject = row.get("subject_ref")
        expected_seq, expected_prev = heads.get(subject, (0, "0" * 64))
        if row.get("seq") != expected_seq or row.get("prev_hash") != expected_prev:
            problems.append(
                f"sealed read {row.get('event_id')}: chain for {subject!r} is broken at "
                f"seq {row.get('seq')!r}")
            break
        heads[subject] = (expected_seq + 1, row.get("event_hash"))
    return problems


def access_log_shape_problem(log) -> str | None:
    """Why a signed access_log cannot be checked, or None when it has the
    SPEC.md 4.5 shape: an object whose ordinal_watermark and tree_size are
    non-negative integers and whose merkle_root is 64 hex characters. A
    malformed log is a failed check, never a crash of the whole run."""
    if not isinstance(log, dict):
        return f"access_log is {type(log).__name__}, not an object"
    for key in ("ordinal_watermark", "tree_size"):
        v = log.get(key)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            return f"access_log.{key} is {v!r}, not a non-negative integer"
    root = log.get("merkle_root")
    if not isinstance(root, str) or len(root) != 64:
        return f"access_log.merkle_root is {root!r}, not 64 hex characters"
    try:
        bytes.fromhex(root)
    except ValueError:
        return f"access_log.merkle_root is {root!r}, not 64 hex characters"
    return None


def access_log_root(rows: list, watermark: int, tree_version: int) -> tuple:
    """(merkle_root_hex, tree_size) over the sealed reads with
    ordinal <= watermark, in ordinal order: what sth_body.access_log signs."""
    leaves = [bytes.fromhex(r["event_hash"]) for r in rows
              if isinstance(r.get("ordinal"), int) and r["ordinal"] <= watermark]
    return _merkle_root_for(leaves, tree_version).hex(), len(leaves)


def _check_bundle_access_log(dir_path: str, checkpoint_files: list,
                             sig_ok_by_cp_id: dict, results: list) -> None:
    """Sealed-read log (SPEC.md 4.5, 13.4 step 4d). Recompute the sealed-read log from
    access_events.jsonl and every signed access_log root from it. Adds no
    result when the bundle carries neither, so a bundle made before reads were sealed
    reports exactly what it always did."""
    name = "sealed-read log reproduces every signed access_log"
    path = os.path.join(dir_path, "access_events.jsonl")
    rows = []
    problems = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    problems.append(f"access_events.jsonl line {n} is not JSON")
                    continue
                if not isinstance(row, dict):
                    problems.append(f"access_events.jsonl line {n} is not an object")
                    continue
                rows.append(row)
    signed = []
    for cp_path in checkpoint_files:
        with open(cp_path, "r", encoding="utf-8") as fh:
            cp = json.load(fh)
        if isinstance(cp, dict) and cp.get("access_log") is not None:
            signed.append((os.path.splitext(os.path.basename(cp_path))[0], cp))
    if not rows and not signed and not problems:
        return
    if not problems:
        problems = check_access_rows(rows)
    if problems:
        # Rows that do not re-derive cannot anchor any signed root.
        results.append((name, False, "; ".join(problems)))
        return
    covered = 0
    for cp_id, cp in signed:
        log = cp["access_log"]
        shape = access_log_shape_problem(log)
        if shape is not None:
            problems.append(f"checkpoint {cp_id}: {shape}")
            continue
        tree_version = cp.get("tree_version") or 1
        if tree_version not in (1, 2):
            problems.append(f"checkpoint {cp_id}: unknown tree_version {tree_version!r}")
            continue
        root, size = access_log_root(rows, log["ordinal_watermark"], tree_version)
        if root != log.get("merkle_root") or size != log.get("tree_size"):
            problems.append(
                f"checkpoint {cp_id}: signed access_log does not reproduce from "
                f"access_events.jsonl ({size} read(s) up to ordinal "
                f"{log.get('ordinal_watermark')})")
        elif not sig_ok_by_cp_id.get(cp_id):
            problems.append(
                f"checkpoint {cp_id}: access_log reproduces, but the checkpoint's own "
                "signature did not verify, so it proves nothing")
        else:
            covered = max(covered, size)
    detail = ("; ".join(problems) if problems else
              f"{len(rows)} sealed read(s) re-derive and link; {covered} are inside a "
              f"signed access_log" + (f", {len(rows) - covered} await the next checkpoint"
                                      if len(rows) > covered else ""))
    results.append((name, not problems, detail))


def _sha256_file(path: str) -> str:
    import hashlib as _hashlib
    with open(path, "rb") as fh:
        return _hashlib.sha256(fh.read()).hexdigest()


def _v1_merkle_root(leaf_data: list[bytes]) -> bytes:
    """
    Rebuild a tree_version 1 (duplicate-last-node) Merkle root from raw
    leaf pre-images — mirrors the Coriqo server
    byte-for-byte. Frozen construction (SPEC.md §5.2.1); every checkpoint
    sealed under it must keep verifying against exactly this shape.
    """
    if not leaf_data:
        return hashlib.sha256(b"").digest()
    current = [_leaf_hash(d) for d in leaf_data]
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left
            nxt.append(_node_hash(left, right))
        current = nxt
    return current[0]


def _merkle_root_for(leaf_data: list[bytes], tree_version: int) -> bytes:
    """Dispatch to the tree construction the checkpoint declares — the same
    two constructions the Coriqo server supports.
    `_rfc6962_root` already applies the leaf-hash prefix itself, matching
    `_v1_merkle_root` above."""
    return _rfc6962_root(leaf_data) if tree_version == 2 else _v1_merkle_root(leaf_data)


def _load_bundle_events_by_version(dir_path: str) -> dict[str, list[dict]]:
    """Every events/<version_id>.jsonl row, per version, in ordinal order."""
    events_dir = os.path.join(dir_path, "events")
    by_version: dict[str, list[dict]] = {}
    if not os.path.isdir(events_dir):
        return by_version
    for fname in sorted(os.listdir(events_dir)):
        if not fname.endswith(".jsonl"):
            continue
        version_id = fname[:-len(".jsonl")]
        rows = []
        with open(os.path.join(events_dir, fname), "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        rows.sort(key=lambda r: r.get("ordinal", 0))
        by_version[version_id] = rows
    return by_version


def _check_bundle_merkle_roots(
    dir_path: str, checkpoint_files: list, sig_ok_by_cp_id: dict, results: list,
    by_version: dict | None = None,
) -> set:
    """
    Closes the gap docs/architecture/domains/checkpoints.md documents:
    run_bundle_dir checked events/*.jsonl's own hash-chain linkage (step 4)
    but never recomputed a checkpoint's *signed* merkle_root from the leaf
    range that produced it. Without this, every other bundle-dir check is
    provenance-blind — a forger who discards the real events and writes
    fabricated ones that still hash-chain cleanly (including replaying a
    genuine key.succession row verbatim) passed every prior check, because
    none of them tied the events file's CONTENT to anything the forger
    could not fabricate. Found by chain-guard review running exactly that
    exploit against this repository's own succession-binding fixture — and a
    SECOND round of review found that the first fix here could itself be
    switched off: a checkpoint's own (unsigned) `quarantine` field was
    treated as a reason to skip recomputation entirely, so forging a
    checkpoint with `"quarantine": {...}` bypassed this check outright and
    the bundle still came back CONTINUITY VERIFIED.

    `quarantine` is operator-set, unsigned metadata a forger can write
    freely — it means "do not trust this checkpoint's SIGNATURE" (the
    public key may be gone, per `signing-key-id-collision-dev`), never
    "do not check whether its claimed merkle_root reproduces." Recomputing
    a root is pure hashing over data already on disk; it needs no key at
    all, so there is no legitimate reason a quarantine declaration should
    suppress it — and a forger being ABLE to suppress it by setting an
    unsigned field is precisely the bypass. Every checkpoint bearing a
    merkle_root is therefore recomputed here regardless of quarantine, and
    a mismatch is a hard failure of this check regardless of quarantine.

    A checkpoint's Ed25519 signature covers `merkle_root` inside
    `sth_body` (§6/§7.3) — the one thing a forger cannot fake without the
    signing key. Recomputing that root from the ordinal-ordered leaves in
    events/*.jsonl and comparing against the signed value is what actually
    binds a bundle's events/*.jsonl to something its own author cannot
    fabricate — PROVIDED the checkpoint's own signature also independently
    verified; a root that merely reproduces a claimed field on a
    checkpoint whose signature could not itself be checked (quarantined,
    or a failed signature) proves nothing, since the forger who controls
    both the events file and an unsigned `merkle_root` field can make them
    agree trivially. `sig_ok_by_cp_id` (built earlier, from the actual
    per-checkpoint signature check) is what distinguishes "this root is
    real evidence" from "this root is just the forger's own arithmetic."

    Leaf-set rule, matching
    the Coriqo server's checkpoint issuer exactly: a
    version-scoped checkpoint's leaves are that version's events/*.jsonl
    ONLY; an org_default checkpoint's (`version_id` null) leaves are EVERY
    version's events combined, in one GLOBAL ordinal order — never
    per-file. Both are bounded to `ordinal <= ordinal_watermark` when the
    checkpoint records one, so recomputing an older checkpoint reads what
    it actually sealed, not the bundle's live tail.

    A checkpoint with no `merkle_root` at all (true v1/pre-tree — see
    SPEC.md §13.5) has nothing to recompute; it does not fail this check
    (already disclosed as non-reproducible elsewhere) but also contributes
    nothing to the returned trust set.

    Defense in depth, not currently exploitable given the checks
    downstream: `version_id` picks which leaf file/leaf-set a checkpoint
    reads, but `version_id` is NOT itself inside the signed `sth_body`
    (only `subject`/`issued_at`/`length`/`head_hash`/`merkle_root`/
    `tree_size`/`key_id` are). Before using a checkpoint's `version_id`,
    the SIGNED `subject` field is asserted to actually name that same
    version (`f"version:{version_id}"`, or `"org_default"` when
    `version_id` is absent) — a checkpoint file where the two disagree
    fails loudly here rather than silently reading the wrong leaf source.

    Returns `trusted_leaf_hashes`: the set of `event_hash` hex strings that
    are members of the leaf range of at least one checkpoint whose
    signature independently verified AND whose recomputed root matched its
    signed merkle_root — i.e., hashes actually proven to be part of a real,
    signed history, from EITHER a version-scoped OR an org_default
    checkpoint (org_default's combined leaf set counts for every version
    it spans — this is also what makes an org_default-only checkpoint
    gate a version's succession binding, closing the gap where only
    version-scoped checkpoints were ever consulted). Used by the
    succession-binding check below: a succession event can only be
    trusted to mark a real position in history if its own event_hash is a
    member of this set.
    """
    if by_version is None:
        by_version = _load_bundle_events_by_version(dir_path)
    # Global ordinal order across every version's events, for org_default's
    # (version_id-less) checkpoints — exactly _load_events()'s un-filtered
    # query order.
    all_rows_global = sorted(
        (row for rows in by_version.values() for row in rows),
        key=lambda r: r.get("ordinal", 0),
    )

    trusted_leaf_hashes: set = set()
    problems = []
    checked = 0
    for path in checkpoint_files:
        cp_id = os.path.splitext(os.path.basename(path))[0]
        with open(path, "r", encoding="utf-8") as fh:
            cp = json.load(fh)
        merkle_root = cp.get("merkle_root")
        if merkle_root is None:
            # True v1-no-tree checkpoint — already reported non-reproducible
            # elsewhere (SPEC.md §13.5); nothing to recompute. NOT the same
            # as "quarantined" — a quarantined checkpoint that DOES carry a
            # merkle_root is still recomputed below.
            continue
        version_id = cp.get("version_id")
        subject = cp.get("subject")
        # Defense in depth: `version_id` picks which leaf file this
        # checkpoint reads, but version_id is NOT itself inside the signed
        # sth_body (only subject/issued_at/length/head_hash/merkle_root/
        # tree_size/key_id are — see the sth_body construction in the
        # per-checkpoint signature check above). Nothing else asserts the
        # SIGNED `subject` actually agrees with the unsigned `version_id`
        # label used to pick that file. Not currently exploitable given
        # the field-match/content/leaf-membership checks downstream, but a
        # checkpoint file edited to carry a mismatched pair should fail
        # loudly here rather than silently read the wrong leaf source.
        #
        # The rule mirrors the server's (checkpoints/service.py issue() and
        # _load_events): a version_id forces the subject to version:<id> and
        # reads that version's chain; ANY other subject reads the org-wide
        # chain. "org_default" is not the only org-wide subject: a package
        # seal signs "package:<id>" and the examiner-package seal signs
        # "examiner_package". Requiring "org_default" failed every org- and
        # model-level package seal as a mismatch, on honest bundles.
        if not package_attestation_matches_subject(subject, cp.get("package_attestation")):
            problems.append(
                f"{cp_id}: this checkpoint's SIGNED subject ({subject!r}) names a "
                "different package than its SIGNED package_attestation.package_id "
                f"({(cp.get('package_attestation') or {}).get('package_id')!r}) "
                "(SPEC.md 6.2)."
            )
            checked += 1
            continue
        subject_ok, expected_desc = subject_matches_leaf_source(subject, version_id)
        if not subject_ok:
            problems.append(
                f"{cp_id}: this checkpoint's SIGNED subject ({subject!r}) does not "
                f"match its own version_id field ({version_id!r}) — expected "
                f"{expected_desc}. version_id is not itself covered by the "
                "signature, so a checkpoint file where the two disagree could "
                "otherwise cause the wrong events/*.jsonl leaf source to be read."
            )
            checked += 1
            continue
        tree_version = cp.get("tree_version") or 1
        watermark = cp.get("ordinal_watermark")
        rows = by_version.get(version_id, []) if version_id else all_rows_global
        if watermark is not None:
            rows = [r for r in rows if r.get("ordinal", 0) <= watermark]

        leaf_hex = [r.get("event_hash") or "" for r in rows]
        leaf_data = []
        bad_hex = False
        for h in leaf_hex:
            try:
                leaf_data.append(bytes.fromhex(h))
            except ValueError:
                bad_hex = True
                break

        checked += 1
        if bad_hex:
            ok = False
            detail = (f"{cp_id}: an events row's event_hash is not valid hex — cannot "
                       "recompute this checkpoint's Merkle root")
        else:
            recomputed = _merkle_root_for(leaf_data, tree_version).hex()
            tree_size = cp.get("tree_size")
            ok = recomputed == merkle_root and (tree_size is None or len(leaf_data) == tree_size)
            if not ok:
                where = f"events/{version_id}.jsonl" if version_id else "events/*.jsonl (org_default, combined)"
                detail = (
                    f"{cp_id}: recomputed Merkle root from {len(leaf_data)} leaf(ves) in "
                    f"{where} does not match this checkpoint's own SIGNED merkle_root "
                    f"({recomputed} != {merkle_root}). The events file's hash-chain can be "
                    "internally consistent (step 4 above) while still not being the leaf "
                    "set that actually produced the signature this checkpoint carries — "
                    "chain-linked is not the same as signed-over. Checked regardless of "
                    "this checkpoint's quarantine status: quarantine excuses a broken "
                    "SIGNATURE, never an unreproducible root."
                )
        if not ok:
            problems.append(detail)
        # Only a checkpoint whose OWN signature independently verified makes
        # its recomputed-and-matching leaves trustworthy evidence — a
        # quarantined or signature-failed checkpoint's matching root proves
        # nothing (the forger controls both the events file and this
        # unsigned unverifiable claim), so its leaves are never added to
        # the trust set even when the arithmetic happens to agree.
        if ok and sig_ok_by_cp_id.get(cp_id):
            trusted_leaf_hashes.update(leaf_hex)

    if checked:
        results.append((
            "checkpoint Merkle roots recompute from events/*.jsonl leaves",
            not problems,
            "; ".join(problems) if problems else
            f"{checked} checkpoint(s) with a Merkle root: each one's signed merkle_root "
            "is reproduced from the ordinal-ordered event_hash leaves actually on disk",
        ))
    return trusted_leaf_hashes


def _check_bundle_succession_binding(
    dir_path: str, certs: dict, results: list,
    trusted_leaf_hashes: set | None = None,
) -> None:
    """
    SPEC.md §9.3.5 — closes the certificate-succession replay gap, in
    --bundle-dir mode only.

    A certificate's `succession` record is a free-floating signed
    statement (§9.3): genuine, but not tied to any specific chain — see
    "What this checker does not do" under §9.3 for the exploit this
    leaves open in --proof/--certificate mode. A tenant bundle carries
    something a bare certificate does not: the actual
    `events/<version_id>.jsonl` for the subject, and key rotation
    appends a real `key.succession` GovernanceEvent into that exact chain
    at the moment of a genuine handoff (SPEC.md §9.3.5).

    Binding rule, three checks per succession record, ALL required:

    1. **Field match.** A `key.succession` event in
       events/<version_id>.jsonl — matched first by the
       outgoing_key_id/incoming_key_id pair — must agree with the signed
       record, field for field (minus signature_hex).
    2. **Content integrity of that SPECIFIC matched row**, recomputed
       UNCONDITIONALLY — regardless of the row's own
       `content_hash_verifiable` flag. That flag discloses HISTORICAL
       non-reproducibility (seeded/legacy rows predating the current hash
       formula, SPEC.md §13.3) — it is not a license to skip checking the
       one row this entire mechanism depends on, and a second round of
       chain-guard review found exactly that hole: a bundle that kept the
       succession row's `event_hash`/`prev_hash`/`ordinal` untouched
       (so step 4's chain-linkage and this function's original
       field-match both passed) while REWRITING its `action`/`notes`
       content and marking `content_hash_verifiable: false` on it,
       specifically to dodge step 4's flag-gated re-derivation. Recomputing
       `event_hash` from the row's actual current content and requiring it
       to still equal the row's stored `event_hash` catches this: content
       that no longer matches its own claimed hash is rejected regardless
       of any flag saying otherwise.
    3. **Provenance** — the matched row's `event_hash` must be a member of
       `trusted_leaf_hashes` (built by `_check_bundle_merkle_roots`, run
       earlier as step 3b): the set of leaves proven to be part of a
       checkpoint whose OWN signature independently verified AND whose
       recomputed root matched its signed merkle_root. Checks 1 and 2
       alone are not enough — a forger can write a perfectly
       self-consistent, correctly-hashed, correctly-linked event that was
       simply never covered by any checkpoint's signed watermark at all
       (appended past the last real seal). Membership in a checkpoint's
       verified leaf set is what proves this exact event was part of the
       history the signing key actually attested to, not merely present
       in a file whose hash chain never contradicts itself.

    Chain-linked is not signed-over, and self-consistent is not the same
    as covered by a verified checkpoint — the mistake two earlier versions
    of this function made, in each of those two different ways.

    org_default carries no succession records at all (only version-scoped
    chains can — see certificate.py::_succession_records), so this is a
    no-op for that subject.
    """
    trusted_leaf_hashes = trusted_leaf_hashes or set()
    for subject, cert in sorted(certs.items()):
        if not subject.startswith("version:"):
            continue
        version_id = subject.split(":", 1)[1]
        statement = (cert or {}).get("statement") or {}
        succession = [r for r in (statement.get("succession") or []) if isinstance(r, dict)]
        if not succession:
            continue

        events_path = os.path.join(dir_path, "events", f"{version_id}.jsonl")
        # Keep the RAW row alongside its parsed notes — content-integrity
        # re-derivation (check 2) needs the row's actual current fields
        # (action, actor, from_status, to_status, prev_hash, oversight,
        # notes-as-stored-string), not just the parsed succession record.
        chain_rows: list[dict] = []
        if os.path.isfile(events_path):
            with open(events_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    row = json.loads(line)
                    if row.get("action") != "key.succession":
                        continue
                    chain_rows.append(row)

        problems = []
        for r in succession:
            outgoing = r.get("outgoing_key_id")
            incoming = r.get("incoming_key_id")
            label = f"{outgoing!r} -> {incoming!r}"
            record_body = {k: v for k, v in r.items() if k != "signature_hex"}

            candidates = []
            for row in chain_rows:
                try:
                    notes = json.loads(row.get("notes") or "{}")
                except (TypeError, ValueError):
                    continue
                if not isinstance(notes, dict):
                    continue
                if notes.get("outgoing_key_id") == outgoing and notes.get("incoming_key_id") == incoming:
                    candidates.append((row, notes))

            if not candidates:
                problems.append(
                    f"{subject}: succession record {label} has no matching "
                    f"key.succession event anywhere in events/{version_id}.jsonl. A "
                    "genuine signed succession record with no matching event chained "
                    "into THIS bundle's own history is exactly the splice this check "
                    "exists to catch — the record may be genuine for some chain, but "
                    "not for this one."
                )
                continue

            bound = False
            failure_reasons = []
            for row, notes in candidates:
                event_body = {k: v for k, v in notes.items() if k != "signature_hex"}
                if event_body != record_body:
                    mismatch = {
                        k: (record_body.get(k), event_body.get(k))
                        for k in sorted(set(record_body) | set(event_body))
                        if record_body.get(k) != event_body.get(k)
                    }
                    failure_reasons.append(
                        f"matched by key_id pair but its fields disagree with the "
                        f"signed record: {mismatch}"
                    )
                    continue

                # Check 2 — content integrity, UNCONDITIONAL: recompute
                # this row's event_hash from its OWN current content,
                # regardless of content_hash_verifiable. A row whose stored
                # hash no longer matches its own content has been rewritten
                # after the fact — the exact bypass chain-guard review's
                # second round found.
                recomputed_hash = _event_hash_of(row)
                stored_hash = row.get("event_hash")
                if recomputed_hash != stored_hash:
                    failure_reasons.append(
                        f"matched a key.succession event whose stored event_hash "
                        f"({stored_hash}) does NOT match a fresh hash of its own "
                        f"content ({recomputed_hash}) — this row's content was "
                        "altered after the fact; content_hash_verifiable is "
                        "ignored here on purpose, because it is exactly the flag a "
                        "forger would clear to hide this"
                    )
                    continue

                # Check 3 — provenance: this exact leaf must actually be
                # part of a checkpoint whose signature verified AND whose
                # root reproduced. A self-consistent, correctly-hashed
                # event that was simply never sealed by any checkpoint is
                # not evidence of anything.
                if stored_hash not in trusted_leaf_hashes:
                    failure_reasons.append(
                        f"matched and content-verified, but its event_hash "
                        f"({stored_hash}) is not part of the leaf range of any "
                        "checkpoint whose signature verified and whose Merkle root "
                        "reproduced (see 'checkpoint Merkle roots recompute from "
                        "events/*.jsonl leaves' above) — a well-formed event that was "
                        "never actually sealed proves nothing"
                    )
                    continue

                bound = True
                break

            if not bound:
                problems.append(
                    f"{subject}: succession record {label} " + "; ".join(failure_reasons)
                )
        if problems:
            results.append(("succession bound to chain (bundle-dir)", False, "; ".join(problems)))
        else:
            results.append((
                "succession bound to chain (bundle-dir)",
                True,
                f"{len(succession)} succession record(s) for {subject} each match a "
                f"key.succession event in events/{version_id}.jsonl whose own content "
                "re-derives its stored event_hash and whose event_hash is a member of "
                "a checkpoint's independently verified, signed Merkle root (SPEC.md "
                "§9.3.5)",
            ))


def subject_matches_leaf_source(subject, version_id):
    """(ok, expected) for a checkpoint's SIGNED subject against its unsigned
    version_id, which picks the events/*.jsonl leaf source.

    Mirrors the server (checkpoints/service.py issue() and _load_events): a
    version_id forces the subject to version:<id>; any other subject seals the
    org-wide chain. "org_default" is not the only org-wide subject: package
    seals sign "package:<id>" and the examiner-package seal signs
    "examiner_package"."""
    if version_id:
        return subject == f"version:{version_id}", f"'version:{version_id}'"
    ok = isinstance(subject, str) and bool(subject) and not subject.startswith("version:")
    return ok, "an org-wide subject (anything not starting 'version:')"


def package_attestation_matches_subject(subject, attestation):
    """False when a checkpoint signs subject "package:<id>" and a
    package_attestation for a different package (SPEC.md 6.2). Both are
    inside the signed body, so a mismatch is a malformed seal, not tampering
    in transit. A version-scoped package seal signs "version:<id>" (the server
    rewrites the subject), so only "package:" subjects are compared."""
    if attestation is None or not isinstance(subject, str) or not subject.startswith("package:"):
        return True
    return isinstance(attestation, dict) and attestation.get("package_id") == subject.split(":", 1)[1]


# Record-wide package seal (SPEC.md 6.2.3-6.2.6). The heads below are
# signed inside package_attestation.record_heads, but SPEC.md does not publish
# their hash formulas and the tenant bundle does not carry their rows, so no
# verifier can recompute them. They are reported as "signed, not checkable
# offline" and never counted as a pass.
SIGNED_NOT_CHECKABLE_HEADS = (
    "committee_decisions", "committee_attestations",
    "examination_questions", "package_approvals",
)
_GE_GENESIS_HEAD = "0" * 64


def _iso_time(ts):
    from datetime import datetime as _dt
    if not isinstance(ts, str) or not ts:
        return None
    try:
        t = _dt.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _rows_upto(rows: list[dict], watermark: int) -> list[dict]:
    return [r for r in rows if (r.get("ordinal") or 0) <= watermark]


def check_package_record_seal(cp_id: str, cp: dict, by_version: dict,
                              checkpoints: dict, sig_ok_by_cp_id: dict,
                              limits: list | None = None) -> tuple[list, list, list]:
    """Check one package seal's record-wide attestation against the bundle
    (SPEC.md 6.2.3-6.2.5). Returns (problems, checked, signed_only):
    `problems` are failures, `checked` describes what recomputed, and
    `signed_only` names signed heads this verifier cannot recompute.
    `limits`, when given, collects what this check cannot prove offline (an
    upper fence end with no checkpoint); those are disclosed, never passed.

    `checkpoints` maps checkpoint_id -> checkpoint dict for every checkpoint
    in the bundle; the fence posts are looked up there."""
    att = cp.get("package_attestation") or {}
    problems: list[str] = []
    checked: list[str] = []
    signed_only: list[str] = []
    if limits is None:
        limits = []
    heads = att.get("record_heads") or {}
    wm = cp.get("ordinal_watermark")
    scope = att.get("scope") or {}

    ge = heads.get("governance_events")
    if ge is None and ("record_heads" in att or "period_fence" in att):
        # A record-wide seal always signs its governance-event heads; a
        # missing list must not read as "nothing to check" (SPEC.md 6.2.5).
        problems.append(f"{cp_id}: record-wide package seal carries no "
                        "record_heads.governance_events, so its governance chains are unchecked")
    if ge is not None:
        if wm is None:
            problems.append(f"{cp_id}: governance-event heads are signed but the checkpoint "
                            "has no ordinal_watermark to recompute them at")
        else:
            listed: dict = {}
            for h in ge:
                vid = (h or {}).get("version_id")
                if vid in listed:
                    problems.append(f"{cp_id}: version {vid!r} is listed twice in record_heads")
                listed[vid] = h
            for vid, h in sorted(listed.items(), key=lambda kv: str(kv[0])):
                rows = _rows_upto(by_version.get(vid, []), wm)
                exp_len = len(rows)
                exp_head = rows[-1].get("event_hash") if rows else _GE_GENESIS_HEAD
                if h.get("length") != exp_len or h.get("head_hash") != exp_head:
                    problems.append(
                        f"{cp_id}: signed head of version {vid} is length {h.get('length')} / "
                        f"{h.get('head_hash')}, but events/{vid}.jsonl up to ordinal {wm} gives "
                        f"length {exp_len} / {exp_head}")
            if scope.get("version_id"):
                if set(listed) != {scope["version_id"]} or cp.get("version_id") != scope["version_id"]:
                    problems.append(f"{cp_id}: a version-pinned package must sign exactly the head "
                                    f"of version {scope['version_id']} and seal that version's chain")
            elif scope.get("model_id"):
                checked.append("model-pinned package: which versions belong to the model is not "
                               "in the bundle, so the version list itself is not checked")
            else:
                present = {vid for vid, rows in by_version.items() if _rows_upto(rows, wm)}
                missing = sorted(present - set(listed))
                if missing:
                    problems.append(f"{cp_id}: org-wide package omits the head of version(s) "
                                    f"{', '.join(missing)}, which have events inside the seal")
            checked.append(f"{len(listed)} governance-event chain head(s) recomputed at ordinal {wm}")

    fence = att.get("period_fence")
    if fence is not None:
        fw, tw = fence.get("from_watermark"), fence.get("to_watermark")
        if not (isinstance(fw, int) and isinstance(tw, int) and 0 <= fw <= tw):
            problems.append(f"{cp_id}: period_fence watermarks are malformed ({fw!r}, {tw!r})")
        else:
            # Every in-scope event inside the fence must be a leaf of this
            # seal. Not "to_watermark <= ordinal_watermark": a version-scoped
            # seal's watermark is that version's last ordinal, while the fence
            # is drawn in the org-wide ordinal space.
            if wm is not None:
                versions = ([h.get("version_id") for h in ge] if ge is not None
                            else [scope["version_id"]] if scope.get("version_id")
                            else list(by_version))
                outside = [f"{r.get('event_id')} (ordinal {r.get('ordinal')})"
                           for vid in versions for r in by_version.get(vid, [])
                           if fw < (r.get("ordinal") or 0) <= tw and (r.get("ordinal") or 0) > wm]
                if outside:
                    problems.append(f"{cp_id}: in-scope event(s) inside the period fence are not "
                                    f"sealed by this checkpoint (watermark {wm}): "
                                    + ", ".join(outside[:10]))
            for side, id_key, want_wm, bound_key in (
                ("from", "from_checkpoint_id", fw, "period_from"),
                ("to", "to_checkpoint_id", tw, "period_to"),
            ):
                post_id = fence.get(id_key) or ""
                bound = _iso_time(fence.get(bound_key))
                if not post_id:
                    if side == "from" and fw != 0:
                        problems.append(f"{cp_id}: period_fence names no lower checkpoint but "
                                        f"starts at ordinal {fw}, not 0")
                    continue
                post = checkpoints.get(post_id)
                if post is None:
                    problems.append(f"{cp_id}: fence checkpoint {post_id} is not in this bundle")
                    continue
                if not sig_ok_by_cp_id.get(post_id):
                    problems.append(f"{cp_id}: fence checkpoint {post_id}'s signature did not verify")
                    continue
                if post.get("version_id") or str(post.get("subject") or "").startswith("version:"):
                    problems.append(f"{cp_id}: fence checkpoint {post_id} is version-scoped; only an "
                                    "org-wide checkpoint bounds every chain")
                    continue
                if post.get("ordinal_watermark") != want_wm:
                    problems.append(f"{cp_id}: fence checkpoint {post_id} signs watermark "
                                    f"{post.get('ordinal_watermark')}, not {want_wm}")
                    continue
                issued = _iso_time(post.get("issued_at"))
                if issued is None or bound is None or (
                        issued > bound if side == "from" else issued < bound):
                    problems.append(
                        f"{cp_id}: fence checkpoint {post_id} was issued at {post.get('issued_at')}, "
                        f"which is {'after the period start' if side == 'from' else 'before the period end'} "
                        f"({fence.get(bound_key)})")
            if not (fence.get("to_checkpoint_id") or ""):
                # No checkpoint bounds the upper end: to_watermark is the
                # highest ordinal when the snapshot was built. Offline we can
                # check it is not below any checkpoint issued before the
                # build; we cannot check that no event written after the last
                # such checkpoint and before the build was cut off.
                built = _iso_time(fence.get("snapshot_built_at"))
                seal_at = _iso_time(cp.get("issued_at"))
                if built is None:
                    problems.append(f"{cp_id}: period_fence has no upper checkpoint and no "
                                    "snapshot_built_at, so its upper end cannot be checked")
                else:
                    if seal_at is not None and built > seal_at:
                        problems.append(f"{cp_id}: snapshot_built_at "
                                        f"{fence.get('snapshot_built_at')} is after the seal")
                    latest = None
                    for pid, post in checkpoints.items():
                        if (pid == cp_id or not sig_ok_by_cp_id.get(pid)
                                or post.get("version_id")
                                or str(post.get("subject") or "").startswith("version:")
                                or post.get("ordinal_watermark") is None):
                            continue
                        t = _iso_time(post.get("issued_at"))
                        if t is None or t > built:
                            continue
                        if post["ordinal_watermark"] > tw:
                            problems.append(
                                f"{cp_id}: period_fence ends at ordinal {tw}, but checkpoint {pid}, "
                                f"issued before the snapshot was built, already sealed up to "
                                f"{post['ordinal_watermark']}: the upper end was cut short")
                        if latest is None or t > latest[0]:
                            latest = (t, pid, post["ordinal_watermark"])
                    limits.append(
                        f"{cp_id}: the period fence's upper end ({tw}) is the highest event "
                        f"number when the snapshot was built ({fence.get('snapshot_built_at')}), "
                        "not a signed checkpoint. Checked: it is at least the watermark of every "
                        "checkpoint issued before the build"
                        + (f" (latest: {latest[1]}, {latest[2]})" if latest else "")
                        + ". Not checkable offline: that no event written after that checkpoint "
                        "and before the build was left out.")
            checked.append(f"period fence: ordinals {fw} < n <= {tw}, bounded by "
                           f"{fence.get('from_checkpoint_id') or 'the first event'} and "
                           f"{fence.get('to_checkpoint_id') or 'the snapshot build'}")

    for key in SIGNED_NOT_CHECKABLE_HEADS:
        if key in heads:
            val = heads[key]
            n = len(val) if isinstance(val, list) else 1
            signed_only.append(f"{key} ({n} chain head{'s' if n != 1 else ''})")
    return problems, checked, signed_only


def check_package_snapshot(snapshot_bytes: bytes, package_seals: list, by_version: dict,
                           sig_ok_by_cp_id: dict) -> tuple[list, list]:
    """--snapshot (SPEC.md 6.2.6). Hash the file's bytes (never a re-encoding,
    Rule 6.2.1), find the package seal that signed that digest, then confirm
    every in-scope governance event inside the signed period fence is listed
    in the snapshot's governance_events with the same event_hash.

    Returns (results, not_checked): results are (label, ok, detail)."""
    digest = hashlib.sha256(snapshot_bytes).hexdigest()
    match = [(i, c) for i, c in package_seals
             if (c.get("package_attestation") or {}).get("snapshot_sha256") == digest]
    if not match:
        return [("snapshot.json is a sealed package in this bundle", False,
                 f"sha256 {digest} is not the snapshot_sha256 of any package seal in the bundle")], []
    cp_id, cp = match[0]
    att = cp["package_attestation"]
    if not sig_ok_by_cp_id.get(cp_id):
        return [("snapshot.json is a sealed package in this bundle", False,
                 f"digest matches checkpoint {cp_id}, but that checkpoint's signature did not verify")], []
    results = [("snapshot.json is a sealed package in this bundle", True,
                f"sha256 {digest} is signed in checkpoint {cp_id} (package {att.get('package_id')})")]
    fence = att.get("period_fence")
    if fence is None:
        return results, ["period fence membership: this seal signs no period_fence "
                         "(package sealed before the fence existed)"]
    try:
        snapshot = json.loads(snapshot_bytes.decode("utf-8"))
    except ValueError as exc:
        return results + [("snapshot.json parses", False, str(exc))], []
    snap_fence = snapshot.get("period_fence") or {}
    fw, tw = fence.get("from_watermark"), fence.get("to_watermark")
    if (snap_fence.get("from_watermark"), snap_fence.get("to_watermark")) != (fw, tw):
        return results + [("snapshot period fence matches the signed one", False,
                           f"snapshot says {snap_fence.get('from_watermark')}..{snap_fence.get('to_watermark')}, "
                           f"seal signs {fw}..{tw}")], []
    ge_heads = (att.get("record_heads") or {}).get("governance_events")
    scope = att.get("scope") or {}
    if ge_heads is not None:
        versions = [h.get("version_id") for h in ge_heads]
    elif scope.get("version_id"):
        versions = [scope["version_id"]]
    else:
        versions = list(by_version)
    # The in-period list and the events inside the fence but dated outside
    # the period together must hold every fenced in-scope event (SPEC.md 6.2.6).
    listed = {e.get("event_id"): e.get("event_hash")
              for key in ("governance_events", "governance_events_outside_period")
              for e in snapshot.get(key) or [] if isinstance(e, dict)}
    missing, expected = [], 0
    for vid in versions:
        for r in by_version.get(vid, []):
            o = r.get("ordinal") or 0
            if fw < o <= tw:
                expected += 1
                if listed.get(r.get("event_id")) != r.get("event_hash"):
                    missing.append(f"{r.get('event_id')} (version {vid}, ordinal {o})")
    if missing:
        detail = (f"{len(missing)} of {expected} in-scope event(s) inside the fence are not in "
                  f"snapshot.json governance_events or governance_events_outside_period: "
                  + ", ".join(missing[:10])
                  + (" ..." if len(missing) > 10 else ""))
    else:
        detail = (f"all {expected} in-scope governance event(s) with ordinal in ({fw}, {tw}] "
                  f"across {len(versions)} version(s) are listed with matching event_hash")
    results.append(("every in-scope event inside the period fence is in snapshot.json", not missing, detail))
    return results, []


def _check_bundle_package_seals(dir_path: str, checkpoint_files: list, sig_ok_by_cp_id: dict,
                                results: list, snapshot_path: str | None = None,
                                by_version: dict | None = None) -> None:
    """Step 3c: record-wide package seals (SPEC.md 6.2.3-6.2.6). `by_version`
    is the events/*.jsonl map step 3b already loaded; read here only when a
    caller has none."""
    if by_version is None:
        by_version = _load_bundle_events_by_version(dir_path)
    checkpoints: dict = {}
    for path in checkpoint_files:
        with open(path, "r", encoding="utf-8") as fh:
            checkpoints[os.path.splitext(os.path.basename(path))[0]] = json.load(fh)
    package_seals = [(i, c) for i, c in sorted(checkpoints.items())
                     if c.get("package_attestation") is not None]
    problems, checked, signed_only_lines, limit_lines = [], [], [], []
    record_wide = 0
    for cp_id, cp in package_seals:
        att = cp["package_attestation"]
        if "record_heads" not in att and "period_fence" not in att:
            continue
        record_wide += 1
        if not sig_ok_by_cp_id.get(cp_id):
            problems.append(f"{cp_id}: signature did not verify, so its record heads prove nothing")
            continue
        p, c, s = check_package_record_seal(cp_id, cp, by_version, checkpoints, sig_ok_by_cp_id,
                                            limit_lines)
        problems += p
        checked += [f"{cp_id}: {x}" for x in c]
        if s:
            signed_only_lines.append(f"{cp_id}: {', '.join(s)}")
    if record_wide:
        results.append((
            "package seals: record heads and period fence recompute from the bundle",
            not problems,
            "; ".join(problems) if problems else "; ".join(checked),
        ))
    for line in signed_only_lines:
        print("  [SIGNED, NOT CHECKABLE OFFLINE] package record heads")
        print(f"         {line}")
        print("         These heads are inside the signature, but their hash formulas are not")
        print("         published and their rows are not in this bundle (SPEC.md 6.2.4).")
        print("         Not a pass and not a fail.")
        print()
    for line in limit_lines:
        print("  [NOT CHECKABLE OFFLINE] period fence upper end")
        print(f"         {line}")
        print("         Disclosed, not a pass (SPEC.md 6.2.5).")
        print()
    if snapshot_path:
        try:
            with open(snapshot_path, "rb") as fh:
                snapshot_bytes = fh.read()
        except OSError as exc:
            results.append(("--snapshot readable", False, str(exc)))
            return
        snap_results, not_checked = check_package_snapshot(
            snapshot_bytes, package_seals, by_version, sig_ok_by_cp_id)
        results.extend(snap_results)
        for line in not_checked:
            print("  [NOT CHECKED] " + line)
            print()


def run_bundle_dir(dir_path: str, pubkey_path: str | None = None,
                    keyring_path: str | None = None,
                    snapshot_path: str | None = None) -> int:
    """
    Verify a tenant record bundle directory (or an already-unzipped copy of
    one) offline. Returns an exit code — EXIT_OK / EXIT_TAMPER /
    EXIT_MALFORMED (a bundle is either produced or it isn't; there is no
    partial-seal EXIT_UNSEALED state here, unlike run_bundle()).

    Checks, in order, stopping at the first hard failure (SPEC.md §13.4):
      1. every file manifest.json.files names exists and hashes match;
      2. manifest.json.continuity_certificate verifies (same checks as
         --certificate) and covers every checkpoint on disk, by name, in
         either its certified or its disclosed-excluded set;
      3. each checkpoints/<id>.json signature verifies under keys/keys.json
         (or --keyring, when given);
      4. each events/<version_id>.jsonl chain re-hashes and links, oldest
         to newest.
    """
    import glob as _glob

    print("=" * 60)
    print("Coriqo — Tenant Record Bundle Verification")
    print("=" * 60)
    print()

    manifest_path = os.path.join(dir_path, "manifest.json")
    if not os.path.isfile(manifest_path):
        print(f"FAIL: {manifest_path} not found — this does not look like a "
              "tenant record bundle directory.")
        return EXIT_MALFORMED
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except Exception as exc:
        print(f"FAIL: manifest.json is not valid JSON: {exc}")
        return EXIT_MALFORMED
    if manifest.get("format") != "tenant_bundle_v1":
        print(f"FAIL: unrecognised bundle format {manifest.get('format')!r} "
              "(expected 'tenant_bundle_v1').")
        return EXIT_MALFORMED

    results: list[tuple[str, bool, str]] = []

    # --- 1. Every file's hash matches the manifest -------------------------
    files_map = manifest.get("files") or {}
    on_disk = set()
    for root, _dirs, names in os.walk(dir_path):
        for name in names:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, dir_path).replace(os.sep, "/")
            if rel == "manifest.json":
                continue
            on_disk.add(rel)
    missing = [rel for rel in files_map if rel not in on_disk]
    mismatched = []
    for rel, expected in files_map.items():
        if rel in missing:
            continue
        actual = _sha256_file(os.path.join(dir_path, rel))
        if actual != expected:
            mismatched.append(rel)
    unlisted = sorted(on_disk - set(files_map))
    ok = not missing and not mismatched
    detail = "every file in manifest.json.files is present with a matching sha256"
    if missing:
        detail = f"missing from disk: {missing}"
    elif mismatched:
        detail = f"sha256 mismatch: {mismatched}"
    elif unlisted:
        detail += f" (note: {len(unlisted)} file(s) on disk are not listed in the manifest: {unlisted[:5]})"
    results.append(("manifest file hashes", ok, detail))
    if not ok:
        for name, passed, det in results:
            print(f"  [{'PASS' if passed else 'FAIL'}] {name}\n         {det}\n")
        print("RESULT: TENANT BUNDLE VERIFICATION FAILED ✗")
        return EXIT_TAMPER

    # --- 2. Continuity certificates (one per subject) + checkpoint coverage -
    #
    # A tenant carries more than one subject: org_default plus one
    # `version:<id>` subject per model version, and a single org_default
    # certificate does not cover version-scoped checkpoints at all — they
    # are a different subject with a different Merkle tree. So
    # manifest.json carries a certificate PER SUBJECT
    # (continuity_certificates, keyed by subject), and coverage is checked
    # per checkpoint against the certificate for ITS OWN subject.
    certs = manifest.get("continuity_certificates")
    if not isinstance(certs, dict) or not certs:
        results.append(("continuity certificates present", False,
                         "manifest.json carries no continuity_certificates object"))
        for name, passed, det in results:
            print(f"  [{'PASS' if passed else 'FAIL'}] {name}\n         {det}\n")
        print("RESULT: TENANT BUNDLE VERIFICATION FAILED ✗")
        return EXIT_MALFORMED

    print("-- step 1/3: continuity certificates (one per subject) " + "-" * 8)
    print()
    cert_ok = True
    certified_by_subject: dict[str, set] = {}
    excluded_by_subject: dict[str, set] = {}
    for subject, cert in sorted(certs.items()):
        print(f"[subject: {subject}]")
        this_ok = isinstance(cert, dict) and verify_certificate_dict(cert, pubkey_path, keyring_path)
        cert_ok = cert_ok and this_ok
        statement = (cert or {}).get("statement") or {}
        certified_by_subject[subject] = {c.get("checkpoint_id") for c in statement.get("checkpoints", [])}
        excluded_by_subject[subject] = {c.get("checkpoint_id")
                                         for c in (statement.get("excluded_checkpoints") or [])}
        print()

    uncertified_subjects = manifest.get("uncertified_subjects") or []
    uncertified_by_subject = {u.get("subject"): u for u in uncertified_subjects if isinstance(u, dict)}

    checkpoint_files = sorted(_glob.glob(os.path.join(dir_path, "checkpoints", "*.json")))
    on_disk_ids = {os.path.splitext(os.path.basename(p))[0] for p in checkpoint_files}
    cp_subject_of: dict[str, str] = {}
    cp_quarantined: set = set()
    for p in checkpoint_files:
        with open(p, "r", encoding="utf-8") as fh:
            body = json.load(fh)
        cp_id = os.path.splitext(os.path.basename(p))[0]
        cp_subject_of[cp_id] = body.get("subject")
        if body.get("quarantine"):
            cp_quarantined.add(cp_id)

    uncovered = []
    disclosed_excluded = set()
    disclosed_uncertified = set()
    for cp_id in sorted(on_disk_ids):
        subject = cp_subject_of.get(cp_id)
        if subject in certified_by_subject and cp_id in certified_by_subject[subject]:
            continue
        if subject in excluded_by_subject and cp_id in excluded_by_subject[subject]:
            disclosed_excluded.add(cp_id)
            continue
        if subject in uncertified_by_subject and cp_id in cp_quarantined:
            # This subject's certificate could not be issued at all, but
            # THIS checkpoint carries its own quarantine declaration — a
            # disclosed reduction, not a coverage gap.
            disclosed_uncertified.add(cp_id)
            continue
        uncovered.append(cp_id)

    coverage_ok = not uncovered
    results.append((
        "every bundled checkpoint is certified or disclosed as excluded",
        coverage_ok,
        "every checkpoints/*.json id appears in its subject's certificate "
        "(certified or disclosed-excluded), or is individually quarantined "
        "under an uncertified subject" if coverage_ok else
        f"checkpoint(s) not covered by any certificate for their subject, and not "
        f"individually quarantined: {sorted(uncovered)}",
    ))
    reduced_range = bool(disclosed_excluded or disclosed_uncertified)

    # --- 3. Per-checkpoint signature -----------------------------------
    keys_path = os.path.join(dir_path, "keys", "keys.json")
    bundled_keys: dict[str, str] = {}
    bundled_revocations: list = []
    if os.path.isfile(keys_path):
        try:
            with open(keys_path, "r", encoding="utf-8") as fh:
                keys_doc = json.load(fh)
            for entry in keys_doc.get("keys", []):
                if entry.get("public_key_pem"):
                    bundled_keys[entry["key_id"]] = entry["public_key_pem"]
            bundled_revocations = keys_doc.get("revocations") or []
        except Exception as exc:  # noqa: BLE001
            results.append(("keys/keys.json readable", False, str(exc)))

    pinned = None
    if pubkey_path or keyring_path:
        try:
            pinned = _merge_pinned(pubkey_path, keyring_path)
        except ValueError as exc:
            results.append(("--keyring/--pubkey", False, str(exc)))

    # SPEC §9.2 / §13.3: a tenant bundle carries its signed revocation records
    # in keys/keys.json alongside the public keys. Reuse the certificate
    # path's index verbatim — one implementation of "is this revocation record
    # genuine, and from when", so a revocation read out of a bundle directory
    # and one read out of a continuity certificate cannot be judged
    # differently. The shim shapes keys.json into the {"statement":
    # {"revocations": ...}, "public_keys": ...} view _revocation_index reads,
    # the same trick run() already uses at the single-proof call site.
    _rev_view = {
        "statement": {"revocations": bundled_revocations} if bundled_revocations else {},
        "public_keys": {k: {"pem": v, "revoked": False} for k, v in bundled_keys.items()},
    }
    bundle_revoked_from, bundle_revocation_failures = _revocation_index(_rev_view, pinned)
    if bundled_revocations:
        results.append((
            "key revocation records (keys/keys.json)",
            not bundle_revocation_failures,
            "; ".join(bundle_revocation_failures) if bundle_revocation_failures else (
                f"{len(bundle_revoked_from)} signed revocation record(s) verified: "
                + ", ".join(f"{k} from {v}" for k, v in sorted(bundle_revoked_from.items()))
            ),
        ))

    # sig_ok_by_cp_id: whether THIS checkpoint's own signature independently
    # verified. False for quarantined checkpoints on purpose — quarantine
    # means the operator has said this checkpoint's signature cannot (or
    # should not) be trusted, and _check_bundle_merkle_roots/
    # _check_bundle_succession_binding downstream rely on this to tell "a
    # real, verified root" apart from "a root a forger's unsigned metadata
    # happens to agree with." A checkpoint absent from this dict (never
    # reached the loop) is treated the same as False by callers using
    # `.get(cp_id)`.
    sig_ok_by_cp_id: dict = {}
    sig_failures = []
    sig_skipped_quarantined = 0
    for path in checkpoint_files:
        with open(path, "r", encoding="utf-8") as fh:
            cp = json.load(fh)
        cp_id = os.path.splitext(os.path.basename(path))[0]
        if cp_id in cp_quarantined:
            # Already declared unverifiable, on the record, with a reason
            # (checkpoints/<id>.json's own `quarantine` field) and excluded
            # from its subject's certified range above. Re-running the same
            # signature check here would either repeat a known failure as a
            # fresh one or (rarer) note a technically-valid signature that
            # the operator quarantined for a different, undisclosed
            # reason — neither adds information the disclosure doesn't
            # already carry, so skip rather than double-report it.
            #
            # sig_ok_by_cp_id[cp_id] is deliberately left False (via the
            # dict default) — quarantine means this checkpoint's signature
            # is not trusted, so nothing downstream may treat this
            # checkpoint's merkle_root as verified evidence even if the
            # arithmetic happens to reproduce it (see _check_bundle_merkle_roots).
            sig_ok_by_cp_id[cp_id] = False
            sig_skipped_quarantined += 1
            continue
        key_id = cp.get("key_id")
        pem = (pinned or {}).get(key_id) or bundled_keys.get(key_id)
        if not pem:
            sig_failures.append(f"{os.path.basename(path)}: no public key available for key_id {key_id!r}")
            sig_ok_by_cp_id[cp_id] = False
            continue
        # Revocation ordering, §9.2.3. `issued_at` is read off the checkpoint
        # document, which is the same value that goes into sth_body below and
        # is therefore covered by the signature this loop is about to check —
        # a forger who edits it to slip past a revocation invalidates the
        # signature in the same stroke.
        _effective_at = bundle_revoked_from.get(key_id)
        if _effective_at is not None and not (
            cp.get("issued_at") and cp["issued_at"] < _effective_at
        ):
            sig_failures.append(
                f"{os.path.basename(path)}: KEY REVOKED — key_id {key_id!r} was revoked "
                f"with effect from {_effective_at}, and this checkpoint was issued at "
                f"{cp.get('issued_at')!r}, at or after that instant"
            )
            sig_ok_by_cp_id[cp_id] = False
            continue
        # Mirrors the Coriqo server's checkpoint body (v1 and v2)
        # exactly: no checkpoint_id (SPEC.md §7.3 — unsigned on purpose),
        # continuity/cohort_rollup only when present, ordering_version/
        # ordinal_watermark only from ordering_version 2, tree_version only
        # from tree_version 2 — each additive field changes the signed
        # bytes, so an unconditional include here would report every
        # pre-migration checkpoint's genuine signature as invalid.
        if cp.get("merkle_root") is None:
            # v1 body: no Merkle fields and NO `algorithm`, mirroring the
            # server's _v1_body, which takes no algorithm argument at all. A
            # v1 checkpoint is pre-Merkle and therefore pre-v3, so it is
            # ed25519 by construction. Adding `algorithm` here would diverge
            # from the bytes the server signs.
            sth_body = {k: cp.get(k) for k in
                        ("subject", "issued_at", "length", "head_hash", "key_id")}
        else:
            sth_body = {k: cp.get(k) for k in
                        ("subject", "issued_at", "length", "head_hash",
                         "merkle_root", "tree_size", "key_id")}
            if cp.get("continuity") is not None:
                sth_body["continuity"] = cp["continuity"]
            if cp.get("cohort_rollup") is not None:
                sth_body["cohort_rollup"] = cp["cohort_rollup"]
            if (cp.get("ordering_version") or 1) >= 2:
                sth_body["ordering_version"] = cp.get("ordering_version")
                sth_body["ordinal_watermark"] = cp.get("ordinal_watermark")
            if (cp.get("tree_version") or 1) >= 2:
                sth_body["tree_version"] = cp.get("tree_version")
            # SPEC.md 6.1: emitted only when NOT ed25519, so reconstructing it
            # unconditionally would change the bytes of every pre-v3
            # checkpoint and report honest evidence as altered.
            #
            # The explicit ed25519 check is not redundant. ed25519 is spelled
            # by ABSENCE, so a source that spells it out -- a backfilled
            # column, a hand-edited export, a future importer -- MUST
            # reconstruct to the same bytes as one that omits it. Without this,
            # such a bundle reports every one of its checkpoints as SIGNATURE
            # INVALID while the signatures are in fact perfectly good. This
            # mirrors the server's signed_body_of, which collapses NULL and
            # "ed25519" identically.
            _alg = cp.get("algorithm")
            if _alg and _alg != ALGORITHM_ED25519:
                sth_body["algorithm"] = _alg
            # SPEC.md 6.2: a package seal's attestation, present only when
            # non-null (additive, like continuity). Checked against the
            # package's snapshot.json by hashing that file's bytes.
            if cp.get("package_attestation") is not None:
                sth_body["package_attestation"] = cp["package_attestation"]
            # SPEC.md 4.5: the signed sealed-read log, present only when
            # non-null (additive, like package_attestation).
            if cp.get("access_log") is not None:
                sth_body["access_log"] = cp["access_log"]
        sig_ok_by_cp_id[cp_id] = verify_signature(
            sth_body, cp.get("signature_hex", ""), pem,
            algorithm=sth_body.get("algorithm", ALGORITHM_ED25519),
        )
        if not sig_ok_by_cp_id[cp_id]:
            sig_failures.append(f"{os.path.basename(path)}: signature does not verify under key_id {key_id!r}")
    sig_detail = "all checkpoints/*.json signatures verify" if not sig_failures else "; ".join(sig_failures)
    if sig_skipped_quarantined:
        sig_detail += f" ({sig_skipped_quarantined} quarantined checkpoint(s) skipped — already disclosed)"
    results.append(("every checkpoint's own signature verifies", not sig_failures, sig_detail))
    if not pinned and bundled_keys:
        print("  [WARN] No --keyring/--pubkey supplied — checkpoint signatures were")
        print("         verified against keys/keys.json, which ships INSIDE this bundle.")
        print("         That proves internal consistency, not who issued it. Pass")
        print("         --keyring with independently-obtained keys to pin trust.")
        print()

    # --- 3b. Checkpoint Merkle roots recompute from events/*.jsonl -------
    #
    # Runs BEFORE step 4's chain-linkage check and before succession
    # binding (4b): a hash chain can be entirely self-consistent while
    # being entirely fabricated, so this is what actually ties
    # events/*.jsonl's content to something a forger without the signing
    # key cannot produce — the checkpoint's own signed merkle_root.
    # Recomputed for EVERY checkpoint bearing a merkle_root regardless of
    # quarantine (quarantine excuses a broken signature, never an
    # unreproducible root); sig_ok_by_cp_id is what keeps a quarantined or
    # signature-failed checkpoint's matching arithmetic from being treated
    # as trustworthy evidence.
    bundle_events = _load_bundle_events_by_version(dir_path)
    trusted_leaf_hashes = _check_bundle_merkle_roots(
        dir_path, checkpoint_files, sig_ok_by_cp_id, results, bundle_events)

    # --- 3c. Record-wide package seals (SPEC.md 6.2.3-6.2.6) ------
    # Governance-event heads and the period fence recompute from the same
    # events/*.jsonl and checkpoints/*.json; heads of other chains are
    # reported as signed but not checkable. --snapshot adds the digest and
    # fence-membership check.
    _check_bundle_package_seals(dir_path, checkpoint_files, sig_ok_by_cp_id,
                                results, snapshot_path, bundle_events)

    # --- 3d. Sealed-read log (SPEC.md 4.5 and 13.4 step 4d) --------------------------
    _check_bundle_access_log(dir_path, checkpoint_files, sig_ok_by_cp_id, results)

    # --- 4. Event chain linkage, per version ----------------------------
    #
    # prev_hash linkage is checked for EVERY row regardless of
    # content_hash_verifiable — that catches reordering/deletion no matter
    # when or how a row was written. Content (event_hash) re-derivation is
    # only attempted for rows the manifest marks content_hash_verifiable —
    # a row marked False is DISCLOSED as not content-verified (its position
    # in the chain still checked) rather than silently skipped or forced to
    # a check that was never possible for it; a row marked True that fails
    # re-derivation is a hard failure, no exceptions.
    events_dir = os.path.join(dir_path, "events")
    chain_failures = []
    not_verifiable_seen = 0
    if os.path.isdir(events_dir):
        for fname in sorted(os.listdir(events_dir)):
            if not fname.endswith(".jsonl"):
                continue
            version_id = fname[:-len(".jsonl")]
            rows = []
            with open(os.path.join(events_dir, fname), "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
            rows.sort(key=lambda r: r.get("ordinal", 0))
            prev = "0" * 64
            for row in rows:
                if row.get("prev_hash") != prev:
                    chain_failures.append(
                        f"{fname}: event {row.get('event_id')} prev_hash does not match "
                        "the prior event's event_hash"
                    )
                    break
                if row.get("content_hash_verifiable"):
                    recomputed = _event_hash_of(row)
                    if recomputed != row.get("event_hash"):
                        chain_failures.append(
                            f"{fname}: event {row.get('event_id')} content hash does not "
                            "match its stored fields"
                        )
                        break
                else:
                    not_verifiable_seen += 1
                prev = row.get("event_hash")
    manifest_not_verifiable = ((manifest.get("counts") or {})
                                .get("events_not_content_verifiable_total"))
    count_mismatch = (
        isinstance(manifest_not_verifiable, int)
        and manifest_not_verifiable != not_verifiable_seen
        and not chain_failures
    )
    if count_mismatch:
        chain_failures.append(
            f"manifest.json claims {manifest_not_verifiable} non-content-verifiable "
            f"event(s), but {not_verifiable_seen} were actually found — the count "
            "itself was tampered with"
        )
    chain_detail = ("every events/*.jsonl file's prev_hash chain links and every "
                     "content-hash-verifiable row re-hashes to its stored event_hash")
    if not chain_failures and not_verifiable_seen:
        chain_detail += (f" ({not_verifiable_seen} event(s) disclosed as not "
                          "content-verifiable — chain position still checked)")
    results.append((
        "governance event chains link and re-hash correctly",
        not chain_failures,
        chain_detail if not chain_failures else "; ".join(chain_failures),
    ))
    reduced_range = reduced_range or bool(not_verifiable_seen)

    # --- 4b. Bind each certificate's succession records to the real,     -
    #         verified-Merkle-root leaf set (SPEC.md §9.3.5) — content    -
    #         re-derived unconditionally, gated on step 3b's trust set    -
    _check_bundle_succession_binding(dir_path, certs, results, trusted_leaf_hashes)

    # --- 5. Global head log (SPEC.md §14) --------------------------
    #
    # Absent head_log/ data is reported as NOT CHECKED, never folded into
    # all_pass — a bundle built before the tenant's first checkpoint or
    # before the periodic head-log seal ran legitimately carries none yet.
    head_log_dir = os.path.join(dir_path, "head_log")
    entries_path = os.path.join(head_log_dir, "entries.jsonl")
    head_path = os.path.join(head_log_dir, "head.json")
    if not os.path.isfile(entries_path):
        print("  [NOT CHECKED] public head log")
        print("         bundle carries no head_log/ data — not a pass or a fail.")
        print()
    else:
        head_log_entries = []
        with open(entries_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    head_log_entries.append(json.loads(line))
        head_log_head = None
        if os.path.isfile(head_path):
            with open(head_path, "r", encoding="utf-8") as fh:
                head_log_head = json.load(fh)

        by_checkpoint = {e.get("checkpoint_id"): e for e in head_log_entries}
        not_in_log = sorted(cid for cid in on_disk_ids if cid not in by_checkpoint)
        if not_in_log:
            print(f"  [FAIL] public head log — NOT IN PUBLIC LOG: {not_in_log}")
            print("         every other checkpoint in this bundle IS recorded in the "
                  "public log below.")
            print()
            results.append(("every bundled checkpoint appears in the public head log",
                             False, f"missing: {not_in_log}"))
        elif head_log_head is None:
            print("  [NOT CHECKED] public head log")
            print(f"         {len(head_log_entries)} entr" +
                  ("y" if len(head_log_entries) == 1 else "ies") +
                  " present but no signed head yet — not a pass or a fail.")
            print()
        else:
            hl = check_bundle_head_log(head_log_entries, head_log_head,
                                       pubkey_path=pubkey_path, keyring_path=keyring_path)
            if hl["pending"]:
                print("  [NOT CHECKED] public head log — not yet checkable")
                print(f"         {len(hl['pending'])} entr" +
                      ("y was" if len(hl["pending"]) == 1 else "ies were") +
                      f" issued after the latest signed head (tree_size "
                      f"{head_log_head.get('tree_size')}): "
                      f"{[e.get('checkpoint_id') for e in hl['pending']]}. "
                      "Not a pass or a fail.")
                print()
            if hl["failures"] or not hl["sig_ok"]:
                reasons = [f"{cid}: {why}" for cid, why in hl["failures"]]
                if not hl["sig_ok"]:
                    reasons.append(hl["sig_detail"])
                detail = "; ".join(reasons)
                print("  [FAIL] public log agrees")
                print(f"         {detail}")
                print()
                results.append(("public log agrees (each covered entry is included under the signed head)",
                                False, detail))
            elif hl["verified"]:
                detail = (f"{len(hl['verified'])} entr" +
                          ("y is" if len(hl["verified"]) == 1 else "ies are") +
                          f" included under the signed log head (tree_size "
                          f"{head_log_head.get('tree_size')}): each entry re-hashes to its "
                          "entry_hash and its RFC 6962 inclusion proof reproduces the "
                          "head's root_hash — " + hl["sig_detail"])
                print("  [PASS] public log agrees")
                print(f"         {detail}")
                print()
                results.append(("public log agrees (each covered entry is included under the signed head)",
                                True, detail))
            elif not hl["pending"]:
                # Nothing verified, nothing pending, nothing failed: a signed
                # head with no entries to check against it. Not reachable from
                # a coherent export (every bundle carries a checkpoint, and an
                # empty log then fails above as NOT IN PUBLIC LOG), but if it
                # ever is, say so: silence reads as a check that never ran.
                print("  [NOT CHECKED] public head log")
                print("         a signed log head is present but head_log/entries.jsonl holds no "
                      "entries to check against it — not a pass or a fail.")
                print()

    for name, passed, det in results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        print(f"         {det}")
        print()

    all_pass = cert_ok and all(r[1] for r in results)
    print("=" * 60)
    if all_pass:
        if reduced_range:
            print("RESULT: CONTINUITY VERIFIED OVER A REDUCED RANGE ✓")
            print()
            if disclosed_excluded:
                print(f"  {len(disclosed_excluded)} checkpoint(s) were declared unverifiable by a "
                      "Coriqo operator and are")
                print("  excluded from their subject's certified range — see each subject's "
                      "entry in")
                print("  manifest.json's continuity_certificates.<subject>.statement."
                      "excluded_checkpoints.")
            if disclosed_uncertified:
                print(f"  {len(disclosed_uncertified)} checkpoint(s) belong to a subject with no "
                      "certificate at all (see")
                print("  manifest.json's uncertified_subjects) but are individually quarantined.")
            if not_verifiable_seen:
                print(f"  {not_verifiable_seen} governance event(s) could not have their content "
                      "re-derived and are")
                print("  disclosed rather than checked — their position in the hash chain was "
                      "still confirmed.")
        else:
            print("RESULT: CONTINUITY VERIFIED ✓")
        print()
        print("  Verified with mathematics alone — no network access, no Coriqo")
        print("  software, and no trust in Coriqo as an institution.")
        return EXIT_OK
    print("RESULT: TENANT BUNDLE VERIFICATION FAILED ✗")
    return EXIT_TAMPER


_BUNDLE_MEMBER_NAMES = ("certificate.json", "proof.json")


def _classify_bundle_json(data: dict) -> str:
    """A certificate carries a top-level "statement" object; a proof does not."""
    return "certificate" if isinstance(data, dict) and isinstance(data.get("statement"), dict) else "proof"


def _extract_bundle_member(names_and_readers, source_label: str) -> tuple[dict, str]:
    """
    Shared by the zip and PDF extraction paths: given (name, read_bytes)
    pairs, pick certificate.json over proof.json when a container carries
    both, parse it, and classify it.
    """
    found = {}
    for name, read in names_and_readers:
        base = name.rsplit("/", 1)[-1]
        if base in _BUNDLE_MEMBER_NAMES and base not in found:
            found[base] = read
    for base in _BUNDLE_MEMBER_NAMES:  # certificate.json takes priority
        if base in found:
            data = json.loads(found[base]())
            return data, _classify_bundle_json(data)
    raise ValueError(
        f"no certificate.json or proof.json found inside {source_label}")


def _zip_has_manifest(zip_path: str) -> bool:
    """True when PATH is a Coriqo deliverables bundle — i.e. it carries
    manifest.json — rather than a plain certificate/proof container."""
    with zipfile.ZipFile(zip_path) as zf:
        return MANIFEST_ENTRY in zf.namelist()


def _load_from_zip(zip_path: str) -> tuple[dict, str]:
    with zipfile.ZipFile(zip_path) as zf:
        return _extract_bundle_member(
            ((info.filename, (lambda i=info: zf.read(i))) for info in zf.infolist()
             if not info.is_dir()),
            zip_path,
        )


def _pdf_attachments(pdf_path: str) -> dict[str, bytes]:
    """{attachment_name: bytes} for every attachment a PDF carries, last
    revision of each name winning (matches pypdf's own "most recent" pick
    used elsewhere in this file). Raises ImportError with the same message
    `_load_from_pdf` uses when pypdf is absent."""
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ImportError(
            "Reading attachments out of a PDF requires the 'pypdf' package "
            "(pip install pypdf). Plain --proof/--certificate/--bundle JSON "
            "verification does not need it."
        ) from exc
    reader = PdfReader(pdf_path)
    out: dict[str, bytes] = {}
    for name in reader.attachments:
        blobs = list(reader.attachments[name])
        if blobs:
            out[name] = blobs[-1]
    return out


def run_pdf_bundle(pdf_path: str, pubkey_path: str | None = None,
                    keyring_path: str | None = None,
                    witness_keyring_path: str | None = None,
                    witness_pubkey_path: str | None = None,
                    independent_witnesses: list[str] | None = None) -> int:
    """Verify a sealed engagement-deliverable PDF offline — the PDF analogue
    of `run_bundle`, for the container `sealed_deliverable.py` produces.

    Structurally NOT the same shape as a deliverables.zip. A PDF only ever
    carries two attachments toward this check — manifest.json and
    certificate.json — never a third bundled file: `manifest["files"]` also
    lists a `deck_content` row, but deck_content's bytes are a JSON snapshot
    that exists only inside the manifest's own hash, not as a separate
    extractable object in this container. So this function checks exactly
    two links — certificate signature/linkage, then manifest bound to the
    signed certificate — and says so, rather than padding the report with a
    fabricated third link or silently failing a row this container was never
    going to attach.

    Never executes anything read from the PDF; same non-negotiable as
    `run_bundle`.
    """
    print("=" * 60)
    print("Coriqo — Sealed Deliverable (PDF) Verification")
    print("=" * 60)
    print()

    try:
        attachments = _pdf_attachments(pdf_path)
    except ImportError as exc:
        print(f"FAIL: {exc}")
        return EXIT_MALFORMED
    except Exception as exc:
        print(f"FAIL: Cannot open PDF: {exc}")
        return EXIT_MALFORMED

    if MANIFEST_ENTRY not in attachments:
        print(f"FAIL: {MANIFEST_ENTRY} is missing from this PDF's attachments — a "
              "sealed deliverable without a manifest cannot be verified at all.")
        return EXIT_MALFORMED

    manifest_bytes = attachments[MANIFEST_ENTRY]
    try:
        manifest = json.loads(manifest_bytes)
    except Exception as exc:
        print(f"FAIL: {MANIFEST_ENTRY} is not valid JSON: {exc}")
        return EXIT_MALFORMED
    if not isinstance(manifest, dict):
        print(f"FAIL: {MANIFEST_ENTRY} does not decode to a JSON object.")
        return EXIT_MALFORMED

    seal = manifest.get("seal") if isinstance(manifest.get("seal"), dict) else {}

    if CERTIFICATE_ENTRY not in attachments:
        status = seal.get("status", "unknown")
        reason = seal.get("reason") or manifest.get("note") or (
            "manifest.json does not explain why this document is unsealed.")
        print("  [INFO] seal.status" if status != "unknown" else "  [INFO] sealed")
        print(f"         {status!r}" if status != "unknown" else f"         {manifest.get('sealed')!r}")
        print()
        print(f"UNSEALED: this PDF carries no {CERTIFICATE_ENTRY} — {reason}")
        print()
        print("This is not proof of tampering. It means this document was never")
        print("signed, so this tool has nothing to check a signature against.")
        print("=" * 60)
        return EXIT_UNSEALED

    cert_bytes = attachments[CERTIFICATE_ENTRY]
    try:
        cert = json.loads(cert_bytes)
    except Exception as exc:
        print(f"FAIL: {CERTIFICATE_ENTRY} is not valid JSON: {exc}")
        return EXIT_MALFORMED

    print(f"manifest.json sealed : {manifest.get('sealed')!r}")
    print()
    print("-- link 1/2: certificate signature and checkpoint linkage " + "-" * 12)
    print()

    cert_ok = verify_certificate_dict(cert, pubkey_path, keyring_path,
                                       witness_keyring_path, witness_pubkey_path,
                                       independent_witnesses)
    if not cert_ok:
        print()
        print("=" * 60)
        print("RESULT: SEALED DELIVERABLE VERIFICATION FAILED ✗")
        print()
        print("  The certificate's own signature or checkpoint linkage did not verify")
        print("  (see the checks above). This is a problem with the certificate itself —")
        print(f"  it was never checked whether it actually binds this {MANIFEST_ENTRY},")
        print("  because a certificate that fails on its own terms cannot vouch for")
        print("  anything sealed under it.")
        print("=" * 60)
        return EXIT_TAMPER

    print()
    print("-- link 2/2: manifest bound to the signed certificate " + "-" * 12)
    print()

    results = _check_manifest_binding(cert, manifest_bytes)
    for name, passed, detail in results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        print(f"         {detail}")
        print()

    binding_ok = all(r[1] for r in results)

    print("  [INFO] deck_content")
    print(f"         manifest.json records a sha256 for deck_content (the page's rendered")
    print("         figures), but this container attaches no separate deck_content object")
    print("         to check it against — only manifest.json and certificate.json are")
    print("         attached. This check proves manifest.json (and therefore its copy of")
    print("         deck_content's hash) is genuinely what the certificate sealed. It does")
    print("         NOT independently re-derive the figures from source and compare — that")
    print("         would require trusting a live call back to Coriqo, which this offline")
    print("         tool deliberately does not do.")
    print()

    print("=" * 60)
    if binding_ok:
        print("RESULT: SEALED DELIVERABLE VERIFIED ✓")
        print()
        print("  The certificate's signature covers statement.bundle_binding, which")
        print(f"  matches sha256({MANIFEST_ENTRY}) for the {MANIFEST_ENTRY} actually")
        print("  attached to this PDF. Signature -> manifest, unbroken.")
    else:
        print("RESULT: SEALED DELIVERABLE VERIFICATION FAILED ✗")
        print()
        print("  Do not rely on this document. The manifest binding failed — see the")
        print("  checks above for which field broke it.")
    print("=" * 60)

    return EXIT_OK if binding_ok else EXIT_TAMPER


def _load_from_pdf(pdf_path: str) -> tuple[dict, str]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ImportError(
            "Reading a certificate/proof out of a PDF requires the 'pypdf' "
            "package (pip install pypdf). Plain --proof/--certificate/--bundle "
            "JSON verification does not need it."
        ) from exc

    reader = PdfReader(pdf_path)
    pairs = []
    for name in reader.attachments:
        blobs = list(reader.attachments[name])
        if blobs:
            pairs.append((name, (lambda b=blobs[-1]: b)))
    return _extract_bundle_member(pairs, pdf_path)


def _run_extracted(data: dict, kind: str, source: str,
                    pubkey_path: str | None, keyring_path: str | None,
                    witness_keyring_path: str | None, witness_pubkey_path: str | None,
                    independent_witnesses: list[str] | None,
                    *, container: bool) -> int:
    """
    Run the weaker "one attestation object was found, verify only it" path
    shared by (zip without manifest.json), PDF, and bare-JSON input.

    When `container` is true, prints an explicit scope disclaimer first —
    what was checked (the extracted certificate/proof) and what was NOT
    (anything else the container held) — so this is never mistaken for a
    whole-bundle verification.
    """
    if container:
        print("=" * 60)
        print(f"NOTE: {source} is a container. A {kind} was extracted from it and")
        print(f"is verified BELOW on its own — nothing else {source} may contain was")
        print("checked: no manifest, no other bundled files, nothing beyond this")
        print(f"{kind} object. A Coriqo deliverables bundle (a zip carrying")
        print("manifest.json) gets the full signature -> manifest -> file check")
        print("automatically; this is not one of those.")
        print("=" * 60)
        print()

    if kind == "certificate":
        ok = verify_certificate_dict(data, pubkey_path, keyring_path,
                                      witness_keyring_path, witness_pubkey_path,
                                      independent_witnesses)
    else:
        ok = run(None, pubkey_path, keyring_path,
                 witness_keyring_path, witness_pubkey_path,
                 independent_witnesses, proof_data=data)
    return EXIT_OK if ok else EXIT_TAMPER


def run_auto_input(path: str, pubkey_path: str | None = None,
                    keyring_path: str | None = None,
                    witness_keyring_path: str | None = None,
                    witness_pubkey_path: str | None = None,
                    independent_witnesses: list[str] | None = None) -> int:
    """
    Auto-detect a positional INPUT's kind and verify it. Returns an exit code
    from the module's "Exit codes" table (the wide table also used by
    --bundle, since a positional zip can be routed there).

    Routing:
      *.zip WITH a manifest.json entry — a Coriqo deliverables bundle.
        Routed to run_bundle() for the full signature -> manifest -> file
        check, identical to --bundle. Not optional: a zip's certificate.json
        can verify perfectly while its payload files (and the manifest
        describing them) were tampered with, and only run_bundle's
        manifest/file linkage catches that.
      *.pdf WITH a manifest.json attachment — a Coriqo sealed deliverable.
        Routed to run_pdf_bundle() for the two checks this container
        structurally supports: certificate signature/linkage, then manifest
        binding. (Not three: unlike a zip, a PDF attaches no separate
        deck_content object for a manifest row to be checked against — see
        run_pdf_bundle's own docstring for why.)
      *.zip WITHOUT manifest.json, or *.pdf without one — a container that
        is not a Coriqo bundle at all. certificate.json or proof.json is
        pulled out and checked on its own; the report says explicitly that
        only the extracted object was checked.
      anything else (bare JSON) — read directly; certificate vs. proof is
        told apart by shape (a certificate has a top-level "statement").
    """
    suffix = Path(path).suffix.lower()

    if suffix == ".zip":
        try:
            is_bundle = _zip_has_manifest(path)
        except (FileNotFoundError, zipfile.BadZipFile, OSError, PermissionError) as exc:
            print(f"FAIL: Cannot open {path}: {exc}")
            return EXIT_MALFORMED
        if is_bundle:
            print(f"[INFO] {path} carries {MANIFEST_ENTRY} — this is a Coriqo")
            print("       deliverables bundle. Verifying it in full (same checks as")
            print("       --bundle): certificate signature/linkage, then manifest")
            print("       binding, then every file's hash.")
            print()
            return run_bundle(path, pubkey_path, keyring_path,
                               witness_keyring_path, witness_pubkey_path,
                               independent_witnesses)
        try:
            data, kind = _load_from_zip(path)
        except (zipfile.BadZipFile, ValueError, json.JSONDecodeError, OSError) as exc:
            print(f"FAIL: Cannot read a certificate/proof out of {path}: {exc}")
            return EXIT_MALFORMED
        return _run_extracted(data, kind, path, pubkey_path, keyring_path,
                               witness_keyring_path, witness_pubkey_path,
                               independent_witnesses, container=True)

    if suffix == ".pdf":
        try:
            is_sealed_deliverable = MANIFEST_ENTRY in _pdf_attachments(path)
        except ImportError as exc:
            print(f"FAIL: {exc}")
            return EXIT_MALFORMED
        except Exception as exc:
            print(f"FAIL: Cannot open {path}: {exc}")
            return EXIT_MALFORMED
        if is_sealed_deliverable:
            print(f"[INFO] {path} carries {MANIFEST_ENTRY} — this is a Coriqo sealed")
            print("       deliverable PDF. Verifying it in full: certificate")
            print("       signature/linkage, then manifest binding.")
            print()
            return run_pdf_bundle(path, pubkey_path, keyring_path,
                                   witness_keyring_path, witness_pubkey_path,
                                   independent_witnesses)
        try:
            data, kind = _load_from_pdf(path)
        except ImportError as exc:
            print(f"FAIL: {exc}")
            return EXIT_MALFORMED
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            print(f"FAIL: Cannot read a certificate/proof out of {path}: {exc}")
            return EXIT_MALFORMED
        return _run_extracted(data, kind, path, pubkey_path, keyring_path,
                               witness_keyring_path, witness_pubkey_path,
                               independent_witnesses, container=True)

    # Bare JSON — not a container, so no scope disclaimer is needed: there is
    # nothing else in the file that this tool declined to check.
    try:
        data = json.loads(Path(path).read_text())
    except Exception as exc:
        print(f"FAIL: Cannot load {path}: {exc}")
        return EXIT_MALFORMED
    if not isinstance(data, dict):
        print(f"FAIL: {path} does not decode to a JSON object.")
        return EXIT_MALFORMED
    if data.get("kind") == TRACE_KIND:
        return run_trace(path, pubkey_path, keyring_path)
    kind = _classify_bundle_json(data)
    return _run_extracted(data, kind, path, pubkey_path, keyring_path,
                           witness_keyring_path, witness_pubkey_path,
                           independent_witnesses, container=False)


# ---------------------------------------------------------------------------
# --attestation mode:
# offline check of a CEI execution_attestation record — its own internal
# envelope chain, AND that the evidence_record content_hash it sealed to is
# actually included under a checkpoint's own signed Merkle root. Standard
# library + `cryptography` only, like the rest of this tool; it needs no
# Coriqo code (see the note on canonical bytes below).
# ---------------------------------------------------------------------------

# A copy of the Coriqo server's canonical_bytes, sha256_hex and
# GENESIS_PREV_HASH. canonical_bytes is a public contract that must never
# change (SPEC.md §3); these ~20 lines reproduce it byte-for-byte rather
# than depending on Coriqo code, and
# test_verify_proof_attestation.py::test_canonical_bytes_matches_chain_module
# pins the two implementations against each other so they cannot silently
# drift apart.
_ATTESTATION_GENESIS_PREV_HASH = "0" * 64


def _attestation_canonical_bytes(obj: dict) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _attestation_sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _attestation_chain_head(events: list[dict]) -> str:
    """H_0 = GENESIS_PREV_HASH; H_n = sha256(H_{n-1} + canonical_bytes(event_n)),
    over events in the order given (ascending seq is the emitter's contract,
    not re-sorted here — see attestation_ingest.compute_chain_head)."""
    prev = _ATTESTATION_GENESIS_PREV_HASH
    for event in events:
        prev = _attestation_sha256_hex(prev.encode("utf-8") + _attestation_canonical_bytes(event))
    return prev


def _attestation_content_hash(envelope: dict) -> str:
    """Mirrors the Coriqo server's canonical hash — the
    hash evidence_records_service.seal() computes over the whole sealed
    payload (here, the attestation envelope) and stores as content_hash."""
    return _attestation_sha256_hex(_attestation_canonical_bytes(envelope))


def run_attestation(path: str, pubkey_path: str | None = None,
                     keyring_path: str | None = None) -> bool:
    """
    Verify a CEI attestation fixture: {envelope, record, checkpoint, events}
    (see the module epilog / docs/architecture/domains/attestations.md for
    the shape, and Coriqo's own test suite for a real
    example exported from a seal). Checks, all independent of one another:

      1. rule 1 — every event carrying `payload` hashes to its `payload_hash`.
      2. the envelope's own hash-chain (`chain_head`) recomputes from its
         events — a v1 envelope with no `resource`/`on_behalf_of` hashes
         exactly as a v2 one with them, since this just hashes whatever keys
         are present.
      3. `record.content_hash` — what evidence_records_service.seal() would
         have computed over this envelope — recomputes.
      4. that content_hash is bound inside one of the exported governance
         events' `notes` (the evidence_seal payload seal() writes), and that
         event's own `event_hash` recomputes.
      5. the checkpoint's SIGNED merkle_root reproduces from the exported
         events' event_hash leaves, in ordinal order, AND the bound event
         from (4) is one of those leaves — this is what "content_hash is
         included under an exported checkpoint" actually proves: not that
         the numbers happen to match, but that the specific leaf carrying
         this record's content_hash is part of the leaf set that produced
         the checkpoint's own signature.
      6. that checkpoint signature itself verifies under a pinned key.

    Returns True iff every check above passed.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    envelope = data.get("envelope") or {}
    record = data.get("record") or {}
    checkpoint = data.get("checkpoint") or {}
    events = data.get("events") or []
    env_events = envelope.get("events") or []

    results: list[tuple[str, bool, str]] = []

    # 1. payload / payload_hash binding.
    payload_problems = []
    for e in env_events:
        if e.get("payload") is not None:
            expected = _attestation_sha256_hex(_attestation_canonical_bytes(e["payload"]))
            if expected != e.get("payload_hash"):
                payload_problems.append(
                    f"seq {e.get('seq')}: payload does not hash to payload_hash "
                    f"({expected} != {e.get('payload_hash')})"
                )
    results.append((
        "every event's payload matches its payload_hash",
        not payload_problems,
        ("; ".join(payload_problems) if payload_problems
         else f"{len(env_events)} event(s) checked"),
    ))

    # 2. envelope chain_head.
    recomputed_head = _attestation_chain_head(env_events)
    claimed_head = envelope.get("chain_head")
    head_ok = bool(claimed_head) and recomputed_head == claimed_head
    results.append((
        "envelope chain_head recomputes from its events",
        head_ok,
        "matches" if head_ok else f"recomputed {recomputed_head} != claimed {claimed_head!r}",
    ))

    # 3. record content_hash.
    recomputed_content_hash = _attestation_content_hash(envelope)
    claimed_content_hash = record.get("content_hash")
    content_ok = bool(claimed_content_hash) and recomputed_content_hash == claimed_content_hash
    results.append((
        "record content_hash recomputes from the envelope",
        content_ok,
        "matches" if content_ok else f"recomputed {recomputed_content_hash} != claimed {claimed_content_hash!r}",
    ))

    # 4. content_hash bound inside an exported governance event's notes.
    target_event = None
    for row in events:
        try:
            notes = json.loads(row.get("notes") or "{}")
        except json.JSONDecodeError:
            continue
        if (notes.get("record_type") == "execution_attestation"
                and claimed_content_hash is not None
                and notes.get("content_hash") == claimed_content_hash):
            target_event = row
            break
    results.append((
        "content_hash is bound inside a governance event's notes",
        target_event is not None,
        (f"event {target_event.get('event_id')}" if target_event is not None
         else "no exported event's notes.content_hash matches this record"),
    ))

    event_hash_ok = False
    if target_event is not None:
        recomputed_event_hash = _event_hash_of(target_event)
        event_hash_ok = recomputed_event_hash == target_event.get("event_hash")
        results.append((
            "bound governance event's event_hash recomputes",
            event_hash_ok,
            ("matches" if event_hash_ok else
             f"recomputed {recomputed_event_hash} != stored {target_event.get('event_hash')!r}"),
        ))
    else:
        results.append(("bound governance event's event_hash recomputes", False,
                         "no bound event to check (see previous check)"))

    # 5. checkpoint merkle_root reproduces, and the bound event is a leaf.
    ordered = sorted(events, key=lambda r: r.get("ordinal", 0))
    leaf_hex = [r.get("event_hash") or "" for r in ordered]
    tree_version = checkpoint.get("tree_version") or 1
    root_ok = False
    membership_ok = False
    if checkpoint.get("merkle_root") is not None:
        try:
            leaf_data = [bytes.fromhex(h) for h in leaf_hex]
            recomputed_root = _merkle_root_for(leaf_data, tree_version).hex()
            root_ok = recomputed_root == checkpoint["merkle_root"]
        except ValueError:
            recomputed_root = None
        results.append((
            "checkpoint's signed merkle_root reproduces from the leaves on file",
            root_ok,
            "matches" if root_ok else f"recomputed {recomputed_root} != signed {checkpoint.get('merkle_root')!r}",
        ))
        membership_ok = target_event is not None and target_event.get("event_hash") in leaf_hex
        results.append((
            "the bound event is one of the leaves that produced this root",
            membership_ok,
            "included" if membership_ok else
            "the bound event's event_hash is not in the leaf set exported for this checkpoint",
        ))
    else:
        results.append((
            "checkpoint carries a Merkle root to check inclusion against",
            False,
            "checkpoint has no merkle_root — pre-Merkle (v1) checkpoint, nothing to include an attestation under",
        ))

    # 6. checkpoint signature — same sth_body construction run_bundle_dir's
    # per-checkpoint check uses (the Coriqo server's
    # _sth_body/_v1_body).
    if checkpoint.get("merkle_root") is None:
        sth_body = {k: checkpoint.get(k) for k in
                    ("subject", "issued_at", "length", "head_hash", "key_id")}
    else:
        sth_body = {k: checkpoint.get(k) for k in
                    ("subject", "issued_at", "length", "head_hash",
                     "merkle_root", "tree_size", "key_id")}
        if checkpoint.get("continuity") is not None:
            sth_body["continuity"] = checkpoint["continuity"]
        if checkpoint.get("cohort_rollup") is not None:
            sth_body["cohort_rollup"] = checkpoint["cohort_rollup"]
        if (checkpoint.get("ordering_version") or 1) >= 2:
            sth_body["ordering_version"] = checkpoint.get("ordering_version")
            sth_body["ordinal_watermark"] = checkpoint.get("ordinal_watermark")
        if (checkpoint.get("tree_version") or 1) >= 2:
            sth_body["tree_version"] = checkpoint.get("tree_version")
        _alg = checkpoint.get("algorithm")
        if _alg and _alg != ALGORITHM_ED25519:
            sth_body["algorithm"] = _alg
        if checkpoint.get("package_attestation") is not None:
            sth_body["package_attestation"] = checkpoint["package_attestation"]
        if checkpoint.get("access_log") is not None:
            sth_body["access_log"] = checkpoint["access_log"]

    pinned = _merge_pinned(pubkey_path, keyring_path) or {}
    key_id = checkpoint.get("key_id")
    pem = pinned.get(key_id) or pinned.get(None)
    sig_ok = False
    if pem:
        sig_ok = verify_signature(
            sth_body, checkpoint.get("signature_hex", ""), pem,
            algorithm=sth_body.get("algorithm", ALGORITHM_ED25519),
        )
        results.append(("checkpoint signature verifies under the pinned key", sig_ok,
                         "valid" if sig_ok else "signature does not verify"))
    else:
        results.append(("checkpoint signature verifies under the pinned key", False,
                         f"no public key pinned for key_id {key_id!r} — pass --pubkey or --keyring"))

    print(f"Verifying attestation: {path}\n")
    all_ok = True
    for name, ok, detail in results:
        status = "PASS" if ok else "FAIL"
        if not ok:
            all_ok = False
        print(f"  [{status}] {name}")
        print(f"         {detail}")
    print()
    if all_ok:
        print("RESULT: PASS — this attestation's chain is intact and its content_hash is")
        print("        included under the checkpoint's signed Merkle root.")
    else:
        print("RESULT: FAIL — see above")
    return all_ok


# ---------------------------------------------------------------------------
# Trust Repair proof (SPEC.md 16): the finding -> fix -> retest -> held -> repeat
# claims in a sealed package, checked against the tenant bundle's chains.
# ---------------------------------------------------------------------------

TR_VERIFIED = "verified"
TR_NOT_COVERED = "not covered"
TR_OFFLINE = "signed, not checkable offline"
TR_FAILED = "failed"
TR_CONTEXT = "signed context"

_TR_CLOSED = ("resolved", "accepted_risk", "examiner_closed")


def _tr_index(by_version: dict) -> dict:
    return {r["event_id"]: r for rows in by_version.values() for r in rows if r.get("event_id")}


def _tr_event(index: dict, ref: str):
    """Resolve '<event id>:<event hash>' to a bundle row whose recomputed hash matches both."""
    if not isinstance(ref, str) or ":" not in ref:
        return None, "malformed ref"
    event_id, _, claimed = ref.partition(":")
    row = index.get(event_id)
    if row is None:
        return None, "event is not in the bundle"
    if _event_hash_of(row) != claimed or row.get("event_hash") != claimed:
        return None, "event hash does not match its content"
    try:
        notes = json.loads(row.get("notes") or "{}")
    except ValueError:
        return None, "event notes are not JSON"
    return (row, notes if isinstance(notes, dict) else {}), None


def _tr_closure_problem(f: dict) -> str | None:
    """The closure basis a package states must follow from the status and retest it states
    (SPEC.md 16.3). Whether the retest run's evidence verified is signed, not checkable here."""
    status, closure, retest = f.get("status"), f.get("closure"), f.get("retest") or {}
    if status not in _TR_CLOSED:
        return None if closure is None else "an open finding states a closure"
    if not isinstance(closure, dict):
        return "a closed finding states no closure"
    basis, strength = closure.get("basis"), closure.get("strength")
    if (isinstance(closure.get("held_back"), dict) and strength == "management"
            and basis in ("retest_verified", "examiner")):
        strength = "independent"     # held back by the tenant's minimum; _tr_held_back_problem checks that claim
    passed = retest.get("result") == "pass"
    verified = retest.get("evidence_verified")
    if status == "accepted_risk":
        return None if (basis, strength) == ("risk_accepted", "none") else "accepted risk must read as not fixed"
    if status == "examiner_closed":
        return None if (basis, strength) == ("examiner", "independent") else "examiner closure misstated"
    if passed and verified is True:
        return None if (basis, strength) == ("retest_verified", "independent") else \
            "a verified passing retest must read as independent evidence"
    if strength != "management" or basis not in ("retest_waived", "retest_unverified", "management_signoff"):
        return "a closure without a verified passing retest is stated as independent"
    if passed and verified is False and basis not in ("retest_waived", "retest_unverified"):
        return "a retest whose evidence did not verify is stated as a plain sign-off"
    return None


_TR_ORIGIN_ORDER = ("signed_push", "keyed_push", "pulled_with_credentials", "file_upload")


def _tr_is_weak(origins, minimum: str) -> bool:
    """True when an article's evidence_origins hold a class weaker than `minimum`. An unrecorded or
    unknown class cannot meet the bar and counts as weaker. No events: not judged (SPEC.md 16.3 claim 8)."""
    if not isinstance(origins, dict):
        return False
    seen = [k for k, n in origins.items() if isinstance(n, int) and n > 0]
    if not seen:
        return False
    floor = _TR_ORIGIN_ORDER.index(minimum)
    return any(k not in _TR_ORIGIN_ORDER or _TR_ORIGIN_ORDER.index(k) > floor for k in seen)


def _tr_held_back_problem(art: dict, weak_ids: list, minimum) -> tuple[str | None, str]:
    """(problem, detail) for the held-back claim of one article (SPEC.md 16.3 claim 8)."""
    closure = (art.get("finding") or {}).get("closure")
    held = closure.get("held_back") if isinstance(closure, dict) else None
    if held is not None and not isinstance(held, dict):
        return "held_back is not an object", ""
    if minimum is None:
        return ("a closure is held back but the package states no minimum", "") if held else (None, "")
    if not isinstance(closure, dict):
        return None, ""
    if held:
        if closure.get("strength") != "management":
            return "a held-back closure must read as sign-off", ""
        if held.get("min_origin") != minimum:
            return "the hold names a different minimum than the package states", ""
        if not weak_ids:
            return "held back, but no article on this finding has evidence weaker than the minimum", ""
        named = held.get("articles")
        if isinstance(named, list) and sorted(str(c.get("article_id")) for c in named if isinstance(c, dict)) != sorted(weak_ids):
            return "the hold names different articles than the ones whose evidence is weaker", ""
        return None, f"held back by {len(weak_ids)} article(s) with evidence weaker than {minimum}"
    if weak_ids and closure.get("strength") == "independent":
        return "evidence weaker than the minimum, yet the closure is stated as independent", ""
    return None, "no evidence weaker than the minimum" if not weak_ids else "closure was not independent to begin with"


def check_trust_repair(snapshot: dict, by_version: dict) -> list[tuple[str, str, str]]:
    """[(claim, verdict, detail)] for every article's finding trail and for the determination
    method, if the snapshot carries them. Pure: takes the parsed snapshot and the bundle's
    events by version, so the caller decides how the bundle itself was authenticated."""
    out: list[tuple[str, str, str]] = []
    index = _tr_index(by_version)
    ordinal = {eid: r.get("ordinal") for eid, r in index.items()}
    rem = snapshot.get("remediation_status") if isinstance(snapshot, dict) else None
    minimum = (rem or {}).get("closure_min_origin")
    weak_by_finding: dict = {}
    if minimum in _TR_ORIGIN_ORDER[:-1]:
        for a in (rem or {}).get("articles", []) or []:
            if _tr_is_weak(a.get("evidence_origins"), minimum):
                weak_by_finding.setdefault(a.get("finding_id"), []).append(str(a.get("article_id")))
    elif minimum is not None:
        out.append(("closure minimum", TR_FAILED, f"closure_min_origin {minimum!r} is not a known class"))
        minimum = None
    for art in (rem or {}).get("articles", []) or []:
        origins = art.get("evidence_origins")
        if isinstance(origins, dict) and origins:
            out.append((f"article {art.get('number')}: how its evidence arrived", TR_CONTEXT,
                        ", ".join(f"{k} {v}" for k, v in sorted(origins.items()))))
        f = art.get("finding")
        if not isinstance(f, dict):
            continue
        fid = art.get("finding_id")
        label = f"article {art.get('number')} finding {str(fid)[:8]}"
        steps = f.get("sealed_steps") or []
        origin = (f.get("closure") or {}).get("origin") if isinstance(f.get("closure"), dict) else None
        if isinstance(origin, dict):
            out.append((f"{label}: how the retest's evidence arrived", TR_CONTEXT,
                        f"{origin.get('class') or 'not verified'} ({origin.get('label')})"))
        problem = _tr_closure_problem(f)
        out.append((f"{label}: closure follows from the stated retest",
                    TR_FAILED if problem else TR_VERIFIED, problem or f"{f.get('closure') and f['closure']['basis']}"))
        hb_problem, hb_detail = _tr_held_back_problem(art, weak_by_finding.get(fid, []), minimum)
        if hb_problem:
            out.append((f"{label}: held back follows the minimum", TR_FAILED, hb_problem))
        elif minimum and hb_detail:
            out.append((f"{label}: held back follows the minimum", TR_VERIFIED, hb_detail))
        repeats = f.get("repeats") or []
        if int(f.get("occurrence_count") or 1) != len(repeats) + 1:
            out.append((f"{label}: repeat count", TR_FAILED,
                        f"occurrence_count {f.get('occurrence_count')} but {len(repeats)} earlier findings listed"))
        elif repeats:
            out.append((f"{label}: repeat count", TR_VERIFIED, f"{len(repeats)} earlier findings"))
        if f.get("status") in _TR_CLOSED and not steps:
            out.append((f"{label}: sealed steps", TR_NOT_COVERED,
                        "closed before steps were sealed on a covered chain (older record)"))
            continue
        last_ord, bad = None, None
        events = []
        for st in steps:
            got, err = _tr_event(index, st.get("ref"))
            if err:
                bad = f"step to {st.get('to')}: {err}"
                break
            row, notes = got
            if notes.get("finding_id") != fid or notes.get("to") != st.get("to"):
                bad = f"step to {st.get('to')}: event names a different finding or status"
                break
            o = ordinal.get(row["event_id"])
            if last_ord is not None and (o is None or o <= last_ord):
                bad = f"step to {st.get('to')}: not in chain order"
                break
            last_ord = o
            events.append((st, notes))
        if bad:
            out.append((f"{label}: sealed steps", TR_FAILED, bad))
            continue
        if steps:
            if steps[-1].get("to") != f.get("status"):
                out.append((f"{label}: sealed steps", TR_FAILED,
                            f"last sealed step is {steps[-1].get('to')}, package says {f.get('status')}"))
                continue
            out.append((f"{label}: sealed steps", TR_VERIFIED, f"{len(steps)} steps, in order"))
        retest = f.get("retest")
        resolved = [n for s, n in events if s.get("to") == "resolved"]
        if retest and resolved:
            n = resolved[-1]
            if (n.get("retest_execution_id"), n.get("retest_result")) != (retest.get("execution_id"), retest.get("result")):
                out.append((f"{label}: retest matches the sealed closure", TR_FAILED,
                            "the package's retest differs from the retest named when the closure was sealed"))
            else:
                out.append((f"{label}: retest matches the sealed closure", TR_VERIFIED, str(retest.get("execution_id"))))
        if retest and retest.get("evidence_verified") is not None:
            out.append((f"{label}: retest evidence verified", TR_OFFLINE,
                        "the run's manifest check is inside the package signature"))
    ad = snapshot.get("assurance_determination") if isinstance(snapshot, dict) else None
    if isinstance(ad, dict) and isinstance(ad.get("method"), dict):
        m = ad["method"]
        body = {k: v for k, v in m.items() if k != "sha256"}
        digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if digest != m.get("sha256"):
            out.append(("determination method hash", TR_FAILED, "the method block does not hash to its sha256"))
        elif not ad.get("method_seal_ref"):
            out.append(("determination method sealed", TR_NOT_COVERED,
                        "signed before the method hash was sealed on a covered chain (older record)"))
        else:
            got, err = _tr_event(index, ad["method_seal_ref"])
            if err:
                out.append(("determination method sealed", TR_FAILED, err))
            elif got[1].get("method_sha256") != m["sha256"]:
                out.append(("determination method sealed", TR_FAILED, "the sealed event holds a different method hash"))
            else:
                out.append(("determination method sealed", TR_VERIFIED, m["sha256"][:16]))
    return out


def run_trust_repair(dir_path: str, snapshot_path: str, pubkey_path=None, keyring_path=None) -> int:
    """`--bundle-dir D --snapshot S --trust-repair`: authenticate the bundle exactly as
    --bundle-dir does, then check the package's remediation claims against its chains."""
    rc = run_bundle_dir(dir_path, pubkey_path, keyring_path, snapshot_path=snapshot_path)
    if rc != EXIT_OK:
        print("\nTrust Repair claims NOT checked: the bundle did not verify.")
        return rc
    try:
        with open(snapshot_path, "r", encoding="utf-8") as fh:
            snapshot = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"snapshot unreadable: {exc}")
        return EXIT_MALFORMED
    results = check_trust_repair(snapshot, _load_bundle_events_by_version(dir_path))
    print("\nTrust Repair claims")
    for claim, verdict, detail in results:
        print(f"  [{verdict.upper()}] {claim}" + (f" ({detail})" if detail else ""))
    failed = [r for r in results if r[1] == TR_FAILED]
    if not results:
        print("  Nothing to check: the package carries no remediation or determination claims.")
    print("\nTRUST REPAIR CLAIMS: " + ("FAILED" if failed else "VERIFIED (see any NOT COVERED lines above)"))
    return EXIT_TAMPER if failed else EXIT_OK


# ---------------------------------------------------------------------------
# E-signature records (SPEC.md section 17): `--esign PATH`
# ---------------------------------------------------------------------------

_ES_RECORD_FILES = (("sent", "records/signature_sent.json", "signature_sent"),
                    ("completed", "records/signature_completed.json", "signature_completed"))
# esign/ file -> (record that seals its hash, payload field)
_ES_FILE_HASHES = {
    "sent.pdf": ("sent", "sent_sha256"),
    "signed.pdf": ("completed", "signed_sha256"),
    "audit_trail.pdf": ("completed", "audit_trail_pdf_sha256"),
    "audit_trail.json": ("completed", "audit_trail_json_sha256"),
    "certificate.pdf": ("completed", "certificate_sha256"),
}
_ES_UNSEALED_OK = ("request.json",)      # display only; never trusted
_ES_MAX_BYTES = 256 * 1024 * 1024


class _EsignMalformed(Exception):
    pass


def _esign_load_files(path: str) -> dict[str, bytes]:
    """{path relative to esign/: bytes} from a zip (entries under esign/) or a directory that
    holds the esign/ files directly (or holds an esign/ folder)."""
    p = Path(path)
    files: dict[str, bytes] = {}
    total = 0
    if p.is_dir():
        root = p / "esign" if (p / "esign").is_dir() else p
        for f in sorted(root.rglob("*")):
            if f.is_file():
                total += f.stat().st_size
                if total > _ES_MAX_BYTES:
                    raise _EsignMalformed("bundle is larger than 256 MB")
                files[f.relative_to(root).as_posix()] = f.read_bytes()
    elif p.is_file() and zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as zf:
            for info in zf.infolist():
                name = info.filename
                if info.is_dir() or not name.startswith("esign/") or ".." in name.split("/"):
                    continue
                total += info.file_size
                if total > _ES_MAX_BYTES:
                    raise _EsignMalformed("bundle is larger than 256 MB")
                files[name[len("esign/"):]] = zf.read(info)
    else:
        raise _EsignMalformed(f"{path} is neither a zip nor a folder")
    if not files:
        raise _EsignMalformed("no esign/ files found")
    return files


def _esign_split(files: dict[str, bytes]) -> dict[str, dict[str, bytes]]:
    """One request's files, or (a package proof zip) one set per esign/<request_id>/ folder.
    Returns {request label: files relative to that request}; "" labels a single request."""
    if any(k.startswith("records/") for k in files):
        return {"": files}
    sets: dict[str, dict[str, bytes]] = {}
    for k, v in files.items():
        head, _, rest = k.partition("/")
        if rest:
            sets.setdefault(head, {})[rest] = v
    sets = {rid: fs for rid, fs in sets.items() if any(r.startswith("records/") for r in fs)}
    if not sets:
        raise _EsignMalformed("no records/ folder found, neither under esign/ nor under esign/<request_id>/")
    return sets


def _esign_parse_record(files: dict, rel: str, expect_type: str) -> dict | None:
    raw = files.get(rel)
    if raw is None:
        return None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise _EsignMalformed(f"{rel} is not JSON ({exc})")
    rec, ev = (doc.get("record"), doc.get("event")) if isinstance(doc, dict) else (None, None)
    if not (isinstance(rec, dict) and isinstance(ev, dict) and isinstance(rec.get("payload"), dict)
            and isinstance(rec.get("content_hash"), str) and isinstance(rec.get("id"), str)
            and isinstance(ev.get("event_hash"), str)):
        raise _EsignMalformed(f"{rel} does not have the shape {{record, event, proof}}")
    if doc.get("proof") is not None and not isinstance(doc["proof"], dict):
        raise _EsignMalformed(f"{rel}: proof must be an object or null")
    if rec.get("record_type") != expect_type:
        raise _EsignMalformed(f"{rel} carries record_type {rec.get('record_type')!r}, expected {expect_type!r}")
    return doc


def _esign_check_proof(proof: dict, event: dict, pinned: dict | None) -> tuple[str, str]:
    """Section 17.2 check 3 for one record: (verdict, detail)."""
    try:
        sth = proof["sth_body"]
        problems = []
        if proof.get("event_id") != event.get("event_id"):
            problems.append("the proof is for a different event")
        if proof.get("leaf_input") != event.get("event_hash"):
            problems.append("leaf_input is not this event's event_hash")
        for field in ("merkle_root", "tree_size"):
            if sth.get(field) is None or proof.get(field) != sth.get(field):
                problems.append(f"{field} in the proof disagrees with the signed checkpoint body")
        if problems:
            return TR_FAILED, "; ".join(problems)
        if not verify_inclusion(
                leaf_input_hex=proof["leaf_input"], leaf_index=proof["leaf_index"],
                tree_size=sth["tree_size"], proof_path_hex=proof["proof_path"],
                expected_root_hex=sth["merkle_root"], tree_version=sth.get("tree_version", 1)):
            return TR_FAILED, "the Merkle path does not lead from this event to the signed root"
        key_id = sth.get("key_id")
        if proof.get("key_id") not in (None, key_id):
            return TR_FAILED, "the proof names a different key than the signed body"
        pem, _revoked, key_detail = _resolve_bundle_key(
            {"public_keys": {key_id: {"pem": proof.get("public_key_pem") or "", "revoked": False}}},
            key_id, pinned)
        if not pem:
            return TR_FAILED, key_detail or "no public key to check the checkpoint signature with"
        if not verify_signature(sth, proof["checkpoint_signature"], pem,
                                algorithm=sth.get("algorithm", ALGORITHM_ED25519)):
            return TR_FAILED, "the checkpoint signature does not verify"
        how = "under your pinned key" if pinned is not None else "under the key in the bundle (not pinned)"
        return TR_VERIFIED, f"checkpoint {proof.get('checkpoint_id')}, signature valid {how}"
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return TR_FAILED, f"the proof is malformed ({type(exc).__name__}: {exc})"


def _esign_roots(pem_text: str) -> list[bytes]:
    from asn1crypto import pem
    return [der for _t, _h, der in pem.unarmor(pem_text.encode("utf-8"), multiple=True)]


def _esign_pades(signed: bytes, roots_der: list[bytes] | None) -> list[tuple[str, str, str]]:
    """Check 7. (verdict, name, detail) lines; needs pyHanko."""
    name = "7. PDF signatures are intact and the last covers the whole file"
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.diff_analysis import ModificationLevel
        from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
        from pyhanko.sign.validation.status import SignatureCoverageLevel
        from pyhanko_certvalidator import ValidationContext
    except ImportError:
        return [(TR_OFFLINE, name, "pyhanko is not installed (pip install pyhanko pypdf)")]

    def is_ts(emb) -> bool:
        try:
            return emb.sig_object.get("/Type") == "/DocTimeStamp"
        except Exception:  # noqa: BLE001
            return False

    try:
        r = PdfFileReader(io.BytesIO(signed), strict=True)
        if r.encrypted:
            return [(TR_FAILED, name, "the file is encrypted")]
        sigs = list(r.embedded_signatures)
    except Exception as exc:  # noqa: BLE001
        return [(TR_FAILED, name, f"signed.pdf cannot be read as a PDF ({type(exc).__name__})")]
    if not sigs:
        return [(TR_FAILED, name, "signed.pdf carries no signature")]
    for i, emb in enumerate(sigs, 1):
        try:
            ctx = ValidationContext(trust_roots=[], allow_fetching=False)
            st = (validate_pdf_timestamp(emb, validation_context=ctx) if is_ts(emb)
                  else validate_pdf_signature(emb, signer_validation_context=ctx))
        except Exception as exc:  # noqa: BLE001
            return [(TR_FAILED, name, f"signature {i} of {len(sigs)} could not be validated ({type(exc).__name__})")]
        if not (st.intact and st.valid):
            return [(TR_FAILED, name, f"signature {i} of {len(sigs)} does not match the file contents")]
        if i == len(sigs):
            lta_tail = (st.coverage == SignatureCoverageLevel.ENTIRE_REVISION
                        and st.modification_level == ModificationLevel.LTA_UPDATES)
            if st.coverage != SignatureCoverageLevel.ENTIRE_FILE and not lta_tail:
                return [(TR_FAILED, name, "the last signature does not cover the whole file; content was added after it")]
        else:
            lvl = st.modification_level
            if lvl is None or lvl > ModificationLevel.FORM_FILLING or st.docmdp_ok is False:
                return [(TR_FAILED, name, f"the document was changed after signature {i} in a way it does not allow")]
    out = [(TR_VERIFIED, name, f"{len(sigs)} signature(s) valid; the last one covers the whole file")]
    if roots_der:
        tname = "7. signer certificate chains to the roots you supplied"
        idx = len(sigs) - 1
        while idx >= 0 and is_ts(sigs[idx]):
            idx -= 1
        if idx < 0:
            out.append((TR_FAILED, tname, "the file carries only document timestamps; there is no "
                        "signer certificate to judge"))
            return out
        try:
            from asn1crypto import x509
            from pyhanko.sign.validation.dss import DocumentSecurityStore
            kwargs = dict(trust_roots=[x509.Certificate.load(d) for d in roots_der], allow_fetching=False,
                          revocation_mode="require", crls=[], ocsps=[])
            try:
                dss = DocumentSecurityStore.read_dss(r)
            except Exception:  # noqa: BLE001
                dss = None
            ctx = dss.as_validation_context(kwargs) if dss is not None else ValidationContext(**kwargs)
            st = validate_pdf_signature(sigs[idx], signer_validation_context=ctx)
            if st.trusted:
                out.append((TR_VERIFIED, tname, "chains to a supplied root; revocation data in the file confirms it"))
            else:
                out.append((TR_FAILED, tname, "the certificate does not chain to a supplied root, or the file "
                            "carries no revocation data that confirms it"))
        except Exception as exc:  # noqa: BLE001
            out.append((TR_FAILED, tname, f"the certificate could not be checked ({type(exc).__name__})"))
    return out


def _esign_pdf_ref(signed: bytes, request_id: str, source_sha: str | None) -> tuple[str, str]:
    """Check 6."""
    try:
        from pypdf import PdfReader
    except ImportError:
        return TR_OFFLINE, "pypdf is not installed (pip install pyhanko pypdf)"
    try:
        meta = PdfReader(io.BytesIO(signed)).metadata or {}
        ref, src = meta.get("/CoriqoRef"), meta.get("/CoriqoSourceSha256")
    except Exception as exc:  # noqa: BLE001
        return TR_FAILED, f"signed.pdf cannot be read as a PDF ({type(exc).__name__})"
    if ref is None or src is None:
        return TR_FAILED, "signed.pdf does not carry the Coriqo reference and source hash"
    if str(ref) != request_id:
        return TR_FAILED, f"/CoriqoRef is {str(ref)!r}, the request is {request_id!r}"
    if source_sha is None or str(src) != source_sha:
        return TR_FAILED, "/CoriqoSourceSha256 is not the source hash that was sent"
    return TR_VERIFIED, f"reference {request_id} and source hash {source_sha[:16]}... match what was sent"


def run_esign(path: str, pubkey_path: str | None = None, keyring_path: str | None = None,
              roots_path: str | None = None) -> int:
    """`--esign PATH` (SPEC.md section 17). Exit 0 when no check failed, 1 when one did,
    3 when the input is not a readable bundle or nothing was signed yet."""
    print(f"Verifying e-signature record: {path}\n")
    # pyHanko logs every untrusted or self-signed certificate with a full traceback on stderr.
    # The verdict line already says it in plain words, so keep the report readable.
    import logging
    for name in ("pyhanko", "pyhanko_certvalidator"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    try:
        pinned = _merge_pinned(pubkey_path, keyring_path)
        roots_der = _esign_roots(Path(roots_path).read_text()) if roots_path else None
        if roots_path and not roots_der:
            raise ValueError(f"--esign-roots {roots_path} holds no PEM certificate")
        sets = _esign_split(_esign_load_files(path))
    except (_EsignMalformed, ValueError, OSError) as exc:
        print(f"MALFORMED: {exc}")
        return EXIT_MALFORMED
    codes = []
    for label, files in sorted(sets.items()):
        if label:
            print(f"\n=== Signature request {label} ===\n")
        codes.append(_run_esign_one(files, pinned, roots_der))
    if len(codes) > 1:
        print(f"\n{len(codes)} signature requests checked.")
    for code in (EXIT_TAMPER, EXIT_MALFORMED, EXIT_UNSEALED):
        if code in codes:
            return code
    return EXIT_OK


def _run_esign_one(files: dict[str, bytes], pinned, roots_der) -> int:
    try:
        recs = {k: _esign_parse_record(files, rel, typ) for k, rel, typ in _ES_RECORD_FILES}
    except _EsignMalformed as exc:
        print(f"MALFORMED: {exc}")
        return EXIT_MALFORMED
    if recs["sent"] is None:
        print("MALFORMED: records/signature_sent.json is missing.")
        return EXIT_MALFORMED
    if recs["completed"] is None:
        print("NOTHING SIGNED TO VERIFY YET: this request has no signature_completed record. "
              "It was not signed, or was not collected, when this bundle was made.")
        return EXIT_MALFORMED

    results: list[tuple[str, str, str]] = []

    def add(verdict, name, detail=""):
        results.append((verdict, name, detail))

    labels = {"sent": "signature_sent", "completed": "signature_completed"}
    # 1. content_hash recomputes from payload
    for k, doc in recs.items():
        rec = doc["record"]
        got = _attestation_sha256_hex(_attestation_canonical_bytes(rec["payload"]))
        ok = got == rec["content_hash"]
        add(TR_VERIFIED if ok else TR_FAILED, f"1. {labels[k]}: content hash recomputes from the payload",
            "matches" if ok else f"payload hashes to {got}, the record says {rec['content_hash']}")
    # 2. sealed in its event
    for k, doc in recs.items():
        rec, ev = doc["record"], doc["event"]
        seal = ev["oversight"].get("evidence_seal") if isinstance(ev.get("oversight"), dict) else None
        name = f"2. {labels[k]}: sealed in its governance event"
        if not isinstance(seal, dict):
            add(TR_FAILED, name, "the event carries no evidence_seal")
            continue
        mism = [f for f, v in (("record_id", rec["id"]), ("record_type", rec.get("record_type")),
                               ("content_hash", rec["content_hash"])) if seal.get(f) != v]
        try:
            eh = _event_hash_of(ev)
        except Exception as exc:  # noqa: BLE001
            add(TR_FAILED, name, f"the event cannot be hashed ({type(exc).__name__})")
            continue
        if mism:
            add(TR_FAILED, name, "the event's evidence_seal disagrees on " + ", ".join(mism))
        elif eh != ev["event_hash"]:
            add(TR_FAILED, name, f"event_hash recomputes to {eh}, the event says {ev['event_hash']}")
        else:
            add(TR_VERIFIED, name,
                f"event {ev.get('event_id')}; record id, type and content hash match; event hash recomputes")
    # 3. inclusion in a signed checkpoint
    for k, doc in recs.items():
        name = f"3. {labels[k]}: event is under a signed checkpoint"
        if doc.get("proof") is None:
            add(TR_NOT_COVERED, name, "no checkpoint covered this record when the bundle was made")
        else:
            v, d = _esign_check_proof(doc["proof"], doc["event"], pinned)
            add(v, name, d)
    # 4. the two records belong together
    sp, cp = recs["sent"]["record"]["payload"], recs["completed"]["record"]["payload"]
    problems = []
    if sp.get("request_id") is None or sp.get("request_id") != cp.get("request_id"):
        problems.append("request_id differs between the two records")
    if cp.get("sent_record_id") != recs["sent"]["record"]["id"]:
        problems.append("the completed record does not name the sent record's id")
    if sp.get("sent_sha256") is None or sp.get("sent_sha256") != cp.get("sent_sha256"):
        problems.append("sent_sha256 differs between the two records")
    if cp.get("source_sha256") is not None and cp.get("source_sha256") != sp.get("source_sha256"):
        problems.append("source_sha256 differs between the two records")
    add(TR_FAILED if problems else TR_VERIFIED, "4. the sent and completed records belong together",
        "; ".join(problems) if problems else f"request {sp.get('request_id')}")
    # 5. files hash to their sealed hashes
    bad, present = [], []
    for fname, (which, field) in _ES_FILE_HASHES.items():
        sealed = recs[which]["record"]["payload"].get(field)
        data = files.get(fname)
        if sealed is None and data is None:
            continue
        if data is None:
            bad.append(f"{fname} is missing but its hash is sealed")
        elif sealed is None:
            bad.append(f"{fname} is present but no record seals a hash for it")
        elif hashlib.sha256(data).hexdigest() != sealed:
            bad.append(f"{fname} does not hash to the sealed value")
        else:
            present.append(fname)
    known_records = {rel for _k, rel, _t in _ES_RECORD_FILES}
    for fname in sorted(files):
        if fname not in _ES_FILE_HASHES and fname not in _ES_UNSEALED_OK and fname not in known_records:
            bad.append(f"{fname} is not a file this format defines, and nothing seals it")
    add(TR_FAILED if bad else TR_VERIFIED, "5. every file hashes to its sealed hash",
        "; ".join(bad) if bad else ", ".join(present))
    # 6 and 7. the signed PDF
    signed = files.get("signed.pdf")
    if signed is None:
        add(TR_FAILED, "6. signed.pdf carries the Coriqo reference and source hash", "signed.pdf is missing")
        add(TR_FAILED, "7. PDF signatures are intact and the last covers the whole file", "signed.pdf is missing")
    else:
        v, d = _esign_pdf_ref(signed, str(sp.get("request_id")), sp.get("source_sha256"))
        add(v, "6. signed.pdf carries the Coriqo reference and source hash", d)
        for line in _esign_pades(signed, roots_der):
            add(*line)
    if not roots_der:
        trust = next((c for c in cp.get("checks") or []
                      if isinstance(c, dict) and c.get("key") == "certificate_trust"), None)
        add(TR_CONTEXT, "7. signer certificate trust, as Coriqo recorded it",
            (f"{trust.get('status')}: {trust.get('detail')}" if trust else "no certificate_trust line was sealed")
            + " (pass --esign-roots to judge it here)")
    # 8. sealed verdict and lines, as context
    add(TR_CONTEXT, "8. verdict Coriqo sealed", str(cp.get("verdict")))
    for c in cp.get("checks") or []:
        if isinstance(c, dict):
            add(TR_CONTEXT, f"8. sealed line: {c.get('label') or c.get('key')}",
                f"{c.get('status')}: {c.get('detail')}")

    for verdict, name, detail in results:
        print(f"  [{verdict.upper()}] {name}" + (f" ({detail})" if detail else ""))
    failed = [r for r in results if r[0] == TR_FAILED]
    print("\nWhat this does not show: that the person named is the person who signed. That is the "
          "signing service's authentication, at the level recorded, and nothing more.")
    if failed:
        print("\nE-SIGNATURE RECORD: FAILED")
        return EXIT_TAMPER
    if any(r[0] == TR_NOT_COVERED and r[1].startswith("3.") for r in results):
        # Without a signed checkpoint the records only agree with each other: someone who rewrote
        # the records, their events and the files together would pass every other line.
        print("\nE-SIGNATURE RECORD: NOT ANCHORED. The files and records agree with each other, but no "
              "signed checkpoint covers them yet, so this does not show they were not rewritten. Download "
              "the bundle again after Coriqo's next checkpoint.")
        return EXIT_UNSEALED
    if pinned is None:
        # The checkpoint key came from the bundle itself, so a forger who signed their own
        # checkpoint passes too. Only a key the reader fetched independently anchors the record.
        print("\nE-SIGNATURE RECORD: NOT PINNED. Every check passed, but the checkpoint signature was "
              "checked with the key inside the bundle, which proves only that the bundle agrees with "
              "itself. Run again with --pubkey <Coriqo public key PEM> (or --keyring) using a key you "
              "got from Coriqo yourself.")
        return EXIT_UNSEALED
    print("\nE-SIGNATURE RECORD: VERIFIED (see any NOT CHECKABLE OFFLINE lines above)")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Agent decision traces (SPEC.md section 18): `--trace PATH`
# ---------------------------------------------------------------------------

TRACE_KIND = "coriqo_decision_trace_proof"


def trace_content_hash(value) -> str:
    """SHA-256 of a trace field's canonical JSON (SPEC.md 3 rules, applied to any
    JSON value): how input_hash, output_hash and tool_calls_hash are made."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def check_trace(data: dict, pinned: dict | None) -> list[tuple[str, str, str]]:
    """Section 18.3 checks for one decision-trace proof file: (check, verdict, detail)."""
    trace, event, proof = data["trace"], data["event"], data["proof"]
    out: list[tuple[str, str, str]] = []

    def add(name: str, ok: bool, good: str, bad: str) -> None:
        out.append((name, TR_VERIFIED if ok else TR_FAILED, good if ok else bad))

    notes = json.loads(event["notes"])
    if not isinstance(notes, dict):
        raise ValueError("the sealed event's notes are not a JSON object")

    # 1. The trace's own content reproduces its hashes. A purged decision kept
    # its hashes but not its content, so there is nothing left to re-hash.
    # A real purge sets output and tool_calls to None. content_purged is not
    # sealed, so a file that claims a purge but still carries content is
    # re-hashed as normal and the claim itself fails.
    claims_purge = bool(trace.get("content_purged"))
    still_has_content = trace.get("output") is not None or trace.get("tool_calls") is not None
    purged = claims_purge and not still_has_content
    if claims_purge and still_has_content:
        out.append(("purge claim", TR_FAILED,
                    "the file says the content was purged but still carries content, "
                    "so the purge claim is false; the content was checked against its hashes"))
    purged_note = (f"the content was deleted under a retention purge ({trace.get('purged_at') or 'date not given'}); "
                   "only its sealed hashes remain")
    if purged:
        out.append(("output", TR_NOT_COVERED, purged_note))
    else:
        out_hash = trace_content_hash(trace.get("output")) if trace.get("output") is not None else None
        add("output", out_hash == trace.get("output_hash"),
            "the output text hashes to the recorded output_hash",
            "the output text does not hash to the recorded output_hash: the output was changed")
    if "inputs" in trace:
        add("inputs", trace_content_hash(trace["inputs"]) == trace.get("input_hash"),
            "the inputs you supplied hash to the recorded input_hash",
            "the inputs you supplied do not hash to the recorded input_hash")
    else:
        out.append(("inputs", TR_NOT_COVERED,
                    "Coriqo keeps only the hash of the inputs. Add the original inputs to the "
                    "file as \"inputs\" to check them too."))

    # 2. The sealed event commits to exactly this trace.
    add("sealed event names this decision", notes.get("trace_id") == trace.get("trace_id")
        and event.get("action") == "agent_decision" and event.get("version_id") == trace.get("version_id"),
        "the event is this decision's agent_decision event on its mandate version",
        "the event is not this decision's agent_decision event")
    # The agent the header names must be the one sealed. Decisions sealed
    # before agent_id was part of the seal can't be tied to an agent here.
    if "agent_id" in notes:
        add("sealed agent", notes.get("agent_id") == trace.get("agent_id"),
            "the sealed event names the same agent",
            "the sealed event names a different agent: this decision is credited to the wrong agent")
    else:
        out.append(("sealed agent", TR_NOT_COVERED,
                    "this decision was sealed before the agent was part of the seal, so the agent shown is not checked"))
    for field in ("input_hash", "output_hash"):
        add(f"sealed {field}", notes.get(field) == trace.get(field),
            f"the sealed event carries the same {field}",
            f"the sealed event carries a different {field}: the record no longer matches what was sealed")
    add("sealed grounding_refs", notes.get("grounding_refs") == (trace.get("grounding_refs") or []),
        "the sealed event carries the same grounding references",
        "the grounding references differ from what was sealed")
    if purged:
        out.append(("sealed tool calls", TR_NOT_COVERED, purged_note))
    elif "tool_calls_hash" in notes:
        add("sealed tool calls", notes["tool_calls_hash"] == trace_content_hash(trace.get("tool_calls") or []),
            "the tool calls, in this order, are the ones sealed",
            "the tool calls differ from what was sealed (a call was changed, added, removed or reordered)")
    else:
        out.append(("sealed tool calls", TR_NOT_COVERED,
                    "this decision was sealed before tool calls were part of the seal, so they are not checked"))

    # 3. The event hash re-derives, and the trace points at it.
    recomputed = _event_hash_of(event)
    add("event hash", recomputed == event.get("event_hash") == trace.get("event_hash"),
        "the event's fields re-hash to its event_hash, and the trace records the same hash",
        "the event's fields do not re-hash to the event_hash the trace records")

    # 4. The event is a leaf under a signed checkpoint.
    verdict, detail = _esign_check_proof(proof, event, pinned)
    out.append(("included under a signed checkpoint", verdict, detail))
    return out


# ---------------------------------------------------------------------------
# Recorded tool calls against the sealed mandate (SPEC.md section 19)
# ---------------------------------------------------------------------------

MANDATE_SNAPSHOT_ACTION = "mandate_snapshot"
MANDATE_DOC_SPEC = "coriqo.mandate/v1"


def _mandate_tools(document) -> tuple[list | None, list]:
    """(allowed, prohibited) from a normalised mandate document (MANDATE_SPEC.md
    6.1). ValueError when the document does not have that shape."""
    if not isinstance(document, dict) or document.get("spec") != MANDATE_DOC_SPEC:
        raise ValueError(f"the sealed document is not a {MANDATE_DOC_SPEC} mandate")
    tools = document.get("tools")
    if not isinstance(tools, dict):
        raise ValueError("the sealed mandate has no tools block")
    allowed, prohibited = tools.get("allowed"), tools.get("prohibited")
    if allowed is not None and not (isinstance(allowed, list) and all(isinstance(t, str) for t in allowed)):
        raise ValueError("tools.allowed in the sealed mandate is not a list of names or null")
    if not (isinstance(prohibited, list) and all(isinstance(t, str) for t in prohibited)):
        raise ValueError("tools.prohibited in the sealed mandate is not a list of names")
    return allowed, prohibited


def calls_outside_mandate(tool_calls, allowed: list | None, prohibited: list) -> list[dict]:
    """Section 19.4: each recorded call the mandate does not permit, as
    {step, tool, why}. A tool on tools.prohibited is outside; with an allow-list
    (allowed not null), so is any tool not on it. An entry with no tool name is
    not a tool call and is skipped."""
    out = []
    for call in tool_calls or []:
        if not isinstance(call, dict) or not call.get("tool"):
            continue
        name = str(call["tool"])
        if name in prohibited:
            out.append({"step": call.get("step"), "tool": name, "why": "prohibited"})
        elif allowed is not None and name not in allowed:
            out.append({"step": call.get("step"), "tool": name, "why": "not on the allowed list"})
    return out


def _count_calls(tool_calls) -> int:
    return sum(1 for c in tool_calls or [] if isinstance(c, dict) and c.get("tool"))


def _sealed_notes(event: dict) -> dict:
    notes = json.loads(event["notes"])
    if not isinstance(notes, dict):
        raise ValueError("the sealed event's notes are not a JSON object")
    return notes


def _outer_key(proof: dict) -> dict:
    """The key the file's own checkpoint is signed under: what every entry in
    its mandate_check block must use when no key is pinned (section 19.3)."""
    sth = proof.get("sth_body") or {}
    return {"pem": proof.get("public_key_pem"), "key_id": sth.get("key_id"), "subject": sth.get("subject")}


def _same_pem(a, b) -> bool:
    norm = lambda p: "".join(str(p or "").split())  # noqa: E731
    return bool(norm(a)) and norm(a) == norm(b)


def _check_sealed_entry(entry: dict, action: str, pinned: dict | None, outer: dict | None = None) -> list[str]:
    """What is wrong with one {event, proof} entry: it must be the named action,
    re-hash to its event_hash, and be a leaf under a signed checkpoint. Empty
    when all three hold.

    Unpinned, the reader is told the file's own key was used; an entry signed
    under any other key would borrow that statement, so it must be the same
    key. A version-scoped checkpoint must cover the entry's own version."""
    event = entry["event"]
    problems = []
    sth = (entry.get("proof") or {}).get("sth_body") or {}
    if pinned is None and outer is not None and (
            not _same_pem((entry.get("proof") or {}).get("public_key_pem"), outer["pem"])
            or sth.get("key_id") != outer["key_id"]):
        problems.append(f"event {event.get('event_id')} is signed under a different key than this file's checkpoint")
    # Fail closed: the entry's checkpoint covers this file's log or the
    # event's own version, and nothing else (a missing subject included).
    subject = sth.get("subject")
    allowed_subjects = {f"version:{event.get('version_id')}"}
    if outer is not None and outer.get("subject"):
        allowed_subjects.add(outer["subject"])
    if subject not in allowed_subjects:
        problems.append(f"event {event.get('event_id')}: its checkpoint covers {subject!r}, "
                        "not this file's log or the event's own version")
    if event.get("action") != action:
        problems.append(f"event {event.get('event_id')} is not a {action} event")
    if _event_hash_of(event) != event.get("event_hash"):
        problems.append(f"event {event.get('event_id')} does not re-hash to its event_hash")
    verdict, detail = _esign_check_proof(entry["proof"], event, pinned)
    if verdict != TR_VERIFIED:
        problems.append(f"event {event.get('event_id')}: {detail}")
    return problems


def _verified_mandates(entries, pinned, lines, outer=None, seen=None) -> tuple[dict[str, dict], int]:
    """Section 19.3 step 1: the sealed mandates that check out, by hash."""
    mandates: dict[str, dict] = {}
    seen = set() if seen is None else seen
    for entry in entries:
        problems = _check_sealed_entry(entry, MANDATE_SNAPSHOT_ACTION, pinned, outer)
        event_id = entry["event"].get("event_id")
        if event_id in seen:
            problems.append(f"event {event_id} appears more than once in this file")
        seen.add(event_id)
        notes = _sealed_notes(entry["event"])
        sha = notes.get("mandate_sha256")
        try:
            allowed, prohibited = _mandate_tools(notes.get("document"))
        except ValueError as exc:
            problems.append(str(exc))
            allowed, prohibited = None, []
        if trace_content_hash(notes.get("document")) != sha:
            problems.append("the sealed mandate document does not hash to its mandate_sha256")
        if problems:
            lines.append((f"sealed mandate {str(sha)[:12]}", TR_FAILED, "; ".join(problems)))
            continue
        mandates[sha] = {"allowed": allowed, "prohibited": prohibited,
                         "version_id": entry["event"].get("version_id"), "agent_id": notes.get("agent_id")}
        allow_text = "no allow-list" if allowed is None else f"{len(allowed)} allowed"
        lines.append((f"sealed mandate {sha[:12]}", TR_VERIFIED,
                      f"agent {notes.get('agent_id')}: {allow_text}, {len(prohibited)} prohibited; the "
                      "document hashes to the sealed value and its event is under a signed checkpoint"))
    return mandates, len(mandates)


def _verified_decisions(entries, pinned, lines, outer=None, seen=None, seen_traces=None) -> tuple[list[dict], int]:
    """Section 19.3 step 2: the sealed decisions in the block that check out.
    A repeated decision (same event or trace) fails: it would count its calls
    twice."""
    decisions = []
    seen = set() if seen is None else seen
    seen_traces = set() if seen_traces is None else seen_traces
    for entry in entries:
        problems = _check_sealed_entry(entry, "agent_decision", pinned, outer)
        event_id = entry["event"].get("event_id")
        if event_id in seen:
            problems.append(f"event {event_id} appears more than once in this file")
        if entry.get("trace_id") in seen_traces:
            problems.append(f"decision {entry.get('trace_id')} appears more than once in this file")
        seen.add(event_id)
        seen_traces.add(entry.get("trace_id"))
        notes = _sealed_notes(entry["event"])
        if notes.get("trace_id") != entry.get("trace_id"):
            problems.append("the sealed event names a different decision")
        if entry.get("tool_calls") is not None and "tool_calls_hash" in notes \
                and notes["tool_calls_hash"] != trace_content_hash(entry["tool_calls"]):
            problems.append("the tool calls differ from what was sealed (changed, added, removed or reordered)")
        if problems:
            lines.append((f"decision {entry.get('trace_id')}", TR_FAILED, "; ".join(problems)))
            continue
        decisions.append({**entry, "notes": notes})
    return decisions, len(decisions)


def _sequence_gaps(decisions, lines) -> list[str]:
    """Section 19.3 step 4: missing or repeated decision_seq numbers per chain."""
    by_version: dict[str, list[int]] = {}
    for d in decisions:
        seq = d["notes"].get("decision_seq")
        if isinstance(seq, int) and not isinstance(seq, bool):
            by_version.setdefault(str(d["event"].get("version_id")), []).append(seq)
    gaps = []
    for version_id, seqs in sorted(by_version.items()):
        dupes = sorted({s for s in seqs if seqs.count(s) > 1})
        if dupes:
            lines.append((f"decision numbers on {version_id}", TR_FAILED,
                          "two sealed decisions carry the same number: " + ", ".join(map(str, dupes))))
        missing, more = _missing_numbers(seqs)
        if missing:
            gaps.append(f"{version_id}: #" + ", #".join(map(str, missing)) + (" and more" if more else ""))
    return gaps


def _missing_numbers(seqs, limit: int = 10) -> tuple[list[int], bool]:
    """The first `limit` numbers missing between the lowest and highest, and
    whether there are more. Built from the sorted distinct numbers, never by
    walking the range: a file can name decision 1 and decision 10**12."""
    uniq = sorted(set(seqs))
    missing: list[int] = []
    for lo, hi in zip(uniq, uniq[1:]):
        for n in range(lo + 1, hi):
            if len(missing) == limit:
                return missing, True
            missing.append(n)
    return missing, False


def check_mandate_calls(block: dict, pinned: dict | None, own_decision: dict | None = None,
                        outer: dict | None = None) -> dict:
    """Section 19.3. `block` is a file's `mandate_check`. `own_decision`, for a
    decision-trace proof (section 18), is {trace_id, tool_calls, event} for the
    file's own decision, which check_trace() has already checked.

    Returns {"lines": [(check, verdict, detail)], "decisions", "calls",
    "outside": [{trace_id, step, tool, why}], "gaps", "signatures": (ok, total),
    "complete"}."""
    if not isinstance(block, dict):
        raise ValueError("mandate_check is not an object")
    lines: list[tuple[str, str, str]] = []
    mandate_entries, decision_entries = block.get("mandates") or [], block.get("decisions") or []
    seen: set = set()
    seen_traces: set = set()
    if own_decision is not None:
        seen.add(own_decision["event"].get("event_id"))
        seen_traces.add(own_decision.get("trace_id"))
    mandates, ok_m = _verified_mandates(mandate_entries, pinned, lines, outer, seen)
    decisions, ok_d = _verified_decisions(decision_entries, pinned, lines, outer, seen, seen_traces)
    if own_decision is not None:
        decisions.insert(0, {**own_decision, "notes": _sealed_notes(own_decision["event"])})

    calls, outside = 0, []
    skipped: dict[str, list] = {"unstamped": [], "unmatched": [], "unhashed": []}
    for d in decisions:
        notes, trace_id = d["notes"], d.get("trace_id")
        if d.get("tool_calls") is None or "tool_calls_hash" not in notes:
            skipped["unhashed"].append(trace_id)  # purged, or sealed before tool calls were
            continue
        sha = notes.get("mandate_sha256")
        if sha is None:
            skipped["unstamped"].append(trace_id)
            continue
        m = mandates.get(sha)
        if m is None or m["version_id"] != d["event"].get("version_id") \
                or ("agent_id" in notes and m["agent_id"] != notes.get("agent_id")):
            skipped["unmatched"].append(trace_id)
            continue
        calls += _count_calls(d["tool_calls"])
        outside += [{"trace_id": trace_id, **o}
                    for o in calls_outside_mandate(d["tool_calls"], m["allowed"], m["prohibited"])]

    for key, label, why in (
        ("unstamped", "decisions without a sealed mandate hash",
         "recorded before decisions named the mandate they ran under, so their tool calls are not checked"),
        ("unmatched", "mandate missing from this file",
         "the file carries no verified sealed mandate with the hash these decisions name, "
         "so their tool calls are not checked"),
        ("unhashed", "tool calls not sealed",
         "their tool calls were purged, or were not part of the seal when recorded, so they are not checked"),
    ):
        ids = skipped[key]
        if ids:
            shown = ", ".join(map(str, ids[:5])) + (", ..." if len(ids) > 5 else "")
            lines.append((label, TR_NOT_COVERED, f"{len(ids)} decision(s) ({shown}): {why}"))

    return {"lines": lines, "decisions": len(decisions), "calls": calls, "outside": outside,
            "gaps": _sequence_gaps(decisions, lines),
            "signatures": (ok_m + ok_d, len(mandate_entries) + len(decision_entries)),
            "complete": not any(skipped.values())}


def mandate_summary(result: dict) -> list[str]:
    """The plain-language lines section 19.5 prints after the checks."""
    ok, total = result["signatures"]
    outside = result["outside"]
    out = [f"Decisions checked : {result['decisions']}",
           f"Signatures        : {ok} of {total} sealed entries verified under a signed checkpoint",
           f"Mandate           : {len(outside)} of {result['calls']} recorded tool calls fell outside "
           "the sealed mandate"]
    for o in outside[:50]:
        out.append(f"  outside: decision {o['trace_id']}, step {o.get('step')}, tool {o['tool']} ({o['why']})")
    if len(outside) > 50:
        out.append(f"  ... and {len(outside) - 50} more")
    out.append("Sequence gaps     : " + ("; ".join(result["gaps"]) if result["gaps"]
                                         else "none among the decisions in this file"))
    return out


def print_mandate_section(result: dict) -> None:
    print("  Recorded tool calls against the sealed mandate (SPEC.md section 19)")
    for name, verdict, detail in result["lines"]:
        print(f"    [{verdict.upper()}] {name}: {detail}")
    for line in mandate_summary(result):
        print(f"    {line}")
    print()


def mandate_failed(result: dict) -> bool:
    return any(v == TR_FAILED for _, v, _ in result["lines"])


def _trace_mandate_check(data: dict, pinned: dict | None) -> dict | None:
    """Section 19 for a decision-trace proof. None for a file with no mandate
    block whose decision names no mandate (every file issued before 19 existed)."""
    block = data.get("mandate_check")
    notes = _sealed_notes(data["event"])
    if block is None and "mandate_sha256" not in notes:
        return None
    trace = data["trace"]
    own = {"trace_id": trace.get("trace_id"), "tool_calls": trace.get("tool_calls"), "event": data["event"]}
    return check_mandate_calls(block if block is not None else {}, pinned, own_decision=own,
                               outer=_outer_key(data["proof"]))


def run_trace(path: str, pubkey_path: str | None = None, keyring_path: str | None = None) -> int:
    """`--trace PATH` (SPEC.md section 18). Exit 0 verified under a pinned key, 1 a
    check failed, 2 every check passed but the checkpoint key was not pinned,
    3 the file is not a decision-trace proof."""
    print(f"Verifying agent decision: {path}\n")
    try:
        pinned = _merge_pinned(pubkey_path, keyring_path)
        data = json.loads(Path(path).read_text())
        if not isinstance(data, dict) or data.get("kind") != TRACE_KIND:
            raise ValueError(f"not a decision-trace proof (expected kind '{TRACE_KIND}')")
        results = check_trace(data, pinned)
        mandate = _trace_mandate_check(data, pinned)
    except (KeyError, TypeError, ValueError, AttributeError, OSError) as exc:
        print(f"MALFORMED: {exc}")
        return EXIT_MALFORMED
    trace = data["trace"]
    print(f"  Decision : {trace.get('trace_id')}")
    agent_checked = any(n == "sealed agent" and v == TR_VERIFIED for n, v, _ in results)
    print(f"  Agent    : {trace.get('agent_id')}{'' if agent_checked else ' (not checked against the seal)'}")
    print(f"  Version  : {trace.get('version_id')}\n")
    for name, verdict, detail in results:
        print(f"  [{verdict.upper()}] {name}: {detail}")
    if mandate is not None:
        print()
        print_mandate_section(mandate)
        results = results + mandate["lines"]
    if any(v == TR_FAILED for _, v, _ in results):
        print("\nAGENT DECISION: FAILED. This record does not match what was sealed.")
        return EXIT_TAMPER
    if pinned is None:
        print("\nAGENT DECISION: NOT PINNED. Every check passed, but the checkpoint signature was "
              "checked with the key inside the file. Run again with --pubkey (or --keyring) using "
              "a key you got from the bank or Coriqo yourself.")
        return EXIT_UNSEALED
    if trace.get("content_purged"):
        # Not a pass: the purge claim is not sealed, so a file that simply
        # withholds the output and tool calls looks the same as a real purge.
        print("\nAGENT DECISION: HASHES ONLY, NOT FULLY VERIFIED. The file says the content was purged, so "
              "the output and tool calls were not checked. The sealed hashes are under the signed checkpoint, "
              "but the purge itself is not sealed: ask the bank for its retention record.")
        return EXIT_UNSEALED
    print("\nAGENT DECISION: VERIFIED. This decision is the one sealed under the signed checkpoint "
          "(see any NOT COVERED lines above).")
    return EXIT_OK


def main():
    parser = argparse.ArgumentParser(
        description="Verify a Coriqo attestation offline (inclusion proof or continuity certificate).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", action="version", version=f"coriqo seal verifier {VERIFIER_VERSION}")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "input", nargs="?", default=None, metavar="INPUT",
        help=("A single file to auto-detect and verify, in place of "
              "--proof/--certificate/--bundle: a .zip (routed to the full "
              "--bundle check when it carries manifest.json, otherwise a "
              "certificate/proof is extracted and verified on its own), a "
              ".pdf (certificate/proof read out of a PDF attachment; "
              "requires the 'pypdf' package), or a bare certificate.json / "
              "proof.json (told apart by shape). Mutually exclusive with "
              "--proof/--certificate/--bundle."),
    )
    mode.add_argument(
        "--proof", required=False, default=None,
        help="Path to the proof bundle JSON file from GET /api/v1/checkpoints/{id}/proof/{event_id}",
    )
    mode.add_argument(
        "--certificate", required=False, default=None,
        help="Path to a Governance Continuity Certificate from GET /api/v1/checkpoints/certificate",
    )
    mode.add_argument(
        "--bundle-dir", required=False, default=None,
        help=("Path to a tenant record bundle directory (or an unzipped copy "
              "of one) from POST /api/v1/checkpoints/export — the full-tenant "
              "export (every checkpoint, the whole governance_events leaf "
              "set, keys, audit log) defined in SPEC.md §13. Checks manifest "
              "file hashes, the embedded continuity certificate, every "
              "checkpoint signature, and every event chain's linkage."),
    )
    mode.add_argument(
        "--attestation", required=False, default=None,
        help=("Path to a CEI attestation fixture: {envelope, record, "
              "checkpoint, events}. Recomputes the envelope's own chain_head "
              "and payload hashes, then checks that the sealed record's "
              "content_hash is bound inside a governance event that is "
              "actually a leaf of the checkpoint's own signed Merkle root — "
              "i.e. that the attestation is included under an exported "
              "checkpoint, not merely internally consistent."),
    )
    mode.add_argument(
        "--bundle", required=False, default=None,
        help=("Path to a deliverables.zip from GET /api/v1/engagements/{id}/"
              "deliverables.zip. Checks, in order: the certificate.json entry's "
              "own signature and checkpoint linkage (same checks as --certificate); "
              "that sha256(manifest.json) matches the certificate's signed "
              "statement.bundle_binding.manifest_sha256; and that every file "
              "manifest.json marks present matches the sha256 of that zip entry's "
              "actual bytes. Exit code distinguishes tamper (1) from an unsealed "
              "bundle (2) from a malformed one (3) — see 'Exit codes' above."),
    )
    mode.add_argument(
        "--esign", required=False, default=None, metavar="PATH",
        help=("A signature-request proof bundle: the zip from GET /api/v1/esign/"
              "requests/{id}/bundle, or a folder holding its esign/ files (SPEC.md "
              "section 17). Checks the two sealed records, their events and "
              "checkpoint proofs, every file's hash, and the signed PDF. Needs "
              "'pyhanko pypdf' for the PDF lines; without them those lines say "
              "'not checkable offline'. Exit 0, 1, or 3."),
    )
    mode.add_argument(
        "--trace", required=False, default=None, metavar="PATH",
        help=("One agent decision: the JSON file from GET /api/v1/agents/{agent_id}/"
              "traces/{trace_id}/proof (SPEC.md section 18). Re-hashes the output (and "
              "the inputs, if you add them), checks the sealed event commits to those "
              "hashes and to the tool calls in order, and that the event sits under a "
              "signed checkpoint. Exit 0, 1, 2 (key not pinned) or 3."),
    )
    parser.add_argument(
        "--esign-roots", required=False, default=None, metavar="PEM",
        help=("With --esign: a PEM file of CA certificates. The signer's certificate "
              "is then judged against these roots (revocation data must be in the "
              "file). Without it, Coriqo's sealed certificate-trust line is shown as "
              "signed context."),
    )
    parser.add_argument(
        "--pubkey", required=False, default=None,
        help=("Path to the Coriqo Ed25519 public key PEM. Optional but recommended: "
              "without it, keys are read from the bundle, which proves the bundle is "
              "internally consistent but not who issued it. With it, signatures are "
              "pinned to the key you supply."),
    )
    parser.add_argument(
        "--keyring", required=False, default=None,
        help=("Pin MULTIPLE keys at once, one per key_id: a directory of "
              "'<key_id>.pem' files, or a single JSON file mapping key_id -> "
              "PEM text. Ahead of per-tenant signing keys / key rotation, "
              "where a certificate can span more than one key_id and a bare "
              "--pubkey has nothing to disambiguate against. Merges with "
              "--pubkey, which covers any key_id --keyring does not name."),
    )
    parser.add_argument(
        "--witness-keyring", required=False, default=None,
        help=("Pin WITNESS public keys — same two forms as --keyring, a "
              "directory of '<witness_key_id>.pem' files or a JSON file "
              "mapping witness_key_id -> PEM text. A cosignature is checked "
              "ONLY against a key pinned here; there is no fallback to the "
              "bundle and no key is ever fetched from Coriqo. Get these keys "
              "from the witnesses themselves."),
    )
    parser.add_argument(
        "--witness-pubkey", required=False, default=None,
        help=("A single witness public key PEM, covering any witness_key_id "
              "--witness-keyring does not name. The common case: your own "
              "organisation is the only witness on its own chain. It asserts "
              "that EVERY otherwise-unnamed cosignature verifies under this "
              "key, so a bundle carrying a second witness fails — use "
              "--witness-keyring when more than one witness is in play."),
    )
    parser.add_argument(
        "--countersign-keyring", required=False, default=None,
        help=("The bank's passkey keyring (JSON, fingerprint -> PEM), from "
              "Signing keys > Download keyring. A countersignature counts "
              "as the bank's only when its key is in this file. Keep your own "
              "copy; one fetched from Coriqo at verify time proves less."),
    )
    parser.add_argument(
        "--tsa-ca", required=False, default=None,
        help=("Path to a PEM bundle of CA certificate(s) trusted to have "
              "issued a checkpoint's RFC 3161 TSA signing certificate "
              "(W2-D). Without it, a stored TSA token's internal signature "
              "and messageImprint are still checked, but the report says "
              "plainly 'TSA token present, CA not pinned — not verified' "
              "rather than a false PASS on the chain of trust. Applies to "
              "--proof and --certificate modes."),
    )
    parser.add_argument(
        "--independent-witness", action="append", default=None,
        metavar="WITNESS_KEY_ID",
        help=("Repeatable. Assert that this witness key belongs to a third "
              "party independent of the organisation whose chain this is. "
              "Without it, a verified cosignature reports as SELF-WITNESSED: "
              "the bundle's own label is unsigned and can only downgrade."),
    )
    mode.add_argument(
        "--head-log-proof", required=False, default=None, metavar="PATH",
        help=("Path to a JSON file shaped like GET /api/v1/public/head-log/"
              "entries/{sth_hash} — one head-log entry plus its inclusion "
              "proof and the signed log head it is checked against ("
              "SPEC.md §14). Verifies the checkpoint under test is the one "
              "the Coriqo-wide public log actually recorded, independent of "
              "--bundle-dir/--certificate/--proof. Combine with "
              "--expect-head to also assert this is the specific checkpoint "
              "a bank told an examiner about."),
    )
    parser.add_argument(
        "--snapshot", required=False, default=None, metavar="SNAPSHOT_JSON",
        help=("With --bundle-dir: a sealed package's snapshot.json (GET "
              "/api/v1/packages/{id}/snapshot.json). Hashes the file's bytes, "
              "finds the package seal that signed that digest, and checks that "
              "every in-scope governance event inside the seal's period fence "
              "is listed in the snapshot (SPEC.md 6.2.6)."),
    )
    parser.add_argument(
        "--expect-head", required=False, default=None, metavar="STH_HASH",
        help=("The sth_hash a bank (or examiner) was told to expect, e.g. "
              "pasted from the other party's copy of the same checkpoint. "
              "Used only with --head-log-proof: fails loud if the proof "
              "file names a different checkpoint, which is exactly the "
              "split-view case this exists to "
              "catch."),
    )
    parser.add_argument(
        "--trust-repair", action="store_true",
        help=("With --bundle-dir and --snapshot: after the bundle verifies, check the package's "
              "remediation claims (SPEC.md section 16): each finding's sealed steps resolve to chain "
              "events in the bundle, in order, naming that finding; the closure follows from the "
              "stated retest; repeat counts add up; the determination method hash is sealed."),
    )
    args = parser.parse_args()

    if args.trust_repair and not (args.bundle_dir and args.snapshot):
        parser.error("--trust-repair requires --bundle-dir and --snapshot.")

    if args.expect_head and not args.head_log_proof:
        parser.error("--expect-head requires --head-log-proof.")

    modes = (bool(args.input), bool(args.proof), bool(args.certificate),
              bool(args.bundle), bool(args.bundle_dir), bool(args.head_log_proof),
              bool(args.attestation), bool(args.esign), bool(args.trace))
    if sum(modes) != 1:
        parser.error("Pass exactly one of INPUT, --proof, --certificate, --bundle, "
                      "--bundle-dir, --attestation, --esign, --trace, or --head-log-proof.")

    if args.trace:
        sys.exit(run_trace(args.trace, args.pubkey, args.keyring))

    if args.head_log_proof:
        sys.exit(run_head_log_proof(args.head_log_proof, args.expect_head, args.pubkey, args.keyring))

    if args.esign:
        sys.exit(run_esign(args.esign, args.pubkey, args.keyring, args.esign_roots))

    if args.esign_roots:
        parser.error("--esign-roots requires --esign.")

    global _COUNTERSIGN_KEYRING_PATH
    _COUNTERSIGN_KEYRING_PATH = args.countersign_keyring

    if args.attestation:
        sys.exit(0 if run_attestation(args.attestation, args.pubkey, args.keyring) else 1)

    if args.snapshot and not args.bundle_dir:
        parser.error("--snapshot requires --bundle-dir.")

    if args.bundle_dir and args.trust_repair:
        sys.exit(run_trust_repair(args.bundle_dir, args.snapshot, args.pubkey, args.keyring))

    if args.bundle_dir:
        sys.exit(run_bundle_dir(args.bundle_dir, args.pubkey, args.keyring,
                                snapshot_path=args.snapshot))

    if args.input:
        sys.exit(run_auto_input(args.input, args.pubkey, args.keyring,
                                 args.witness_keyring, args.witness_pubkey,
                                 args.independent_witness))

    if args.bundle:
        sys.exit(run_bundle(args.bundle, args.pubkey, args.keyring,
                             args.witness_keyring, args.witness_pubkey,
                             args.independent_witness))

    ok = (run_certificate(args.certificate, args.pubkey, args.keyring,
                          args.witness_keyring, args.witness_pubkey,
                          args.independent_witness, args.tsa_ca) if args.certificate
          else run(args.proof, args.pubkey, args.keyring,
                   args.witness_keyring, args.witness_pubkey,
                   args.independent_witness, tsa_ca_path=args.tsa_ca))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

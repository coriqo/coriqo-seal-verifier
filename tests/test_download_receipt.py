"""
Download receipts: the coriqo-receipt.json every PDF from Coriqo carries
(SPEC.md §20). Keys are generated here; nothing is read from a Coriqo server.

The receipt covers the PDF as rendered (`covers_bytes`) and is attached after
those bytes as an incremental update, which the verifier rebuilds and compares.

Run:  python -m pytest tests/ -q
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof  # noqa: E402

pypdf = pytest.importorskip("pypdf", reason="PDF receipts need pypdf")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

ED_KEY = Ed25519PrivateKey.generate()
EC_KEY = ec.generate_private_key(ec.SECP256R1())
OTHER_KEY = Ed25519PrivateKey.generate()


def _pem(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _sign(key, body: dict) -> str:
    msg = verify_proof._canonical_bytes(body)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(msg, ec.ECDSA(hashes.SHA256())).hex()
    return key.sign(msg).hex()


def _rendered(attachments: dict[str, bytes] | None = None) -> bytes:
    w = pypdf.PdfWriter()
    w.add_blank_page(width=72, height=72)
    for name, data in (attachments or {}).items():
        w.add_attachment(name, data)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def _receipt(pdf: bytes, *, key=ED_KEY, key_id="coriqo-v1", algorithm="ed25519",
             version=2, pem=None) -> dict:
    receipt = {
        "subject": "download_receipt", "generated_at": "2026-10-22T10:00:00+00:00",
        "artifact": "reports.board_pack", "file_name": "board.pdf",
        "media_type": "application/pdf", "tenant": "t_bank_00000000", "actor_id": "u-1",
        "file_bytes": len(pdf), "covers_bytes": len(pdf),
    }
    body = {"subject": "download_receipt", "generated_at": receipt["generated_at"],
            "content_hash": hashlib.sha256(pdf).hexdigest(), "key_id": key_id}
    if version == 2:
        receipt["subject_version"] = 2
        body.update(subject_version=2, key_policy="tenant", algorithm=algorithm)
        for field in verify_proof.RECEIPT_SIGNED_FIELDS:
            body[field] = receipt[field]
    receipt["seal"] = {"content_hash": body["content_hash"], "key_id": key_id,
                       "signature": _sign(key, body), "public_key_pem": pem or _pem(key),
                       "signed_body": body}
    if version == 2:
        receipt["seal"].update(key_policy="tenant", algorithm=algorithm)
    return receipt


def _handed_over(pdf: bytes, receipt: dict) -> bytes:
    return verify_proof._rebuild_receipt_update(pdf, receipt)


def _run(tmp_path, data: bytes, **kw) -> int:
    path = tmp_path / "file.pdf"
    path.write_bytes(data)
    return verify_proof.run_auto_input(str(path), **kw)


def _states(data: bytes, receipt: dict, **kw) -> dict[str, str]:
    return {name: state for name, state, _ in verify_proof.check_download_receipt(data, receipt, **kw)}


def test_an_ed25519_receipt_verifies(tmp_path):
    pdf = _rendered()
    assert _run(tmp_path, _handed_over(pdf, _receipt(pdf))) == verify_proof.EXIT_OK


def test_an_es256_receipt_verifies(tmp_path):
    pdf = _rendered()
    receipt = _receipt(pdf, key=EC_KEY, algorithm="es256")
    assert _run(tmp_path, _handed_over(pdf, receipt)) == verify_proof.EXIT_OK


def test_a_pdf_without_the_pdf_suffix_is_still_read_as_one(tmp_path):
    pdf = _rendered()
    path = tmp_path / "download"
    path.write_bytes(_handed_over(pdf, _receipt(pdf)))
    assert verify_proof.run_auto_input(str(path)) == verify_proof.EXIT_OK


def test_a_changed_byte_in_the_signed_part_fails(tmp_path):
    pdf = _rendered()
    data = bytearray(_handed_over(pdf, _receipt(pdf)))
    data[30] ^= 0x01
    assert _run(tmp_path, bytes(data)) == verify_proof.EXIT_TAMPER


def test_anything_added_after_the_receipt_fails(tmp_path):
    pdf = _rendered()
    data = _handed_over(pdf, _receipt(pdf))
    buf = io.BytesIO(data)
    w = pypdf.PdfWriter(fileobj=buf, incremental=True)
    w.add_attachment("note.txt", b"added later")
    w.write(buf)
    receipt = _receipt(pdf)
    assert _states(buf.getvalue(), receipt)["Bytes after the signed part are only the receipt"] == "FAIL"
    assert _run(tmp_path, buf.getvalue()) == verify_proof.EXIT_TAMPER


def test_an_edited_receipt_field_fails(tmp_path):
    pdf = _rendered()
    receipt = _receipt(pdf)
    receipt["actor_id"] = "someone-else"
    assert _states(_handed_over(pdf, receipt), receipt)["Receipt fields match what was signed"] == "FAIL"
    assert _run(tmp_path, _handed_over(pdf, receipt)) == verify_proof.EXIT_TAMPER


def test_covers_past_the_end_fails():
    pdf = _rendered()
    receipt = _receipt(pdf)
    receipt["covers_bytes"] = len(pdf) + 10
    assert _states(pdf, receipt)["Signed part of this file is unchanged"] == "FAIL"


def test_the_declared_algorithm_must_match_the_key():
    pdf = _rendered()
    receipt = _receipt(pdf, key=ED_KEY, algorithm="es256")
    assert _states(_handed_over(pdf, receipt), receipt)["Receipt signature"] == "FAIL"


def test_a_version_1_receipt_verifies_and_says_what_it_does_not_sign(tmp_path):
    pdf = _rendered()
    receipt = _receipt(pdf, version=1)
    states = _states(_handed_over(pdf, receipt), receipt)
    assert states["Receipt fields match what was signed"] == "INFO"
    assert _run(tmp_path, _handed_over(pdf, receipt)) == verify_proof.EXIT_OK


def test_a_receipt_stripped_of_its_version_does_not_take_the_version_1_path():
    pdf = _rendered()
    receipt = _receipt(pdf)
    del receipt["subject_version"]
    assert _states(_handed_over(pdf, receipt), receipt)["Receipt fields match what was signed"] == "FAIL"


def test_a_pinned_key_is_used_instead_of_the_one_the_receipt_carries(tmp_path):
    pdf = _rendered()
    data = _handed_over(pdf, _receipt(pdf))
    right, wrong = tmp_path / "right.pem", tmp_path / "wrong.pem"
    right.write_text(_pem(ED_KEY))
    wrong.write_text(_pem(OTHER_KEY))
    assert _run(tmp_path, data, pubkey_path=str(right)) == verify_proof.EXIT_OK
    assert _run(tmp_path, data, pubkey_path=str(wrong)) == verify_proof.EXIT_TAMPER


def test_a_keyring_that_does_not_name_the_key_fails(tmp_path):
    pdf = _rendered()
    keyring = tmp_path / "keys.json"
    keyring.write_text(json.dumps({"some-other-key": _pem(ED_KEY)}))
    data = _handed_over(pdf, _receipt(pdf))
    assert _run(tmp_path, data, keyring_path=str(keyring)) == verify_proof.EXIT_TAMPER


def test_a_receipt_cannot_borrow_a_certificates_key_id():
    pdf = _rendered()
    receipt = _receipt(pdf, key=OTHER_KEY, key_id="coriqo-v1")
    cert_keys = {"coriqo-v1": {"pem": _pem(ED_KEY), "revoked": False}}
    assert _states(_handed_over(pdf, receipt), receipt, cert_keys=cert_keys)["One key per key id"] == "FAIL"


def test_an_unsigned_receipt_is_unsealed_not_tampered(tmp_path):
    pdf = _rendered()
    receipt = {"subject": "download_receipt", "sealed": False, "unavailable_reason": "no signing key",
               "covers_bytes": len(pdf)}
    assert _run(tmp_path, _handed_over(pdf, receipt)) == verify_proof.EXIT_UNSEALED


def test_a_pdf_with_no_seal_and_no_receipt_is_malformed(tmp_path):
    assert _run(tmp_path, _rendered()) == verify_proof.EXIT_MALFORMED


CERTIFICATE = Path(__file__).resolve().parent.parent / "testdata" / "certificate.json"


def test_a_certificate_and_its_receipt_are_both_checked(tmp_path):
    pdf = _rendered({"certificate.json": CERTIFICATE.read_bytes()})
    assert _run(tmp_path, _handed_over(pdf, _receipt(pdf))) == verify_proof.EXIT_OK
    assert _run(tmp_path, pdf) == verify_proof.EXIT_OK  # a certificate alone, as before


def test_a_good_receipt_does_not_rescue_a_bad_certificate(tmp_path):
    cert = json.loads(CERTIFICATE.read_text())
    cert["statement"]["checkpoint_count"] += 1
    pdf = _rendered({"certificate.json": json.dumps(cert).encode()})
    assert _run(tmp_path, _handed_over(pdf, _receipt(pdf))) == verify_proof.EXIT_TAMPER

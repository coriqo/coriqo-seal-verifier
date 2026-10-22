"""verify_proof.py --esign (SPEC.md section 17).

The fixture is built here from SPEC.md alone (its own canonical JSON, event hash and RFC 6962 tree),
not from Coriqo's code, so a disagreement with the verifier points at the spec. The signed PDF is
real: a stamped PDF carrying /CoriqoRef and /CoriqoSourceSha256, signed with a throwaway key.

Run: python -m pytest seal-verifier/tests/test_esign_bundle.py -q
"""
from __future__ import annotations

import builtins
import copy
import datetime as dt
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("pyhanko")
pytest.importorskip("pypdf")

from asn1crypto import keys as a_keys  # noqa: E402
from asn1crypto import x509 as a_x509  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter  # noqa: E402
from pyhanko.sign import signers  # noqa: E402
from pyhanko_certvalidator.registry import SimpleCertificateStore  # noqa: E402
from pypdf import PdfReader, PdfWriter  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof as vp  # noqa: E402

REQ = "11111111-2222-3333-4444-555555555555"
VERSION = "v-anchor"


# ------------------------------------------------------------------ SPEC-only helpers
def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def event_hash(ev: dict) -> str:
    h = {"seq": ev["seq"], "actor": ev["actor"], "action": ev["action"], "model_version_id": ev["version_id"],
         "from_status": ev["from_status"], "to_status": ev["to_status"], "notes": ev["notes"],
         "prev_hash": ev["prev_hash"]}
    if ev.get("oversight") is not None:
        h["oversight"] = ev["oversight"]
    return sha(canon(h))


def mth(leaves):
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:])).digest()


def path_of(m, leaves):
    if len(leaves) == 1:
        return []
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    if m < k:
        return path_of(m, leaves[:k]) + [mth(leaves[k:])]
    return path_of(m - k, leaves[k:]) + [mth(leaves[:k])]


def pub_pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


# ------------------------------------------------------------------ PDF
def raw_pdf(text: str) -> bytes:
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 "
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>"]
    stream = f"BT /F1 12 Tf 72 700 Td ({text}) Tj ET".encode()
    objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offs = []
    for i, body in enumerate(objs, 1):
        offs.append(out.tell())
        out.write(f"{i} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    for o in offs:
        out.write(f"{o:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return out.getvalue()


def stamped(ref: str, source_sha: str) -> bytes:
    w = PdfWriter(clone_from=PdfReader(io.BytesIO(raw_pdf("Loan policy " + ref))))
    w.add_metadata({"/CoriqoRef": ref, "/CoriqoSourceSha256": source_sha})
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


class Pki:
    def __init__(self, cn="Jane Signer"):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = dt.datetime.now(dt.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                     .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                     .sign(self.key, hashes.SHA256()))

    def root_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def sign(self, pdf: bytes) -> bytes:
        a_cert = a_x509.Certificate.load(self.cert.public_bytes(serialization.Encoding.DER))
        a_key = a_keys.PrivateKeyInfo.load(self.key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        s = signers.SimpleSigner(signing_cert=a_cert, signing_key=a_key,
                                 cert_registry=SimpleCertificateStore.from_certs([a_cert]))
        out = signers.sign_pdf(IncrementalPdfFileWriter(io.BytesIO(pdf)),
                               signers.PdfSignatureMetadata(field_name="Sig1", md_algorithm="sha256"), signer=s)
        return out.getvalue()


# ------------------------------------------------------------------ the bundle
class World:
    """One valid bundle plus the pieces a test needs to forge variants of it."""

    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.pki = Pki()
        self.source_sha = sha(b"the source document")
        self.sent_pdf = stamped(REQ, self.source_sha)
        self.signed_pdf = self.pki.sign(self.sent_pdf)
        self.audit_json = b'{"events":[]}'
        self.files: dict[str, bytes] = {
            "request.json": b'{"note":"display only"}',
            "sent.pdf": self.sent_pdf, "signed.pdf": self.signed_pdf, "audit_trail.json": self.audit_json}
        self.sent_payload = {"request_id": REQ, "sent_sha256": sha(self.sent_pdf), "source_sha256": self.source_sha,
                             "purpose": "package_final_signoff"}
        self.completed_payload = {
            "request_id": REQ, "verdict": "verified_with_notes", "signed_sha256": sha(self.signed_pdf),
            "sent_sha256": sha(self.sent_pdf), "source_sha256": self.source_sha, "sent_record_id": "rec-sent",
            "audit_trail_json_sha256": sha(self.audit_json),
            "checks": [{"key": "signature_intact", "status": "pass", "label": "Signature intact", "detail": "ok"},
                       {"key": "certificate_trust", "status": "note", "label": "Certificate trust",
                        "detail": "no trusted roots held"}],
            "signers": []}
        self.docs: dict[str, dict] = {}
        self.build_records()

    def event_for(self, rec_id, rtype, payload, seq, prev):
        seal = {"record_id": rec_id, "record_type": rtype, "schema_version": 1,
                "content_hash": sha(canon(payload)), "effective_at": "2026-10-11T00:00:00Z"}
        ev = {"event_id": f"ev-{seq}", "version_id": VERSION, "seq": seq, "actor": "system",
              "action": "evidence_record_sealed", "from_status": "", "to_status": "sealed",
              "notes": json.dumps(seal), "prev_hash": prev, "oversight": {"evidence_seal": seal}}
        ev["event_hash"] = event_hash(ev)
        return ev

    def build_records(self):
        fillers = []
        prev = "0" * 64
        for i in range(3):
            f = {"event_id": f"ev-f{i}", "version_id": VERSION, "seq": i, "actor": "a", "action": "x",
                 "from_status": "", "to_status": "y", "notes": "", "prev_hash": prev, "oversight": None}
            f["event_hash"] = event_hash(f)
            prev = f["event_hash"]
            fillers.append(f)
        e_sent = self.event_for("rec-sent", "signature_sent", self.sent_payload, 3, prev)
        e_done = self.event_for("rec-done", "signature_completed", self.completed_payload, 4, e_sent["event_hash"])
        evs = fillers + [e_sent, e_done]
        leaves = [bytes.fromhex(e["event_hash"]) for e in evs]
        sth = {"subject": f"version:{VERSION}", "issued_at": "2026-10-11T00:00:00Z", "length": len(evs),
               "head_hash": evs[-1]["event_hash"], "merkle_root": mth(leaves).hex(), "tree_size": len(evs),
               "key_id": "k1", "tree_version": 2, "ordering_version": 2, "ordinal_watermark": len(evs) - 1}
        sig = self.key.sign(canon(sth)).hex()

        def proof(i):
            return {"checkpoint_id": "cp-1", "event_id": evs[i]["event_id"], "leaf_index": i,
                    "tree_size": len(evs), "merkle_root": sth["merkle_root"], "leaf_input": evs[i]["event_hash"],
                    "proof_path": [p.hex() for p in path_of(i, leaves)], "checkpoint_signature": sig,
                    "key_id": "k1", "public_key_pem": pub_pem(self.key), "sth_body": sth}

        def doc(rec_id, rtype, payload, ev, i):
            ev = {k: v for k, v in ev.items() if not (k == "oversight" and v is None)}
            return {"record": {"id": rec_id, "record_type": rtype, "schema_version": 1, "payload": payload,
                               "content_hash": sha(canon(payload)), "effective_at": "2026-10-11T00:00:00Z"},
                    "event": ev, "proof": proof(i)}
        self.docs = {"sent": doc("rec-sent", "signature_sent", self.sent_payload, e_sent, 3),
                     "completed": doc("rec-done", "signature_completed", self.completed_payload, e_done, 4)}

    def files_out(self) -> dict[str, bytes]:
        out = dict(self.files)
        out["records/signature_sent.json"] = json.dumps(self.docs["sent"]).encode()
        out["records/signature_completed.json"] = json.dumps(self.docs["completed"]).encode()
        return out


@pytest.fixture(scope="module")
def world():
    return World()


def check(files: dict[str, bytes], tmp_path, capsys, *args, as_dir=False):
    """Write files as a zip (or folder), run --esign on it, return (exit code, output)."""
    if as_dir:
        target = tmp_path / "bundle"
        for rel, data in files.items():
            (target / rel).parent.mkdir(parents=True, exist_ok=True)
            (target / rel).write_bytes(data)
        path = str(target)
    else:
        path = str(tmp_path / "b.zip")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("README.txt", "x")
            for rel, data in files.items():
                z.writestr(f"esign/{rel}", data)
    rc = vp.run_esign(path, *args)
    return rc, capsys.readouterr().out


def pin(world, tmp_path) -> str:
    """The checkpoint key as a reader would pin it (--pubkey). Without one the run is NOT PINNED."""
    p = tmp_path / "pinned.pem"
    p.write_text(pub_pem(world.key))
    return str(p)


def edit(files, rel, fn):
    files = dict(files)
    doc = json.loads(files[rel])
    fn(doc)
    files[rel] = json.dumps(doc).encode()
    return files


def line(out, start):
    return next((ln for ln in out.splitlines() if start in ln), "")


# ------------------------------------------------------------------ tests
def test_valid_bundle_verifies(world, tmp_path, capsys):
    rc, out = check(world.files_out(), tmp_path, capsys, pin(world, tmp_path))
    assert rc == 0, out
    assert "[FAILED]" not in out
    for n in ("1. signature_sent", "2. signature_completed", "3. signature_completed", "4. ", "5. ", "6. ", "7. PDF"):
        assert "[VERIFIED] " + n in out, (n, out)
    assert "[SIGNED CONTEXT] 8. verdict Coriqo sealed (verified_with_notes)" in out
    assert "[SIGNED CONTEXT] 7. signer certificate trust" in out
    assert "does not show: that the person named" in out


def test_valid_bundle_from_a_folder(world, tmp_path, capsys):
    rc, out = check(world.files_out(), tmp_path, capsys, pin(world, tmp_path), as_dir=True)
    assert rc == 0, out


def test_pinned_key_verifies_and_a_different_key_fails(world, tmp_path, capsys):
    good = tmp_path / "good.pem"
    good.write_text(pub_pem(world.key))
    rc, out = check(world.files_out(), tmp_path, capsys, str(good))
    assert rc == 0 and "under your pinned key" in out
    other = tmp_path / "other.pem"
    other.write_text(pub_pem(Ed25519PrivateKey.generate()))
    rc, out = check(world.files_out(), tmp_path, capsys, str(other))
    assert rc == 1
    assert "[FAILED] 3. signature_sent" in out and "checkpoint signature does not verify" in out


def test_one_byte_of_signed_pdf_changed(world, tmp_path, capsys):
    f = world.files_out()
    b = bytearray(f["signed.pdf"])
    b[len(b) // 3] ^= 0x01
    f["signed.pdf"] = bytes(b)
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1
    assert "[FAILED] 5." in out and "signed.pdf does not hash to the sealed value" in out


def test_sent_pdf_swapped(world, tmp_path, capsys):
    f = world.files_out()
    f["sent.pdf"] = stamped(REQ, sha(b"another source"))
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1 and "sent.pdf does not hash to the sealed value" in out


def test_completed_payload_edited(world, tmp_path, capsys):
    f = edit(world.files_out(), "records/signature_completed.json",
             lambda d: d["record"]["payload"].update(verdict="verified"))
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1 and "[FAILED] 1. signature_completed: content hash" in out


def test_payload_edited_and_content_hash_recomputed(world, tmp_path, capsys):
    def fn(d):
        d["record"]["payload"]["verdict"] = "verified"
        d["record"]["content_hash"] = sha(canon(d["record"]["payload"]))
    f = edit(world.files_out(), "records/signature_completed.json", fn)
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1
    assert "[VERIFIED] 1. signature_completed" in out
    assert "[FAILED] 2. signature_completed" in out and "disagrees on content_hash" in out


def test_event_field_edited(world, tmp_path, capsys):
    f = edit(world.files_out(), "records/signature_sent.json", lambda d: d["event"].update(actor="someone else"))
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1 and "[FAILED] 2. signature_sent" in out and "event_hash recomputes" in out


def test_forger_rewrites_record_and_event_but_cannot_resign_the_checkpoint(world, tmp_path, capsys):
    def fn(d):
        d["record"]["payload"]["verdict"] = "verified"
        d["record"]["content_hash"] = sha(canon(d["record"]["payload"]))
        seal = d["event"]["oversight"]["evidence_seal"]
        seal["content_hash"] = d["record"]["content_hash"]
        d["event"]["notes"] = json.dumps(seal)
        d["event"]["event_hash"] = event_hash(d["event"])
    f = edit(world.files_out(), "records/signature_completed.json", fn)
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1
    assert "[VERIFIED] 2. signature_completed" in out        # internally consistent now
    assert "[FAILED] 3. signature_completed" in out and "leaf_input is not this event's event_hash" in out


def test_proof_path_sibling_changed(world, tmp_path, capsys):
    def fn(d):
        d["proof"]["proof_path"][0] = "00" * 32
    f = edit(world.files_out(), "records/signature_sent.json", fn)
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1 and "[FAILED] 3. signature_sent" in out and "Merkle path" in out


def test_signed_pdf_replaced_by_a_validly_signed_pdf_for_another_ref(world, tmp_path, capsys):
    other = world.pki.sign(stamped("another-request", world.source_sha))
    f = world.files_out()
    f["signed.pdf"] = other
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1
    assert "signed.pdf does not hash to the sealed value" in out
    assert "[FAILED] 6." in out and "/CoriqoRef" in out
    assert "[VERIFIED] 7. PDF" in out        # the signature itself is fine: the document is the wrong one

    # Forger also rewrites the sealed hash: the record, event and checkpoint chain breaks instead.
    def fn(d):
        d["record"]["payload"]["signed_sha256"] = sha(other)
    f = edit(f, "records/signature_completed.json", fn)
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1 and "[FAILED] 1. signature_completed" in out and "[FAILED] 6." in out


def test_sealed_hash_with_its_file_removed(world, tmp_path, capsys):
    f = world.files_out()
    del f["audit_trail.json"]
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1 and "audit_trail.json is missing but its hash is sealed" in out


def test_file_with_no_sealed_hash_and_unknown_files_fail(world, tmp_path, capsys):
    f = world.files_out()
    f["certificate.pdf"] = b"%PDF cert"
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1 and "certificate.pdf is present but no record seals a hash for it" in out
    f = world.files_out()
    f["notes.txt"] = b"hello"
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1 and "notes.txt is not a file this format defines" in out


def test_request_json_is_ignored(world, tmp_path, capsys):
    f = world.files_out()
    f["request.json"] = b'{"status": "anything at all"}'
    rc, out = check(f, tmp_path, capsys, pin(world, tmp_path))
    assert rc == 0, out


def test_null_proof_is_not_covered_and_never_reads_as_verified(world, tmp_path, capsys):
    """Security review: with the proofs stripped, a rewritten-but-consistent bundle passes every
    other line, so a missing checkpoint is exit 2 ("not anchored"), never VERIFIED."""
    f = world.files_out()
    for rel in ("records/signature_sent.json", "records/signature_completed.json"):
        f = edit(f, rel, lambda d: d.update(proof=None))
    rc, out = check(f, tmp_path, capsys)
    assert rc == 2, out
    assert "NOT ANCHORED" in out and "E-SIGNATURE RECORD: VERIFIED" not in out
    assert "[NOT COVERED] 3. signature_sent" in out and "[NOT COVERED] 3. signature_completed" in out


def test_requests_pair_mismatch(world, tmp_path, capsys):
    f = edit(world.files_out(), "records/signature_sent.json", lambda d: d["record"]["payload"].update(request_id="x"))
    rc, out = check(f, tmp_path, capsys)
    assert rc == 1 and "[FAILED] 4." in out


def test_without_pyhanko_and_pypdf_the_pdf_lines_are_not_checkable_and_never_pass(world, tmp_path, capsys, monkeypatch):
    real = builtins.__import__

    def fake(name, *a, **k):
        if name.split(".")[0] in ("pyhanko", "pypdf", "pyhanko_certvalidator"):
            raise ImportError(name)
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    rc, out = check(world.files_out(), tmp_path, capsys, pin(world, tmp_path))
    assert rc == 0, out
    assert "[SIGNED, NOT CHECKABLE OFFLINE] 6." in out and "[SIGNED, NOT CHECKABLE OFFLINE] 7." in out
    assert "[VERIFIED] 6." not in out and "[VERIFIED] 7. PDF" not in out
    assert "[VERIFIED] 5." in out        # the hash lines still run


def test_no_completed_record_is_nothing_to_verify(world, tmp_path, capsys):
    f = world.files_out()
    del f["records/signature_completed.json"]
    rc, out = check(f, tmp_path, capsys)
    assert rc == 3 and "NOTHING SIGNED TO VERIFY YET" in out


def test_not_a_bundle_exits_three(tmp_path, capsys):
    p = tmp_path / "x.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("hello.txt", "x")
    assert vp.run_esign(str(p)) == 3
    assert "MALFORMED" in capsys.readouterr().out
    assert vp.run_esign(str(tmp_path / "missing")) == 3


def test_esign_roots_are_judged_and_an_unrelated_root_fails(world, tmp_path, capsys):
    other = Pki("Other Root")
    roots = tmp_path / "roots.pem"
    roots.write_bytes(other.root_pem())
    rc, out = check(world.files_out(), tmp_path, capsys, None, None, str(roots))
    assert rc == 1
    assert "[FAILED] 7. signer certificate chains to the roots you supplied" in out
    assert "[VERIFIED] 7. PDF signatures" in out
    assert "signer certificate trust, as Coriqo recorded it" not in out


def test_cli_flag_runs_the_same_check(world, tmp_path, capsys, monkeypatch):
    files = world.files_out()
    path = tmp_path / "cli.zip"
    with zipfile.ZipFile(path, "w") as z:
        for rel, data in files.items():
            z.writestr(f"esign/{rel}", data)
    monkeypatch.setattr(sys, "argv", ["verify_proof.py", "--esign", str(path), "--pubkey", pin(world, tmp_path)])
    with pytest.raises(SystemExit) as e:
        vp.main()
    assert e.value.code == 0
    assert "E-SIGNATURE RECORD: VERIFIED" in capsys.readouterr().out


def test_unpinned_key_is_not_pinned_and_never_reads_as_verified(world, tmp_path, capsys):
    """Security review: with the key taken from the bundle, a forger who signed their own
    checkpoint passes every line, so an unpinned run is exit 2 ("not pinned"), never VERIFIED."""
    rc, out = check(world.files_out(), tmp_path, capsys)
    assert rc == 2, out
    assert "NOT PINNED" in out and "E-SIGNATURE RECORD: VERIFIED" not in out
    assert "under the key in the bundle (not pinned)" in out

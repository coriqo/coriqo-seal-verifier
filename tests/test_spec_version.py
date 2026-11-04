"""SPEC.md §12.1: a bundle's spec_version decides whether this verifier runs.

Run:  python -m pytest tests/ -q
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TESTDATA = ROOT / "testdata"


def _proof(**extra):
    d = json.loads((TESTDATA / "proof_v2.json").read_text())
    d.update(extra)
    return d


def _run(bundle, tmp_path, name="proof.json"):
    p = tmp_path / name
    p.write_text(json.dumps(bundle))
    return verify_proof.run(str(p), None)


def test_absent_spec_version_is_1_0_and_verifies(tmp_path):
    assert "spec_version" not in _proof()
    assert _run(_proof(), tmp_path)


@pytest.mark.parametrize("version", ["1.0", "1.7"])
def test_same_major_verifies(tmp_path, version):
    # A newer MINOR only adds fields, so it is checked as normal.
    assert _run(_proof(spec_version=version), tmp_path)


@pytest.mark.parametrize("version", ["2.0", "0.9"])
def test_other_major_is_refused_with_a_clear_message(tmp_path, capsys, version):
    assert not _run(_proof(spec_version=version), tmp_path)
    out = capsys.readouterr().out
    assert "UNSUPPORTED SPEC VERSION" in out
    assert f"spec version {version}" in out and "implements spec version 1.1" in out
    # Refused before any check runs: no PASS/FAIL verdict is printed.
    assert "[PASS]" not in out and "[FAIL]" not in out


@pytest.mark.parametrize("version", ["2", "v1.0", 1, None])
def test_malformed_spec_version_is_refused(tmp_path, capsys, version):
    assert not _run(_proof(spec_version=version), tmp_path)
    assert "is not MAJOR.MINOR" in capsys.readouterr().out


def test_certificate_with_other_major_is_refused(tmp_path, capsys):
    cert = json.loads((TESTDATA / "certificate.json").read_text())
    cert["spec_version"] = "2.0"
    p = tmp_path / "certificate.json"
    p.write_text(json.dumps(cert))
    assert not verify_proof.run_certificate(str(p), None)
    assert "UNSUPPORTED SPEC VERSION" in capsys.readouterr().out


def test_cli_exits_1_on_unknown_major_through_auto_detect(tmp_path):
    p = tmp_path / "sample-proof.json"
    p.write_text(json.dumps(_proof(spec_version="3.0")))
    r = subprocess.run([sys.executable, str(ROOT / "verify_proof.py"), str(p)],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert "UNSUPPORTED SPEC VERSION" in r.stdout


def test_one_byte_edit_fails_naming_the_check(tmp_path):
    """The examiner quickstart's tamper step: change one hex digit of leaf_input."""
    d = _proof(spec_version="1.0")
    h = d["leaf_input"]
    d["leaf_input"] = ("0" if h[0] != "0" else "1") + h[1:]
    p = tmp_path / "sample-proof.json"
    p.write_text(json.dumps(d))
    r = subprocess.run([sys.executable, str(ROOT / "verify_proof.py"), str(p)],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert "[FAIL]" in r.stdout and "Merkle" in r.stdout

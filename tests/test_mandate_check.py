"""SPEC.md section 19: recorded tool calls checked against the sealed mandate.

The corpus (testdata/mandate_check/) is built by make_mandate_check_corpus.py
from the spec. A conforming verifier reaches each case's exit code and line;
every mutation below must fail or be reported as not checked.

Run: python -m pytest tests/test_mandate_check.py -q
"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import verify_proof as vp  # noqa: E402

CORPUS = ROOT / "testdata" / "mandate_check"
PUBKEY = ROOT / "testdata" / "pubkey.pem"
CASES = json.loads((CORPUS / "cases.json").read_text())


def load(name: str) -> dict:
    return json.loads((CORPUS / name).read_text())


def run_file(tmp_path, data: dict, mode: str, *, pinned: bool = True):
    f = tmp_path / "file.json"
    f.write_text(json.dumps(data))
    key = str(PUBKEY) if pinned else None
    if mode == "trace":
        return vp.run_trace(str(f), key)
    return vp.EXIT_OK if vp.run(str(f), key) else vp.EXIT_TAMPER


@pytest.mark.parametrize("case", CASES, ids=[c["file"] for c in CASES])
def test_corpus_case(case, tmp_path, capsys):
    assert run_file(tmp_path, load(case["file"]), case["mode"]) == case["exit"]
    assert case["line"] in capsys.readouterr().out


@pytest.mark.parametrize("case", CASES, ids=[c["file"] for c in CASES])
def test_corpus_case_result(case):
    data = load(case["file"])
    own = None
    if case["mode"] == "trace":
        own = {"trace_id": data["trace"]["trace_id"], "tool_calls": data["trace"]["tool_calls"],
               "event": data["event"]}
    result = vp.check_mandate_calls(data["mandate_check"], {None: PUBKEY.read_text()}, own_decision=own)
    assert not vp.mandate_failed(result) and result["complete"]
    if "outside" in case:
        assert result["outside"] == case["outside"]
    if "gaps" in case:
        assert result["gaps"] == case["gaps"]


def test_corpus_regenerates_byte_for_byte():
    before = {p.name: p.read_bytes() for p in CORPUS.iterdir()}
    subprocess.run([sys.executable, str(Path(__file__).parent / "make_mandate_check_corpus.py")],
                   check=True, capture_output=True)
    assert {p.name: p.read_bytes() for p in CORPUS.iterdir()} == before


def test_unpinned_decision_is_not_a_pass(tmp_path):
    assert run_file(tmp_path, load("decision_inside.json"), "trace", pinned=False) == vp.EXIT_UNSEALED


def test_mandate_widened_after_the_fact_fails(tmp_path, capsys):
    # Someone adds wire_transfer to the allowed list so the outside call disappears.
    d = load("decision_outside.json")
    doc = json.loads(d["mandate_check"]["mandates"][0]["event"]["notes"])
    doc["document"]["tools"] = {"allowed": ["credit_check", "income_check", "wire_transfer"], "prohibited": []}
    d["mandate_check"]["mandates"][0]["event"]["notes"] = json.dumps(doc)
    assert run_file(tmp_path, d, "trace") == vp.EXIT_TAMPER
    out = capsys.readouterr().out
    assert "does not re-hash" in out and "does not hash to its mandate_sha256" in out


def test_rehashed_mandate_still_fails_its_seal(tmp_path, capsys):
    # The forger also fixes mandate_sha256 to match the widened document; the
    # snapshot event no longer re-hashes, and the decision names the old hash.
    d = load("proof_with_gap.json")
    entry = d["mandate_check"]["mandates"][0]
    notes = json.loads(entry["event"]["notes"])
    notes["document"]["tools"]["prohibited"] = []
    notes["mandate_sha256"] = vp.trace_content_hash(notes["document"])
    entry["event"]["notes"] = json.dumps(notes)
    assert run_file(tmp_path, d, "proof") == vp.EXIT_TAMPER
    assert "RESULT: VERIFICATION FAILED" in capsys.readouterr().out


def test_hidden_tool_call_fails(tmp_path, capsys):
    # Dropping the prohibited call from the decision's tool calls.
    d = load("proof_with_gap.json")
    dec = d["mandate_check"]["decisions"][1]
    dec["tool_calls"] = []
    assert run_file(tmp_path, d, "proof") == vp.EXIT_TAMPER
    assert "the tool calls differ from what was sealed" in capsys.readouterr().out


def test_decision_from_another_checkpoint_tree_fails(tmp_path):
    d = load("proof_inside.json")
    d["mandate_check"]["decisions"][0]["proof"]["leaf_index"] = 3
    assert run_file(tmp_path, d, "proof") == vp.EXIT_TAMPER


def test_missing_mandate_is_reported_not_checked(tmp_path, capsys):
    d = load("decision_inside.json")
    d["mandate_check"]["mandates"] = []
    assert run_file(tmp_path, d, "trace") == vp.EXIT_OK
    out = capsys.readouterr().out
    assert "[NOT COVERED] mandate missing from this file" in out
    assert "0 of 0 recorded tool calls" in out


def test_decision_naming_a_mandate_without_a_block_says_so(tmp_path, capsys):
    d = load("decision_inside.json")
    del d["mandate_check"]
    assert run_file(tmp_path, d, "trace") == vp.EXIT_OK
    assert "mandate missing from this file" in capsys.readouterr().out


def test_mandate_from_another_chain_does_not_count():
    d = load("proof_inside.json")
    block = copy.deepcopy(d["mandate_check"])
    result = vp.check_mandate_calls(block, None)
    assert result["calls"] == 3
    # The same hash claimed by a decision on another version is not matched.
    for dec in block["decisions"]:
        dec["event"]["version_id"] = "v-other"
    result = vp.check_mandate_calls(block, None)
    assert vp.mandate_failed(result)  # its event no longer re-hashes


def test_rule_matches_the_api():
    calls = [{"step": 1, "tool": "a"}, {"step": 2, "tool": "b"}, {"step": 3, "tool": "c"}, {"step": 4}]
    assert vp.calls_outside_mandate(calls, None, []) == []
    assert [o["tool"] for o in vp.calls_outside_mandate(calls, None, ["b"])] == ["b"]
    assert [o["tool"] for o in vp.calls_outside_mandate(calls, ["a"], ["b"])] == ["b", "c"]
    assert [o["tool"] for o in vp.calls_outside_mandate(calls, [], [])] == ["a", "b", "c"]


def test_duplicate_decision_numbers_fail():
    lines: list = []
    decisions = [{"notes": {"decision_seq": n}, "event": {"version_id": "v"}} for n in (1, 2, 2, 5)]
    assert vp._sequence_gaps(decisions, lines) == ["v: #3, #4"]
    assert lines and lines[0][1] == vp.TR_FAILED


def test_proof_without_a_block_prints_no_mandate_line(tmp_path, capsys):
    assert vp.run(str(ROOT / "testdata" / "proof_v2.json"), str(PUBKEY))
    assert "sealed mandate" not in capsys.readouterr().out


def test_unpinned_entry_under_another_key_fails(tmp_path):
    # Unpinned, the reader is told the file's own key was used. An entry
    # re-signed under any other key, with its own valid signature, fails.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    d = load("proof_inside.json")
    proof = d["mandate_check"]["decisions"][0]["proof"]
    key = Ed25519PrivateKey.generate()
    proof["public_key_pem"] = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    proof["checkpoint_signature"] = key.sign(vp._canonical_bytes(proof["sth_body"])).hex()
    result = vp.check_mandate_calls(d["mandate_check"], None, outer=vp._outer_key(d))
    assert vp.mandate_failed(result)
    assert any("different key" in detail for _, _, detail in result["lines"])
    assert run_file(tmp_path, d, "proof", pinned=False) == vp.EXIT_TAMPER


def test_entry_from_another_versions_checkpoint_fails():
    d = load("proof_inside.json")
    d["mandate_check"]["decisions"][0]["proof"]["sth_body"]["subject"] = "version:someone-elses"
    assert vp.mandate_failed(vp.check_mandate_calls(d["mandate_check"], None, outer=vp._outer_key(d)))


def test_repeated_decision_fails_and_is_not_counted_twice():
    d = load("proof_inside.json")
    block = d["mandate_check"]
    block["decisions"].append(copy.deepcopy(block["decisions"][0]))
    result = vp.check_mandate_calls(block, None, outer=vp._outer_key(d))
    assert vp.mandate_failed(result)
    assert result["calls"] == 3  # the copy adds nothing


def test_gap_range_is_not_walked():
    import time
    t0 = time.monotonic()
    missing, more = vp._missing_numbers([1, 3, 10**12])
    assert time.monotonic() - t0 < 0.5
    assert missing == [2, 4, 5, 6, 7, 8, 9, 10, 11, 12] and more
    assert vp._missing_numbers([2, 2, 3]) == ([], False)


def test_entry_without_a_checkpoint_subject_fails():
    d = load("proof_inside.json")
    del d["mandate_check"]["decisions"][0]["proof"]["sth_body"]["subject"]
    assert vp.mandate_failed(vp.check_mandate_calls(d["mandate_check"], None, outer=vp._outer_key(d)))

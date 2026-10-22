"""verify_proof.py --trace (SPEC.md section 18): one agent decision, offline.

The fixture is built here from SPEC.md alone (canonical JSON, the event hash,
an RFC 6962 tree, an Ed25519 checkpoint), not from Coriqo's code, so a
disagreement with the verifier points at the spec.

Run: python -m pytest seal-verifier/tests/test_trace_proof.py -q
"""
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
import verify_proof as vp  # noqa: E402

VERSION = "v-mandate-1"
KEY = Ed25519PrivateKey.generate()
PEM = KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def event_hash(ev: dict) -> str:
    return sha(canon({"seq": ev["seq"], "actor": ev["actor"], "action": ev["action"],
                      "model_version_id": ev["version_id"], "from_status": ev["from_status"],
                      "to_status": ev["to_status"], "notes": ev["notes"], "prev_hash": ev["prev_hash"]}))


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


def build(*, seal_tool_calls: bool = True, seal_agent: bool = True) -> dict:
    output = {"decision": "approve", "limit": 2500, "note": "Café income verified"}
    inputs = {"applicant": "A-17", "score": 712}
    tool_calls = [{"step": 1, "tool": "credit_bureau", "args_hash": "a" * 64, "result_hash": "b" * 64},
                  {"step": 2, "tool": "income_check", "args_hash": "c" * 64, "result_hash": "d" * 64}]
    trace = {"trace_id": "t-1", "agent_id": "ag-1", "version_id": VERSION,
             "input_hash": sha(canon(inputs)), "output": output, "output_hash": sha(canon(output)),
             "tool_calls": tool_calls, "grounding_refs": [{"type": "doc", "id": "d-9"}]}
    notes = {"trace_id": "t-1", "input_hash": trace["input_hash"], "output_hash": trace["output_hash"],
             "grounding_refs": trace["grounding_refs"]}
    if seal_agent:
        notes["agent_id"] = "ag-1"
    if seal_tool_calls:
        notes["tool_calls_hash"] = sha(canon(tool_calls))
    first = {"event_id": "e-0", "version_id": VERSION, "seq": 0, "actor": "admin", "action": "register",
             "from_status": "", "to_status": "approved", "notes": "{}", "prev_hash": "0" * 64}
    first["event_hash"] = event_hash(first)
    ev = {"event_id": "e-1", "version_id": VERSION, "seq": 1, "actor": "svc-agent", "action": "agent_decision",
          "from_status": "approved", "to_status": "approved",
          "notes": json.dumps(notes, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
          "prev_hash": first["event_hash"]}
    ev["event_hash"] = event_hash(ev)
    trace["event_hash"] = ev["event_hash"]
    leaves = [bytes.fromhex(first["event_hash"]), bytes.fromhex(ev["event_hash"])]
    sth = {"subject": f"version:{VERSION}", "issued_at": "2026-10-15T00:00:00Z", "length": 2,
           "head_hash": ev["event_hash"], "merkle_root": mth(leaves).hex(), "tree_size": 2,
           "key_id": "k-1", "tree_version": 2}
    proof = {"checkpoint_id": "cp-1", "event_id": "e-1", "leaf_index": 1, "tree_size": 2,
             "merkle_root": sth["merkle_root"], "leaf_input": ev["event_hash"],
             "proof_path": [p.hex() for p in path_of(1, leaves)], "sth_body": sth,
             "checkpoint_signature": KEY.sign(canon(sth)).hex(), "key_id": "k-1", "public_key_pem": PEM}
    return {"kind": "coriqo_decision_trace_proof", "format_version": 1,
            "trace": trace, "event": ev, "proof": proof, "_inputs": inputs}


def run(tmp_path, data: dict, *, pinned: bool = True) -> int:
    data = {k: v for k, v in data.items() if k != "_inputs"}
    f = tmp_path / "trace.json"
    f.write_text(json.dumps(data))
    key = tmp_path / "pub.pem"
    key.write_text(PEM)
    return vp.run_trace(str(f), str(key) if pinned else None)


def test_untouched_decision_verifies(tmp_path, capsys):
    assert run(tmp_path, build()) == vp.EXIT_OK
    out = capsys.readouterr().out
    assert "AGENT DECISION: VERIFIED" in out
    assert "the tool calls, in this order, are the ones sealed" in out


def test_without_a_pinned_key_is_not_a_pass(tmp_path):
    assert run(tmp_path, build(), pinned=False) == vp.EXIT_UNSEALED


def test_supplied_inputs_are_checked(tmp_path):
    d = build()
    d["trace"]["inputs"] = d["_inputs"]
    assert run(tmp_path, d) == vp.EXIT_OK
    d["trace"]["inputs"] = {**d["_inputs"], "score": 800}
    assert run(tmp_path, d) == vp.EXIT_TAMPER


def test_changed_output_fails(tmp_path, capsys):
    d = build()
    d["trace"]["output"]["limit"] = 25000
    assert run(tmp_path, d) == vp.EXIT_TAMPER
    assert "the output was changed" in capsys.readouterr().out


def test_changed_output_with_rehashed_output_hash_still_fails(tmp_path):
    d = build()
    d["trace"]["output"]["limit"] = 25000
    d["trace"]["output_hash"] = sha(canon(d["trace"]["output"]))
    assert run(tmp_path, d) == vp.EXIT_TAMPER


def test_reordered_tool_calls_fail(tmp_path, capsys):
    d = build()
    d["trace"]["tool_calls"].reverse()
    assert run(tmp_path, d) == vp.EXIT_TAMPER
    assert "reordered" in capsys.readouterr().out


def test_edited_sealed_event_fails(tmp_path):
    d = build()
    notes = json.loads(d["event"]["notes"])
    notes["output_hash"] = "0" * 64
    d["event"]["notes"] = json.dumps(notes)
    assert run(tmp_path, d) == vp.EXIT_TAMPER


def test_proof_for_another_event_fails(tmp_path):
    d = build()
    d["proof"]["leaf_index"] = 0
    d["proof"]["leaf_input"] = "f" * 64
    assert run(tmp_path, d) == vp.EXIT_TAMPER


def test_forged_checkpoint_signature_fails(tmp_path):
    d = build()
    d["proof"]["sth_body"]["issued_at"] = "2027-01-01T00:00:00Z"
    assert run(tmp_path, d) == vp.EXIT_TAMPER


def test_decision_sealed_before_tool_calls_were_sealed(tmp_path, capsys):
    d = build(seal_tool_calls=False)
    assert run(tmp_path, d) == vp.EXIT_OK
    assert "sealed before tool calls were part of the seal" in capsys.readouterr().out


@pytest.mark.parametrize("data", [{"kind": "something_else"}, {"kind": "coriqo_decision_trace_proof"}])
def test_malformed(tmp_path, data):
    f = tmp_path / "x.json"
    f.write_text(json.dumps(data))
    assert vp.run_trace(str(f)) == vp.EXIT_MALFORMED


def test_positional_input_detects_a_trace(tmp_path):
    d = copy.deepcopy(build())
    d.pop("_inputs")
    f = tmp_path / "decision.json"
    f.write_text(json.dumps(d))
    key = tmp_path / "pub.pem"
    key.write_text(PEM)
    assert vp.run_auto_input(str(f), str(key)) == vp.EXIT_OK


def test_purged_decision_checks_hashes_only(tmp_path, capsys):
    d = build()
    d["trace"].update(output=None, tool_calls=None, content_purged=True, purged_at="2026-10-01T00:00:00Z")
    # Hashes only is not a pass: the purge claim is not sealed (exit 2).
    assert run(tmp_path, d) == vp.EXIT_UNSEALED
    out = capsys.readouterr().out
    assert "HASHES ONLY, NOT FULLY VERIFIED" in out and "retention purge" in out


def test_purge_claim_cannot_hide_changed_content(tmp_path, capsys):
    # content_purged is not sealed: a file that claims a purge but still carries
    # content must not skip the output and tool-call checks.
    d = build()
    d["trace"]["output"] = "FORGED"
    d["trace"]["tool_calls"].reverse()
    d["trace"]["content_purged"] = True
    assert run(tmp_path, d) == vp.EXIT_TAMPER
    out = capsys.readouterr().out
    assert "says the content was purged but still carries content" in out
    assert "the output was changed" in out and "reordered" in out
    assert "HASHES ONLY" not in out


def test_purge_claim_with_untouched_content_still_fails(tmp_path):
    d = build()
    d["trace"]["content_purged"] = True
    assert run(tmp_path, d) == vp.EXIT_TAMPER


def test_decision_credited_to_another_agent_fails(tmp_path, capsys):
    d = build()
    d["trace"]["agent_id"] = "ag-other"
    assert run(tmp_path, d) == vp.EXIT_TAMPER
    assert "names a different agent" in capsys.readouterr().out


def test_decision_sealed_before_the_agent_was_sealed(tmp_path, capsys):
    d = build(seal_agent=False)
    d["trace"]["agent_id"] = "ag-anyone"
    assert run(tmp_path, d) == vp.EXIT_OK
    out = capsys.readouterr().out
    assert "(not checked against the seal)" in out and "sealed before the agent was part of the seal" in out


def test_withheld_content_claiming_a_purge_is_not_a_pass(tmp_path):
    d = build()
    d["trace"].update(output=None, tool_calls=None, content_purged=True)
    assert run(tmp_path, d) != vp.EXIT_OK

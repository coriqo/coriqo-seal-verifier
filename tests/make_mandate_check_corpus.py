"""Regenerate testdata/mandate_check/, the SPEC.md section 19 conformance corpus.

Written from SPEC.md (sections 3, 4, 5.2.2, 6, 7, 18 and 19) and MANDATE_SPEC.md
section 6, not from Coriqo's server code. The tree, signing and canonical JSON
helpers come from make_corpus.py, so both corpora share one key (testdata/pubkey.pem).

One agent's mandate chain, five events:

    0  agent_registered
    1  mandate_snapshot   the mandate in force: credit_check and income_check
                          allowed, wire_transfer prohibited
    2  agent_decision #1  credit_check, income_check
    3  agent_decision #2  credit_check
    4  agent_decision #3  wire_transfer        (outside the mandate)

and one RFC 6962 checkpoint over all five.

    python tests/make_mandate_check_corpus.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import make_corpus as mc  # noqa: E402
import mandate_format as mf  # noqa: E402

OUT = mc.TESTDATA / "mandate_check"
VERSION = "v-loan-agent-1"
AGENT = "ag-loan-1"
GENESIS = "0" * 64

MANDATE_FILE = {
    "spec": "coriqo.mandate/v1",
    "agent": {"name": "loan-agent", "id": AGENT},
    "mandate": "Approve consumer loans under 50,000. Never move money.",
    "mode": "enforce",
    "tools": {"allowed": ["credit_check", "income_check"], "prohibited": ["wire_transfer"]},
}

DECISIONS = [
    ("t-1", [("credit_check", "a"), ("income_check", "b")]),
    ("t-2", [("credit_check", "c")]),
    ("t-3", [("wire_transfer", "d")]),
]


def canon_str(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def h(value) -> str:
    return mc.sha256_hex(canon_str(value).encode("utf-8"))


def event_hash(ev: dict) -> str:
    """SPEC.md 13.3: the event hash field set, with version_id spelled model_version_id."""
    return h({"seq": ev["seq"], "actor": ev["actor"], "action": ev["action"],
              "model_version_id": ev["version_id"], "from_status": ev["from_status"],
              "to_status": ev["to_status"], "notes": ev["notes"], "prev_hash": ev["prev_hash"]})


def build():
    document = mf.normalise(MANDATE_FILE)
    mandate_sha = mf.document_sha256(MANDATE_FILE)
    assert h(document) == mandate_sha, "SPEC.md 19.1: the sealed document hashes to the document hash"

    raw = [("svc-admin", "agent_registered", {"agent_id": AGENT})]
    raw.append(("svc-loan", "mandate_snapshot",
                {"agent_id": AGENT, "mandate_sha256": mandate_sha, "document": document}))
    traces = {}
    for n, (trace_id, calls) in enumerate(DECISIONS, start=1):
        tool_calls = [{"step": i, "tool": tool, "args_hash": c * 64, "result_hash": c.upper() * 64}
                      for i, (tool, c) in enumerate(calls, start=1)]
        output = f"decision {n}"
        trace = {"trace_id": trace_id, "agent_id": AGENT, "version_id": VERSION,
                 "input_hash": h({"applicant": f"A-{n}"}), "output": output, "output_hash": h(output),
                 "tool_calls": tool_calls, "grounding_refs": [],
                 "occurred_at": f"2026-10-0{n}T09:00:00Z"}
        traces[trace_id] = trace
        raw.append(("svc-loan", "agent_decision", {
            "trace_id": trace_id, "agent_id": AGENT, "input_hash": trace["input_hash"],
            "output_hash": trace["output_hash"], "grounding_refs": [],
            "tool_calls_hash": h(tool_calls), "mandate_sha256": mandate_sha, "decision_seq": n}))

    chain, prev = [], GENESIS
    for seq, (actor, action, notes) in enumerate(raw):
        ev = {"event_id": f"ev-{seq}", "version_id": VERSION, "seq": seq, "actor": actor,
              "action": action, "from_status": "approved", "to_status": "approved",
              "notes": canon_str(notes), "prev_hash": prev}
        ev["event_hash"] = event_hash(ev)
        chain.append(ev)
        prev = ev["event_hash"]
    for ev in chain:
        if ev["action"] == "agent_decision":
            traces[json.loads(ev["notes"])["trace_id"]]["event_hash"] = ev["event_hash"]

    key = Ed25519PrivateKey.from_private_bytes(mc.SEED)
    pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    leaves = [bytes.fromhex(e["event_hash"]) for e in chain]
    sth = {"subject": f"version:{VERSION}", "issued_at": "2026-10-10T00:00:00Z", "length": len(chain),
           "head_hash": chain[-1]["event_hash"], "merkle_root": mc.merkle_root(leaves, 2),
           "tree_size": len(leaves), "key_id": mc.KEY_ID, "tree_version": 2}
    signature = mc.sign(sth, key)

    def proof(i: int) -> dict:
        return {"checkpoint_id": "cp-agent-2026-10", "event_id": chain[i]["event_id"],
                "issued_at": sth["issued_at"], "subject": sth["subject"], "leaf_index": i,
                "tree_size": len(leaves), "leaf_input": chain[i]["event_hash"],
                "proof_path": mc.inclusion_proof(i, leaves, 2), "merkle_root": sth["merkle_root"],
                "sth_body": sth, "checkpoint_signature": signature, "key_id": mc.KEY_ID,
                "public_key_pem": pem}

    def entry(i: int) -> dict:
        return {"event": chain[i], "proof": proof(i)}

    def decision_entry(i: int) -> dict:
        trace = traces[json.loads(chain[i]["notes"])["trace_id"]]
        return {"trace_id": trace["trace_id"], "tool_calls": trace["tool_calls"], **entry(i)}

    def trace_file(i: int) -> dict:
        trace = traces[json.loads(chain[i]["notes"])["trace_id"]]
        return {"kind": "coriqo_decision_trace_proof", "format_version": 1, "spec_version": "1.1",
                "trace": trace, "event": chain[i], "proof": proof(i),
                "mandate_check": {"format_version": 1, "mandates": [entry(1)]}}

    def proof_file(decisions: list[int]) -> dict:
        return {**proof(0), "spec_version": "1.1",
                "mandate_check": {"format_version": 1, "mandates": [entry(1)],
                                  "decisions": [decision_entry(i) for i in decisions]}}

    return {
        "decision_inside.json": trace_file(2),
        "decision_outside.json": trace_file(4),
        "proof_inside.json": proof_file([2, 3]),
        "proof_with_gap.json": proof_file([2, 4]),
    }


CASES = [
    {"file": "decision_inside.json", "mode": "trace", "exit": 0,
     "line": "0 of 2 recorded tool calls fell outside the sealed mandate"},
    {"file": "decision_outside.json", "mode": "trace", "exit": 0,
     "line": "1 of 1 recorded tool calls fell outside the sealed mandate",
     "outside": [{"trace_id": "t-3", "step": 1, "tool": "wire_transfer", "why": "prohibited"}]},
    {"file": "proof_inside.json", "mode": "proof", "exit": 0,
     "line": "0 of 3 recorded tool calls fell outside the sealed mandate", "gaps": []},
    {"file": "proof_with_gap.json", "mode": "proof", "exit": 0,
     "line": "1 of 3 recorded tool calls fell outside the sealed mandate", "gaps": ["v-loan-agent-1: #2"]},
]


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, data in build().items():
        (OUT / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote testdata/mandate_check/{name}")
    (OUT / "cases.json").write_text(json.dumps(CASES, indent=2) + "\n")
    print("wrote testdata/mandate_check/cases.json")


if __name__ == "__main__":
    main()

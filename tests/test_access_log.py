"""Sealed-read log (SPEC.md 4.5): the --bundle-dir step and the proof
mode check a signed access_log, and a malformed one is a failed check, never
a crash of the whole run."""
from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof  # noqa: E402

CHECK = "sealed-read log reproduces every signed access_log"


def _rows(n=3):
    rows, heads = [], {}
    for i in range(n):
        subject = "tenant" if i % 2 == 0 else "teams_channel:c1"
        seq, prev = heads.get(subject, (0, "0" * 64))
        row = {
            "event_id": f"e{i}", "ordinal": i + 1, "seq": seq, "subject_ref": subject,
            "actor_id": "u1", "actor_label": "alice", "actor_type": "human",
            "accessed_at": f"2026-09-22T10:0{i}:00+00:00", "access_kind": "export",
            "seal_reason": "export", "record_count": 5, "query_fingerprint": None,
            "declared_purpose_id": None, "prev_hash": prev,
        }
        row["event_hash"] = verify_proof.access_event_hash_of(row)
        heads[subject] = (seq + 1, row["event_hash"])
        rows.append(row)
    return rows


def _good_log(rows):
    root, size = verify_proof.access_log_root(rows, rows[-1]["ordinal"], 2)
    return {"ordinal_watermark": rows[-1]["ordinal"], "tree_size": size, "merkle_root": root}


def _bundle(tmp_path, access_log, rows=None, raw_lines=None):
    (tmp_path / "checkpoints").mkdir()
    cp = tmp_path / "checkpoints" / "cp1.json"
    cp.write_text(json.dumps({"checkpoint_id": "cp1", "tree_version": 2, "access_log": access_log}))
    lines = raw_lines if raw_lines is not None else [json.dumps(r) for r in (rows or [])]
    (tmp_path / "access_events.jsonl").write_text("\n".join(lines) + "\n")
    return [str(cp)]


def _run_check(tmp_path, access_log, rows=None, raw_lines=None):
    files = _bundle(tmp_path, access_log, rows, raw_lines)
    results: list = []
    verify_proof._check_bundle_access_log(str(tmp_path), files, {"cp1": True}, results)
    assert len(results) == 1 and results[0][0] == CHECK
    return results[0]


def test_sound_log_passes(tmp_path):
    rows = _rows()
    _name, ok, detail = _run_check(tmp_path, _good_log(rows), rows)
    assert ok, detail


@pytest.mark.parametrize("mutate", [
    lambda log: "not-an-object",
    lambda log: [log],
    lambda log: {**log, "ordinal_watermark": None},
    lambda log: {**log, "ordinal_watermark": "3"},
    lambda log: {k: v for k, v in log.items() if k != "tree_size"},
    lambda log: {**log, "tree_size": -1},
    lambda log: {k: v for k, v in log.items() if k != "merkle_root"},
    lambda log: {**log, "merkle_root": "zz" * 32},
    lambda log: {**log, "merkle_root": 7},
], ids=["string", "list", "watermark-null", "watermark-str", "no-tree-size",
        "negative-size", "no-root", "root-not-hex", "root-int"])
def test_malformed_signed_log_fails_without_crashing(tmp_path, mutate):
    rows = _rows()
    _name, ok, detail = _run_check(tmp_path, mutate(_good_log(rows)), rows)
    assert not ok
    assert "checkpoint cp1" in detail


def test_edited_row_fails(tmp_path):
    rows = _rows()
    log = _good_log(rows)
    rows[1]["record_count"] = 10_000
    _name, ok, detail = _run_check(tmp_path, log, rows)
    assert not ok and "does not match its event_hash" in detail


@pytest.mark.parametrize("line", ["{not json", "[1, 2]", '{"event_id": "e0"}'],
                         ids=["not-json", "not-object", "missing-fields"])
def test_malformed_rows_fail_without_crashing(tmp_path, line):
    rows = _rows()
    lines = [json.dumps(r) for r in rows] + [line]
    _name, ok, _detail = _run_check(tmp_path, _good_log(rows), raw_lines=lines)
    assert not ok


@pytest.mark.parametrize("signed_log", [
    "not-an-object", {"ordinal_watermark": None, "tree_size": 1, "merkle_root": "00" * 32},
    {"ordinal_watermark": 1, "merkle_root": "00" * 32},
], ids=["string", "watermark-null", "no-tree-size"])
def test_proof_mode_malformed_signed_log_fails_without_crashing(signed_log):
    rows = _rows(1)
    proof = {
        "checkpoint_id": "cp1", "event_id": "e0", "leaf_tree": "access_log",
        "leaf_index": 0, "tree_size": 1, "merkle_root": "00" * 32,
        "leaf_input": rows[0]["event_hash"], "proof_path": [],
        "access_event": {k: v for k, v in rows[0].items() if k not in ("ordinal", "event_hash")},
        "sth_body": {"subject": "org_default", "issued_at": "2026-09-22T11:00:00+00:00",
                     "length": 0, "head_hash": "0" * 64, "merkle_root": "00" * 32,
                     "tree_size": 0, "key_id": "k", "tree_version": 2,
                     "access_log": signed_log},
        "checkpoint_signature": "00" * 64, "key_id": "k", "public_key_pem": "",
        "issued_at": "2026-09-22T11:00:00+00:00", "subject": "org_default",
    }
    with redirect_stdout(io.StringIO()) as out:
        ok = verify_proof.run(None, None, proof_data=proof)
    assert ok is False
    assert "access_log" in out.getvalue()

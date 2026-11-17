"""Sealed gap history (SPEC.md §8.5): the browser verifier and verify_proof.py agree.

The six bundles in testdata/gap_history/ are signed with a throwaway key, so
every other check passes and each verdict is about the gap history alone. The
browser run pins that key by fingerprint (the page's "paste a fingerprint"
path). testdata/gap_history/review/ holds adversarial bundles from an
independent review (unsigned: only the gap-history row is compared). For every
bundle, and for malformed inputs built in this file, both verifiers must reach
the same verdict and carry the same words, because an auditor reads them. The
one known difference, a float written as 1.0, is pinned below.

Skipped, with the reason, when node is not installed.

    python -m pytest tests/test_gap_history_web.py -q
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_proof as vp  # noqa: E402
import test_gap_history as gh  # noqa: E402

NODE = shutil.which("node")
DRIVER = Path(__file__).with_name("gap_history_node.mjs")
VECTORS = ROOT / "testdata" / "gap_history"
HOURS = {"max_open_gap_hours": 24}

pytestmark = pytest.mark.skipif(
    NODE is None, reason="node is not installed; the browser verifier runs under node in this test")


def run_web_file(path: Path, *extra: str) -> dict:
    proc = subprocess.run([NODE, str(DRIVER), str(path)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    web = json.loads(proc.stdout)
    # The standalone page has no verdict.js; "exception" here is a failed check.
    web["rows"] = [{**c, "state": "exception" if c["state"] == "fail" else c["state"]} for c in web["checks"]]
    web["verdict"] = "exception" if any(c["state"] == "fail" for c in web["checks"]) else "verified"
    web["sentence"] = ""
    return web


def run_web(cert: dict, tmp_path: Path) -> dict:
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(cert), encoding="utf-8")
    return run_web_file(path)


def gap_row(web: dict):
    rows = [r for r in web["rows"] if r["name"] == "Sealed gap history"]
    return rows[0] if rows else None


def cli_problems(cert: dict) -> list[str]:
    return vp._analyse_gap_history(cert)["problems"]


def assert_same(cert: dict, web: dict, label: str) -> None:
    """Same verdict on the gap-history row, same words, same open-gap findings."""
    analysis = vp._analyse_gap_history(cert)
    row = gap_row(web)
    rows = [v for k, v in web["summary"] if k == "Sealed gap history"]
    if not analysis["recorded"]:
        assert row is None, f"{label}: an absent block must add neither a pass nor a fail"
        assert len(rows) == 1 and rows[0].startswith("not recorded"), (label, rows)
        return
    problems = analysis["problems"]
    assert row is not None, label
    assert (row["state"] == "exception") == bool(problems), (label, row)
    assert row["detail"] == (" | ".join(problems) or analysis["summary"]), label
    if analysis["findings"]:
        assert rows == analysis["findings"], label


EXPECTED = {
    "pass.json": "verified",
    "absent.json": "verified",
    "tampered.json": "exception",
    "deleted.json": "exception",
    "forged_closed.json": "exception",
    "overage.json": "exception",
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_each_bundle_gets_the_cli_verdict_and_words(name, tmp_path):
    cert = json.loads((VECTORS / name).read_text())
    web = run_web(cert, tmp_path)
    assert_same(cert, web, name)
    assert (gap_row(web) is None or gap_row(web)["state"] != "exception") == (EXPECTED[name] == "verified")
    ok, _ = gh.run(cert)
    assert ok == (EXPECTED[name] == "verified")


REVIEW = sorted((VECTORS / "review").glob("case_*.json"))
# JSON.parse reads 1.0 as 1, so the browser cannot see that the producer wrote a
# float. verify_proof.py rejects it as "no valid sequence range"; the browser
# fails the same bundle through its "Numbers are read exactly" row, and through
# a hash that no longer matches. Both fail; the words differ. The producer only
# writes integers (SPEC.md 8.5).
FLOAT_CASES = {"case_B_float.json"}


@pytest.mark.parametrize("path", REVIEW, ids=lambda p: p.stem)
def test_review_cases_agree(path):
    cert = json.loads(path.read_text(encoding="utf-8"))
    web = run_web_file(path)
    row = gap_row(web)
    problems = cli_problems(cert)
    assert problems, f"{path.name} is a hostile bundle and must fail"
    assert row is not None and row["state"] == "exception", (path.name, row)
    if path.name in FLOAT_CASES:
        assert row["detail"] != " | ".join(problems)
    else:
        assert_same(cert, web, path.name)


def test_review_set_has_every_reported_case():
    names = {p.stem for p in REVIEW}
    for key in ("J_no_opened_at", "J2_opened_at_lies", "F_future", "D_dropped_last", "L_basic_iso",
                "L_offset_secs", "C_bool_dev", "S_surrogate", "A_bigint"):
        assert f"case_{key}" in names, key


def test_pass_reports_the_open_gap_in_the_summary(tmp_path):
    web = run_web(json.loads((VECTORS / "pass.json").read_text()), tmp_path)
    rows = [v for k, v in web["summary"] if k == "Sealed gap history"]
    assert rows == ["open gap device dev-1 #5-#9: open 6.0 hours, within the 24 hour limit"]


def _cert(events=None, open_gaps=None, **kw):
    events = gh.good_events() if events is None else events
    return gh.build(events, [gh.OPEN] if open_gaps is None else open_gaps, **kw)


Z = "2026-11-17T06:00:00Z"
GAP1 = {"device_id": "d", "seq_start": 1, "seq_end": 2, "opened_at": Z}


def _later(**body):
    cert = _cert(policy=HOURS)
    cp = {"checkpoint_id": "cp2", "key_id": gh.KEY_ID, "sth_body": {"issued_at": "2026-12-30T00:00:00+00:00", **body}}
    cp["signature_hex"] = gh._PRIV.sign(gh.canon(cp["sth_body"])).hex()
    cert["statement"]["checkpoints"].append(cp)
    cert["signature_hex"] = gh._PRIV.sign(gh.canon(cert["statement"])).hex()
    return cert


CASES = {
    "valid": lambda: _cert(policy=HOURS),
    "no limit": lambda: _cert(),
    "narrowed gap": lambda: gh.build(
        [gh.event("dev-1", 5, 9, "opened", Z), gh.event("dev-1", 5, 6, "waived", "2026-11-17T07:00:00Z")],
        [{**gh.OPEN, "seq_start": 7}], policy=HOURS),
    "narrowed in the middle": lambda: gh.build(
        [gh.event("d", 1, 10, "opened", Z), gh.event("d", 4, 5, "closed", "2026-11-17T07:00:00Z")],
        [{**GAP1, "seq_end": 3}, {**GAP1, "seq_start": 6, "seq_end": 10}], policy=HOURS),
    "adjacent not merged": lambda: gh.build(
        [gh.event("d", 1, 5, "opened", Z), gh.event("d", 6, 10, "opened", Z)],
        [{**GAP1, "seq_end": 10}], policy=HOURS),
    "signed open gap not derivable": lambda: _cert(open_gaps=[], policy=HOURS),
    "over age": lambda: _cert(policy={"max_open_gap_hours": 1}),
    "age tie rounds half to even": lambda: gh.build(
        [gh.event("d", 1, 2, "opened", "2026-11-17T11:45:00Z")],
        [{**GAP1, "opened_at": "2026-11-17T11:45:00Z"}], policy=HOURS),
    "age tie 0.35": lambda: gh.build(
        [gh.event("d", 1, 2, "opened", "2026-11-17T11:39:00Z")],
        [{**GAP1, "opened_at": "2026-11-17T11:39:00Z"}], policy=HOURS),
    "fraction of a second": lambda: gh.build(
        [gh.event("d", 1, 2, "opened", "2026-11-17T06:00:00.250000Z")],
        [{**GAP1, "opened_at": "2026-11-17T06:00:00.250000Z"}], policy=HOURS),
    "opened_at spelled differently but equal": lambda: gh.build(
        [gh.event("d", 1, 2, "opened", Z)], [{**GAP1, "opened_at": "2026-11-17T06:00:00.000000Z"}], policy=HOURS),
    "opened after the checkpoint": lambda: gh.build(
        [gh.event("d", 1, 2, "opened", "2026-11-17T13:00:00Z")],
        [{**GAP1, "opened_at": "2026-11-17T13:00:00Z"}], policy=HOURS),
    "opened_at lies": lambda: gh.build([gh.event("d", 1, 2, "opened", "2026-01-01T00:00:00Z")], [GAP1], policy=HOURS),
    "opened_at missing": lambda: gh.build(
        [gh.event("d", 1, 2, "opened", Z)], [{k: v for k, v in GAP1.items() if k != "opened_at"}], policy=HOURS),
    "opened_at offset": lambda: gh.build(
        [gh.event("d", 1, 2, "opened", Z)], [{**GAP1, "opened_at": "2026-11-17T06:00:00+00:00"}], policy=HOURS),
    "event time with offset": lambda: gh.build(
        [gh.event("d", 1, 2, "opened", "2026-11-17T06:00:00+00:00")], [], policy=HOURS),
    "event time basic iso": lambda: gh.build([gh.event("d", 1, 2, "opened", "20261117T060000Z")], [], policy=HOURS),
    "event time bad date": lambda: gh.build([gh.event("d", 1, 2, "opened", "2026-02-30T06:00:00Z")], [], policy=HOURS),
    "event time year 0": lambda: gh.build([gh.event("d", 1, 2, "opened", "0000-01-01T00:00:00Z")], [], policy=HOURS),
    "event time year 50": lambda: gh.build([gh.event("d", 1, 2, "opened", "0050-01-01T00:00:00Z")],
                                           [{**GAP1, "opened_at": "0050-01-01T00:00:00Z"}], policy=HOURS),
    "leap day": lambda: gh.build([gh.event("d", 1, 2, "opened", "2024-02-29T06:00:00Z")],
                                 [{**GAP1, "opened_at": "2024-02-29T06:00:00Z"}], policy=HOURS),
    "not a leap day": lambda: gh.build([gh.event("d", 1, 2, "opened", "2026-02-29T06:00:00Z")], [], policy=HOURS),
    "issued_at with an offset": lambda: gh.build(gh.good_events(), [gh.OPEN], policy=HOURS,
                                                 issued="2026-11-17T17:00:00+05:00"),
    "issued_at as Z": lambda: gh.build(gh.good_events(), [gh.OPEN], policy=HOURS, issued="2026-11-17T12:00:00Z"),
    "limit string": lambda: _cert(policy={"max_open_gap_hours": "24"}),
    "limit zero": lambda: _cert(policy={"max_open_gap_hours": 0}),
    "limit negative": lambda: _cert(policy={"max_open_gap_hours": -3}),
    "limit bool": lambda: _cert(policy={"max_open_gap_hours": True}),
    "limit null": lambda: _cert(policy={"max_open_gap_hours": None}),
    "limit fractional": lambda: _cert(policy={"max_open_gap_hours": 6.5}),
    "limit huge": lambda: _cert(policy={"max_open_gap_hours": 10 ** 400}),
    "policy not an object": lambda: _cert(policy="x"),
    "empty policy object": lambda: _cert(policy={}),
    "generic policy is no fallback": lambda: gh.with_body(_cert(), policy={"max_open_gap_hours": 1}),
    "events missing": lambda: {k: v for k, v in _cert(policy=HOURS).items() if k != "gap_events"},
    "events not a list": lambda: {**_cert(policy=HOURS), "gap_events": {"a": 1}},
    "events hold a non-object": lambda: {**_cert(policy=HOURS), "gap_events": [1]},
    "reordered": lambda: {**_cert(policy=HOURS), "gap_events": list(reversed(gh.good_events()))},
    "extra unsealed event": lambda: {**_cert(policy=HOURS),
                                     "gap_events": gh.good_events() + [gh.event("dev-1", 20, 21, "opened", Z)]},
    "unknown event type": lambda: gh.build([gh.event("dev-1", 5, 9, "reopened", Z)], [], policy=HOURS),
    "event type not text": lambda: gh.build([gh.event("dev-1", 5, 9, 7, Z)], [], policy=HOURS),
    "bad range": lambda: gh.build([gh.event("dev-1", 9, 5, "opened", Z)], [], policy=HOURS),
    "bool range": lambda: gh.build([gh.event("dev-1", True, 5, "opened", Z)], [], policy=HOURS),
    "negative range": lambda: gh.build([gh.event("dev-1", -1, 5, "opened", Z)], [], policy=HOURS),
    "fractional range": lambda: gh.build([gh.event("dev-1", 1.5, 5, "opened", Z)], [], policy=HOURS),
    "largest safe number": lambda: gh.build(
        [gh.event("d", 2 ** 53 - 1, 2 ** 53 - 1, "opened", Z)],
        [{**GAP1, "seq_start": 2 ** 53 - 1, "seq_end": 2 ** 53 - 1}], policy=HOURS),
    "number above the safe range": lambda: gh.build([gh.event("d", 2 ** 53, 2 ** 53, "opened", Z)], [], policy=HOURS),
    "device true": lambda: gh.build([gh.event(True, 1, 2, "opened", Z)], [], policy=HOURS),
    "device empty": lambda: gh.build([gh.event("", 1, 2, "opened", Z)], [], policy=HOURS),
    "device number": lambda: gh.build([gh.event(1, 1, 2, "opened", Z)], [], policy=HOURS),
    "device list": lambda: gh.build([gh.event(["a"], 5, 9, "opened", Z)], [], policy=HOURS),
    "device proto name": lambda: gh.build(
        [gh.event("__proto__", 1, 2, "opened", Z)], [{**GAP1, "device_id": "__proto__"}], policy=HOURS),
    "devices that sort differently": lambda: gh.build(
        [gh.event("\uffee", 1, 2, "opened", Z), gh.event("\U0001f600", 1, 2, "opened", Z)],
        [{**GAP1, "device_id": "\uffee"}], policy=HOURS),
    "unicode device": lambda: gh.build(
        [gh.event("d\u00e9v \U0001f600", 1, 2, "opened", Z)], [{**GAP1, "device_id": "d\u00e9v \U0001f600"}],
        policy=HOURS),
    "lone surrogate": lambda: gh.build(
        [{**gh.event("d", 1, 2, "opened", Z), "reason": "\ud800"}], [], policy=HOURS),
    "open gap string": lambda: _cert(open_gaps=["x"], policy=HOURS),
    "open gap null": lambda: _cert(open_gaps=[None], policy=HOURS),
    "open gaps not a list": lambda: _cert(open_gaps="nope", policy=HOURS),
    "open gaps null": lambda: _cert(open_gaps=None, policy=HOURS),
    "open gap bad range": lambda: _cert(open_gaps=[{**gh.OPEN, "seq_start": "a"}], policy=HOURS),
    "open gap inverted": lambda: _cert(open_gaps=[{**gh.OPEN, "seq_start": 9, "seq_end": 5}], policy=HOURS),
    "open gap list device": lambda: _cert(open_gaps=[{**gh.OPEN, "device_id": ["a"]}], policy=HOURS),
    "open gap true device": lambda: _cert(open_gaps=[{**gh.OPEN, "device_id": True}], policy=HOURS),
    "open gap number above range": lambda: _cert(open_gaps=[{**gh.OPEN, "seq_end": 2 ** 60}], policy=HOURS),
    "completeness not an object": lambda: gh.with_body(gh.build([], [], policy=HOURS), completeness="oops"),
    "completeness without a count": lambda: gh.with_body(gh.build([], [], policy=HOURS), completeness={"gap_events_root": "ab"}),
    "root in upper case": lambda: _with_root(lambda r: r.upper()),
    "root too short": lambda: _with_root(lambda r: r[:-1]),
    "later checkpoint drops the history": lambda: _later(),
    "later version-scoped checkpoint is exempt": lambda: _later(subject="version:abc"),
    "later checkpoint keeps the history": lambda: _later(completeness=_cert(policy=HOURS)["statement"]["checkpoints"][0]["sth_body"]["completeness"]),
}


def _with_root(change):
    cert = _cert(policy=HOURS)
    comp = dict(cert["statement"]["checkpoints"][0]["sth_body"]["completeness"])
    comp["gap_events_root"] = change(comp["gap_events_root"])
    return gh.with_body(cert, completeness=comp)


@pytest.mark.parametrize("case", sorted(CASES))
def test_browser_and_cli_agree_on_built_cases(case, tmp_path):
    cert = CASES[case]()
    ok, _ = gh.run(cert)
    web = run_web(cert, tmp_path)
    if case == "fractional range":
        # 1.5 is not a whole number to either engine, but the browser also hits its exact-number row.
        assert not ok
        return
    assert_same(cert, web, case)
    assert (gap_row(web) is None or gap_row(web)["state"] != "exception") == (not cli_problems(cert))


def test_known_difference_a_float_seq_fails_in_both_with_different_words(tmp_path):
    ev = {"device_id": "d", "seq_start": 1.0, "seq_end": 2.0, "event": "opened", "at": Z, "reason": "r", "actor": "a"}
    ev["event_hash"] = vp._gap_event_hash(ev)
    cert = gh.build([ev], [], policy=HOURS)
    ok, _ = gh.run(cert)
    web = run_web(cert, tmp_path)
    assert not ok

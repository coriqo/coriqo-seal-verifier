"""Sealed gap history (SPEC.md §8.5), checked offline by verify_proof.py.

Fixtures are hand-built and signed with a throwaway Ed25519 key, so the
signature, linkage and coverage checks all pass and each assertion is about
the gap history alone. Needs only the standard library and `cryptography`.

Run: python -m pytest tests/test_gap_history.py -q
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof as vp  # noqa: E402

KEY_ID = "test-key"
ISSUED = "2026-11-17T12:00:00+00:00"
_PRIV = ed25519.Ed25519PrivateKey.generate()
_PEM = _PRIV.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def event(device, start, end, kind, at, reason="", actor="reconcile"):
    ev = {"device_id": device, "seq_start": start, "seq_end": end, "event": kind,
          "at": at, "reason": reason, "actor": actor}
    ev["event_hash"] = hashlib.sha256(canon(ev)).hexdigest()
    return ev


def root_of(events) -> str:
    root = hashlib.sha256(b"").hexdigest()
    for ev in events:
        root = hashlib.sha256(bytes.fromhex(root) + bytes.fromhex(ev["event_hash"])).hexdigest()
    return root


def build(events, open_gaps, *, policy=None, with_block=True, issued=ISSUED):
    """A one-checkpoint certificate signed end to end."""
    body = {"issued_at": issued, "length": 10, "root_hash": "00" * 32}
    if with_block:
        body["completeness"] = {
            "gap_events_root": root_of(events), "gap_event_count": len(events),
            "open_gaps": open_gaps, "device_seq_heads": {"dev-1": 40}}
    if policy is not None:
        body["completeness_policy"] = policy
    cp = {"checkpoint_id": "cp1", "key_id": KEY_ID, "sth_body": body,
          "signature_hex": _PRIV.sign(canon(body)).hex()}
    statement = {
        "subject": "t", "period": {"from": issued, "to": issued}, "checkpoint_count": 1,
        "checkpoints": [cp], "linkage": [], "linkage_status": "not_applicable", "linkage_unbroken": True,
        "coverage": {"sealed_event_count": 10, "events_added_in_period": 0,
                     "obligations_in_period": {}, "obligations_closing": {}},
        "coverage_gaps": [], "gap_summary": {"total": 0}}
    return {"statement": statement, "key_id": KEY_ID,
            "signature_hex": _PRIV.sign(canon(statement)).hex(),
            "public_keys": {KEY_ID: {"pem": _PEM}}, "gap_events": events}


def run(cert):
    buf = io.StringIO()
    with redirect_stdout(buf):
        ok = vp.verify_certificate_dict(cert)
    return ok, buf.getvalue()


OPEN = {"device_id": "dev-1", "seq_start": 5, "seq_end": 9, "opened_at": "2026-11-17T06:00:00Z"}


def good_events():
    return [event("dev-1", 5, 9, "opened", "2026-11-17T06:00:00Z"),
            event("dev-1", 1, 2, "opened", "2026-11-16T01:00:00Z"),
            event("dev-1", 1, 2, "closed", "2026-11-16T02:00:00Z")]


def test_valid_history_passes():
    ok, out = run(build(good_events(), [OPEN], policy={"max_open_gap_hours": 24}))
    assert ok, out
    assert "[PASS] sealed gap history" in out


def test_tampered_event_fails():
    cert = build(good_events(), [OPEN], policy={"max_open_gap_hours": 24})
    cert["gap_events"][1]["reason"] = "nothing to see"  # hash left stale
    ok, out = run(cert)
    assert not ok
    assert "was changed after it was recorded" in out


def test_tampered_event_with_recomputed_hash_still_fails_root():
    cert = build(good_events(), [OPEN], policy={"max_open_gap_hours": 24})
    ev = cert["gap_events"][1]
    ev["seq_end"] = 3
    ev["event_hash"] = hashlib.sha256(canon({k: v for k, v in ev.items() if k != "event_hash"})).hexdigest()
    ok, out = run(cert)
    assert not ok
    assert "do not reproduce the root signed" in out


def test_deleted_event_fails():
    """F2: the opened event of a gap is deleted after the fact."""
    cert = build(good_events(), [OPEN], policy={"max_open_gap_hours": 24})
    del cert["gap_events"][0]
    ok, out = run(cert)
    assert not ok
    assert "signed 3 gap event(s) but the bundle carries only 2" in out


def test_forged_closed_without_opened_fails():
    events = [event("dev-1", 7, 8, "closed", "2026-11-17T07:00:00Z")]
    ok, out = run(build(events, []))
    assert not ok
    assert "no earlier 'opened' event covers that range" in out


def test_partial_narrowing_is_allowed():
    events = [event("dev-1", 5, 9, "opened", "2026-11-17T06:00:00Z"),
              event("dev-1", 5, 6, "closed", "2026-11-17T07:00:00Z")]
    narrowed = {**OPEN, "seq_start": 7}
    ok, out = run(build(events, [narrowed], policy={"max_open_gap_hours": 24}))
    assert ok, out


def test_signed_open_gap_not_derivable_fails():
    ok, out = run(build(good_events(), [], policy={"max_open_gap_hours": 24}))
    assert not ok
    assert "do not match the gaps still open" in out


def test_open_gap_older_than_policy_fails():
    ok, out = run(build(good_events(), [OPEN], policy={"max_open_gap_hours": 4}))
    assert not ok
    assert "has been open 6.0 hours, longer than the 4 hours the signed policy allows" in out


def test_open_gap_without_policy_is_a_visible_finding_not_a_fail():
    ok, out = run(build(good_events(), [OPEN]))
    assert ok, out
    assert "records no age limit, so this is reported but not failed" in out


def test_absent_block_reads_not_recorded():
    ok, out = run(build([], [], with_block=False))
    assert ok, out
    assert "not recorded" in out
    assert "[PASS] sealed gap history" not in out and "[FAIL] sealed gap history" not in out


def test_block_present_but_bundle_has_no_events_fails():
    cert = build(good_events(), [OPEN], policy={"max_open_gap_hours": 24})
    del cert["gap_events"]
    ok, out = run(cert)
    assert not ok
    assert "carries no list of gap events" in out


def test_reordered_events_fail():
    cert = build(good_events(), [OPEN], policy={"max_open_gap_hours": 24})
    cert["gap_events"].reverse()
    ok, out = run(cert)
    assert not ok
    assert "do not reproduce the root" in out


def test_does_not_mutate_input():
    cert = build(good_events(), [OPEN])
    before = copy.deepcopy(cert)
    run(cert)
    assert cert == before


def test_malformed_open_gaps_fail_cleanly():
    for bad in (["x"], [None], [5], "nope", [{"device_id": ["a"], "seq_start": 1, "seq_end": 2}],
                [{"device_id": "dev-1", "seq_start": "a", "seq_end": 2}]):
        ok, out = run(build(good_events(), bad, policy={"max_open_gap_hours": 24}))
        assert not ok, bad
        assert "the signed open gaps contain a malformed range" in out, bad
        assert "Traceback" not in out


def test_event_with_a_list_for_device_fails_cleanly():
    events = [event(["dev-1"], 5, 9, "opened", "2026-11-17T06:00:00Z")]
    ok, out = run(build(events, [], policy={"max_open_gap_hours": 24}))
    assert not ok
    assert "has no valid device" in out


def with_body(cert, **changes):
    """Re-sign the certificate after changing the closing checkpoint's body."""
    cp = cert["statement"]["checkpoints"][-1]
    for k, v in changes.items():
        if v is _DROP:
            cp["sth_body"].pop(k, None)
        else:
            cp["sth_body"][k] = v
    cp["signature_hex"] = _PRIV.sign(canon(cp["sth_body"])).hex()
    cert["signature_hex"] = _PRIV.sign(canon(cert["statement"])).hex()
    return cert


_DROP = object()


def problems_of(cert):
    return vp._analyse_gap_history(cert)["problems"]


def test_age_comes_from_the_opened_event_not_the_signed_opened_at():
    old = [event("dev-1", 1, 2, "opened", "2026-01-01T00:00:00Z")]
    lying = {"device_id": "dev-1", "seq_start": 1, "seq_end": 2, "opened_at": "2026-11-17T11:00:00Z"}
    assert any("does not match the time its 'opened' event was recorded" in p
               for p in problems_of(build(old, [lying], policy={"max_open_gap_hours": 24})))
    missing = {"device_id": "dev-1", "seq_start": 1, "seq_end": 2}
    assert any("the age of an open gap cannot be worked out" in p
               for p in problems_of(build(old, [missing], policy={"max_open_gap_hours": 24})))


def test_narrowing_keeps_the_time_of_the_original_opening():
    events = [event("dev-1", 1, 10, "opened", "2026-11-17T06:00:00Z"),
              event("dev-1", 4, 5, "closed", "2026-11-17T09:00:00Z")]
    open_gaps = [{"device_id": "dev-1", "seq_start": 1, "seq_end": 3, "opened_at": "2026-11-17T06:00:00Z"},
                 {"device_id": "dev-1", "seq_start": 6, "seq_end": 10, "opened_at": "2026-11-17T06:00:00Z"}]
    assert problems_of(build(events, open_gaps, policy={"max_open_gap_hours": 24})) == []


def test_adjacent_open_ranges_are_not_merged():
    events = [event("d", 1, 5, "opened", "2026-11-17T06:00:00Z"), event("d", 6, 10, "opened", "2026-11-17T06:00:00Z")]
    whole = [{"device_id": "d", "seq_start": 1, "seq_end": 10, "opened_at": "2026-11-17T06:00:00Z"}]
    assert any("do not match the gaps still open" in p for p in problems_of(build(events, whole)))


def test_only_the_one_time_form_is_accepted():
    ev_ok = [event("dev-1", 1, 2, "opened", "2026-11-17T06:00:00.123456Z")]
    gap = {"device_id": "dev-1", "seq_start": 1, "seq_end": 2, "opened_at": "2026-11-17T06:00:00.123456Z"}
    assert problems_of(build(ev_ok, [gap], policy={"max_open_gap_hours": 24})) == []
    for bad in ("2026-11-17T06:00:00+00:00", "20261117T060000Z", "2026-11-17T06:00:00", "2026-11-17 06:00:00Z",
                "2026-11-17T06:00:00.1Z", "2026-02-30T06:00:00Z", "2026-11-17T06:00:60Z", "0000-01-01T00:00:00Z"):
        out = problems_of(build([event("dev-1", 1, 2, "opened", bad)], [], policy={"max_open_gap_hours": 24}))
        assert any("is not RFC 3339 UTC" in p for p in out), bad
    gap_bad = {**gap, "opened_at": "2026-11-16T12:00:00+05:00:00"}
    assert any("cannot be worked out" in p for p in problems_of(build(ev_ok, [gap_bad])))


def test_issued_at_may_be_the_producers_utc_offset_form():
    ev = [event("dev-1", 1, 2, "opened", "2026-11-17T06:00:00Z")]
    gap = {"device_id": "dev-1", "seq_start": 1, "seq_end": 2, "opened_at": "2026-11-17T06:00:00Z"}
    for issued in ("2026-11-17T12:00:00+00:00", "2026-11-17T12:00:00.5+00:00".replace(".5", ".500000"),
                   "2026-11-17T12:00:00Z"):
        assert problems_of(build(ev, [gap], issued=issued)) == [], issued
    out = problems_of(build(ev, [gap], issued="2026-11-17T17:00:00+05:00"))
    assert any("issued_at is missing or not a UTC time" in p for p in out)


def test_gap_opened_after_the_checkpoint_fails():
    ev = [event("dev-1", 1, 2, "opened", "2026-11-17T13:00:00Z")]
    gap = {"device_id": "dev-1", "seq_start": 1, "seq_end": 2, "opened_at": "2026-11-17T13:00:00Z"}
    assert any("was opened after the closing checkpoint was issued" in p for p in problems_of(build(ev, [gap])))


def test_age_limit_must_be_a_positive_number():
    for bad in ("24", 0, -1, True, None, [24], float("nan"), float("inf")):
        out = problems_of(build(good_events(), [OPEN], policy={"max_open_gap_hours": bad}))
        assert "the signed age limit is malformed" in out, bad
    out = problems_of(with_body(build(good_events(), [OPEN]), completeness_policy="x"))
    assert "the signed age limit is malformed" in out


def test_the_generic_policy_field_is_not_a_fallback():
    cert = with_body(build(good_events(), [OPEN]), policy={"max_open_gap_hours": 1})
    assert problems_of(cert) == []
    assert any("records no age limit" in f for f in vp._analyse_gap_history(cert)["findings"])


def test_a_later_org_wide_checkpoint_must_keep_the_history():
    cert = build(good_events(), [OPEN], policy={"max_open_gap_hours": 24})
    later = {"checkpoint_id": "cp2", "key_id": KEY_ID, "sth_body": {"issued_at": "2026-12-30T00:00:00+00:00"}}
    later["signature_hex"] = _PRIV.sign(canon(later["sth_body"])).hex()
    cert["statement"]["checkpoints"].append(later)
    cert["signature_hex"] = _PRIV.sign(canon(cert["statement"])).hex()
    assert any("a later checkpoint no longer records the gap history: checkpoint cp2" in p for p in problems_of(cert))
    later["sth_body"]["subject"] = "version:abc"
    later["signature_hex"] = _PRIV.sign(canon(later["sth_body"])).hex()
    assert problems_of(cert) == []


def test_age_is_measured_at_the_org_wide_closing_checkpoint():
    cert = build(good_events(), [OPEN], policy={"max_open_gap_hours": 4})
    cps = cert["statement"]["checkpoints"]
    assert any("longer than the 4 hours" in p for p in problems_of(cert))
    assert len(cps) == 1


def test_lone_surrogate_fails_cleanly():
    ev = {"device_id": "d", "seq_start": 1, "seq_end": 2, "event": "opened", "at": "2026-11-17T06:00:00Z",
          "reason": "\ud800", "actor": "a", "event_hash": "0" * 64}
    out = problems_of(build([ev], [], policy={"max_open_gap_hours": 24}))
    assert out == ["gap event 1 cannot be canonicalised"]


def test_device_must_be_a_non_empty_string():
    for dev in (True, 1, "", None):
        ev = [event(dev, 1, 2, "opened", "2026-11-17T06:00:00Z")]
        assert "gap event 1 has no valid device" in problems_of(build(ev, []))
    gap = {"device_id": True, "seq_start": 1, "seq_end": 2, "opened_at": "2026-11-17T06:00:00Z"}
    assert "the signed open gaps contain a malformed range" in problems_of(build(good_events(), [gap]))


def test_sequence_numbers_are_whole_numbers_up_to_2_pow_53_minus_1():
    top = 2 ** 53 - 1
    ok = [event("d", top, top, "opened", "2026-11-17T06:00:00Z")]
    gap = {"device_id": "d", "seq_start": top, "seq_end": top, "opened_at": "2026-11-17T06:00:00Z"}
    assert problems_of(build(ok, [gap], policy={"max_open_gap_hours": 24})) == []
    for bad in (2 ** 53, 2 ** 53 + 1, 10 ** 18):
        out = problems_of(build([event("d", bad, bad, "opened", "2026-11-17T06:00:00Z")], []))
        assert any("above 9007199254740991" in p for p in out), bad
    for bad in (-1, 1.5, "1", True, None):
        out = problems_of(build([event("d", bad, 5, "opened", "2026-11-17T06:00:00Z")], []))
        assert any("no valid sequence range" in p for p in out), bad


def test_inverted_ranges_in_the_signed_open_gaps_fail():
    gap = {"device_id": "dev-1", "seq_start": 9, "seq_end": 5, "opened_at": "2026-11-17T06:00:00Z"}
    assert "the signed open gaps contain a malformed range" in problems_of(build(good_events(), [gap]))


def test_gap_events_root_must_be_64_lowercase_hex():
    cert = build(good_events(), [OPEN], policy={"max_open_gap_hours": 24})
    root = cert["statement"]["checkpoints"][0]["sth_body"]["completeness"]["gap_events_root"]
    for bad in (root.upper(), root[:-1], root + "0"):
        out = problems_of(with_body(build(good_events(), [OPEN], policy={"max_open_gap_hours": 24}),
                                    completeness={**cert["statement"]["checkpoints"][0]["sth_body"]["completeness"],
                                                  "gap_events_root": bad}))
        assert any("has no valid gap event count and root" in p for p in out), bad


def test_overlapping_opens_cannot_be_closed_across_both():
    events = [event("d", 1, 10, "opened", "2026-11-17T06:00:00Z"), event("d", 5, 15, "opened", "2026-11-17T06:00:00Z"),
              event("d", 1, 15, "closed", "2026-11-17T07:00:00Z")]
    assert any("A gap cannot be closed that was never opened" in p for p in problems_of(build(events, [])))

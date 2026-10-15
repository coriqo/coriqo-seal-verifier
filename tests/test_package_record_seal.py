"""
Record-wide package seals (SPEC.md 6.2.3-6.2.6).

A package seal's package_attestation carries `record_heads` (per-version
governance-event heads the verifier recomputes; four other chain heads it
cannot) and `period_fence` (an ordinal range bounded by two signed org-wide
checkpoints). These tests drive the pure check functions with a synthetic
bundle view; signatures are covered elsewhere, so every checkpoint here is
passed in as signature-verified unless a test says otherwise.

Run:  python -m pytest tests/ -q
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof  # noqa: E402


def _h(tag: str) -> str:
    return hashlib.sha256(tag.encode()).hexdigest()


# Two versions. v1 holds ordinals 1, 3, 5, 7; v2 holds 2, 4, 6.
BY_VERSION = {
    "v1": [{"event_id": f"v1-{o}", "event_hash": _h(f"v1-{o}"), "ordinal": o} for o in (1, 3, 5, 7)],
    "v2": [{"event_id": f"v2-{o}", "event_hash": _h(f"v2-{o}"), "ordinal": o} for o in (2, 4, 6)],
}

LOWER = {"subject": "org_default", "issued_at": "2026-01-01T00:00:00+00:00", "ordinal_watermark": 2}
UPPER = {"subject": "org_default", "issued_at": "2026-04-01T00:00:00+00:00", "ordinal_watermark": 6}


def _seal(scope=None, ge=None, fence=None) -> dict:
    fence = fence or {
        "period_from": "2026-01-15T00:00:00+00:00", "period_to": "2026-03-31T00:00:00+00:00",
        "from_watermark": 2, "from_checkpoint_id": "lo",
        "to_watermark": 6, "to_checkpoint_id": "hi",
    }
    return {
        "subject": "package:p1", "issued_at": "2026-05-01T00:00:00+00:00", "ordinal_watermark": 7,
        "version_id": None,
        "package_attestation": {
            "package_id": "p1", "snapshot_sha256": "", "package_event_hash": _h("pkg"),
            "approval_head_hash": _h("appr"),
            "scope": scope or {"model_id": "", "version_id": ""},
            "record_heads": {
                "governance_events": ge if ge is not None else [
                    {"version_id": "v1", "length": 4, "head_hash": _h("v1-7")},
                    {"version_id": "v2", "length": 3, "head_hash": _h("v2-6")},
                ],
                "committee_decisions": {"length": 1, "head_hash": _h("cd")},
                "committee_attestations": [{"decision_id": "d1", "length": 2, "head_hash": _h("ca")}],
                "examination_questions": [],
                "package_approvals": {"length": 2, "head_hash": _h("appr")},
            },
            "period_fence": fence,
        },
    }


def _check(cp, checkpoints=None, sig_ok=None):
    checkpoints = checkpoints if checkpoints is not None else {"lo": LOWER, "hi": UPPER, "seal": cp}
    sig_ok = sig_ok if sig_ok is not None else {k: True for k in checkpoints}
    return verify_proof.check_package_record_seal("seal", cp, BY_VERSION, checkpoints, sig_ok)


def test_clean_org_wide_seal_recomputes():
    problems, checked, signed_only = _check(_seal())
    assert problems == []
    assert any("2 governance-event chain head(s)" in c for c in checked)
    # The four chains without a published formula are named, never passed.
    assert [s.split(" ")[0] for s in signed_only] == list(verify_proof.SIGNED_NOT_CHECKABLE_HEADS)


def test_wrong_head_is_caught():
    cp = _seal()
    cp["package_attestation"]["record_heads"]["governance_events"][1]["head_hash"] = _h("v2-4")
    problems, _, _ = _check(cp)
    assert any("signed head of version v2" in p for p in problems)


def test_org_wide_seal_must_list_every_version_with_sealed_events():
    cp = _seal(ge=[{"version_id": "v1", "length": 4, "head_hash": _h("v1-7")}])
    problems, _, _ = _check(cp)
    assert any("omits the head of version(s) v2" in p for p in problems)


def test_version_pinned_seal_must_list_exactly_that_version():
    cp = _seal(scope={"model_id": "m", "version_id": "v1"})
    cp["version_id"] = "v1"
    problems, _, _ = _check(cp)
    assert any("must sign exactly the head of version v1" in p for p in problems)
    cp["package_attestation"]["record_heads"]["governance_events"] = [
        {"version_id": "v1", "length": 4, "head_hash": _h("v1-7")}]
    assert _check(cp)[0] == []


def test_fence_reaching_unsealed_events_is_caught():
    cp = _seal()
    cp["ordinal_watermark"] = 5
    # re-sign heads at 5 so only the fence is wrong: v2-6 is inside (2, 6]
    # but not a leaf of a seal at watermark 5
    cp["package_attestation"]["record_heads"]["governance_events"] = [
        {"version_id": "v1", "length": 3, "head_hash": _h("v1-5")},
        {"version_id": "v2", "length": 2, "head_hash": _h("v2-4")},
    ]
    problems, _, _ = _check(cp)
    assert problems and all("not sealed by this checkpoint" in p for p in problems), problems
    assert "v2-6" in problems[0]


def test_version_seal_watermark_below_the_org_fence_is_fine():
    """A version seal's watermark is that version's last ordinal (7 for v1
    here, 6 for v2); the fence runs in org-wide ordinals. v2's seal at
    watermark 6 with a fence to 7 is honest: no v2 event sits in (6, 7]."""
    fence = {"period_from": "2026-01-15T00:00:00+00:00", "period_to": "2026-03-31T00:00:00+00:00",
             "from_watermark": 0, "from_checkpoint_id": "", "to_watermark": 7, "to_checkpoint_id": "",
             "snapshot_built_at": "2026-04-15T00:00:00+00:00"}
    cp = _seal(scope={"model_id": "", "version_id": "v2"}, fence=fence,
               ge=[{"version_id": "v2", "length": 3, "head_hash": _h("v2-6")}])
    cp["version_id"] = "v2"
    cp["subject"] = "version:v2"
    cp["ordinal_watermark"] = 6
    assert _check(cp)[0] == []


def test_record_wide_seal_without_governance_heads_fails():
    """A seal carrying period_fence (or record_heads) but no governance-event
    heads must not pass by having nothing to recompute."""
    cp = _seal()
    del cp["package_attestation"]["record_heads"]["governance_events"]
    problems, _, _ = _check(cp)
    assert any("carries no record_heads.governance_events" in p for p in problems), problems
    cp = _seal()
    del cp["package_attestation"]["record_heads"]
    assert any("carries no record_heads.governance_events" in p for p in _check(cp)[0])


def _open_upper_fence(tw: int, built: str = "2026-04-15T00:00:00+00:00") -> dict:
    return {"period_from": "2026-01-15T00:00:00+00:00", "period_to": "2026-03-31T00:00:00+00:00",
            "from_watermark": 2, "from_checkpoint_id": "lo", "to_watermark": tw,
            "to_checkpoint_id": "", "snapshot_built_at": built}


def test_open_upper_end_is_disclosed_not_passed():
    limits: list = []
    problems, _, _ = verify_proof.check_package_record_seal(
        "seal", _seal(fence=_open_upper_fence(6)), BY_VERSION,
        {"lo": LOWER, "hi": UPPER}, {"lo": True, "hi": True}, limits)
    assert problems == []
    assert limits and "Not checkable offline" in limits[0]
    assert "latest: hi, 6" in limits[0]


def test_open_upper_end_cut_below_an_earlier_checkpoint_fails():
    """UPPER (issued 2026-04-01, watermark 6) predates the snapshot build, so
    an upper end of 4 was truncated: events 5 and 6 existed at build time."""
    problems, _, _ = _check(_seal(fence=_open_upper_fence(4)), {"lo": LOWER, "hi": UPPER})
    assert any("the upper end was cut short" in p for p in problems), problems
    # A checkpoint issued AFTER the build proves nothing about it.
    late_hi = {**UPPER, "issued_at": "2026-04-20T00:00:00+00:00"}
    assert _check(_seal(fence=_open_upper_fence(4)), {"lo": LOWER, "hi": late_hi})[0] == []


def test_open_upper_end_needs_a_build_time():
    fence = _open_upper_fence(6)
    del fence["snapshot_built_at"]
    assert any("no snapshot_built_at" in p for p in _check(_seal(fence=fence))[0])
    after_seal = _open_upper_fence(6, built="2026-06-01T00:00:00+00:00")
    assert any("is after the seal" in p for p in _check(_seal(fence=after_seal))[0])


def test_lower_post_after_the_period_start_is_caught():
    late = {**LOWER, "issued_at": "2026-02-01T00:00:00+00:00"}
    problems, _, _ = _check(_seal(), {"lo": late, "hi": UPPER})
    assert any("after the period start" in p for p in problems)


def test_upper_post_before_the_period_end_is_caught():
    early = {**UPPER, "issued_at": "2026-03-01T00:00:00+00:00"}
    problems, _, _ = _check(_seal(), {"lo": LOWER, "hi": early})
    assert any("before the period end" in p for p in problems)


def test_version_scoped_or_unverified_or_mismatched_post_is_caught():
    ver = {**LOWER, "subject": "version:v1", "version_id": "v1"}
    assert any("version-scoped" in p for p in _check(_seal(), {"lo": ver, "hi": UPPER})[0])
    assert any("did not verify" in p for p in _check(
        _seal(), {"lo": LOWER, "hi": UPPER}, {"lo": False, "hi": True})[0])
    wrong_wm = {**LOWER, "ordinal_watermark": 1}
    assert any("signs watermark 1, not 2" in p for p in _check(_seal(), {"lo": wrong_wm, "hi": UPPER})[0])
    assert any("not in this bundle" in p for p in _check(_seal(), {"hi": UPPER})[0])


def test_no_lower_checkpoint_means_from_zero():
    fence = {"period_from": "2026-01-15T00:00:00+00:00", "period_to": "2026-03-31T00:00:00+00:00",
             "from_watermark": 0, "from_checkpoint_id": "", "to_watermark": 6, "to_checkpoint_id": "hi"}
    assert _check(_seal(fence=fence))[0] == []
    fence["from_watermark"] = 2
    assert any("not 0" in p for p in _check(_seal(fence=fence))[0])


def _snapshot_and_seal(listed_ids):
    events = [e for rows in BY_VERSION.values() for e in rows if e["event_id"] in listed_ids]
    snapshot = {"period_fence": {"from_watermark": 2, "to_watermark": 6},
                "governance_events": [{"event_id": e["event_id"], "event_hash": e["event_hash"],
                                       "value": 0.1} for e in events]}
    data = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    cp = _seal()
    cp["package_attestation"]["snapshot_sha256"] = hashlib.sha256(data).hexdigest()
    return data, cp


def test_snapshot_listing_every_fenced_event_passes():
    # ordinals 3, 4, 5, 6 are inside (2, 6]
    data, cp = _snapshot_and_seal({"v1-3", "v2-4", "v1-5", "v2-6"})
    results, not_checked = verify_proof.check_package_snapshot(data, [("seal", cp)], BY_VERSION, {"seal": True})
    assert all(ok for _, ok, _ in results), results
    assert "all 4 in-scope governance event(s)" in results[-1][2]
    assert not_checked == []


def test_snapshot_missing_a_fenced_event_fails():
    data, cp = _snapshot_and_seal({"v1-3", "v2-4", "v1-5"})
    results, _ = verify_proof.check_package_snapshot(data, [("seal", cp)], BY_VERSION, {"seal": True})
    assert results[0][1] is True           # the digest is signed
    assert results[-1][1] is False         # but v2-6 was left out
    assert "v2-6" in results[-1][2]


def test_snapshot_outside_period_list_counts_toward_the_fence():
    """governance_events holds the in-period rows; fenced rows dated outside
    the period sit in governance_events_outside_period. Together they must
    hold every fenced in-scope event."""
    events = {e["event_id"]: e for rows in BY_VERSION.values() for e in rows}
    snapshot = {"period_fence": {"from_watermark": 2, "to_watermark": 6},
                "governance_events": [{"event_id": i, "event_hash": events[i]["event_hash"]}
                                      for i in ("v1-3", "v2-4")],
                "governance_events_outside_period": [{"event_id": i, "event_hash": events[i]["event_hash"]}
                                                     for i in ("v1-5", "v2-6")]}
    data = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    cp = _seal()
    cp["package_attestation"]["snapshot_sha256"] = hashlib.sha256(data).hexdigest()
    results, _ = verify_proof.check_package_snapshot(data, [("seal", cp)], BY_VERSION, {"seal": True})
    assert all(ok for _, ok, _ in results), results


def test_snapshot_not_matching_any_seal_fails():
    data, cp = _snapshot_and_seal({"v1-3", "v2-4", "v1-5", "v2-6"})
    results, _ = verify_proof.check_package_snapshot(data + b" ", [("seal", cp)], BY_VERSION, {"seal": True})
    assert results == [(results[0][0], False, results[0][2])]
    results, _ = verify_proof.check_package_snapshot(data, [("seal", cp)], BY_VERSION, {"seal": False})
    assert results[0][1] is False and "did not verify" in results[0][2]


def test_seal_without_a_fence_reports_not_checked():
    data, cp = _snapshot_and_seal({"v1-3"})
    att = cp["package_attestation"]
    for k in ("period_fence", "record_heads", "scope"):
        att.pop(k)
    results, not_checked = verify_proof.check_package_snapshot(data, [("seal", cp)], BY_VERSION, {"seal": True})
    assert [ok for _, ok, _ in results] == [True]
    assert not_checked and "signs no period_fence" in not_checked[0]


def test_pre_record_wide_seal_adds_no_result(tmp_path):
    """A package seal carrying only the original four fields gets no
    record-wide check at all: not a pass, not a fail."""
    cp = copy.deepcopy(_seal())
    att = cp["package_attestation"]
    for k in ("period_fence", "record_heads", "scope"):
        att.pop(k)
    (tmp_path / "checkpoints").mkdir()
    path = tmp_path / "checkpoints" / "seal.json"
    path.write_text(json.dumps(cp))
    results: list = []
    verify_proof._check_bundle_package_seals(str(tmp_path), [str(path)], {"seal": True}, results)
    assert results == []

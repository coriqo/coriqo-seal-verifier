"""
Trust Repair proof (SPEC.md 16, P5/P6): the claims a sealed package makes about a finding's
path, checked against governance events in the tenant bundle. Each tamper test changes one
thing and expects the checker to fail that claim.

Run:  python -m pytest seal-verifier/tests/test_trust_repair.py -q
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import verify_proof as vp  # noqa: E402

V = "ver-remediation"
FID = "finding-1"


def _event(seq, ordinal, prev, action, notes, event_id):
    row = {"event_id": event_id, "seq": seq, "ordinal": ordinal, "actor": "system", "action": action,
           "version_id": V, "from_status": "approved", "to_status": "approved", "prev_hash": prev,
           "notes": json.dumps(notes, sort_keys=True, separators=(",", ":"), ensure_ascii=False)}
    row["event_hash"] = vp._event_hash_of(row)
    return row


def _method():
    m = {"library_version": "1", "controls": {"AC-008": {"determination": "EFFECTIVE"}}}
    m["sha256"] = hashlib.sha256(json.dumps(m, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return m


def _world():
    prev = "0" * 64
    rows = []
    specs = [
        ("finding_status_changed", {"finding_id": FID, "from": "open", "to": "in_remediation"}),
        ("finding_status_changed", {"finding_id": FID, "from": "in_remediation", "to": "resolved",
                                    "retest_execution_id": "run-9", "retest_result": "pass"}),
    ]
    for i, (action, notes) in enumerate(specs):
        r = _event(i, i + 1, prev, action, notes, f"ev{i}")
        rows.append(r)
        prev = r["event_hash"]
    m = _method()
    r = _event(2, 3, prev, "assurance_determination_sealed",
               {"execution_id": "run-9", "method_sha256": m["sha256"], "resource_id": "camp-1"}, "ev2")
    rows.append(r)
    snapshot = {
        "remediation_status": {"articles": [{
            "number": 1, "finding_id": FID,
            "finding": {
                "status": "resolved", "occurrence_count": 2, "repeats": ["older-1"],
                "retest": {"execution_id": "run-9", "result": "pass", "evidence_verified": True},
                "closure": {"basis": "retest_verified", "strength": "independent", "label": "x"},
                "sealed_steps": [{"to": "in_remediation", "ref": f"ev0:{rows[0]['event_hash']}"},
                                 {"to": "resolved", "ref": f"ev1:{rows[1]['event_hash']}"}],
            }}]},
        "assurance_determination": {"method": m, "method_seal_ref": f"ev2:{rows[2]['event_hash']}"},
    }
    return snapshot, {V: rows}


def _verdicts(snapshot, by_version):
    return {(c, v) for c, v, _d in vp.check_trust_repair(snapshot, by_version)}


def _failed(snapshot, by_version):
    return [c for c, v, _d in vp.check_trust_repair(snapshot, by_version) if v == vp.TR_FAILED]


def test_an_untouched_package_passes():
    snap, bv = _world()
    res = vp.check_trust_repair(snap, bv)
    assert not [r for r in res if r[1] == vp.TR_FAILED], res
    assert any("sealed steps" in c and v == vp.TR_VERIFIED for c, v, _ in res)
    assert any("retest matches" in c and v == vp.TR_VERIFIED for c, v, _ in res)
    assert any("determination method sealed" in c and v == vp.TR_VERIFIED for c, v, _ in res)
    assert any(v == vp.TR_OFFLINE for _c, v, _ in res)


def test_a_closure_upgraded_to_independent_fails():
    snap, bv = _world()
    f = snap["remediation_status"]["articles"][0]["finding"]
    f["retest"] = {"execution_id": "run-9", "result": "pass", "evidence_verified": False}
    f["closure"] = {"basis": "retest_verified", "strength": "independent", "label": "x"}
    assert any("closure follows" in c for c in _failed(snap, bv))


def test_a_changed_retest_result_fails_against_the_sealed_closure():
    snap, bv = _world()
    snap["remediation_status"]["articles"][0]["finding"]["retest"]["execution_id"] = "run-OTHER"
    assert any("retest matches" in c for c in _failed(snap, bv))


def test_an_altered_chain_event_fails():
    snap, bv = _world()
    bv[V][1]["notes"] = bv[V][1]["notes"].replace("pass", "fail")
    assert any("sealed steps" in c for c in _failed(snap, bv))


def test_a_ref_to_a_missing_event_fails():
    snap, bv = _world()
    bv[V].pop(0)
    assert any("sealed steps" in c for c in _failed(snap, bv))


def test_a_step_that_names_another_finding_fails():
    snap, bv = _world()
    snap["remediation_status"]["articles"][0]["finding_id"] = "someone-else"
    assert any("sealed steps" in c for c in _failed(snap, bv))


def test_steps_out_of_chain_order_fail():
    snap, bv = _world()
    steps = snap["remediation_status"]["articles"][0]["finding"]["sealed_steps"]
    steps.reverse()
    assert any("sealed steps" in c for c in _failed(snap, bv))


def test_a_status_the_chain_does_not_end_on_fails():
    snap, bv = _world()
    snap["remediation_status"]["articles"][0]["finding"]["status"] = "examiner_closed"
    snap["remediation_status"]["articles"][0]["finding"]["closure"] = {
        "basis": "examiner", "strength": "independent", "label": "x"}
    assert any("sealed steps" in c for c in _failed(snap, bv))


def test_a_repeat_count_that_does_not_add_up_fails():
    snap, bv = _world()
    snap["remediation_status"]["articles"][0]["finding"]["occurrence_count"] = 5
    assert any("repeat count" in c for c in _failed(snap, bv))


def test_an_altered_method_block_fails_its_hash():
    snap, bv = _world()
    snap["assurance_determination"]["method"]["controls"]["AC-008"]["determination"] = "INEFFECTIVE"
    assert "determination method hash" in _failed(snap, bv)


def test_a_method_hash_that_differs_from_the_sealed_event_fails():
    snap, bv = _world()
    m = _method()
    m["controls"]["AC-008"]["determination"] = "PARTIALLY_EFFECTIVE"
    body = {k: v for k, v in m.items() if k != "sha256"}
    m["sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    snap["assurance_determination"]["method"] = m
    assert "determination method sealed" in _failed(snap, bv)


def test_older_records_are_disclosed_not_failed():
    snap, bv = _world()
    f = snap["remediation_status"]["articles"][0]["finding"]
    f["sealed_steps"] = []
    snap["assurance_determination"]["method_seal_ref"] = None
    res = vp.check_trust_repair(copy.deepcopy(snap), bv)
    assert not [r for r in res if r[1] == vp.TR_FAILED]
    assert sum(1 for r in res if r[1] == vp.TR_NOT_COVERED) == 2


def test_retest_origin_is_context_never_a_verdict():
    snap, bv = _world()
    f = snap["remediation_status"]["articles"][0]["finding"]
    base_failed = [r for r in vp.check_trust_repair(copy.deepcopy(snap), bv) if r[1] == vp.TR_FAILED]
    f["closure"]["origin"] = {"class": "signed_push", "label": "Manifest checked", "checked": "x"}
    res = vp.check_trust_repair(snap, bv)
    ctx = [r for r in res if r[1] == vp.TR_CONTEXT]
    assert len(ctx) == 1 and "signed_push" in ctx[0][2]
    assert [r for r in res if r[1] == vp.TR_FAILED] == base_failed


def test_an_unverified_retest_origin_stays_non_failing():
    snap, bv = _world()
    f = snap["remediation_status"]["articles"][0]["finding"]
    base_failed = [r for r in vp.check_trust_repair(copy.deepcopy(snap), bv) if r[1] == vp.TR_FAILED]
    f["closure"]["origin"] = {"class": None, "label": "Manifest not verified", "checked": "x"}
    res = vp.check_trust_repair(snap, bv)
    ctx = [r for r in res if r[1] == vp.TR_CONTEXT]
    assert len(ctx) == 1 and "not verified" in ctx[0][2]
    assert [r for r in res if r[1] == vp.TR_FAILED] == base_failed


def test_a_package_with_no_claims_checks_nothing():
    assert vp.check_trust_repair({}, {}) == []


def test_evidence_origins_are_reported_as_context_never_a_verdict():
    snap, bv = _world()
    snap["remediation_status"]["articles"][0]["evidence_origins"] = {"signed_push": 4, "file_upload": 1}
    res = vp.check_trust_repair(snap, bv)
    ctx = [r for r in res if r[1] == vp.TR_CONTEXT]
    assert len(ctx) == 1 and "file_upload 1" in ctx[0][2] and "signed_push 4" in ctx[0][2]
    assert not [r for r in res if r[1] == vp.TR_FAILED]


# ---- claim 8: held back follows the tenant's minimum evidence origin --------------------------------

def _held_world(origins=None, minimum="keyed_push", held=True):
    snap, bv = _world()
    rem = snap["remediation_status"]
    art = rem["articles"][0]
    art["article_id"] = "art-1"
    art["evidence_origins"] = origins or {"signed_push": 3, "file_upload": 1}
    f = art["finding"]
    f["retest"]["evidence_verified"] = True
    rem["closure_min_origin"] = minimum
    if held:
        f["closure"] = {"basis": "retest_verified", "strength": "management", "label": "x",
                        "held_back": {"min_origin": minimum, "weakest_origin": "file_upload",
                                      "articles": [{"article_id": "art-1", "number": "1", "weakest_origin": "file_upload"}]}}
    else:
        f["closure"] = {"basis": "retest_verified", "strength": "independent", "label": "x"}
    return snap, bv


def test_a_lawful_hold_passes_and_does_not_trip_the_closure_claim():
    snap, bv = _held_world()
    res = vp.check_trust_repair(snap, bv)
    assert not [r for r in res if r[1] == vp.TR_FAILED], res
    assert any("held back follows" in c and v == vp.TR_VERIFIED for c, v, _ in res)


def test_dropping_the_hold_to_look_independent_fails():
    snap, bv = _held_world(held=False)
    assert any("held back follows" in c for c in _failed(snap, bv))


def test_a_hold_with_no_weak_evidence_fails():
    snap, bv = _held_world(origins={"signed_push": 4})
    assert any("held back follows" in c for c in _failed(snap, bv))


def test_a_hold_naming_a_different_minimum_or_article_fails():
    snap, bv = _held_world()
    snap["remediation_status"]["articles"][0]["finding"]["closure"]["held_back"]["min_origin"] = "signed_push"
    assert any("held back follows" in c for c in _failed(snap, bv))
    snap, bv = _held_world()
    snap["remediation_status"]["articles"][0]["finding"]["closure"]["held_back"]["articles"][0]["article_id"] = "other"
    assert any("held back follows" in c for c in _failed(snap, bv))


def test_a_hold_with_no_minimum_in_the_package_fails_and_off_with_no_hold_is_silent():
    snap, bv = _held_world()
    del snap["remediation_status"]["closure_min_origin"]
    assert any("held back follows" in c for c in _failed(snap, bv))
    snap, bv = _world()
    assert not [c for c, _v, _d in vp.check_trust_repair(snap, bv) if "held back" in c]


def test_an_unrecorded_origin_counts_as_weak_and_an_unknown_minimum_fails():
    snap, bv = _held_world(origins={"signed_push": 2, "not_recorded": 1})
    assert not _failed(snap, bv)
    snap["remediation_status"]["closure_min_origin"] = "file_upload"
    assert "closure minimum" in _failed(snap, bv)

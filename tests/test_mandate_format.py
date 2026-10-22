"""Conformance corpus for coriqo.mandate.yaml v1 (MANDATE_SPEC.md section 8).

Every file in testdata/mandate/ is listed in cases.json with its verdict, and
every listed file must exist, so a fixture cannot be added without a verdict
or a verdict kept for a fixture that is gone.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

import mandate_format as mf  # noqa: E402

CORPUS = HERE / "testdata" / "mandate"
CASES = json.loads((CORPUS / "cases.json").read_text())
SCHEMA = json.loads((HERE / "mandate.schema.json").read_text())


def _load(rel: str):
    return mf.parse_text((CORPUS / rel).read_text(encoding="utf-8"))


def test_every_fixture_has_a_verdict():
    listed = {c["file"] for c in CASES["valid"] + CASES["invalid"]}
    on_disk = {str(p.relative_to(CORPUS)) for p in CORPUS.rglob("*") if p.is_file() and p.name != "cases.json"}
    assert listed == on_disk


@pytest.mark.parametrize("case", CASES["valid"], ids=lambda c: c["file"])
def test_valid_files_pass_with_their_hash(case):
    doc = _load(case["file"])
    errors, warnings = mf.check(doc)
    assert errors == []
    assert len(warnings) == case["warnings"]
    assert mf.document_sha256(doc) == case["sha256"]


@pytest.mark.parametrize("case", CASES["invalid"], ids=lambda c: c["file"])
def test_invalid_files_fail_naming_the_field(case):
    errors, _ = mf.check(_load(case["file"]))
    assert errors, f"{case['file']} should be refused"
    assert any(e.startswith(case["field"]) for e in errors), errors


@pytest.mark.parametrize("case", CASES["valid"] + CASES["invalid"], ids=lambda c: c["file"])
def test_json_schema_agrees_where_it_can(case):
    jsonschema = pytest.importorskip("jsonschema")
    doc = _load(case["file"])
    schema_ok = jsonschema.Draft202012Validator(SCHEMA).is_valid(doc)
    reader_ok = not mf.check(doc)[0]
    if case["schema_agrees"]:
        assert schema_ok == reader_ok
    else:
        assert schema_ok != reader_ok


def test_defaults_in_the_schema_match_the_reader():
    props = SCHEMA["properties"]
    for key in ("mode", "on_stale_snapshot", "max_staleness_s", "on_violation"):
        assert props[key]["default"] == mf.DEFAULTS[key]
    assert {k: v["default"] for k, v in props["delegation"]["properties"].items()} == {
        "policy": mf.DEFAULTS["delegation"]["policy"], "max_depth": mf.DEFAULTS["delegation"]["max_depth"],
    }
    assert {k: v["default"] for k, v in props["output_inspection"]["properties"].items()} == mf.DEFAULTS["output_inspection"]


def test_default_mode_is_shadow():
    # Founder decision 2026-10-19: a file that says nothing about mode records
    # violations and blocks nothing.
    assert mf.normalise(_load("valid/minimal.yaml"))["mode"] == "shadow"


def test_hash_is_sha256_of_canonical_normalised_json():
    import hashlib
    doc = _load("valid/full.yaml")
    body = json.dumps(mf.normalise(doc), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() == mf.document_sha256(doc)
    assert mf.normalise(doc)["max_cost_usd"] == "1.5"


def test_import_merge_changes_only_stated_fields():
    # MANDATE_SPEC.md section 5: a field the file leaves out keeps the value held.
    held = _load("valid/full.yaml")
    assert mf.changes(held, mf.merge(held, _load("valid/minimal.yaml"))) == []
    incoming = {"spec": mf.SPEC_ID, "agent": {"name": "x"}, "mode": "shadow",
                "delegation": {"max_depth": 2}, "x-note": "ignored"}
    diff = mf.changes(held, mf.merge(held, incoming))
    assert [(c["field"], c["old"], c["new"]) for c in diff] == [
        ("mode", "enforce", "shadow"), ("delegation.max_depth", 1, 2),
    ]


# Document hashes of v1.0 corpus files, as v1.0 readers computed them. A field
# added in v1.1 is hashed only when set (MANDATE_SPEC.md section 6.1), so a
# v1.1 reader must reproduce every one of these exactly.
V1_0_HASHES = {
    "valid/minimal.yaml": "02b471ffd7c0c91832e9f0860030db33724cd4b4ef9e0e859a088578f30bfdf5",
    "valid/defaults_explicit.yaml": "02b471ffd7c0c91832e9f0860030db33724cd4b4ef9e0e859a088578f30bfdf5",
    "valid/nulls_explicit.yaml": "02b471ffd7c0c91832e9f0860030db33724cd4b4ef9e0e859a088578f30bfdf5",
    "valid/full.yaml": "830d0806bca8b2b2b0a6012f446041bc3eb99d499a68d2ee222ac7e87198654a",
    "valid/full_reordered.json": "830d0806bca8b2b2b0a6012f446041bc3eb99d499a68d2ee222ac7e87198654a",
}


@pytest.mark.parametrize("rel", sorted(V1_0_HASHES))
def test_v1_1_reader_hashes_v1_0_documents_as_before(rel):
    doc = _load(rel)
    assert "stop_grace_s" not in mf.normalise(doc)
    assert mf.document_sha256(doc) == V1_0_HASHES[rel]


def test_stop_grace_is_hashed_only_when_set():
    held = _load("valid/minimal.yaml")
    assert mf.normalise({**held, "stop_grace_s": None}) == mf.normalise(held)
    set_doc = _load("valid/stop_grace_set.yaml")
    assert mf.normalise(set_doc)["stop_grace_s"] == 30
    assert mf.document_sha256(set_doc) != mf.document_sha256(held)


def test_changes_reports_a_field_only_one_side_has():
    held = _load("valid/full.yaml")
    added = mf.merge(held, {"spec": "coriqo.mandate/v1.1", "agent": {"name": "x"}, "stop_grace_s": 45})
    assert mf.changes(held, added) == [{"field": "stop_grace_s", "old": None, "new": 45}]
    assert mf.changes(added, held) == [{"field": "stop_grace_s", "old": 45, "new": None}]
    # A file that leaves it out keeps the value held (section 5).
    assert mf.changes(added, mf.merge(added, _load("valid/minimal.yaml"))) == []
    cleared = mf.merge(added, {"spec": "coriqo.mandate/v1.1", "agent": {"name": "x"}, "stop_grace_s": None})
    assert mf.changes(added, cleared) == [{"field": "stop_grace_s", "old": 45, "new": None}]


def test_a_field_from_a_later_revision_is_warned_not_refused():
    # Rule 2 of section 3, now that this reader is v1.1.
    doc = _load("valid/stop_grace_set.yaml")
    errors, warnings = mf.check({**doc, "spec": "coriqo.mandate/v1.2", "later_field": 1})
    assert errors == [] and warnings == ["later_field: not part of v1.1; ignored"]


def test_unreadable_text_is_an_error_not_a_verdict():
    with pytest.raises(mf.MandateFileError):
        mf.parse_text("")
    with pytest.raises(mf.MandateFileError):
        mf.parse_text("x" * (mf.MAX_FILE_BYTES + 1))


@pytest.mark.parametrize("rel,code", [("valid/full.yaml", 0), ("invalid/bad_mode.yaml", 1), ("nope.yaml", 2)])
def test_command_line_exit_codes(rel, code):
    res = subprocess.run([sys.executable, str(HERE / "mandate_format.py"), str(CORPUS / rel), "--hash"],
                         capture_output=True, text=True)
    assert res.returncode == code, res.stdout + res.stderr

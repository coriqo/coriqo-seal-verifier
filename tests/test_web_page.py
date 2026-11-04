"""The GitHub Pages verifier page (web/) keeps its promises.

The page says it makes no network request and loads nothing from another
origin. These tests fail if a change breaks either claim, or if the embedded
sample drifts from testdata/proof.json.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
PAGE = (WEB / "index.html").read_text(encoding="utf-8")


def test_sample_matches_testdata():
    js = (WEB / "sample.js").read_text(encoding="utf-8")
    body = js.split("window.CORIQO_SAMPLE_PROOF = ", 1)[1].rstrip().rstrip(";")
    assert json.loads(body) == json.loads((ROOT / "testdata" / "proof.json").read_text())


def test_csp_blocks_every_network_request():
    m = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', PAGE)
    assert m, "the page needs a Content-Security-Policy meta tag"
    csp = m.group(1)
    assert "connect-src 'none'" in csp
    assert "default-src 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp


def test_csp_is_the_first_element_in_head():
    head = PAGE.split("<head>", 1)[1].lstrip()
    assert head.startswith('<meta http-equiv="Content-Security-Policy"')


def test_no_inline_script_or_style():
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", PAGE), "inline <script>"
    assert "<style" not in PAGE and " style=" not in PAGE


def test_no_script_or_style_from_another_origin():
    for tag in re.findall(r"<(?:script|link|img)\b[^>]*>", PAGE):
        assert not re.search(r'(?:src|href)="(?:https?:)?//', tag), tag


def test_no_network_calls_in_page_code():
    for name in ("verify.js", "verify-ui.js", "page-ui.js", "keyring.js", "sample.js"):
        code = re.sub(r"//.*|/\*[\s\S]*?\*/", "", (WEB / name).read_text(encoding="utf-8"))
        assert not re.search(r"\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon|importScripts", code), name


def test_every_script_the_page_names_exists():
    for ref in re.findall(r'(?:src|href)="([^"#:]+\.(?:js|css|svg))"', PAGE):
        assert (WEB / ref).is_file(), ref


def test_every_check_the_page_describes_exists_in_the_verifier():
    """The page's "What each check means" table must not promise a check the
    browser verifier does not run."""
    code = (WEB / "verify.js").read_text(encoding="utf-8")
    for name in ("Merkle inclusion proof", "Timestamp consistency"):
        assert f"name: '{name}'" in code, name
        assert name.lower() in PAGE.lower(), name

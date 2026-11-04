/*
 * Drop-zone UI for the in-browser verifier.
 *
 * Every string that reaches the DOM here goes through textContent, and the
 * container is cleared with replaceChildren() rather than innerHTML. That is
 * not incidental tidiness: the input to this page is, by design, a file a
 * stranger built specifically to make our checker behave wrongly. Filenames,
 * zip entry names and parse errors all come from it and are all rendered.
 *
 * Reads a .zip bundle or a bare .json attestation, hands it to CoriqoVerify,
 * and renders the verdict. Nothing leaves the page: no fetch, no upload, no
 * analytics call on the file. A challenger checking their own forgery should
 * not have to take our word for that, so the code is short enough to read.
 */
(function () {
  'use strict';

  // -------------------------------------------------------------------
  // Minimal zip reader
  //
  // Enough of the format to pull two known filenames out of a bundle we
  // produced: walk the end-of-central-directory record, then the central
  // directory, and inflate stored/deflated entries. Not a general zip library
  // and not trying to be — anything it cannot read falls back to "drop the
  // JSON instead", which always works.
  // -------------------------------------------------------------------

  var EOCD_SIG = 0x06054b50, CEN_SIG = 0x02014b50;

  async function readZip(buffer) {
    var view = new DataView(buffer);
    var eocd = -1;
    // The EOCD sits at the end, after a comment of up to 65535 bytes.
    for (var i = buffer.byteLength - 22; i >= 0 && i >= buffer.byteLength - 22 - 65535; i--) {
      if (view.getUint32(i, true) === EOCD_SIG) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error('Not a zip file (no end-of-central-directory record).');

    var count = view.getUint16(eocd + 10, true);
    var offset = view.getUint32(eocd + 16, true);
    var entries = {};

    for (var n = 0; n < count; n++) {
      if (view.getUint32(offset, true) !== CEN_SIG) break;
      var method = view.getUint16(offset + 10, true);
      var compSize = view.getUint32(offset + 20, true);
      var nameLen = view.getUint16(offset + 28, true);
      var extraLen = view.getUint16(offset + 30, true);
      var commentLen = view.getUint16(offset + 32, true);
      var localOffset = view.getUint32(offset + 42, true);
      var name = new TextDecoder().decode(new Uint8Array(buffer, offset + 46, nameLen));

      // The local header repeats the name/extra lengths, and its extra field
      // length can differ from the central one — read it from the local header.
      var lNameLen = view.getUint16(localOffset + 26, true);
      var lExtraLen = view.getUint16(localOffset + 28, true);
      var dataStart = localOffset + 30 + lNameLen + lExtraLen;
      var raw = new Uint8Array(buffer, dataStart, compSize);

      entries[name] = { method: method, raw: raw };
      offset += 46 + nameLen + extraLen + commentLen;
    }
    return entries;
  }

  async function entryText(entry) {
    if (entry.method === 0) return new TextDecoder().decode(entry.raw);
    if (entry.method === 8) {
      if (typeof DecompressionStream === 'undefined') {
        throw new Error('This browser cannot decompress the zip. Drop certificate.json ' +
                        'or proof.json from inside it instead.');
      }
      var stream = new Blob([entry.raw]).stream()
        .pipeThrough(new DecompressionStream('deflate-raw'));
      return new Response(stream).text();
    }
    throw new Error('Unsupported compression in the zip. Drop the JSON file instead.');
  }

  // A zip with no certificate.json/proof.json is not necessarily a bad drop —
  // engagement-deliverables exports carry a manifest.json that says outright
  // whether the bundle is sealed, and why not when it isn't (no examiner
  // package was ever generated for the tenant, sealing lives in a different
  // pipeline, etc). That reason is more useful than a bare list of filenames,
  // so read it when it's there instead of always falling back to the generic
  // "here's what's in the zip" message.
  async function explainUnsealedZip(entries) {
    var manifestKey = Object.keys(entries).filter(function (k) {
      return k.replace(/^.*\//, '') === 'manifest.json';
    })[0];
    if (!manifestKey) return null;
    var manifest;
    try { manifest = JSON.parse(await entryText(entries[manifestKey])); }
    catch (e) { return null; }
    if (!manifest || manifest.sealed !== false) return null;

    var msg = manifest.bundle_note ||
      'This zip is marked unsealed (manifest.json: "sealed": false) — there is nothing here for the verifier to check.';
    var examinerEntry = (manifest.files || []).filter(function (f) {
      return f && f.name === 'examiner-package.pdf';
    })[0];
    if (examinerEntry && examinerEntry.status === 'absent' && examinerEntry.reason) {
      msg += ' ' + examinerEntry.reason;
    }
    return msg;
  }

  // -------------------------------------------------------------------
  // Rendering
  // -------------------------------------------------------------------

  var STATE_LABEL = { pass: 'PASS', fail: 'FAIL', skip: 'NOT RUN' };

  // Plain-language wording for the checks. verify.js keeps the technical names
  // (they match verify_proof.py, so a researcher can line the two up); the page
  // shows these first and keeps the technical rows under "Show technical details".
  var PLAIN = {
    'Certificate signature': {
      title: 'The seal on this record is genuine',
      bad: 'The seal on this record does not match its contents',
      ok: 'The signature on the certificate matches its contents, so nothing in it was edited after it was sealed.'
    },
    'Ed25519 signature': {
      title: 'The seal on this record is genuine',
      bad: 'The seal on this record does not match its contents',
      ok: 'The signature matches the sealed contents, so nothing in it was edited after it was sealed.'
    },
    'Timestamp consistency': {
      title: 'The time on this file is the time that was sealed',
      bad: 'The time on this file doesn\u2019t match the sealed time',
      ok: 'The time the file states is the time inside the signed checkpoint.'
    },
    'One seal in this PDF': {
      title: 'This PDF carries one seal',
      bad: 'This PDF carries more than one seal',
      ok: 'The PDF carries a single seal.'
    },
    'PDF pages covered by the seal': {
      title: 'The pages of this PDF are not covered by the seal',
      bad: 'The pages of this PDF are not covered by the seal',
      ok: 'The pages of this PDF are covered by the seal.'
    },
    'Continuity linkage': {
      title: 'Nothing was removed or reordered',
      bad: 'The chain of checkpoints is broken',
      ok: 'Each checkpoint is chained to the one before it, so the record is one unbroken history across the whole period.'
    },
    'Coverage claims': {
      title: 'The totals in this report are backed by the seals',
      bad: 'The totals in this report don\u2019t match the seals',
      ok: 'Every count and date range stated in the report can be re-derived from the signed checkpoints.'
    },
    'Bundle matches the signed checkpoint body': {
      title: 'This proof describes the checkpoint it claims to',
      bad: 'This proof doesn\u2019t match the checkpoint it claims to',
      ok: 'The tree root and size in the bundle are the values the signature covers.'
    },
    'ES256 signature': {
      title: 'The seal on this record is genuine',
      bad: 'The seal on this record does not match its contents',
      ok: 'The signature (ES256, from a key such as one held in AWS KMS or Azure Key Vault) matches the sealed contents, so nothing in it was edited after it was sealed.'
    },
    'Signed part of this file is unchanged': {
      title: 'The part Coriqo signed is unchanged',
      bad: 'This file was changed after Coriqo handed it over',
      ok: 'The signed part of the file hashes to the value in its download receipt.'
    },
    'Bytes added after the signed part': {
      title: 'The part added after signing was not checked here'
    },
    'Certificate is inside the signed part': {
      title: 'The certificate is part of what was signed',
      bad: 'The certificate was added after the file was signed',
      ok: 'The attached certificate sits inside the bytes the download receipt signed.'
    },
    'Receipt fields match what was signed': {
      title: 'The receipt\u2019s details are the ones that were signed',
      bad: 'The receipt\u2019s details were edited',
      ok: 'The file name, size, who downloaded it and when are all inside the signature.'
    },
    'Receipt signature': {
      title: 'The download receipt is genuine',
      bad: 'The download receipt\u2019s signature does not check out',
      ok: 'The receipt carries a valid signature over its own contents.'
    },
    'manifest.json hash matches the signed binding': {
      title: 'The deliverable\u2019s file list is the one that was sealed',
      bad: 'The deliverable\u2019s file list was changed after it was sealed',
      ok: 'The attached manifest.json is exactly the one the certificate signed.'
    },
    'Merkle inclusion proof': {
      title: 'This event is part of the sealed record',
      bad: 'This event can\u2019t be shown to be in the sealed record',
      ok: 'The event is proven to be one of the entries the checkpoint sealed.'
    }
  };

  var SUMMARY_LABEL = {
    'Period': 'Covers',
    'Checkpoints': 'Seals in range',
    'Events sealed': 'Records sealed',
    'Quiet periods': 'Quiet stretches',
    'Checkpoint': 'Checkpoint',
    'Sealed at': 'Sealed at'
  };

  var SIG_ROW = /^Checkpoint signature — /;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function niceDate(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
  }

  function niceSummaryValue(label, value) {
    if (label === 'Period') {
      var m = String(value).match(/^(\S+) to (\S+)$/);
      if (m) return niceDate(m[1]) + ' to ' + niceDate(m[2]);
    }
    if (label === 'Sealed at' || label === 'Downloaded') return niceDate(value);
    return String(value);
  }

  // Collapse the per-checkpoint signature rows into one plain row. A failing
  // checkpoint keeps its own row (id and reason) so it is never averaged away.
  function plainChecks(checks) {
    var sigs = checks.filter(function (c) { return SIG_ROW.test(c.name); });
    var rest = checks.filter(function (c) { return !SIG_ROW.test(c.name); });
    var out = [];

    rest.forEach(function (c) {
      var p = PLAIN[c.name];
      out.push({
        state: c.state,
        title: !p ? c.name : (c.state === 'fail' && p.bad) ? p.bad : p.title,
        // Passing rows get the plain sentence; failing or skipped rows keep the
        // technical reason, because that is what a researcher needs.
        text: (c.state === 'pass' && p) ? p.ok : c.detail
      });
    });

    if (sigs.length) {
      var bad = sigs.filter(function (c) { return c.state !== 'pass'; });
      if (!bad.length) {
        out.push({
          state: 'pass',
          title: 'All ' + sigs.length + ' checkpoint seals are genuine',
          text: 'Each checkpoint in the range carries a valid signature over its own contents.'
        });
      } else {
        out.push({
          state: bad.some(function (c) { return c.state === 'fail'; }) ? 'fail' : 'skip',
          title: bad.length + ' of ' + sigs.length + ' checkpoint seals did not check out',
          text: 'The others are valid. Each one that failed is listed below.'
        });
        bad.forEach(function (c) {
          out.push({ state: c.state, title: c.name.replace(SIG_ROW,
            c.state === 'fail' ? 'Seal failed on checkpoint ' : 'Seal not checked on checkpoint '), text: c.detail });
        });
      }
    }
    // Failures first, so a red row is never buried under green ones.
    var rank = { fail: 0, skip: 1, pass: 2 };
    return out.sort(function (a, b) { return rank[a.state] - rank[b.state]; });
  }

  function normFp(s) { return String(s || '').toLowerCase().replace(/[^0-9a-f]/g, ''); }

  // Authorship is a different question from integrity. The keys come from the
  // file, so a forger's own bundle passes integrity. This panel stays amber
  // until the key is matched against something the file did not supply: either
  // window.CORIQO_PUBLISHED_FINGERPRINTS (config.js) or a value the reader pastes.
  function renderAuthorship(root, keys, integrity, ownKeyPossible) {
    var published = (window.CORIQO_PUBLISHED_FINGERPRINTS || []).map(normFp);
    // Revocation has to come from outside the file: a forger controls the file's
    // own `revoked` flag and would simply leave it off.
    var revokedFps = (window.CORIQO_REVOKED_FINGERPRINTS || []).map(normFp);
    var box = el('div', 'v-verdict v-partial');
    var title = el('strong', null, 'Not yet confirmed as issued by Coriqo');
    var sub = el('span', null,
      'Everything above proves the file is consistent. It can’t prove who made it, because the ' +
      'signing key is inside the file. A forger’s file would pass the same checks. ' +
      'Match the key below against ours.');
    var idleTitle = title.textContent, idleSub = sub.textContent;
    box.appendChild(title);
    box.appendChild(sub);

    var ul = el('ul', 'v-keys');
    var fps = [];
    keys.forEach(function (k) {
      var li = el('li');
      li.appendChild(el('span', null, 'Key ' + k.key_id + (k.revoked ? ' (REVOKED)' : '')));
      var fp = el('span', 'mono v-fp', 'computing…');
      li.appendChild(fp);
      ul.appendChild(li);
      var entry = { el: fp, hex: null };
      fps.push(entry);
      window.CoriqoVerify.pemFingerprint(k.pem).then(function (hex) {
        entry.hex = hex; fp.textContent = hex; judge();
      });
    });
    box.appendChild(ul);

    var label = el('label', 'v-paste', 'Paste the fingerprint from Coriqo’s published keyring to compare:');
    var input = document.createElement('input');
    input.type = 'text'; input.className = 'mono'; input.autocomplete = 'off'; input.spellcheck = false;
    input.placeholder = '64 hex characters';
    label.appendChild(input);
    // A file that failed integrity can't be confirmed, so the comparison box would do nothing.
    // With a published list on the page the match is automatic, so the box is
    // only offered when there is nothing to compare against.
    if (integrity === 'pass' && !published.length) box.appendChild(label);

    function setState(cls, t, s) {
      box.className = 'v-verdict ' + cls;
      title.textContent = t; sub.textContent = s;
    }
    function judge() {
      var have = fps.map(function (f) { return normFp(f.hex); });
      if (have.some(function (h) { return !h; })) return;
      // Never confirm authorship of a file whose integrity checks did not all pass.
      if (integrity !== 'pass') {
        setState('v-fail', 'Authorship not assessed',
          'The integrity checks did not all pass, so this file can\u2019t be confirmed as a Coriqo record.');
        return;
      }
      var pasted = normFp(input.value);
      var against = published.length ? published : (pasted.length === 64 ? [pasted] : []);
      if (!against.length) { setState('v-partial', idleTitle, idleSub); return; }
      // A revoked key must not read as confirmed even when the fingerprint matches.
      if (keys.some(function (k) { return k.revoked; }) ||
          have.some(function (h) { return revokedFps.indexOf(h) !== -1; })) {
        setState('v-fail', 'Signed with a revoked key',
          'This key has been revoked. Don\u2019t treat the file as a current Coriqo record.');
        return;
      }
      var allMatch = have.every(function (h) { return against.indexOf(h) !== -1; });
      if (allMatch) {
        setState('v-pass', 'Confirmed as issued by Coriqo',
          (published.length
            ? 'The signing key matches Coriqo’s published key (keyring.js on this site). '
            : 'The signing key matches the fingerprint you compared it with. ') +
          'Revocation is only checked against the list this page ships with.');
      } else if (ownKeyPossible) {
        // Download receipts are signed with the organisation's own key when it
        // has one, and Coriqo does not publish those. Not confirmed, but not a
        // forgery either: say where to confirm it.
        setState('v-partial', 'Unconfirmed key: it says it is your organisation\u2019s own',
          'This key is not one Coriqo publishes. The receipt says it belongs to your organisation, but a forger could ' +
          'say the same, so treat it as unconfirmed until you check it: use Verify receipt in Coriqo, or compare the ' +
          'fingerprint above with the one your administrator holds.');
      } else {
        setState('v-fail', 'Key does NOT match Coriqo’s',
          'This file was sealed with a key Coriqo hasn’t published. It may be a test file or a forgery. ' +
          'Don’t treat it as a Coriqo record.');
      }
    }
    input.addEventListener('input', function () {
      judge();
    });
    root.appendChild(box);
    if (published.length) judge();
  }

  function renderResult(root, result, fileLabel, sha, fileBytes) {
    root.replaceChildren();

    var failed = result.checks.filter(function (c) { return c.state === 'fail'; });
    var skipped = result.checks.filter(function (c) { return c.state === 'skip'; });
    var skippedCount = skipped.length;
    var verdict = failed.length ? 'fail' : (skippedCount ? 'partial' : 'pass');
    // The only unchecked part is what a PDF gains after it is signed: the signed
    // part passed, so say exactly that rather than blaming the browser.
    var onlyAppended = verdict === 'partial' && skipped.every(function (c) { return c.appended; });

    var head = el('div', 'v-verdict v-' + verdict);
    head.className += ' has-seal';
    head.insertAdjacentHTML('beforeend',
      '<svg class="v-seal" viewBox="0 0 52 52" aria-hidden="true">' +
      '<circle class="vs-ring" cx="26" cy="26" r="22" pathLength="1"/>' +
      (verdict === 'fail' ? '<circle class="vs-frag" cx="26" cy="26" r="22" pathLength="1"/>' : '') +
      '<circle class="vs-core" cx="26" cy="26" r="5"/></svg>');
    head.appendChild(el('strong', null,
      verdict === 'pass' ? 'Unaltered since it was sealed' :
      verdict === 'fail' ? 'Not verified' :
      onlyAppended ? 'The signed part is unaltered' : 'Incomplete'));
    var cov = (result.summary || []).filter(function (r) { return r[0] === 'Events sealed'; })[0];
    var count = cov ? String(cov[1]).split(' ')[0] : null;
    head.appendChild(el('span', null,
      verdict === 'pass'
        ? (count ? count + ' records checked' : result.kind + ' checked') +
          ' on your machine, with no network call. Nothing was edited, removed or reordered.'
        : verdict === 'fail'
          ? failed.length + ' check' + (failed.length > 1 ? 's' : '') + ' failed. Don’t rely on this file.'
          : onlyAppended
            ? 'Everything the receipt signed checks out on your machine. Bytes were added after signing, which this ' +
              'page can\u2019t check, so read the signed copy below rather than the file as a viewer shows it.'
            : 'Some checks could not run in this browser, so this result is incomplete.'));
    root.appendChild(head);

    // Only offered when the receipt's own signature verified. The wording stays
    // neutral: whether Coriqo made that signature is the key panel's question.
    var receiptSig = result.checks.filter(function (c) { return c.name === 'Receipt signature'; })[0];
    if (result.signedLength && fileBytes && verdict !== 'fail' && receiptSig && receiptSig.state === 'pass') {
      var btn = el('button', 'btn btn-ghost-d v-signed-copy', 'Open the signed copy');
      btn.type = 'button';
      btn.addEventListener('click', function () {
        var blob = new Blob([fileBytes.slice(0, result.signedLength)], { type: 'application/pdf' });
        window.open(URL.createObjectURL(blob), '_blank', 'noopener');
      });
      var wrap = el('p', 'v-note');
      wrap.appendChild(btn);
      wrap.appendChild(document.createTextNode(' The first ' + result.signedLength +
        ' bytes, the part the receipt\u2019s signature covers. It is a complete PDF on its own. ' +
        'Whether Coriqo made that signature is shown in the key check below.'));
      root.appendChild(wrap);
    }

    if (result.keys && result.keys.length && result.keys[0].pem) {
      var publishedIds = window.CORIQO_PUBLISHED_KEY_IDS || [];
      // ownKeyPossible is only ever set for a receipt-only file (verifyPdf).
      var ownKey = !!result.ownKeyPossible && !result.keys.some(function (k) {
        return publishedIds.indexOf(k.key_id) !== -1;
      });
      // When only the added bytes went unchecked, everything signed passed, so
      // the key can still be judged.
      renderAuthorship(root, result.keys, onlyAppended ? 'pass' : verdict, ownKey);
    }

    var meta = el('dl', 'v-meta');
    meta.appendChild(el('dt', null, 'File'));
    meta.appendChild(el('dd', null, fileLabel));
    (result.summary || []).forEach(function (row) {
      meta.appendChild(el('dt', null, SUMMARY_LABEL[row[0]] || row[0]));
      meta.appendChild(el('dd', null, niceSummaryValue(row[0], row[1])));
    });
    root.appendChild(meta);

    (result.notes || []).forEach(function (n) { root.appendChild(el('p', 'v-note', n)); });

    var gaps = (result.summary || []).filter(function (r) { return r[0] === 'Quiet periods'; })[0];
    if (gaps && gaps[1] !== '0') {
      root.appendChild(el('p', 'v-note',
        'Quiet stretches are periods with no activity. They are recorded in the signed data, ' +
        'so they are disclosed, not hidden.'));
    }

    var list = el('ul', 'v-checks');
    plainChecks(result.checks).forEach(function (c) {
      var li = el('li', 'v-' + c.state);
      li.appendChild(el('span', 'v-tag', STATE_LABEL[c.state]));
      var body = el('div');
      body.appendChild(el('h4', null, c.title));
      body.appendChild(el('p', null, c.text));
      li.appendChild(body);
      list.appendChild(li);
    });
    root.appendChild(list);

    root.appendChild(el('p', 'v-note',
      'What this does not show: that the events were complete when they were captured. ' +
      'It shows the record was not changed after it was sealed.'));

    var tech = el('details', 'v-tech');
    tech.appendChild(el('summary', null, 'Show technical details'));
    if (sha) {
      var dl = el('dl', 'v-meta');
      dl.appendChild(el('dt', null, 'File SHA-256'));
      dl.appendChild(el('dd', 'mono', sha));
      tech.appendChild(dl);
    }
    var raw = el('ul', 'v-checks');
    result.checks.forEach(function (c) {
      var li = el('li', 'v-' + c.state);
      li.appendChild(el('span', 'v-tag', STATE_LABEL[c.state]));
      var body = el('div');
      body.appendChild(el('h4', null, c.name));
      body.appendChild(el('p', null, c.detail));
      li.appendChild(body);
      raw.appendChild(li);
    });
    tech.appendChild(raw);
    root.appendChild(tech);

    if (result.excluded && result.excluded.length) {
      // Collapsed by default, like "Show technical details": a long list of
      // excluded checkpoints otherwise pushes the verdict cards off screen.
      var ex = el('details', 'v-keynote v-tech');
      ex.appendChild(el('summary', null, 'Checkpoints excluded from linkage (' + result.excluded.length + ')'));
      // Group by reason: a package can list dozens of checkpoints excluded for
      // the same reason, so say each reason once and list its checkpoints.
      var groups = [];
      result.excluded.forEach(function (item) {
        var why = item.detail || item.reason || '';
        var g = groups.filter(function (x) { return x.why === why; })[0];
        if (!g) { g = { why: why, ids: [] }; groups.push(g); }
        g.ids.push(item.checkpoint_id);
      });
      groups.forEach(function (g) {
        ex.appendChild(el('p', null, g.why + (g.ids.length > 1 ? ' (' + g.ids.length + ' checkpoints)' : '')));
        var exUl = el('ul');
        g.ids.forEach(function (id) { exUl.appendChild(el('li', 'mono', id)); });
        ex.appendChild(exUl);
      });
      root.appendChild(ex);
    }
  }

  function renderError(root, message) {
    root.replaceChildren();
    var head = el('div', 'v-verdict v-fail');
    head.appendChild(el('strong', null, "Couldn't read that"));
    head.appendChild(el('span', null, message));
    root.appendChild(head);
  }

  function isPdfBytes(buffer) {
    var b = new Uint8Array(buffer, 0, Math.min(5, buffer.byteLength));
    return String.fromCharCode.apply(null, b) === '%PDF-';
  }

  // -------------------------------------------------------------------
  // Wiring
  // -------------------------------------------------------------------

  function init() {
    var zone = document.getElementById('verify-drop');
    var input = document.getElementById('verify-file');
    var out = document.getElementById('verify-out');
    if (!zone || !input || !out) return;

    async function handle(file) {
      out.replaceChildren();
      out.appendChild(el('p', 'v-working', 'Checking ' + file.name + ' on this machine…'));
      try {
        var buffer = await file.arrayBuffer();
        var sha = window.CoriqoVerify.bytesToHex(
          await window.CoriqoVerify.sha256(new Uint8Array(buffer)));

        var text, label = file.name, parsed = null;
        if (/\.pdf$/i.test(file.name) || isPdfBytes(buffer)) {
          // Any PDF from Coriqo: its seal when it has one, the sealed
          // deliverable's manifest binding, and the signed download receipt.
          var pdfBytes = new Uint8Array(buffer);
          var pdfResult = await window.CoriqoVerify.verifyPdf(pdfBytes);
          renderResult(out, pdfResult, file.name + ' \u2192 ' + pdfResult.fileLabel, sha, pdfBytes);
          return;
        } else if (/\.zip$/i.test(file.name)) {
          var entries = await readZip(buffer);
          var pick = null;
          ['certificate.json', 'proof.json'].forEach(function (n) {
            Object.keys(entries).forEach(function (k) {
              if (!pick && k.replace(/^.*\//, '') === n) pick = { name: k, entry: entries[k] };
            });
          });
          if (!pick) {
            var fileList = 'No certificate.json or proof.json inside that zip. It has: ' +
              Object.keys(entries).join(', ');
            var unsealedNote = await explainUnsealedZip(entries);
            throw new Error(unsealedNote ? (unsealedNote + ' ' + fileList) : fileList);
          }
          text = await entryText(pick.entry);
          label = file.name + ' → ' + pick.name;
        } else {
          text = new TextDecoder().decode(buffer);
        }

        if (!parsed) {
          try { parsed = JSON.parse(text); }
          catch (e) { throw new Error('That file is not valid JSON: ' + e.message); }
        }

        var result = await window.CoriqoVerify.verifyJson(parsed);
        renderResult(out, result, label, sha);
      } catch (e) {
        renderError(out, String(e.message || e));
      }
    }

    input.addEventListener('change', function () {
      if (input.files && input.files[0]) handle(input.files[0]);
    });

    ['dragenter', 'dragover'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) {
        e.preventDefault(); zone.classList.add('is-over');
      });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) {
        e.preventDefault(); zone.classList.remove('is-over');
      });
    });
    zone.addEventListener('drop', function (e) {
      var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) handle(f);
    });

    // The drop zone is a label for the file input, so keyboard and screen-reader
    // users get the picker without needing drag and drop at all.
    window.CoriqoVerify.hasEd25519().then(function (ok) {
      if (ok) return;
      var warn = document.getElementById('verify-ed25519-warning');
      if (warn) warn.hidden = false;
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

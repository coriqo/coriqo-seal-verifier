/*
 * In-browser Coriqo attestation verifier.
 *
 * A second implementation of seal-verifier/SPEC.md, written from the spec
 * rather than ported from tools/verify_proof.py. That is deliberate: a port
 * inherits the original's bugs, and two implementations that agree are worth
 * more than one that is trusted. Where this disagrees with verify_proof.py,
 * verify_proof.py is the reference and one of them has a bug worth reporting.
 *
 * Everything runs on the visitor's machine. Nothing is uploaded, and the page
 * makes no network request while checking a file — the honesty of the whole
 * exercise depends on that being true, so there is no fetch() in this file.
 *
 * Ed25519 comes from WebCrypto. Where a browser does not implement it the
 * signature check is reported as NOT RUN, never quietly skipped: a green verdict
 * that silently omitted the signature would be exactly the overclaim this
 * challenge exists to catch.
 */
(function (global) {
  'use strict';

  var LEAF_PREFIX = 0x00;
  var NODE_PREFIX = 0x01;

  // ---------------------------------------------------------------------
  // SPEC.md §3 — canonicalisation
  // ---------------------------------------------------------------------

  /*
   * UTF-8 bytes of JSON with keys sorted at every depth, no whitespace, and
   * non-ASCII emitted literally. Must byte-match Python's
   *   json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
   *
   * JSON.stringify already emits `,`/`:` with no padding and does not escape
   * non-ASCII, so the only thing to add is key order. Two known limits, stated
   * rather than hidden:
   *   - Array.prototype.sort orders by UTF-16 code unit and Python by code
   *     point; they differ only for non-BMP key names, which this format does
   *     not have.
   *   - Every numeric field in this format is an integer, which round-trips
   *     identically. A float would not be guaranteed to.
   */
  function canonicalBytes(obj) {
    return new TextEncoder().encode(canonicalString(obj));
  }

  function canonicalString(value) {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(canonicalString).join(',') + ']';
    var keys = Object.keys(value).sort();
    var parts = [];
    for (var i = 0; i < keys.length; i++) {
      if (value[keys[i]] === undefined) continue;
      parts.push(JSON.stringify(keys[i]) + ':' + canonicalString(value[keys[i]]));
    }
    return '{' + parts.join(',') + '}';
  }

  // ---------------------------------------------------------------------
  // Bytes and hashing
  // ---------------------------------------------------------------------

  function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
      throw new Error('not hex: ' + String(hex).slice(0, 24));
    }
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToHex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
  }

  function concat(prefix, a, b) {
    var len = 1 + a.length + (b ? b.length : 0);
    var out = new Uint8Array(len);
    out[0] = prefix;
    out.set(a, 1);
    if (b) out.set(b, 1 + a.length);
    return out;
  }

  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  }

  // SPEC.md §5.1 — leaf and node hashing, identical in both tree versions.
  async function leafHash(data) { return sha256(concat(LEAF_PREFIX, data, null)); }
  async function nodeHash(l, r) { return sha256(concat(NODE_PREFIX, l, r)); }

  function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  // ---------------------------------------------------------------------
  // SPEC.md §5 / §7 — inclusion proof walks
  // ---------------------------------------------------------------------

  // tree_version 1: duplicate-last-node. Sibling side is index parity alone,
  // and the path is always exactly bit_length(tree_size - 1) long.
  async function verifyInclusionV1(leafInputHex, leafIndex, treeSize, pathHex, rootHex) {
    if (treeSize === 0 || leafIndex < 0 || leafIndex >= treeSize) {
      return { ok: false, detail: 'leaf_index is outside a tree of ' + treeSize };
    }
    var expectedDepth = treeSize === 1 ? 0 : (treeSize - 1).toString(2).length;
    if (pathHex.length !== expectedDepth) {
      return {
        ok: false,
        detail: 'proof_path has ' + pathHex.length + ' sibling(s); a version-1 tree of ' +
          treeSize + ' leaves requires exactly ' + expectedDepth
      };
    }
    var computed = await leafHash(hexToBytes(leafInputHex));
    var idx = leafIndex;
    for (var i = 0; i < pathHex.length; i++) {
      var sib = hexToBytes(pathHex[i]);
      computed = (idx % 2 === 0) ? await nodeHash(computed, sib) : await nodeHash(sib, computed);
      idx = Math.floor(idx / 2);
    }
    return { ok: equalBytes(computed, hexToBytes(rootHex)),
             detail: 'version-1 (duplicate-last-node) tree' };
  }

  /*
   * tree_version 2: RFC 6962 §2.1.1. tree_size is threaded through the walk —
   * sn must reach exactly 0 as the path is consumed — so the size is checked by
   * the algorithm itself. A fixed proof-depth rule would be WRONG here: RFC 6962
   * path length varies by leaf index (in a 5,161-leaf tree, leaf 5160's path is
   * 4 elements where leaf 0's is 13), and applying version 1's depth rule to a
   * version-2 proof rejects honest proofs. SPEC.md rule 5.3.2.
   */
  async function verifyInclusionV2(leafInputHex, leafIndex, treeSize, pathHex, rootHex) {
    if (treeSize === 0 || leafIndex < 0 || leafIndex >= treeSize) {
      return { ok: false, detail: 'leaf_index is outside a tree of ' + treeSize };
    }
    var fn = leafIndex, sn = treeSize - 1;
    var r = await leafHash(hexToBytes(leafInputHex));
    for (var i = 0; i < pathHex.length; i++) {
      var p = hexToBytes(pathHex[i]);
      if (sn === 0) return { ok: false, detail: 'proof_path is longer than the tree is deep' };
      if (fn % 2 === 1 || fn === sn) {
        r = await nodeHash(p, r);
        while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
      } else {
        r = await nodeHash(r, p);
      }
      fn >>= 1; sn >>= 1;
    }
    if (sn !== 0) return { ok: false, detail: 'proof_path is shorter than the tree requires' };
    return { ok: equalBytes(r, hexToBytes(rootHex)), detail: 'version-2 (RFC 6962) tree' };
  }

  function treeVersionOf(sthBody) {
    // Absent means 1: every checkpoint sealed before tree_version existed used
    // the duplicating construction, and the field only appears from version 2.
    var v = (sthBody || {}).tree_version;
    return (v === undefined || v === null) ? 1 : v;
  }

  async function verifyInclusion(leafInputHex, leafIndex, treeSize, pathHex, rootHex, treeVersion) {
    if (treeVersion === 2) {
      return verifyInclusionV2(leafInputHex, leafIndex, treeSize, pathHex, rootHex);
    }
    if (treeVersion === 1) {
      return verifyInclusionV1(leafInputHex, leafIndex, treeSize, pathHex, rootHex);
    }
    return { ok: false, detail: 'unsupported tree_version ' + JSON.stringify(treeVersion) };
  }

  // ---------------------------------------------------------------------
  // SPEC.md §9 — Ed25519
  // ---------------------------------------------------------------------

  var ed25519Available = null;

  async function hasEd25519() {
    if (ed25519Available !== null) return ed25519Available;
    try {
      await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
      ed25519Available = true;
    } catch (e) {
      ed25519Available = false;
    }
    return ed25519Available;
  }

  function pemToDer(pem) {
    var body = String(pem).split(/\r?\n/)
      .filter(function (l) { return l.indexOf('-----') !== 0; })
      .join('').replace(/\s+/g, '');
    var raw = atob(body);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  // The fingerprint an examiner compares against the published keyring, so they
  // can tell "this bundle is internally consistent" from "this bundle is ours".
  async function pemFingerprint(pem) {
    try { return bytesToHex(await sha256(pemToDer(pem))); }
    catch (e) { return 'unavailable'; }
  }

  // Which algorithm a public key is for, read from its SPKI algorithm OID:
  // Ed25519 (1.3.101.112) or an EC P-256 key (1.2.840.10045.2.1) for ES256.
  // Keys in KMS or Azure Key Vault are P-256, so their seals are ES256.
  function keyAlgorithm(der) {
    if (findFrom(der, [0x06, 0x03, 0x2b, 0x65, 0x70], 0) >= 0) return 'ed25519';
    if (findFrom(der, [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], 0) >= 0) return 'es256';
    return null;
  }

  // ES256 signatures are stored DER-encoded (SEQUENCE of two INTEGERs);
  // WebCrypto wants the raw 64-byte r||s.
  function derToRawEcdsa(sig) {
    if (sig.length === 64) return sig;
    var i = 2;
    if (sig[0] !== 0x30) throw new Error('ES256 signature is not DER-encoded');
    if (sig[1] & 0x80) i = 2 + (sig[1] & 0x7f);
    function readInt() {
      if (sig[i++] !== 0x02) throw new Error('ES256 signature is malformed');
      var len = sig[i++], v = sig.subarray(i, i + len);
      i += len;
      while (v.length > 32 && v[0] === 0) v = v.subarray(1);
      if (v.length > 32) throw new Error('ES256 signature integer is too long');
      var out = new Uint8Array(32);
      out.set(v, 32 - v.length);
      return out;
    }
    var r = readInt(), s = readInt(), raw = new Uint8Array(64);
    raw.set(r, 0); raw.set(s, 32);
    return raw;
  }

  // `algorithm`, when the signed body names one, must agree with the key, the
  // way attestation.keys.verify_signature refuses a mismatch. Without it the
  // algorithm is read off the key (version-1 manifests, certificates).
  async function verifySignature(body, signatureHex, publicKeyPem, algorithm) {
    var der, alg;
    try {
      der = pemToDer(publicKeyPem);
      alg = keyAlgorithm(der);
    } catch (e) {
      return { ran: true, ok: false, error: 'the public key could not be read' };
    }
    var stated = algorithm ? String(algorithm).toLowerCase() : null;
    if (stated && alg && stated !== alg) {
      return { ran: true, ok: false, algorithm: alg,
               error: 'the signed body says ' + stated + ' but the key is ' + alg };
    }
    alg = alg || stated;
    try {
      if (alg === 'es256') {
        var ecKey = await crypto.subtle.importKey(
          'spki', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        var ecOk = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, ecKey,
          derToRawEcdsa(hexToBytes(signatureHex)), canonicalBytes(body));
        return { ran: true, ok: ecOk, algorithm: 'es256' };
      }
      if (!(await hasEd25519())) return { ran: false, ok: false, algorithm: 'ed25519' };
      var key = await crypto.subtle.importKey('spki', der, { name: 'Ed25519' }, false, ['verify']);
      var ok = await crypto.subtle.verify(
        'Ed25519', key, hexToBytes(signatureHex), canonicalBytes(body));
      return { ran: true, ok: ok, algorithm: 'ed25519' };
    } catch (e) {
      return { ran: true, ok: false, error: String(e.message || e) };
    }
  }

  // ---------------------------------------------------------------------
  // SPEC.md §7 — inclusion proof bundle
  // ---------------------------------------------------------------------

  async function checkProof(proof) {
    var checks = [];
    var sth = proof.sth_body || {};

    /*
     * SPEC.md rule 7.3.1. Everything above sth_body is unsigned. Without this
     * check a forger keeps a genuine signed body and its genuine signature and
     * supplies the root and path of a tree they built themselves — and an event
     * that was never sealed verifies as sealed.
     */
    var binding = [];
    ['merkle_root', 'tree_size'].forEach(function (f) {
      if (sth[f] === undefined || sth[f] === null) binding.push('sth_body is missing ' + f);
      else if (proof[f] !== sth[f]) {
        binding.push(f + ' in the bundle disagrees with the signed checkpoint body');
      }
    });
    checks.push({
      name: 'Bundle matches the signed checkpoint body',
      state: binding.length ? 'fail' : 'pass',
      detail: binding.length ? binding.join('; ')
        : 'merkle_root and tree_size are the values the signature covers'
    });

    var treeVersion = treeVersionOf(sth);
    if (binding.length) {
      checks.push({ name: 'Merkle inclusion proof', state: 'fail',
                    detail: 'not attempted — the bundle does not describe the checkpoint it is signed under' });
    } else {
      var res;
      try {
        res = await verifyInclusion(proof.leaf_input, proof.leaf_index,
          sth.tree_size, proof.proof_path || [], sth.merkle_root, treeVersion);
      } catch (e) {
        res = { ok: false, detail: String(e.message || e) };
      }
      checks.push({
        name: 'Merkle inclusion proof',
        state: res.ok ? 'pass' : 'fail',
        detail: res.ok
          ? 'the event hash is proven to be a leaf of the signed tree — ' + res.detail
          : 'the path does not reproduce the signed root — ' + res.detail
      });
    }

    var sig = await verifySignature(sth, proof.checkpoint_signature, proof.public_key_pem || '');
    checks.push(signatureCheck(sig, 'checkpoint', proof.key_id));

    // SPEC.md: the bundle's own issued_at is unsigned. It is only believed when
    // it equals the signed body's. A signed body with no issued_at is a failure,
    // not a pass, because there is then nothing to compare against.
    if (!sth.issued_at) {
      checks.push({ name: 'Timestamp consistency', state: 'fail',
        detail: 'the signed checkpoint body has no issued_at, so the time in the bundle cannot be checked' });
    } else if (proof.issued_at !== sth.issued_at) {
      checks.push({ name: 'Timestamp consistency', state: 'fail',
        detail: 'the bundle says ' + JSON.stringify(proof.issued_at) + ' but the signed checkpoint says ' +
          JSON.stringify(sth.issued_at) });
    } else {
      checks.push({ name: 'Timestamp consistency', state: 'pass',
        detail: 'the time in the bundle is the time inside the signed checkpoint' });
    }

    var summary = describeProof(proof, sth, treeVersion);
    var mandate = null;
    if (proof.mandate_check !== undefined) {
      try {
        mandate = await checkMandateCalls(proof.mandate_check,
          { public_key_pem: proof.public_key_pem, key_id: sth.key_id, subject: sth.subject });
      } catch (e) {
        checks.push({ name: 'Recorded tool calls against the sealed mandate', state: 'fail',
                      detail: 'the mandate_check block could not be read: ' + (e.message || e) });
      }
      if (mandate) {
        mandate.checks.forEach(function (c) { checks.push(c); });
        if (mandate.sigsSkipped) {
          checks.push(signatureCheck({ ran: false }, 'mandate and decision', proof.key_id,
                                     'Ed25519 signatures on the mandate entries'));
        }
        summary = summary.concat(mandateSummaryRows(mandate));
      }
    }

    return {
      kind: 'Inclusion proof',
      subject: sth.subject || proof.subject,
      summary: summary,
      checks: checks,
      mandate: mandate,
      keys: [{ key_id: proof.key_id, pem: proof.public_key_pem }]
    };
  }

  function describeProof(proof, sth, treeVersion) {
    return [
      ['Checkpoint', proof.checkpoint_id],
      ['Sealed at', sth.issued_at || 'not in the signed checkpoint'],
      ['Leaf', proof.leaf_index + ' of ' + sth.tree_size],
      ['Tree', 'version ' + treeVersion + (treeVersion === 1 ? ' (duplicate-last-node)' : ' (RFC 6962)')],
      ['Path length', (proof.proof_path || []).length + ' sibling hashes']
    ];
  }

  function signatureCheck(sig, label, keyId, name) {
    name = name || (sig.algorithm === 'es256' ? 'ES256 signature' : 'Ed25519 signature');
    if (!sig.ran) {
      return {
        name: name,
        state: 'skip',
        detail: 'This browser does not implement Ed25519 in WebCrypto, so the ' + label +
          ' signature was NOT checked. The result above is therefore incomplete — ' +
          'run verify_proof.py from the bundle for the full check.'
      };
    }
    return {
      name: name,
      state: sig.ok ? 'pass' : 'fail',
      detail: sig.ok
        ? 'valid over the canonical bytes of the signed body, under ' + (keyId || 'the bundle key')
        : 'the signature does not verify — the signed body has been altered' +
          (sig.error ? ' (' + sig.error + ')' : '')
    };
  }

  // ---------------------------------------------------------------------
  // SPEC.md §8 — continuity certificate
  // ---------------------------------------------------------------------

  async function checkCertificate(cert) {
    var checks = [];
    var st = cert.statement || {};
    var keys = cert.public_keys || {};
    var cps = st.checkpoints || [];

    function pemFor(keyId) {
      var entry = keys[keyId] || {};
      return { pem: entry.pem, revoked: !!entry.revoked };
    }

    // Certificate's own signature.
    var own = pemFor(cert.key_id);
    if (own.revoked) {
      checks.push({ name: 'Certificate signature', state: 'fail',
        detail: 'key ' + cert.key_id + ' is REVOKED. A revoked key must fail even when the ' +
                'signature is mathematically valid, or revocation means nothing.' });
    } else if (!own.pem) {
      checks.push({ name: 'Certificate signature', state: 'fail',
        detail: 'no public key in the bundle for key_id ' + cert.key_id });
    } else {
      var s = await verifySignature(st, cert.signature_hex, own.pem);
      checks.push(signatureCheck(s, 'certificate', cert.key_id));
    }

    // Every checkpoint under its own recorded key, one row per checkpoint —
    // lumping them into a single pass/fail line hid which checkpoint was the
    // problem behind a semicolon-joined string, while the excluded-checkpoints
    // and keys sections just below already give every checkpoint its own row.
    // Look-alike rows (here: N checkpoints) must be told apart.
    if (!cps.length) {
      checks.push({ name: 'Checkpoint signatures', state: 'fail',
                    detail: 'no checkpoints in the bundle' });
    }
    for (var i = 0; i < cps.length; i++) {
      var cp = cps[i], k = pemFor(cp.key_id);
      var label = 'Checkpoint signature — ' + (cp.checkpoint_id || '(no id)');
      if (k.revoked) {
        checks.push({ name: label, state: 'fail',
          detail: 'key ' + cp.key_id + ' is REVOKED — must not be trusted even if the signature is mathematically valid' });
        continue;
      }
      if (!k.pem) {
        checks.push({ name: label, state: 'fail',
          detail: 'no public key in the bundle for key_id ' + cp.key_id });
        continue;
      }
      var r = await verifySignature(cp.sth_body || {}, cp.signature_hex, k.pem);
      checks.push(signatureCheck(r, 'checkpoint ' + cp.checkpoint_id, cp.key_id, label));
    }

    checks.push(await checkLinkage(st, cps));
    checks.push(checkCoverage(st, cps));
    var gapHistory = await analyseGapHistory(cert, cps);
    if (gapHistory.recorded) {
      checks.push({ name: 'Sealed gap history', state: gapHistory.problems.length ? 'fail' : 'pass',
        detail: gapHistory.problems.length ? gapHistory.problems.join(' | ') : gapHistory.summary });
    }

    return {
      kind: 'Continuity certificate',
      subject: st.subject,
      summary: describeCertificate(st, cps).concat(gapHistoryRows(gapHistory)),
      checks: checks,
      gaps: st.coverage_gaps || [],
      excluded: st.excluded_checkpoints || [],
      keys: Object.keys(keys).map(function (id) {
        return { key_id: id, pem: (keys[id] || {}).pem, revoked: !!(keys[id] || {}).revoked };
      })
    };
  }

  async function checkLinkage(st, cps) {
    var links = st.linkage || [];
    var expected = Math.max(0, cps.length - 1);
    var problems = [];

    // SPEC.md rule 8.2.2 — the vacuous forgery: claim continuity, ship no links.
    if (links.length !== expected) {
      problems.push('expected ' + expected + ' link(s) for ' + cps.length +
                    ' checkpoint(s), found ' + links.length);
      links = [];
    }
    if (st.linkage_status === 'proven' && expected === 0) {
      problems.push("claims linkage 'proven' but a single checkpoint has no pair to link");
    }
    if (typeof st.links_proven === 'number' && st.links_proven > expected) {
      problems.push('claims ' + st.links_proven + ' proven link(s) but only ' + expected + ' are possible');
    }

    for (var i = 0; i < links.length; i++) {
      var link = links[i], earlier = cps[i], later = cps[i + 1];
      var eb = earlier.sth_body || {}, lb = later.sth_body || {};
      var label = (link.from_checkpoint_id || '?') + ' -> ' + (link.to_checkpoint_id || '?');

      // SPEC.md rule 8.2.1 — every value comes from the SIGNED bodies, never
      // from the link's own restatement, which a forger can make self-consistent.
      if (link.from_checkpoint_id !== earlier.checkpoint_id ||
          link.to_checkpoint_id !== later.checkpoint_id) {
        problems.push(label + ': does not join consecutive checkpoints'); continue;
      }
      if (link.sealed_head !== eb.head_hash) {
        problems.push(label + ': sealed_head disagrees with the signed body'); continue;
      }
      if (link.merkle_root !== lb.merkle_root || link.tree_size !== lb.tree_size) {
        problems.push(label + ': merkle_root/tree_size disagree with the signed body'); continue;
      }
      if (eb.length > lb.tree_size) {
        problems.push(label + ': the chain shrank between seals'); continue;
      }
      if (eb.length === 0) continue;
      if (link.leaf_index !== eb.length - 1) {
        problems.push(label + ': leaf_index does not match the signed length'); continue;
      }
      if (!link.provable) { problems.push(label + ': ' + (link.detail || 'not provable')); continue; }

      var res;
      try {
        res = await verifyInclusion(eb.head_hash, link.leaf_index, lb.tree_size,
          link.proof_path || [], lb.merkle_root, treeVersionOf(lb));
      } catch (e) { res = { ok: false, detail: String(e.message || e) }; }
      if (!res.ok) problems.push(label + ': ' + res.detail);
    }

    if (!st.linkage_unbroken) {
      (st.linkage_problems || []).forEach(function (p) { problems.push(p); });
      if (!problems.length) problems.push('the certificate does not claim unbroken linkage');
    }

    return {
      name: 'Continuity linkage',
      state: problems.length ? 'fail' : 'pass',
      detail: problems.length ? problems.join('; ')
        : links.length + ' consecutive link(s) proven against the signed roots — ' +
          'governance was continuous across the certified range'
    };
  }

  // SPEC.md §8.3 — re-derive every claim from the signed bodies.
  function checkCoverage(st, cps) {
    if (!cps.length) {
      return { name: 'Coverage claims', state: 'fail', detail: 'no checkpoints in the bundle' };
    }
    var first = cps[0].sth_body || {}, last = cps[cps.length - 1].sth_body || {};
    var cov = st.coverage || {}, problems = [];

    if (cov.sealed_event_count !== last.length) {
      problems.push("sealed_event_count does not match the closing checkpoint's signed length");
    }
    var expectedAdded = (last.length || 0) - (first.length || 0);
    if (cov.events_added_in_period !== expectedAdded) {
      problems.push('events_added_in_period claims ' + cov.events_added_in_period +
                    ', the signed lengths give ' + expectedAdded);
    }
    var opening = ((first.continuity || {}).obligations) || {};
    var closing = ((last.continuity || {}).obligations) || {};
    Object.keys(cov.obligations_in_period || {}).forEach(function (k) {
      var o = opening[k], c = closing[k];
      var exp = (typeof o === 'number' && typeof c === 'number') ? c - o : null;
      if (cov.obligations_in_period[k] !== exp) {
        problems.push("obligation '" + k + "' claims " + cov.obligations_in_period[k] +
                      ', the signed bodies give ' + exp);
      }
    });
    Object.keys(cov.obligations_closing || {}).forEach(function (k) {
      if (cov.obligations_closing[k] !== closing[k]) {
        problems.push("cumulative obligation '" + k + "' claims " + cov.obligations_closing[k] +
                      ', the closing signed body gives ' + closing[k]);
      }
    });
    var sealedGaps = ((last.continuity || {}).coverage_gaps) || [];
    var sealedKeys = {};
    sealedGaps.forEach(function (g) { sealedKeys[g.from + '|' + g.to] = true; });
    (st.coverage_gaps || []).forEach(function (g) {
      if (!sealedKeys[g.from + '|' + g.to]) {
        problems.push('reported gap ' + g.from + ' -> ' + g.to + ' is not in the signed record');
      }
    });

    return {
      name: 'Coverage claims',
      state: problems.length ? 'fail' : 'pass',
      detail: problems.length ? problems.join('; ')
        : 'every coverage and gap claim is backed by a signed checkpoint body'
    };
  }

  // SPEC.md §8.5 — sealed gap history. Mirrors verify_proof.py
  // _analyse_gap_history line for line, failure strings included: an auditor
  // reads them, and the parity tests compare the two verifiers on the same bytes.
  //
  //   root_0 = sha256(b"")  (hex)
  //   root_n = sha256(root_{n-1} || event_hash_n)   (raw bytes, hex out)
  //   event_hash = sha256(canonical JSON of the event minus `event_hash`)
  //
  // The age of an open gap is the `at` of the 'opened' event that opened it,
  // replayed from the committed history; the signed `opened_at` must equal it.

  var GAP_MAX_SEQ = 9007199254740991;
  var GAP_KINDS = ['opened', 'closed', 'waived'];
  var GAP_TIME_FORM = 'YYYY-MM-DDTHH:MM:SS[.ffffff]Z';
  var GAP_AT_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{6}))?Z$/;
  // The checkpoint's own `issued_at` is isoformat() of a UTC datetime: "+00:00".
  var GAP_ISSUED_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{6}))?(?:Z|\+00:00)$/;
  var GAP_LIMIT_MALFORMED = 'the signed age limit is malformed';

  function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
  function isInt(v) { return typeof v === 'number' && isFinite(v) && Math.floor(v) === v; }
  function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }

  // Strings sort by code point, as Python sorts them.
  function cpCompare(a, b) {
    var x = Array.from(a), y = Array.from(b), n = Math.min(x.length, y.length);
    for (var i = 0; i < n; i++) {
      var p = x[i].codePointAt(0), q = y[i].codePointAt(0);
      if (p !== q) return p < q ? -1 : 1;
    }
    return x.length - y.length;
  }

  // A lone surrogate cannot be written as UTF-8, so Python cannot canonicalise it.
  function hasLoneSurrogate(value) {
    if (typeof value === 'string') {
      for (var i = 0; i < value.length; i++) {
        var c = value.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
          var d = value.charCodeAt(i + 1);
          if (d >= 0xdc00 && d <= 0xdfff) i++; else return true;
        } else if (c >= 0xdc00 && c <= 0xdfff) {
          return true;
        }
      }
      return false;
    }
    if (Array.isArray(value)) return value.some(hasLoneSurrogate);
    if (isObj(value)) {
      return Object.keys(value).some(function (k) { return hasLoneSurrogate(k) || hasLoneSurrogate(value[k]); });
    }
    return false;
  }

  async function gapEventHash(ev) {
    var body = {};
    Object.keys(ev).forEach(function (k) { if (k !== 'event_hash') body[k] = ev[k]; });
    return bytesToHex(await sha256(canonicalBytes(body)));
  }

  // roots[n] is the root after n events; roots[0] is the hash of nothing.
  async function gapRootChain(hashes) {
    var roots = [bytesToHex(await sha256(new Uint8Array(0)))];
    for (var i = 0; i < hashes.length; i++) {
      var prev = hexToBytes(roots[roots.length - 1]), h = hexToBytes(hashes[i]);
      var joined = new Uint8Array(prev.length + h.length);
      joined.set(prev, 0); joined.set(h, prev.length);
      roots.push(bytesToHex(await sha256(joined)));
    }
    return roots;
  }

  function daysFromCivil(y, m, d) {
    y -= m <= 2 ? 1 : 0;
    var era = Math.floor(y / 400), yoe = y - era * 400;
    var doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
    return era * 146097 + yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  }

  // [seconds, microseconds] for the one accepted spelling, else null. Only
  // differences and equality are used.
  function gapTime(value, issued) {
    if (typeof value !== 'string') return null;
    var m = (issued ? GAP_ISSUED_RE : GAP_AT_RE).exec(value);
    if (!m) return null;
    var y = +m[1], mo = +m[2], d = +m[3], h = +m[4], mi = +m[5], s = +m[6];
    var leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
    var dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
    if (y < 1 || mo < 1 || mo > 12 || d < 1 || d > dim || h > 23 || mi > 59 || s > 59) return null;
    return [daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s, m[7] ? +m[7] : 0];
  }

  function sameTime(a, b) { return a[0] === b[0] && a[1] === b[1]; }
  function cmpTime(a, b) { return a[0] - b[0] || a[1] - b[1]; }

  function gapMicrosBetween(later, earlier) {
    return (BigInt(later[0]) - BigInt(earlier[0])) * 1000000n + BigInt(later[1] - earlier[1]);
  }

  // Hours to one decimal, rounded half to even on the exact value.
  function gapHoursText(micros) {
    var unit = 360000000n, q = micros / unit, r = micros % unit;
    if (2n * r > unit || (2n * r === unit && q % 2n === 1n)) q += 1n;
    return (q / 10n).toString() + '.' + (q % 10n).toString();
  }

  function gapNumberText(v) { return String(v); }

  function gapValidDevice(v) { return typeof v === 'string' && v !== ''; }

  // null when both are whole numbers in 0..2^53-1 with start <= end.
  function gapSeqProblem(start, end) {
    if (!isInt(start) || start < 0 || !isInt(end) || end < 0) return 'no valid sequence range';
    if (start > GAP_MAX_SEQ || end > GAP_MAX_SEQ) {
      return 'a sequence number above ' + GAP_MAX_SEQ + ', which this verifier cannot check exactly';
    }
    if (start > end) return 'no valid sequence range';
    return null;
  }

  // Everything that must hold of one event before it can be hashed or replayed.
  // When any fails, the rest of the check does not run.
  function gapStructureProblems(events) {
    var problems = [];
    events.forEach(function (ev, idx) {
      var i = idx + 1;
      if (!gapValidDevice(ev.device_id)) problems.push('gap event ' + i + ' has no valid device');
      var bad = gapSeqProblem(ev.seq_start, ev.seq_end);
      if (bad) problems.push('gap event ' + i + ' has ' + bad);
      if (!(typeof ev.event === 'string' && GAP_KINDS.indexOf(ev.event) >= 0)) {
        problems.push('gap event ' + i + ' has an unknown event type (expected opened, closed or waived)');
      }
      if (gapTime(ev.at, false) === null) {
        problems.push('gap event ' + i + ' has a time that is not RFC 3339 UTC (' + GAP_TIME_FORM + ')');
      }
      var body = {};
      Object.keys(ev).forEach(function (k) { if (k !== 'event_hash') body[k] = ev[k]; });
      if (hasLoneSurrogate(body)) problems.push('gap event ' + i + ' cannot be canonicalised');
    });
    return problems;
  }

  // Replay the events. A closed or waived range must sit inside one range that
  // is open at that moment; it may narrow it (the rest stays open and keeps the
  // time its 'opened' event was recorded). Each open range is [start, end, openedAt].
  function deriveOpenRanges(events, problems) {
    var byDevice = new Map();
    events.forEach(function (ev, idx) {
      var device = ev.device_id, kind = ev.event, start = ev.seq_start, end = ev.seq_end;
      var where = 'gap event ' + (idx + 1) + ' (device ' + device + ', #' + start + '-#' + end + ')';
      if (!byDevice.has(device)) byDevice.set(device, []);
      var ranges = byDevice.get(device);
      if (kind === 'opened') {
        ranges.push([start, end, gapTime(ev.at, false)]);
        return;
      }
      var at = -1;
      for (var i = 0; i < ranges.length; i++) {
        if (ranges[i][0] <= start && end <= ranges[i][1]) { at = i; break; }
      }
      if (at < 0) {
        problems.push(where + ' is recorded as ' + kind + ', but no earlier \'opened\' event covers that ' +
          'range and leaves it open. A gap cannot be closed that was never opened.');
        return;
      }
      var host = ranges.splice(at, 1)[0];
      if (host[0] < start) ranges.push([host[0], start - 1, host[2]]);
      if (end < host[1]) ranges.push([end + 1, host[1], host[2]]);
    });
    return byDevice;
  }

  function gapShow(ranges) {
    return ranges.map(function (r) { return '#' + r[0] + '-#' + r[1]; }).join(', ') || 'none';
  }

  function gapVersionScoped(body) {
    return typeof body.subject === 'string' && body.subject.indexOf('version:') === 0;
  }

  // The signed open gaps as an array, or null when they are malformed.
  function gapSignedOpenGaps(final) {
    var gaps = final.open_gaps;
    if (gaps === undefined || gaps === null) return [];
    if (!Array.isArray(gaps)) return null;
    for (var i = 0; i < gaps.length; i++) {
      var g = gaps[i];
      if (!isObj(g) || !gapValidDevice(g.device_id) || gapSeqProblem(g.seq_start, g.seq_end)) return null;
    }
    return gaps;
  }

  // {limit, malformed}; limit is null when the checkpoint signs none.
  function gapAgeLimit(body) {
    if (!has(body, 'completeness_policy')) return { limit: null, malformed: false };
    var policy = body.completeness_policy;
    if (!isObj(policy)) return { limit: null, malformed: true };
    if (!has(policy, 'max_open_gap_hours')) return { limit: null, malformed: false };
    var v = policy.max_open_gap_hours;
    if (typeof v !== 'number' || !isFinite(v) || v <= 0 || !isFinite(v * 3600000000)) {
      return { limit: null, malformed: true };
    }
    return { limit: v, malformed: false };
  }

  async function analyseGapHistory(cert, cps) {
    cps = cps.filter(isObj);
    function bodyOf(cp) { return isObj(cp.sth_body) ? cp.sth_body : {}; }
    var recorded = [];
    cps.forEach(function (cp) {
      var c = bodyOf(cp).completeness;
      if (c !== undefined && c !== null) recorded.push({ cp: cp, comp: c });
    });
    if (!recorded.length) return { recorded: false, problems: [], findings: [], summary: '' };

    var problems = [], findings = [];
    var events = cert.gap_events;
    if (!Array.isArray(events) || !events.every(isObj)) {
      return { recorded: true, summary: '', findings: [], problems: [
        'a checkpoint signs a gap history, but the bundle carries no list of gap events to check it against'] };
    }
    var structure = gapStructureProblems(events);
    if (structure.length) return { recorded: true, summary: '', findings: [], problems: structure };

    // (a) every event hashes to its stated hash; the chain reproduces each signed root.
    var hashes = [];
    for (var i = 0; i < events.length; i++) {
      var expected = await gapEventHash(events[i]);
      if (events[i].event_hash !== expected) {
        problems.push('gap event ' + (i + 1) + ' was changed after it was recorded: its stored hash does ' +
          'not match its contents');
      }
      hashes.push(expected);
    }
    var roots = await gapRootChain(hashes);

    var previous = -1;
    recorded.forEach(function (r) {
      var which = 'checkpoint ' + (r.cp.checkpoint_id === undefined ? 'None' : r.cp.checkpoint_id);
      if (!isObj(r.comp)) { problems.push(which + ' has a malformed completeness block'); return; }
      var count = r.comp.gap_event_count, root = r.comp.gap_events_root;
      if (!isInt(count) || count < 0 || typeof root !== 'string' || !/^[0-9a-f]{64}$/.test(root)) {
        problems.push(which + ' has no valid gap event count and root'); return;
      }
      if (count < previous) {
        problems.push(which + ' signs ' + count + ' gap event(s), fewer than an earlier checkpoint signed (' +
          previous + '). The gap history only grows; events were removed.');
      }
      previous = Math.max(previous, count);
      if (count > events.length) {
        problems.push(which + ' signed ' + count + ' gap event(s) but the bundle carries only ' + events.length +
          '. Gap events were removed from the bundle.');
      } else if (roots[count] !== root) {
        problems.push('the first ' + count + ' gap event(s) do not reproduce the root signed in ' + which +
          '. The gap history was altered, reordered or had events deleted.');
      }
    });

    // Once a checkpoint signs a gap history, every later org-wide checkpoint must. A
    // version-scoped checkpoint (subject "version:<id>") never carries one.
    var seen = false;
    cps.forEach(function (cp) {
      var body = bodyOf(cp);
      if (body.completeness !== undefined && body.completeness !== null) seen = true;
      else if (seen && !gapVersionScoped(body)) {
        problems.push('a later checkpoint no longer records the gap history: checkpoint ' +
          (cp.checkpoint_id === undefined || cp.checkpoint_id === null ? 'None' : cp.checkpoint_id));
      }
    });
    var orgWide = cps.filter(function (cp) { return !gapVersionScoped(bodyOf(cp)); });
    var closing = bodyOf((orgWide.length ? orgWide : cps)[orgWide.length ? orgWide.length - 1 : cps.length - 1]);
    var final = closing.completeness;
    if (!isObj(final)) return { recorded: true, problems: problems, findings: findings, summary: '' };
    if (isInt(final.gap_event_count) && events.length > final.gap_event_count) {
      problems.push('the bundle carries ' + events.length + ' gap event(s) but the closing checkpoint signed ' +
        'only ' + final.gap_event_count + '. Events after the signed head are not sealed.');
    }

    // (b) replay, then compare with the open gaps the closing checkpoint signed.
    var derivedMap = deriveOpenRanges(events, problems);
    var derived = new Map();
    derivedMap.forEach(function (rs, device) {
      if (rs.length) {
        derived.set(device, rs.slice().sort(function (a, b) { return a[0] - b[0] || a[1] - b[1] || cmpTime(a[2], b[2]); }));
      }
    });
    var signed = gapSignedOpenGaps(final);
    if (signed === null) {
      problems.push('the signed open gaps contain a malformed range');
    } else {
      var claimed = new Map();
      signed.forEach(function (g) {
        if (!claimed.has(g.device_id)) claimed.set(g.device_id, []);
        claimed.get(g.device_id).push(g);
      });
      var devices = [];
      derived.forEach(function (_, d) { devices.push(d); });
      claimed.forEach(function (_, d) { if (!derived.has(d)) devices.push(d); });
      devices.sort(cpCompare).forEach(function (device) {
        var a = derived.get(device) || [];
        var b = (claimed.get(device) || []).slice().sort(function (x, y) {
          return x.seq_start - y.seq_start || x.seq_end - y.seq_end ||
            cmpTime(gapTime(x.opened_at, false) || [-1, 0], gapTime(y.opened_at, false) || [-1, 0]);
        });
        var aKey = a.map(function (r) { return r[0] + '-' + r[1]; }).join(',');
        var bKey = b.map(function (g) { return g.seq_start + '-' + g.seq_end; }).join(',');
        if (aKey !== bKey) {
          problems.push('device ' + device + ': the signed open gaps (' +
            gapShow(b.map(function (g) { return [g.seq_start, g.seq_end]; })) + ') do not match the gaps ' +
            'still open after replaying the events (' + gapShow(a) + ')');
          return;
        }
        a.forEach(function (r, k) {
          var name = 'device ' + device + ' #' + r[0] + '-#' + r[1];
          var opened = gapTime(b[k].opened_at, false);
          if (opened === null) {
            problems.push('open gap ' + name + ': the age of an open gap cannot be worked out, because its ' +
              'signed opened_at is missing or not in the form ' + GAP_TIME_FORM);
          } else if (!sameTime(opened, r[2])) {
            problems.push('open gap ' + name + ': the signed opened_at does not match the time its ' +
              '\'opened\' event was recorded');
          }
        });
      });
    }

    // (c) age, from the recorded time of the 'opened' event, measured at the closing
    // checkpoint's own signed time.
    var lim = gapAgeLimit(closing);
    if (lim.malformed) problems.push(GAP_LIMIT_MALFORMED);
    var issued = gapTime(closing.issued_at, true);
    var openCount = 0;
    var order = [];
    derived.forEach(function (_, d) { order.push(d); });
    order.forEach(function (device) {
      derived.get(device).forEach(function (r) {
        openCount++;
        var name = 'device ' + device + ' #' + r[0] + '-#' + r[1];
        if (issued === null) {
          problems.push('open gap ' + name + ': the age of an open gap cannot be worked out, because the closing ' +
            'checkpoint\'s issued_at is missing or not a UTC time');
          return;
        }
        var micros = gapMicrosBetween(issued, r[2]);
        if (micros < 0n) {
          problems.push('open gap ' + name + ' was opened after the closing checkpoint was issued');
          return;
        }
        var age = gapHoursText(micros);
        if (lim.malformed) return;
        if (lim.limit === null) {
          findings.push('open gap ' + name + ': open ' + age + ' hours. The checkpoint records no age ' +
            'limit, so this is reported but not failed');
        } else if (Number(micros) > lim.limit * 3600000000) {
          problems.push('open gap ' + name + ' has been open ' + age + ' hours, longer than the ' +
            gapNumberText(lim.limit) + ' hours the signed policy allows');
        } else {
          findings.push('open gap ' + name + ': open ' + age + ' hours, within the ' +
            gapNumberText(lim.limit) + ' hour limit');
        }
      });
    });

    return { recorded: true, problems: problems, findings: findings,
      summary: events.length + ' gap event(s) reproduce the signed root; ' + openCount + ' gap(s) still open' };
  }

  // One check only when a checkpoint signs a gap history. A certificate with
  // none gets no pass and no fail, so a summary row says "not recorded".
  function gapHistoryRows(analysis) {
    if (!analysis.recorded) {
      return [['Sealed gap history', 'not recorded. No checkpoint in this certificate signs a gap history, ' +
        'so nothing here can be said about gaps that were opened and later closed.']];
    }
    var rows = analysis.findings.map(function (f) { return ['Sealed gap history', f]; });
    if (!rows.length) {
      rows.push(['Sealed gap history', analysis.problems.length
        ? 'this check failed, so what it says about open gaps is not shown. The failed check below says why.'
        : 'no gap is open']);
    }
    return rows;
  }

  function describeCertificate(st, cps) {
    var period = st.period || {};
    var cov = st.coverage || {};
    return [
      ['Period', (period.from || '?') + ' to ' + (period.to || '?')],
      ['Checkpoints', String(cps.length)],
      ['Events sealed', String(cov.sealed_event_count) + ' (' + cov.events_added_in_period + ' added in period)'],
      ['Quiet periods', String((st.gap_summary || {}).total || 0)]
    ];
  }

  // ---------------------------------------------------------------------
  // Entry point
  // ---------------------------------------------------------------------

  // SPEC.md §12.1: a file's spec_version ("MAJOR.MINOR", absent = 1.0) decides
  // whether this checker runs at all. A different major can change what a field
  // means, so it is refused, never given a verdict.
  var SPEC_MAJOR = 1;
  // ---------------------------------------------------------------------
  // SPEC.md §19 — recorded tool calls against the sealed mandate
  // ---------------------------------------------------------------------

  var MANDATE_SNAPSHOT_ACTION = 'mandate_snapshot';
  var MANDATE_DOC_SPEC = 'coriqo.mandate/v1';

  async function contentHash(value) {
    return bytesToHex(await sha256(canonicalBytes(value)));
  }

  // The event hash, recomputed the way the server makes it (the field set the
  // reference verifier's _event_hash_of uses): never the stored event_hash.
  async function eventHashOf(ev) {
    var hashable = {
      seq: ev.seq, actor: ev.actor, action: ev.action, model_version_id: ev.version_id,
      from_status: ev.from_status, to_status: ev.to_status, notes: ev.notes, prev_hash: ev.prev_hash
    };
    ['seq', 'actor', 'action', 'model_version_id', 'from_status', 'to_status', 'notes', 'prev_hash']
      .forEach(function (k) { if (hashable[k] === undefined) hashable[k] = null; });
    if (ev.oversight !== undefined && ev.oversight !== null) hashable.oversight = ev.oversight;
    return contentHash(hashable);
  }

  function sealedNotes(ev) {
    var notes = JSON.parse(ev.notes);
    if (!notes || typeof notes !== 'object' || Array.isArray(notes)) {
      throw new Error('the sealed event\u2019s notes are not a JSON object');
    }
    return notes;
  }

  function isNameList(v) {
    return Array.isArray(v) && v.every(function (t) { return typeof t === 'string'; });
  }

  // §19.3 step 1: (allowed, prohibited) from a normalised mandate document.
  function mandateTools(doc) {
    if (!doc || typeof doc !== 'object' || doc.spec !== MANDATE_DOC_SPEC) {
      throw new Error('the sealed document is not a ' + MANDATE_DOC_SPEC + ' mandate');
    }
    var tools = doc.tools;
    if (!tools || typeof tools !== 'object') throw new Error('the sealed mandate has no tools block');
    if (tools.allowed !== null && tools.allowed !== undefined && !isNameList(tools.allowed)) {
      throw new Error('tools.allowed in the sealed mandate is not a list of names or null');
    }
    if (!isNameList(tools.prohibited)) {
      throw new Error('tools.prohibited in the sealed mandate is not a list of names');
    }
    return { allowed: tools.allowed === undefined ? null : tools.allowed, prohibited: tools.prohibited };
  }

  // §19.4: each recorded call the mandate does not permit.
  function callsOutsideMandate(toolCalls, allowed, prohibited) {
    var out = [];
    (toolCalls || []).forEach(function (call) {
      if (!call || typeof call !== 'object' || !call.tool) return;
      var name = String(call.tool);
      if (prohibited.indexOf(name) !== -1) out.push({ step: call.step, tool: name, why: 'prohibited' });
      else if (allowed !== null && allowed.indexOf(name) === -1) {
        out.push({ step: call.step, tool: name, why: 'not on the allowed list' });
      }
    });
    return out;
  }

  function countCalls(toolCalls) {
    return (toolCalls || []).filter(function (c) { return c && typeof c === 'object' && c.tool; }).length;
  }

  // One {event, proof}: the named action, re-hashes to its event_hash, and is a
  // leaf under a signed checkpoint. Returns the problems (empty when all hold)
  // and whether the signature check ran.
  function samePem(a, b) {
    var norm = function (p) { return String(p || '').replace(/\s+/g, ''); };
    return norm(a) !== '' && norm(a) === norm(b);
  }

  async function checkSealedEntry(entry, action, outer) {
    var ev = entry.event || {};
    var proof = entry.proof || {};
    var sth = proof.sth_body || {};
    var problems = [];
    var id = 'event ' + ev.event_id;
    // The page shows one key, the outer proof's, and says whether it is
    // Coriqo's. An entry signed under any other key would borrow that verdict,
    // so it must be the same key.
    if (!samePem(proof.public_key_pem, outer.public_key_pem) || sth.key_id !== outer.key_id) {
      problems.push(id + ': signed under a different key than this file\u2019s checkpoint');
    }
    // Fail closed: the entry's checkpoint covers this file's log or the event's
    // own version, and nothing else (a missing subject included).
    var nonEmpty = function (v) { return typeof v === 'string' && v !== ''; };
    var ownLog = nonEmpty(sth.subject) && nonEmpty(outer.subject) && sth.subject === outer.subject;
    var ownVersion = nonEmpty(sth.subject) && sth.subject === 'version:' + ev.version_id;
    if (!ownLog && !ownVersion) {
      problems.push(id + ': its checkpoint covers ' + JSON.stringify(sth.subject) +
        ', not this file\u2019s log or the event\u2019s own version');
    }
    if (ev.action !== action) problems.push(id + ' is not a ' + action + ' event');
    if ((await eventHashOf(ev)) !== ev.event_hash) problems.push(id + ' does not re-hash to its event_hash');
    if (proof.event_id !== ev.event_id) problems.push(id + ': the proof is for a different event');
    if (proof.leaf_input !== ev.event_hash) problems.push(id + ': leaf_input is not this event\u2019s event_hash');
    ['merkle_root', 'tree_size'].forEach(function (f) {
      if (sth[f] === undefined || sth[f] === null || proof[f] !== sth[f]) {
        problems.push(id + ': ' + f + ' in the proof disagrees with the signed checkpoint body');
      }
    });
    if (proof.key_id !== undefined && proof.key_id !== null && proof.key_id !== sth.key_id) {
      problems.push(id + ': the proof names a different key than the signed body');
    }
    if (problems.length) return { problems: problems, sigRan: true };
    var inc;
    try {
      inc = await verifyInclusion(proof.leaf_input, proof.leaf_index, sth.tree_size,
        proof.proof_path || [], sth.merkle_root, treeVersionOf(sth));
    } catch (e) { inc = { ok: false }; }
    if (!inc.ok) problems.push(id + ': the Merkle path does not lead from this event to the signed root');
    var sig = await verifySignature(sth, proof.checkpoint_signature, proof.public_key_pem || '');
    if (sig.ran && !sig.ok) problems.push(id + ': the checkpoint signature does not verify');
    return { problems: problems, sigRan: sig.ran };
  }

  // The first ten numbers missing between the lowest and highest, from the
  // sorted distinct numbers, never by walking the range: a file can name
  // decision 1 and decision 1e12.
  function missingNumbers(seqs) {
    var uniq = seqs.filter(function (s, k) { return seqs.indexOf(s) === k; })
      .sort(function (a, b) { return a - b; });
    var missing = [];
    for (var k = 1; k < uniq.length; k++) {
      for (var n = uniq[k - 1] + 1; n < uniq[k]; n++) {
        if (missing.length === 10) return { missing: missing, more: true };
        missing.push(n);
      }
    }
    return { missing: missing, more: false };
  }

  async function checkMandateCalls(block, outer) {
    if (!block || typeof block !== 'object' || Array.isArray(block)) {
      throw new Error('mandate_check is not an object');
    }
    var checks = [];
    var mandateEntries = block.mandates || [];
    var decisionEntries = block.decisions || [];
    var mandates = {};
    var seenEvents = {};
    var seenTraces = {};
    var verified = 0;
    var sigsSkipped = 0;

    for (var i = 0; i < mandateEntries.length; i++) {
      var me = mandateEntries[i];
      var r = await checkSealedEntry(me, MANDATE_SNAPSHOT_ACTION, outer);
      var meId = (me.event || {}).event_id;
      if (seenEvents[meId]) r.problems.push('event ' + meId + ' appears more than once in this file');
      seenEvents[meId] = true;
      if (!r.sigRan) sigsSkipped++;
      var notes = {};
      try { notes = sealedNotes(me.event || {}); } catch (e) { r.problems.push(e.message); }
      var sha = notes.mandate_sha256;
      var tools = { allowed: null, prohibited: [] };
      try { tools = mandateTools(notes.document); } catch (e) { r.problems.push(e.message); }
      if ((await contentHash(notes.document === undefined ? null : notes.document)) !== sha) {
        r.problems.push('the sealed mandate document does not hash to its mandate_sha256');
      }
      var label = 'Sealed mandate ' + String(sha).slice(0, 12);
      if (r.problems.length) {
        checks.push({ name: label, state: 'fail', detail: r.problems.join('; ') });
        continue;
      }
      verified++;
      mandates[sha] = { allowed: tools.allowed, prohibited: tools.prohibited,
                        version_id: me.event.version_id, agent_id: notes.agent_id };
      checks.push({ name: label, state: 'pass',
        detail: 'agent ' + notes.agent_id + ': ' +
          (tools.allowed === null ? 'no allow-list' : tools.allowed.length + ' allowed') + ', ' +
          tools.prohibited.length + ' prohibited; the document hashes to the sealed value and its event ' +
          'is under a signed checkpoint' });
    }

    var decisions = [];
    for (var j = 0; j < decisionEntries.length; j++) {
      var de = decisionEntries[j];
      var rd = await checkSealedEntry(de, 'agent_decision', outer);
      var deId = (de.event || {}).event_id;
      // A repeated decision would count its calls twice.
      if (seenEvents[deId]) rd.problems.push('event ' + deId + ' appears more than once in this file');
      if (seenTraces[de.trace_id]) rd.problems.push('decision ' + de.trace_id + ' appears more than once in this file');
      seenEvents[deId] = true;
      seenTraces[de.trace_id] = true;
      if (!rd.sigRan) sigsSkipped++;
      var dn = {};
      try { dn = sealedNotes(de.event || {}); } catch (e) { rd.problems.push(e.message); }
      if (dn.trace_id !== de.trace_id) rd.problems.push('the sealed event names a different decision');
      if (de.tool_calls !== null && de.tool_calls !== undefined && 'tool_calls_hash' in dn &&
          dn.tool_calls_hash !== (await contentHash(de.tool_calls))) {
        rd.problems.push('the tool calls differ from what was sealed (changed, added, removed or reordered)');
      }
      if (rd.problems.length) {
        checks.push({ name: 'Decision ' + de.trace_id, state: 'fail', detail: rd.problems.join('; ') });
        continue;
      }
      verified++;
      decisions.push({ trace_id: de.trace_id, tool_calls: de.tool_calls, event: de.event, notes: dn });
    }

    var calls = 0;
    var outside = [];
    var skipped = { unstamped: [], unmatched: [], unhashed: [] };
    decisions.forEach(function (d) {
      var n = d.notes;
      if (d.tool_calls === null || d.tool_calls === undefined || !('tool_calls_hash' in n)) {
        skipped.unhashed.push(d.trace_id); return;
      }
      if (n.mandate_sha256 === undefined || n.mandate_sha256 === null) { skipped.unstamped.push(d.trace_id); return; }
      var m = mandates[n.mandate_sha256];
      if (!m || m.version_id !== d.event.version_id || ('agent_id' in n && m.agent_id !== n.agent_id)) {
        skipped.unmatched.push(d.trace_id); return;
      }
      calls += countCalls(d.tool_calls);
      callsOutsideMandate(d.tool_calls, m.allowed, m.prohibited).forEach(function (o) {
        outside.push({ trace_id: d.trace_id, step: o.step, tool: o.tool, why: o.why });
      });
    });

    // §19.3 step 4: repeated numbers fail; missing ones are gaps.
    var byVersion = {};
    decisions.forEach(function (d) {
      var seq = d.notes.decision_seq;
      if (typeof seq === 'number' && Math.floor(seq) === seq) {
        var v = String(d.event.version_id);
        (byVersion[v] = byVersion[v] || []).push(seq);
      }
    });
    var gaps = [];
    Object.keys(byVersion).sort().forEach(function (v) {
      var seqs = byVersion[v];
      var dupes = seqs.filter(function (s, k) { return seqs.indexOf(s) !== k; })
        .filter(function (s, k, a) { return a.indexOf(s) === k; }).sort(function (a, b) { return a - b; });
      if (dupes.length) {
        checks.push({ name: 'Decision numbers on ' + v, state: 'fail',
                      detail: 'two sealed decisions carry the same number: ' + dupes.join(', ') });
      }
      var g = missingNumbers(seqs);
      if (g.missing.length) gaps.push(v + ': #' + g.missing.join(', #') + (g.more ? ' and more' : ''));
    });

    var notCovered = [];
    [['unstamped', 'recorded before decisions named the mandate they ran under'],
     ['unmatched', 'the file carries no verified sealed mandate with the hash they name'],
     ['unhashed', 'their tool calls were purged, or were not part of the seal when recorded']
    ].forEach(function (pair) {
      var ids = skipped[pair[0]];
      if (ids.length) {
        notCovered.push(ids.length + ' decision(s) not checked (' + ids.slice(0, 5).join(', ') +
          (ids.length > 5 ? ', \u2026' : '') + '): ' + pair[1]);
      }
    });

    return {
      checks: checks,
      decisions: decisions.length,
      calls: calls,
      outside: outside,
      gaps: gaps,
      notCovered: notCovered,
      signatures: [verified, mandateEntries.length + decisionEntries.length],
      sigsSkipped: sigsSkipped,
      line: outside.length + ' of ' + calls + ' recorded tool calls fell outside the sealed mandate'
    };
  }

  // §19.5: the rows the page shows under the result.
  function mandateSummaryRows(m) {
    var rows = [
      ['Decisions checked', String(m.decisions)],
      ['Mandate', m.line]
    ];
    m.outside.slice(0, 50).forEach(function (o) {
      rows.push(['Outside the mandate', 'decision ' + o.trace_id + ', step ' + o.step + ', tool ' +
        o.tool + ' (' + o.why + ')']);
    });
    if (m.outside.length > 50) rows.push(['Outside the mandate', '\u2026 and ' + (m.outside.length - 50) + ' more']);
    rows.push(['Sequence gaps', m.gaps.length ? m.gaps.join('; ') : 'none among the decisions in this file']);
    m.notCovered.forEach(function (t) { rows.push(['Not checked', t]); });
    return rows;
  }

  function specVersionProblem(obj) {
    if (!obj || typeof obj !== 'object' || !('spec_version' in obj)) return null;
    var v = obj.spec_version;
    if (typeof v !== 'string' || !/^\d+\.\d+$/.test(v)) {
      return 'Its spec_version (' + JSON.stringify(v) + ') is not in the MAJOR.MINOR form, so this page can\u2019t tell which rules apply.';
    }
    if (parseInt(v, 10) !== SPEC_MAJOR) {
      return 'This file was written to spec version ' + v + ', and this page checks spec version 1.x. ' +
        'A new major version can change what a field means, so the file was not checked. ' +
        'Use a newer verifier from github.com/coriqo/coriqo-seal-verifier.';
    }
    return null;
  }

  // ---------------------------------------------------------------------
  // PDFs: attachments, the deliverable binding, and the download receipt
  // ---------------------------------------------------------------------

  // Every JSON object carried in a PDF stream, compressed (FlateDecode, how
  // WeasyPrint writes certificate.json and manifest.json) or not (how pypdf
  // writes the download receipt). No PDF parser: find each stream, inflate it
  // if it is compressed, keep it if it parses as a JSON object. `bytes` is the
  // stream's exact content, so it can be hashed against a signed binding.
  async function inflateBytes(bytes) {
    var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  function asJsonObject(bytes) {
    var k = 0;
    while (k < bytes.length && (bytes[k] === 0x20 || bytes[k] === 0x0a || bytes[k] === 0x0d || bytes[k] === 0x09)) k++;
    if (bytes[k] !== 0x7b /* { */) return null;
    try {
      var v = JSON.parse(new TextDecoder().decode(bytes));
      return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
    } catch (e) { return null; }
  }

  async function pdfJsonStreams(pdf) {
    var canInflate = typeof DecompressionStream !== 'undefined';
    var enc = new TextEncoder();
    var STREAM = enc.encode('stream'), ENDSTREAM = enc.encode('endstream');
    var found = [], at = 0;
    while (true) {
      var s = findFrom(pdf, STREAM, at);
      if (s < 0) break;
      var start = s + STREAM.length;
      if (pdf[start] === 0x0d) start++;
      if (pdf[start] === 0x0a) start++;
      var e = findFrom(pdf, ENDSTREAM, start);
      if (e < 0) break;
      at = e + ENDSTREAM.length;
      var end = e;
      if (end > start && pdf[end - 1] === 0x0a) end--;
      if (end > start && pdf[end - 1] === 0x0d) end--;
      var slice = pdf.subarray(start, end);
      if (slice.length < 2) continue;
      var plain = asJsonObject(slice);
      if (plain) { found.push({ json: plain, bytes: slice, offset: start }); continue; }
      if (!canInflate || slice.length < 8) continue;
      var out;
      try { out = await inflateBytes(slice); } catch (err) { continue; }
      var parsed = asJsonObject(out);
      if (parsed) found.push({ json: parsed, bytes: out, offset: start });
    }
    return { items: found, canInflate: canInflate };
  }

  function findFrom(hay, needle, from) {
    outer: for (var i = from; i + needle.length <= hay.length; i++) {
      for (var j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
      return i;
    }
    return -1;
  }

  // verify_proof.py _check_manifest_binding, for a sealed deliverable PDF: is
  // the attached manifest.json the one the certificate's signed statement
  // commits to? The manifest is found by hash, since there is no PDF parser here.
  async function checkManifestBinding(cert, items) {
    var binding = (cert.statement || {}).bundle_binding;
    var checks = [];
    var hashed = [];
    for (var i = 0; i < items.length; i++) {
      hashed.push({ item: items[i], hex: bytesToHex(await sha256(items[i].bytes)) });
    }
    var match = hashed.filter(function (h) { return h.hex === binding.manifest_sha256; })[0];
    var looksLikeManifest = items.filter(function (it) {
      return Array.isArray(it.json.files) && !it.json.statement;
    });
    if (match) {
      checks.push({ name: 'manifest.json hash matches the signed binding', state: 'pass',
        detail: 'sha256(manifest.json) = ' + match.hex + ', equals statement.bundle_binding.manifest_sha256.' });
    } else {
      checks.push({ name: 'manifest.json hash matches the signed binding', state: 'fail',
        detail: looksLikeManifest.length
          ? 'the attached manifest.json does not hash to statement.bundle_binding.manifest_sha256 (' +
            binding.manifest_sha256 + '). It was changed after the certificate signed it.'
          : 'no attachment in this PDF hashes to statement.bundle_binding.manifest_sha256, so manifest.json ' +
            'is missing or was altered.' });
    }
    checks.push({ name: 'bundle_binding.manifest_filename matches the entry hashed',
      state: binding.manifest_filename === 'manifest.json' ? 'pass' : 'fail',
      detail: binding.manifest_filename === 'manifest.json'
        ? 'the binding names manifest.json'
        : 'statement.bundle_binding.manifest_filename = ' + JSON.stringify(binding.manifest_filename) +
          ', not manifest.json' });
    if (match) {
      var len = match.item.bytes.length;
      checks.push({ name: 'bundle_binding.manifest_bytes matches the entry length',
        state: binding.manifest_bytes === len ? 'pass' : 'fail',
        detail: binding.manifest_bytes === len
          ? 'manifest.json is ' + len + ' bytes, matching the binding'
          : 'manifest.json is ' + len + ' bytes but statement.bundle_binding.manifest_bytes = ' +
            JSON.stringify(binding.manifest_bytes) });
    }
    return checks;
  }

  // signed_export.SIGNED_FIELDS[("download_receipt", 2)]
  var RECEIPT_FIELDS = ['artifact', 'file_name', 'media_type', 'tenant', 'actor_id', 'file_bytes', 'covers_bytes'];

  // download_receipt.verify_download + signed_export.verify_manifest, offline.
  // Every file Coriqo hands over carries this receipt; a PDF carries it inside.
  // A PDF cannot hash itself, so the receipt covers the first `covers_bytes`
  // bytes (the PDF as rendered) and is attached after them.
  async function checkReceipt(receipt, file) {
    var checks = [];
    var seal = receipt.seal || {};
    var body = seal.signed_body || {};
    var version = parseInt(receipt.subject_version || 1, 10);
    if (receipt.sealed === false || !receipt.seal) {
      throw new Error('This file carries a Coriqo download receipt, but the receipt is unsigned' +
        (receipt.unavailable_reason ? ': ' + receipt.unavailable_reason : '.') +
        ' Download the file again from Coriqo to get a signed copy.');
    }

    var covers = receipt.covers_bytes;
    var coveredOk = typeof covers === 'number' && covers % 1 === 0 && covers >= 0 && covers <= file.length;
    var hashHex = coveredOk ? bytesToHex(await sha256(file.subarray(0, covers))) : null;
    var isPdf = file.length >= 5 && String.fromCharCode.apply(null, file.subarray(0, 5)) === '%PDF-';
    var coverProblems = [];
    if (!coveredOk) coverProblems.push('the file is shorter than the receipt says it should be');
    else if (covers !== file.length && !isPdf) coverProblems.push('the file is longer than when it was signed');
    if (coveredOk && body.content_hash !== hashHex) {
      coverProblems.push('the signed part of the file hashes to ' + hashHex +
        ', not the ' + body.content_hash + ' the receipt signed. The file was changed after Coriqo handed it over.');
    }
    checks.push({ name: 'Signed part of this file is unchanged', state: coverProblems.length ? 'fail' : 'pass',
      detail: coverProblems.length ? coverProblems.join('; ')
        : 'sha256 of the first ' + covers + ' bytes = ' + hashHex + ', the content_hash the receipt signed' });

    // A PDF grows after signing: the receipt is attached as an incremental
    // update, and Coriqo's PDF library rewrites page objects in that update.
    // A viewer renders the whole file, so a change made there would show on
    // screen while the signed part still matches. The browser can't rebuild
    // that update byte for byte (verify_download does, server-side), so say so
    // and let the reader open exactly the signed bytes instead.
    var extra = coveredOk ? file.length - covers : 0;
    if (extra > 0 && isPdf && !coverProblems.length) {
      checks.push({ name: 'Bytes added after the signed part', state: 'skip', appended: true,
        detail: extra + ' bytes follow the signed part. Coriqo adds them when it attaches this receipt, but this ' +
          'page can\u2019t confirm they hold only the receipt, and a PDF viewer shows them. Open the signed copy ' +
          'to read exactly what Coriqo signed, or use Verify receipt in Coriqo, which rebuilds that part.' });
    }

    var reasons = [];
    if (receipt.subject !== 'download_receipt') reasons.push('this is not a download receipt');
    if (body.key_id !== seal.key_id) reasons.push('signed_body.key_id does not match seal.key_id');
    if (body.content_hash !== seal.content_hash) reasons.push('signed_body.content_hash does not match seal.content_hash');
    if (body.subject !== receipt.subject) reasons.push('signed_body.subject does not match the receipt');
    if (body.generated_at !== receipt.generated_at) reasons.push('signed_body.generated_at does not match the receipt');
    if (parseInt(body.subject_version || 1, 10) !== version) reasons.push('signed_body.subject_version does not match the receipt');
    if (version === 2) {
      RECEIPT_FIELDS.forEach(function (f) {
        if (JSON.stringify(body[f]) !== JSON.stringify(receipt[f])) reasons.push('signed_body.' + f + ' does not match the receipt');
      });
    }
    if (reasons.length || version === 2) {
      checks.push({ name: 'Receipt fields match what was signed', state: reasons.length ? 'fail' : 'pass',
        detail: reasons.length ? reasons.join('; ')
          : 'file name, size, who downloaded it, when and the content hash are all inside the signature' });
    } else {
      // signed_export.SIGNED_FIELDS has no version-1 download receipt: only the
      // content hash, time and key are signed, so nothing else is shown as signed.
      checks.push({ name: 'Receipt fields match what was signed', state: 'skip',
        detail: 'a version-1 receipt signs only the content hash, the time and the key. Its file name and ' +
          'who downloaded it are not signed, so they are not shown as verified.' });
    }

    var sig = await verifySignature(body, seal.signature || '', seal.public_key_pem || '',
                                    version >= 2 ? body.algorithm : null);
    checks.push(signatureCheck(sig, 'receipt', seal.key_id, 'Receipt signature'));

    // Only signed values in the summary: the body, not the receipt's own copy.
    var summary = [];
    if (version === 2) summary.push(['Receipt for', body.artifact || body.file_name || 'a Coriqo download']);
    summary.push(['Downloaded', body.generated_at]);
    summary.push(['Signed bytes', coveredOk ? covers + ' of ' + file.length : 'unreadable']);
    return {
      kind: 'Download receipt',
      subject: 'download_receipt',
      summary: summary,
      checks: checks,
      signedLength: coveredOk && extra > 0 && isPdf ? covers : null,
      // Read from the signed body. A forger can sign any policy with their own
      // key, so the page treats this as a claim to check, never as confirmation.
      claimsOwnKey: body.key_policy === 'tenant',
      keys: [{ key_id: seal.key_id, pem: seal.public_key_pem }]
    };
  }

  // A PDF from Coriqo: its seal (certificate or proof) when it has one, the
  // deliverable binding when it seals a manifest, and its download receipt.
  async function verifyPdf(pdf) {
    var scan = await pdfJsonStreams(pdf);
    var items = scan.items;
    // The same attachment can be reachable twice in one PDF (a name tree and an
    // annotation), so identical copies count once.
    var seen = {};
    var atts = items.filter(function (it) { return it.json.statement || it.json.sth_body; })
      .filter(function (it) {
        var k = canonicalString(it.json);
        return seen[k] ? false : (seen[k] = true);
      });
    var att = atts[0];
    var receipts = items.filter(function (it) { return it.json.subject === 'download_receipt'; });
    var receiptItem = receipts.length ? receipts[receipts.length - 1] : null;
    var receipt = receiptItem ? receiptItem.json : null;

    if (!att && !receipt) {
      var draft = items.filter(function (it) { return it.json.sealed === false && Array.isArray(it.json.files); })[0];
      if (draft) {
        var certEntry = (draft.json.files || []).filter(function (f) { return f && f.name === 'certificate.json'; })[0];
        throw new Error('This is an unsealed draft, so there is no seal to check. ' +
          ((certEntry && certEntry.reason) || draft.json.bundle_note || 'Seal it in Coriqo, then download it again.'));
      }
      var ledger = items.filter(function (it) {
        return it.json.governance_event_id && it.json.content_hash && it.json.record_id;
      })[0];
      if (ledger) {
        throw new Error('This assurance package names the sealed record it belongs to (' + ledger.json.record_id +
          '), but the file itself carries no signature, so it cannot be checked offline here. Check that record in Coriqo.');
      }
      if (!scan.canInflate) {
        throw new Error('This browser cannot decompress PDF attachments. Open the PDF in your reader, ' +
          'save certificate.json from its attachments pane, and drop that here.');
      }
      throw new Error('This PDF carries no Coriqo seal and no signed download receipt. ' +
        'Files downloaded from Coriqo before receipts were added carry neither: download it again from Coriqo, ' +
        'or drop its certificate.json here.');
    }

    var result = null;
    if (att) {
      result = await verifyJson(att.json);
      var attKind = att.json.statement ? 'certificate' : 'proof';
      result.fileLabel = 'attached ' + attKind;
      var binding = att.json.statement && att.json.statement.bundle_binding;
      if (atts.length > 1) {
        // Only the first seal is read, so a second one could say anything.
        result.checks.push({ name: 'One seal in this PDF', state: 'fail',
          detail: 'this PDF carries ' + atts.length + ' seals. A Coriqo PDF carries one, so this file is not the PDF Coriqo issued' });
      }
      if (!binding && !receipt) {
        result.checks.push({ name: 'PDF pages covered by the seal', state: 'skip',
          detail: 'this PDF has no signed download receipt, so its pages are not covered. Only the attached ' +
            attKind + ' was checked' });
      }
      if (binding) {
        (await checkManifestBinding(att.json, items)).forEach(function (c) { result.checks.push(c); });
      }
    }
    if (receipt) {
      var r = await checkReceipt(receipt, pdf);
      if (!result) {
        result = r;
        result.fileLabel = 'signed download receipt';
        // Only a receipt-only file may be signed with an organisation's own
        // key. Certificates and proofs must always match a published key.
        result.ownKeyPossible = r.claimsOwnKey;
      } else {
        // The certificate must be part of what the receipt signed. A genuine
        // certificate from another record, pasted into the bytes added after
        // signing, would otherwise pass alongside a genuine receipt.
        var covers = receipt.covers_bytes;
        var inside = typeof covers === 'number' && att.offset < covers;
        result.checks.push({ name: 'Certificate is inside the signed part', state: inside ? 'pass' : 'fail',
          detail: inside ? 'the attached certificate sits in the bytes the download receipt signed'
            : 'the certificate sits after the bytes the receipt signed, so it was added after Coriqo handed the file over' });
        r.checks.forEach(function (c) { result.checks.push(c); });
        result.summary = (result.summary || []).concat(r.summary);
        result.fileLabel += ' and download receipt';
        result.signedLength = r.signedLength;
        // Keys are told apart by the key itself, never by name: a forged
        // receipt reusing the certificate's key_id with a different key must
        // still reach the authorship check, and two keys under one id fail.
        var norm = function (pem) { return String(pem || '').replace(/\s+/g, ''); };
        r.keys.forEach(function (k) {
          var sameId = (result.keys || []).filter(function (c) { return c.key_id === k.key_id; });
          if (sameId.some(function (c) { return norm(c.pem) !== norm(k.pem); })) {
            result.checks.push({ name: 'One key per key id', state: 'fail',
              detail: 'the certificate and the download receipt both name key ' + k.key_id +
                ' but carry different keys. One of them was not signed by that key.' });
          }
          if (!(result.keys || []).some(function (c) { return norm(c.pem) === norm(k.pem); })) result.keys.push(k);
        });
      }
    }
    return result;
  }

  async function verifyJson(obj) {
    var specProblem = specVersionProblem(obj);
    if (specProblem) throw new Error('Unsupported spec version. ' + specProblem);
    if (obj && typeof obj === 'object' && obj.statement) return checkCertificate(obj);
    if (obj && typeof obj === 'object' && obj.sth_body) return checkProof(obj);
    throw new Error(
      'Not a Coriqo attestation. Expected a certificate (with a "statement") or an ' +
      'inclusion proof (with an "sth_body").');
  }

  global.CoriqoVerify = {
    verifyJson: verifyJson,
    verifyPdf: verifyPdf,
    checkReceipt: checkReceipt,
    checkManifestBinding: checkManifestBinding,
    checkMandateCalls: checkMandateCalls,
    missingNumbers: missingNumbers,
    canonicalString: canonicalString,
    pemFingerprint: pemFingerprint,
    hasEd25519: hasEd25519,
    bytesToHex: bytesToHex,
    sha256: sha256
  };
})(window);

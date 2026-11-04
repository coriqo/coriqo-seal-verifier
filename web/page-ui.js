/*
 * Page glue: the sample button, the key list and the "arrived from a link"
 * note. verify.js and verify-ui.js do the checking. Nothing here makes a
 * network request: the sample is embedded (sample.js) and the key list comes
 * from keyring.js, the same list the verifier compares against.
 */
(function () {
  'use strict';

  // Framed by another site: refuse to take files (a meta tag cannot set
  // frame-ancestors, so the page checks for itself). The drop zone has its own
  // listeners in verify-ui.js, so drops are stopped in the capture phase,
  // before they reach it.
  if (window.top !== window.self) {
    document.getElementById('framed').classList.add('on');
    document.getElementById('verify-file').disabled = true;
    document.getElementById('verify-sample').disabled = true;
    ['dragover', 'drop'].forEach(function (type) {
      window.addEventListener(type, function (e) {
        e.preventDefault();
        e.stopPropagation();
      }, true);
    });
  }

  var input = document.getElementById('verify-file');
  var button = document.getElementById('verify-sample');
  var sampleText = JSON.stringify(window.CORIQO_SAMPLE_PROOF || null, null, 2);

  button.addEventListener('click', function () {
    var dt = new DataTransfer();
    dt.items.add(new File([sampleText], 'sample-proof.json', { type: 'application/json' }));
    input.files = dt.files;
    input.dispatchEvent(new Event('change'));
  });

  // "Download the sample only": a Blob link built here, so the file saved is
  // exactly the text the button checks.
  var dl = document.getElementById('sample-dl');
  dl.href = URL.createObjectURL(new Blob([sampleText], { type: 'application/json' }));

  var cp = new URLSearchParams(location.search).get('checkpoint');
  if (cp && /^[0-9a-f-]{8,64}$/i.test(cp)) {
    document.getElementById('arrived-cp').textContent = cp;
    document.getElementById('arrived-note').hidden = false;
  }

  var ul = document.getElementById('keyring-list');
  var ids = window.CORIQO_PUBLISHED_KEY_IDS || [];
  var fps = window.CORIQO_PUBLISHED_FINGERPRINTS || [];
  var revoked = window.CORIQO_REVOKED_FINGERPRINTS || [];
  function keyItem(label, fp) {
    var li = document.createElement('li');
    var code = document.createElement('code');
    code.textContent = fp;
    li.append(label, code);
    return li;
  }
  var items = fps.map(function (fp, i) {
    return keyItem((ids[i] || 'key') + ' (active): ', fp);
  }).concat(revoked.map(function (fp) {
    return keyItem('revoked: ', fp);
  }));
  if (!items.length) {
    var none = document.createElement('li');
    none.textContent = 'This copy lists no published keys.';
    items = [none];
  }
  ul.replaceChildren.apply(ul, items);
})();

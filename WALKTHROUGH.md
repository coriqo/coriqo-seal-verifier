# Auditor walkthrough: check a Coriqo seal yourself in under 10 minutes

This is for an outside auditor or examiner who wants to see the verifier work
before trusting any result from it. You need Python 3 and the
`cryptography` package. You do not need a Coriqo account, network access after
the install, or any Coriqo software other than `verify_proof.py` in this folder.

Every command below was run as written, from this folder, on Python 3.11.5 with
`cryptography` 50.0.2. The output shown is copied from those runs, shortened
where marked `...`.

| Step | What you do | Time |
|---|---|---|
| 1 | Set up Python and `cryptography` | 2 to 3 min |
| 2 | Verify a sample proof, read PASS | 1 min |
| 3 | Change one character in a copy, read FAIL | 2 min |
| 4 | Verify a sample certificate | 1 min |
| 5 | Optional: check an AI answer against a live Coriqo host | 3 min |

## 1. Set up (2 to 3 minutes)

Open a terminal in the `seal-verifier` folder. Use a fresh virtual environment
so nothing else on your machine is involved:

```bash
python3 -m venv .venv-audit
. .venv-audit/bin/activate          # Windows: .venv-audit\Scripts\activate
pip install cryptography
```

`verify_proof.py` uses the Python standard library plus `cryptography`, nothing
else. You can read it before running it; it is one file.

## 2. Verify a sample proof (1 minute)

`testdata/` holds synthetic samples: an invented bank and a signing key made
from a published seed. No real record and no Coriqo production key is in it.

```bash
python verify_proof.py --proof testdata/proof.json --pubkey testdata/pubkey.pem
echo "exit code: $?"
```

Output (shortened):

```
  Checkpoint ID : cp-2026-q2
  Event ID      : seq-2
  Issued at     : 2026-06-30T00:00:00Z
  Subject       : Demo Bank — model governance chain
  Leaf index    : 2 of 5 events
...
  [PASS] proof fields match the signed checkpoint body
  [PASS] Merkle inclusion proof
         event_hash is proven to be in the Merkle tree
  [PASS] Ed25519 checkpoint signature
         STH signed by test-key-2026 — signature valid
  [PASS] Timestamp consistency
  [PASS] Compliance coverage percentage
...
RESULT: VERIFIED ✓
exit code: 0
```

**What this proves:** the event's hash is inside the set of events that the
checkpoint signature covers, and the signature was made by the private key that
matches `pubkey.pem`.

**What it does not prove:** that `pubkey.pem` belongs to the bank or to
Coriqo. With a real proof, get the public key through a channel you trust (the
bank's Signing keys screen, a published key, or a witness keyring), not from the
same email as the proof. It also does not tell you the event's content is true,
only that it has not changed since it was sealed.

## 3. Change one character and watch it fail (2 minutes)

Copy the proof, change the first character of the sealed event hash
(`leaf_input`) in the copy, and verify the copy. The original is not touched.

```bash
python -c "
import json
d = json.load(open('testdata/proof.json'))
h = d['leaf_input']
d['leaf_input'] = ('f' if h[0] != 'f' else 'e') + h[1:]
json.dump(d, open('/tmp/proof_tampered.json', 'w'), indent=2)
print('changed leaf_input', h[:12], '->', d['leaf_input'][:12])
"
python verify_proof.py --proof /tmp/proof_tampered.json --pubkey testdata/pubkey.pem
echo "exit code: $?"
```

On Windows, write the copy to a path such as `proof_tampered.json` instead of
`/tmp/...`.

Output (shortened):

```
changed leaf_input eaa13a0effee -> faa13a0effee
...
  [PASS] proof fields match the signed checkpoint body
  [FAIL] Merkle inclusion proof
         PROOF INVALID — event may not be in this checkpoint
  [PASS] Ed25519 checkpoint signature
...
RESULT: VERIFICATION FAILED ✗
exit code: 1
```

**What this proves:** one changed character in the sealed record is enough to
fail the check. The signature line still passes because the checkpoint itself
was not edited; the failure is that the edited event is no longer in it.

Try other edits if you like: change one character of `merkle_root` or of
`checkpoint_signature` and a different check fails instead.

For a Trust Repair proof zip from a real package, `tamper_demo_proof_zip.py`
does the same thing for you: it verifies the zip, then two edited copies, and
exits 0 only if the original passed and both copies failed:

```bash
python tamper_demo_proof_zip.py coriqo_package_<id>_proof.zip
```

There is no sample zip in `testdata/`, so that command needs a zip a bank gave you.

## 4. Verify a sample certificate (1 minute)

A certificate covers a period, not one event. It checks that each checkpoint
links to the one before, with no gap.

```bash
python verify_proof.py testdata/certificate.json
echo "exit code: $?"
```

Output (end):

```
RESULT: CONTINUITY VERIFIED ✓

  Governance was continuous from 2026-03-31 to 2026-06-30 across 2 sealed checkpoints, with 1 quiet period at normal cadence.
...
exit code: 0
```

`testdata/` also holds certificates that must fail (`certificate_backdated.json`,
`certificate_revocation_forged.json`, `certificate_key_rotation_forged_succession.json`).
Run any of them the same way and the exit code is 1.

## 5. Optional: check an AI answer against a Coriqo host (3 minutes)

This step is not offline. It needs a Coriqo host, a signed-in user who can read
models, and an API token. It asks Coriqo whether each record an AI answer cites
is a real sealed record and, where you give a hash, whether that hash matches the
sealed one.

```bash
curl -X POST https://<coriqo-host>/api/v1/verify/grounding \
  -H "Authorization: Bearer $CORIQO_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "output": "The agent was registered as high risk.",
    "sealed_citations": [{"record_id": "<event id>", "event_hash": "<claimed hash>"}],
    "provider": "openai"
  }'
```

Read `verdict` (`grounded` or `issues`) and `issues`: `unknown_record` means a
cited record was never sealed, `hash_mismatch` means the claimed hash differs
from the sealed one, `uncited_id` means the text contains something shaped
like a record id that matches no sealed record. Send the same body with `"provider": "anthropic"` or with no provider and
the verdict fields are the same; the provider is stored as a label only.
Coriqo's own test suite checks this for plain-text and
markdown-footnote answers, and checks that a changed hash and a citation to a
record that was never sealed are both caught under every label.

**What this does not prove:** this step trusts the Coriqo host to answer
honestly about its own records. For a check that does not, use steps 2 to 4 on
a proof the bank exports for the record in question.

## When you are done

```bash
deactivate
rm -rf .venv-audit /tmp/proof_tampered.json
```

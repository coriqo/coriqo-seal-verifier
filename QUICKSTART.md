# Examiner quickstart

Check a sealed Coriqo record on your own machine in three commands. You need
Python 3.10 or newer and git. You don't need a Coriqo account, and the check
never contacts Coriqo: the second command downloads a file, and after that
you can unplug the network.

```bash
git clone https://github.com/coriqo/coriqo-seal-verifier && cd coriqo-seal-verifier && pip install cryptography
curl -fsSLo sample-proof.json https://coriqo.onrender.com/api/v1/public/sample-proof.json
python verify_proof.py sample-proof.json
```

The last line of the output should read `RESULT: VERIFIED`, and the command
exits 0. When the sample carries the demo agent's decisions and the sealed
mandate they ran under, a `Mandate:` line under it gives how many recorded tool
calls fell outside that mandate (SPEC.md §19).

The sample comes from Coriqo's public demo tenant. The bank and the people in
it are invented. The file carries the public key that signed it, so a pass
shows the record has not changed since it was signed under that key. It does
not show who holds the key. For a real record, get the bank's public key from
the bank, not from the file, and add `--pubkey bank-key.pem` (SPEC.md §9).

## Now break it

Change one character of the sealed event hash and check again:

```bash
python -c "import json;d=json.load(open('sample-proof.json'));h=d['leaf_input'];d['leaf_input']=('1' if h[0]=='0' else '0')+h[1:];json.dump(d,open('edited.json','w'))"
python verify_proof.py edited.json
```

This time the output shows `[FAIL] Merkle inclusion proof`, the result is
`VERIFICATION FAILED`, and the command exits 1. Edit any other signed value
(the checkpoint body, the root, the signature) and a different check fails,
named in the output.

## What each check means

| Check | What it tells you |
|---|---|
| Proof fields match the signed checkpoint body | The tree root and size the file quotes are the ones the signature covers, not values added afterwards. |
| Merkle inclusion proof | This event's hash is one of the events the checkpoint sealed. |
| Ed25519 checkpoint signature | The checkpoint was signed by the key named in the file, and not a byte of it has changed since. |
| Timestamp consistency | The time the file states matches the time inside the signed checkpoint. |
| Compliance coverage percentage | Counts, from the signed checkpoint, of the review steps the period recorded. |

The anchor, time-stamp, cosignature and countersignature sections say whether
the record was also published to Sigstore's Rekor log, time-stamped by an
outside authority, or signed by a second party. The sample may have none of
them, and the output says so rather than leaving them out.

## Spec version

The file's `spec_version` field names the version of `SPEC.md` it was written
to (absent means 1.0). This verifier implements 1.x. A file from a different
major version is refused with `UNSUPPORTED SPEC VERSION` rather than given a
verdict; get a newer verifier from this repository. See SPEC.md §12.1.

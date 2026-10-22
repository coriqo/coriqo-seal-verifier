# Coriqo Attestation Format: specification v1.1

Spec version: **1.1**. Bundles state the version they were written to in a
top-level `spec_version` field; see §12.1 for what a verifier does with it.

Author: Abdulrafiu Rabiu, Coriqo. Licensed under the Apache License, Version 2.0.

This document defines the byte formats and verification rules for Coriqo
attestations, so that a verifier can be written from this text alone, in any
language, with no reference to Coriqo's source.

That is the point of publishing it. A verifier without a written format is a
second copy of the original's bugs; only an independent implementation built
from a specification can disagree with the original, and disagreement is the
only thing that makes either one checkable.

`verify_proof.py` in this repository is the reference implementation. Where
this document and that script disagree, **this document is wrong** and should
be corrected. The script is what customers and examiners already run against
sealed records, and its behaviour is fixed by artifacts already issued.

Conformance corpus: `testdata/`. See §11.

---

## 1. What an attestation proves, and what it does not

Coriqo records governance actions (a model registered, submitted, reviewed,
approved, retired) as events in a hash-linked chain, and periodically seals
the chain by signing a **checkpoint** over a Merkle tree of the event hashes.

Two artifacts are derived from those seals:

| Artifact | Question it answers |
|---|---|
| **Inclusion proof** | Was this specific event sealed into this checkpoint? |
| **Continuity certificate** | Did governance run without interruption across a range of checkpoints? |

**What verification proves.** That the bytes in front of you were covered by an
Ed25519 signature at the time the checkpoint was signed, and that nothing has
been altered since. Elapsed time on a hash-linked chain cannot be faked, so a
continuity claim over a range of seals cannot be issued retroactively.

**What verification does not prove.** That the sealed events describe reality.
An organisation that lies to Coriqo gets a tamper-evident record of a lie. The
seal proves the record has not changed since it was made; it says nothing about
whether the record was true when made. Any material that claims otherwise is
overclaiming.

**The trust boundary is §9.** Read it before relying on a verdict. A bundle
carrying its own public key proves internal consistency and nothing about
authorship.

---

## 2. Notation

- `SHA256(x)`: SHA-256 over the byte string `x`, 32 bytes.
- `hex(x)`: lowercase hexadecimal, no prefix, no separators.
- `||`: byte concatenation.
- All hash values in JSON are `hex()` of the raw digest: 64 lowercase hex
  characters, matching `^[0-9a-f]{64}$`.
- All timestamps are ISO 8601 in UTC with a `Z` suffix, e.g.
  `2026-06-30T00:00:00Z`. Timestamps inside signed bodies are compared as
  opaque strings, never parsed, so a verifier must not normalise them.
- "MUST" and "MUST NOT" mark rules a conforming verifier is required to
  enforce. A verifier that skips a MUST will accept forgeries.

---

## 3. Canonicalisation

Every signature and every hash in this format is computed over the canonical
serialisation of a JSON object:

```
canonical_bytes(obj) = UTF-8 encoding of
    JSON.stringify(obj) with:
      - object keys sorted lexicographically by code point, at every depth
      - no whitespace between tokens (separators are "," and ":")
      - non-ASCII characters emitted literally, not \u-escaped
```

The Python reference is:

```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

**This definition is frozen.** Once a record is sealed, changing how these
bytes are produced invalidates every historical hash and signature. Treat any
change as a format-breaking version bump.

Two consequences that trip up reimplementations:

1. **`ensure_ascii=False` matters.** A non-ASCII character in an actor name or
   a note is serialised as its literal UTF-8 bytes, not as `\uXXXX`. A verifier
   that escapes will compute different bytes and report a false FAIL. Most
   languages' default JSON encoders do not escape; Python's does.
2. **Number formatting must round-trip.** All numeric fields in this format are
   integers. A verifier that reserialises them as floats (`5` → `5.0`) will
   compute different bytes. Parse into a representation that preserves integer
   form.

A verifier that recomputes a signature over a re-serialised object MUST
reproduce these bytes exactly. The safest implementation strategy is to
canonicalise from the parsed object, not to reuse the original file's bytes;
whitespace in the transmitted file is not significant and must not be relied on.

---

## 4. The event chain

### 4.1 Event fields

Each governance event commits to these fields, and only these:

| Field | Type | Meaning |
|---|---|---|
| `seq` | integer | Position in the chain, 0-based, contiguous |
| `timestamp` | string | ISO 8601 UTC |
| `actor` | string | User or service account identifier |
| `action` | string | `register`, `submit`, `review`, `approve`, `retire`, … |
| `model_name` | string | Subject model |
| `model_version` | string | Subject model version |
| `payload` | object | Action-specific detail |
| `prev_hash` | string | `event_hash` of event `seq - 1` |

### 4.2 Event hash

```
event_hash = hex(SHA256(canonical_bytes({
    seq, timestamp, actor, action, model_name, model_version, payload, prev_hash
})))
```

`event_hash` is **not** part of the hashed object: a field cannot commit to its
own value. A verifier recomputing an event hash MUST remove `event_hash` from
the object before canonicalising, and MUST NOT add or remove any other field.

### 4.3 Chain linkage

`prev_hash` of event 0 is the genesis value, 64 zero characters:

```
0000000000000000000000000000000000000000000000000000000000000000
```

For every subsequent event, `prev_hash` equals the previous event's
`event_hash`. Altering any event changes its hash and breaks every link after
it, which is what makes the chain tamper-evident without any key at all.

### 4.4 Chain head

The **head hash** is the `event_hash` of the highest-`seq` event, or the genesis
value for an empty chain. This is the single value a checkpoint seals.

### 4.5 Sealed reads (the access log)

A second, independent chain records the reads of the evidence store that have
consequence: exports and export previews, searches of a communications stream
and any page of one after the first, reads of 100 or more rows at once, and
reads by someone outside the subject's owning team. Ordinary single views are
not in it. Each row is one read:

| Field | Type | Meaning |
|---|---|---|
| `seq` | integer | Position in this subject's chain, 0-based, contiguous |
| `subject_ref` | string | What was read, e.g. `version:<id>`, `teams_channel:<id>`, `tenant` |
| `actor_id` | string or null | Reader's user id |
| `actor_label` | string | Reader's username |
| `actor_type` | string | `human` or `service` |
| `accessed_at` | string | ISO 8601 UTC |
| `access_kind` | string | `view`, `search`, `export` or `bulk_read` |
| `seal_reason` | string | `export`, `export_preview`, `comms_search`, `comms_paging`, `bulk_read`, `outside_owning_team`, `purpose_mismatch`, `subject_access` or `source_paging` (the last three since purpose declarations; the set of values grew, the hashed fields did not) |
| `record_count` | integer | Rows the read returned |
| `query_fingerprint` | string or null | SHA-256 of the query's shape (route and names of the filters used), never its values |
| `declared_purpose_id` | string or null | The purpose id the reader declared for this read, or null when none was declared. It names one exact declaration on a source; each amendment mints a new id. Whether it matched the source's purpose is not in the hash: it is derived from this field and the source's declarations in the tenant's audit log |
| `prev_hash` | string | `event_hash` of this subject's previous read, genesis for the first |

```
event_hash = hex(SHA256(canonical_bytes({ the twelve fields above })))
```

Every field is always present in the hashed object, null included. Rows are
chained per `subject_ref` exactly as in §4.3. Across subjects they carry a
tenant-wide `ordinal`, which is not hashed and which orders the access-log
Merkle tree (§5, same leaf and node hashing, same `tree_version` as the
checkpoint that signs it).

An org-wide checkpoint signs the log as `sth_body.access_log` (§6):

| Field | Type | Meaning |
|---|---|---|
| `ordinal_watermark` | integer | Highest sealed-read `ordinal` covered |
| `tree_size` | integer | Number of sealed reads with `ordinal <= ordinal_watermark` |
| `merkle_root` | string | Root over their `event_hash` values in `ordinal` order |

**Rule 4.5.1 (MUST).** A proof that a read was sealed (§7, `leaf_tree` =
`access_log`) is checked against `sth_body.access_log`, never against
`sth_body.merkle_root`, and the bundle's `access_event` MUST re-derive
`leaf_input` under the formula above. A proof without `access_event` fails.

**Absent `access_log`** means the checkpoint signs no read: it is
version-scoped, it predates sealed reads, or no read had been sealed when it
was issued. It is not a failure. A read sealed after a checkpoint is covered
by the next org-wide one.

---

## 5. The Merkle tree

### 5.1 Leaf and node hashing

```
leaf_hash(data) = SHA256(0x00 || data)
node_hash(l, r) = SHA256(0x01 || l || r)
```

The leaf input `data` is the **raw 32 bytes** of an event's `event_hash`,
that is, `bytes.fromhex(event_hash)`, not its 64-character hex text. Hashing the hex
string instead is the single most common reimplementation error.

The `0x00` / `0x01` domain-separation prefixes are taken from RFC 6962 §2.1.
They ensure a leaf hash can never equal an internal node hash, which closes the
second-preimage attack on naive Merkle trees.

### 5.2 Tree construction

Leaves are the event hashes in the order defined by §5.5. **Two constructions
exist**, selected by `sth_body.tree_version`. The field is absent on every
checkpoint sealed before the second construction was introduced, and **absent
means 1**. Both use the leaf/node hashing of §5.1 unchanged; only the shape
differs. An empty tree has the root `SHA256("")` in both.

A verifier MUST implement both. Version-1 checkpoints were signed against the
version-1 shape and do not stop being valid because a newer one exists.

#### 5.2.1 `tree_version` 1: duplicate the last node

Each level is formed by pairing adjacent nodes left to right. **When a level
has an odd number of nodes, the last node is paired with itself.** Repeat until
one node remains: that is the Merkle root.

```
level[0]   = [leaf_hash(e) for e in event_hashes]
level[k+1] = [node_hash(level[k][2i], level[k][2i+1 if it exists else 2i])
              for i in 0 .. ceil(len(level[k])/2) - 1]
root       = the single node in the final level
```

This shape has a known ambiguity; see §5.3.

#### 5.2.2 `tree_version` 2: RFC 6962 Merkle Tree Hash

RFC 6962 §2.1's MTH, which splits at the largest power of two below `n` rather
than duplicating:

```
MTH({})   = SHA256("")
MTH({d0}) = leaf_hash(d0)
MTH(D[n]) = node_hash(MTH(D[0:k]), MTH(D[k:n]))    for n > 1
            where k is the largest power of two strictly less than n
```

Equivalently, and more convenient to implement without recursion: build level
by level as in 5.2.1, but when a level has an odd number of nodes, **promote
the last node unchanged** to the next level instead of pairing it with itself.
The two formulations produce identical trees for every `n`.

This construction is injective over leaf lists: distinct leaf lists give
distinct roots. That is the property §5.3 says version 1 lacks.

**The two shapes agree exactly when `n` is a power of two** (and for `n` of 0
or 1). Test vectors built at 2, 4, or 8 leaves therefore pass under both and
distinguish nothing. Use a leaf count that is not a power of two.

### 5.3 Why `tree_version` 1 is ambiguous, and what a verifier owes it

Version 1 uses RFC 6962's leaf and node hashing with a **different tree shape**
(§5.2.1). That shape has a known ambiguity, the same one behind Bitcoin's
CVE-2012-2459. Distinct leaf lists can produce an identical root:

```
leaves [a, b, c]     root e9636069c740c9ff51625b01a0b040396d265a9b920cc6febdfa5ecc9f58ecce
leaves [a, b, c, c]  root e9636069c740c9ff51625b01a0b040396d265a9b920cc6febdfa5ecc9f58ecce
```

A version-1 root is therefore **not** a unique commitment to its leaf set. Any
consumer that treats such a root alone as the identity of an event set (comparing roots across systems, deduplicating by root, or co-signing a bare
root) loses that guarantee.

What contains it: `tree_size` and `length` are inside the **signed** checkpoint
body (§6), so an issuer cannot present an n-leaf tree as an (n+1)-leaf tree
without breaking the signature. The collisions only occur across different
sizes, so exploiting the ambiguity requires the signing key, at which point it
is not the weakest available attack.

Version 2 (§5.2.2) removes the ambiguity rather than containing it. Version-1
checkpoints cannot be migrated: a root is a signed commitment to a tree of a
specific shape, and recomputing it under version 2 gives a different root. They
remain valid, and remain fully reproducible under version 1.

**Rule 5.3.1 (MUST, `tree_version` 1 only).** Because a version-1 root does not
pin the leaf count, a verifier MUST check the declared size against the proof
depth:

```
expected_depth = 0 if tree_size == 1 else bit_length(tree_size - 1)
len(proof_path) MUST equal expected_depth
```

Without this check `tree_size` is decorative for version 1: the walk only
compares a computed root, so a path of any length reproducing that root would
pass while declaring a tree of a different size.

**Rule 5.3.2 (MUST NOT).** Do **not** apply Rule 5.3.1 to `tree_version` 2.
Under RFC 6962 the audit-path length depends on the leaf's index as well as the
tree size (a 5,161-leaf tree has valid path lengths of 4, 7, 8, 12 and 13), so
a fixed-depth check rejects honest proofs. Version 2 needs no such rule: the
verification walk of §7.2.2 pins `tree_size` itself.

**Rule 5.3.3 (MUST).** Take `tree_version` from `sth_body` and nowhere else. A
`tree_version` read from an unsigned part of a bundle would let a forger select
whichever construction their hand-built path satisfies. This is the same class of
defect as an unsigned `merkle_root` (§7.3).

### 5.5 Leaf ordering

A checkpoint's scope is either an entire chain or a single model version, named
by `sth_body.subject` (`version:<id>` scopes to one version). Within that scope,
from `ordering_version` 2, leaves are the `event_hash` values of the scoped
events with `ordinal <= ordinal_watermark`, ordered by `ordinal`.

`ordinal` is assigned when an event is appended and never changes. That makes
the order **total** (it is unique) and **append-only** (a new event always sorts
after every event already sealed), which are the two properties the tree
depends on. `ordinal_watermark` is inside the signed body, so a checkpoint pins
its own leaf set: "every event with ordinal ≤ W" is exact and reproducible
forever.

`ordinal` is deliberately **not** part of `event_hash` (§4.2). It describes
where an event sits, not what it says.

#### The v1 ordering, and why it was replaced

Checkpoints with `ordering_version` 1 (or with neither field, which means the
same thing) were ordered by `(created_at, seq)`. That key failed both
properties:

- **Not total.** `created_at` is transaction time, so events written together
  share it, and `seq` is per-version rather than global. Events from different
  versions in one transaction tied on both columns, and ties have no defined
  order. On a live tenant: 5,161 events, 4,825 distinct order keys, 279 tied
  groups. Two equally legal orderings of the same unmodified events gave
  different roots.
- **Not append-only.** `created_at` is a business timestamp that can precede
  insertion, so a backdated write landed *mid-stream*. On the same tenant, two
  checkpoints' sealed heads had drifted 759 and 359 positions after later
  writes were dated before them.

The consequence ran in the dangerous direction. This never let anyone forge a
seal; it let an **honest** record fail verification: a recomputed root that
disagrees, inclusion proofs pointing at shifted leaves, continuity linkage that
cannot be proven. A verifier reporting FAIL on an unaltered record is the worst
output this format can produce, because FAIL is supposed to mean something.

For a `ordering_version` 1 checkpoint the sealed permutation was never recorded
and cannot be recovered. Such checkpoints keep a valid signature; what is gone
is the ability to rebuild the tree it covers. Coriqo marks them
`reproducible: false` and excludes them from continuity linkage with a stated
reason, rather than reporting them as breaks. A verifier reading one should say
the same: the signature is sound, the tree is not rebuildable.

### 5.4 Inclusion proof path

For the leaf at `leaf_index`, the proof path is the sequence of sibling hashes
from the leaf level upward, excluding the root. Walk up the levels of the tree
built per §5.2, halving the index at each step.

**`tree_version` 1.** At each level the sibling of an even index `i` is `i + 1`
(or `i` itself if `i + 1` is past the end: the duplicated case); the sibling of
an odd index is `i - 1`. Every leaf's path is the same length.

**`tree_version` 2.** At each level, a node that is the last of an odd-length
level was promoted and has **no sibling** there, so it contributes nothing to
the path; otherwise the sibling is `i XOR 1`. Path length therefore depends on
the leaf index as well as the tree size. Equivalently, RFC 6962 §2.1.1:

```
PATH(0, {d0}) = {}
PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])        if m < k
              = PATH(m - k, D[k:n]) : MTH(D[0:k])     if m >= k
```

A single-leaf tree has an empty proof path in both: the leaf is the root.

---

## 6. Checkpoints

A checkpoint is an Ed25519 signature over a **signed tree head** (`sth_body`).

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `subject` | string | always | What the chain covers |
| `issued_at` | string | always | ISO 8601 UTC, when the seal was made |
| `length` | integer | always | Number of events in the chain at seal time |
| `head_hash` | string | always | Chain head hash (§4.4) at seal time |
| `merkle_root` | string | always (v1.5) | Root of the tree over those events |
| `tree_size` | integer | always (v1.5) | Number of leaves; equals `length` |
| `key_id` | string | always | Which signing key was used |
| `ordering_version` | integer | from v2 | Leaf-ordering rule; absent means 1 (§5.5) |
| `ordinal_watermark` | integer | from v2 | Highest `ordinal` this seal covers |
| `tree_version` | integer | from v2 | Tree construction; absent means 1 (§5.2) |
| `algorithm` | string | from v3 | Signature algorithm; absent means `ed25519` (§6.1) |
| `continuity` | object | when present | Attested obligation counts and coverage gaps (§8.3) |
| `cohort_rollup` | object | when present | Attested cohort oversight rollup |
| `package_attestation` | object | when present | Binds a sealed examiner package to this checkpoint (§6.2) |
| `access_log` | object | when present | Signs the sealed-read log (§4.5) |

`continuity`, `cohort_rollup`, `package_attestation` and `access_log` are included **only when non-null**, so
checkpoints sealed before those fields existed keep verifying against the exact
bytes they were signed over. A verifier MUST NOT insert them as empty defaults.

**There is no `checkpoint_id` in the signed body.** A seal is identified within
its signature by `subject` and `issued_at`. See §7.3.

```
signature = sign(signing_key, canonical_bytes(sth_body))    # see §6.1
```

### 6.1 Signature algorithm

Two algorithms exist:

| `algorithm` | Meaning |
|---|---|
| absent | `ed25519`: pure Ed25519 (RFC 8032), raw 64-byte signature |
| `"es256"` | ECDSA on NIST P-256 with SHA-256 (RFC 6979 not required) |

**`ed25519` is spelled by the field's ABSENCE, and always will be.** Every
checkpoint sealed before this field existed must keep reproducing the exact
bytes it was signed over, and adding a key to a canonical JSON object changes
those bytes. A writer MUST NOT emit `"algorithm": "ed25519"`. A verifier MUST
treat absence as `ed25519` and MUST NOT insert it as a default before
recomputing canonical bytes. This is the same rule `continuity` and `cohort_rollup`
already carry (§6).

`es256` exists because a signing key held in Azure Key Vault or Managed HSM
cannot be Ed25519: those services offer RSA and EC P-256/P-384/P-521/P-256K
only, and their signing operation takes a digest, which pure Ed25519 cannot be
decomposed into. A deployment that requires the private key never to leave a
FIPS 140-3 Level 3 boundary on Azure must therefore sign ES256.

**Rule 6.1.1 (MUST).** Take `algorithm` from `sth_body` and nowhere else. An
`algorithm` read from an unsigned part of a bundle would let a forger select
which verification path runs. This is the same requirement Rule 5.3.3 places on
`tree_version`, for the same reason.

**Rule 6.1.2 (MUST).** The declared algorithm and the resolved public key must
agree: `ed25519` requires an Ed25519 key, `es256` requires an EC P-256 key. A
verifier that finds them in disagreement MUST fail, and MUST NOT fall back to
whichever algorithm the key happens to support. Verifying a body that declares
one algorithm using a key of the other type would make the declaration
decorative and reintroduce exactly the algorithm-confusion class this field
exists to close.

**Rule 6.1.3 (MUST).** An unrecognised `algorithm` value MUST fail closed. A
verifier MUST NOT skip the signature check for an algorithm it does not
implement, and MUST NOT treat it as absent.

**Rule 6.1.5 (interoperability).** A verifier written before v3 cannot check an
`es256` signature, and will report it as invalid rather than as unsupported:
it calls Ed25519's two-argument `verify()` against an EC key, fails, and prints
SIGNATURE INVALID. That verdict is indistinguishable from tampering on evidence
that is sound. A bundle containing any non-`ed25519` checkpoint therefore
carries `signature_algorithms` and `minimum_verifier` in its manifest, so a
reader can tell a stale verifier from bad evidence. Those fields are emitted
**only** when such a checkpoint is present, so an `ed25519`-only bundle is
byte-for-byte what it was before v3, and the bundle `format` is deliberately
not bumped for the same reason. Being manifest fields they are unsigned (§8.2)
and are diagnostics only: a verifier MUST NOT select a verification path from
them; that is what the signed body's `algorithm` is for (Rule 6.1.1).

**Rule 6.1.4 (MUST NOT).** Do not treat an `es256` signature's bytes as an
identity. ECDSA is malleable: `(r, s)` and `(r, n - s)` both verify over the
same message under the same key, so two distinct byte strings can be valid
signatures for one checkpoint. Anything that deduplicates or compares
signatures MUST key on the checkpoint's identity (§7.3), never on the signature
bytes. Ed25519 has no such property, so implementations written before v3 will
not have accounted for this.

Every field a certificate later relies on lives **inside** `sth_body`. This is
deliberate: unsigned restatements elsewhere in a bundle are convenience data and
MUST NOT be trusted (§8.2).

### 6.2 Package attestation

A checkpoint issued when an evidence package is sealed carries
`package_attestation` inside `sth_body`. Every other checkpoint omits the key,
and so does every package seal issued before this field existed.

| Field | Type | Meaning |
|---|---|---|
| `package_id` | string | The sealed package |
| `snapshot_sha256` | string | Lowercase hex SHA-256 of the package's `snapshot.json` bytes |
| `package_event_hash` | string | The package's own chain hash |
| `approval_head_hash` | string | Hash of the last approval in the package's approval chain |
| `signoff` | string, optional | `two_people` or `one_person`: whether this round's sign-offs came from one user or two. Absent in a package sealed before this field existed |
| `signoff_basis` | string, optional | Why one person could sign both roles: `sole_user` (a workspace with one person) or `sole_admin_setting` (the bank's Package sign-off setting). Empty when `signoff` is `two_people` |

Every value is a string, so the object reproduces the same canonical bytes
(§3) in any language. The first four are always present. `signoff` and
`signoff_basis` are additive and signed with the rest; a verifier that does not
know them still verifies the seal and can show them to a reader.

`snapshot.json` is the frozen package content, served by
`GET /api/v1/packages/{package_id}/snapshot.json` as its canonical bytes (§3).
To check that a package is the one that was sealed:

1. Verify the checkpoint's signature (§6, §6.1), with `package_attestation` in
   the reconstructed body.
2. Compute SHA-256 over the `snapshot.json` file exactly as received, with any
   SHA-256 tool (`sha256sum snapshot.json`), and compare it with
   `snapshot_sha256`. `verify_proof.py` does step 1; it is not handed the
   snapshot file, so step 2 is the examiner's.

Informative. A snapshot MAY carry a `control_coverage` object listing the
approved documents behind each control objective. It needs no rule of its own:
it is inside `snapshot.json`, so `snapshot_sha256` already signs it, and a
verifier that ignores it still verifies the seal. A snapshot without the key is
a package built before it existed, not a failed one.

**Rule 6.2.0 (MUST).** When `subject` is `package:<id>`, `package_attestation.package_id`
MUST equal `<id>`. A version-scoped package seal signs `version:<id>` (the
server rewrites the subject), so the rule applies only to `package:` subjects.

**Rule 6.2.1 (MUST NOT).** Do not parse and re-serialise `snapshot.json` before
hashing it. The snapshot contains floating-point numbers, and their text form
differs between languages and libraries, so a re-encoded copy can hash
differently from an unchanged package. Hash the file's bytes.

**Rule 6.2.2 (MUST).** A package sealed before this field existed has a seal
checkpoint without `package_attestation`. Report it as *not attested*: its
signature covers governance events, not the package content. Do not report it
as verified or as failed.

#### 6.2.3 Record-wide fields

A record-wide package seal adds three keys to
`package_attestation`. The four fields above are unchanged, and a seal
without these keys keeps verifying byte for byte. Every value is an integer
or a string.

| Field | Type | Meaning |
|---|---|---|
| `scope` | object | `{model_id, version_id}` of the package; `""` when not pinned |
| `record_heads` | object | Head of every chain the package draws on, at seal time |
| `period_fence` | object | The package period as a governance-event ordinal range |

`record_heads` holds:

| Key | Shape | Recomputable offline |
|---|---|---|
| `governance_events` | list of `{version_id, length, head_hash}`, sorted by `version_id` | Yes, from `events/<version_id>.jsonl` (§13) |
| `committee_decisions` | `{length, head_hash}` of the org-wide committee decision chain | No |
| `committee_attestations` | list of `{decision_id, length, head_hash}`, one per committee decision the snapshot lists | No |
| `examination_questions` | list of `{examination_id, length, head_hash}`, one per examination the snapshot lists | No |
| `package_approvals` | `{length, head_hash}` of this package's approval chain | No |

`governance_events` lists one head per in-scope version: the pinned version;
every version of the pinned model; or, for an org-wide package, every version
with an event at or below the seal's `ordinal_watermark`. `length` is the
number of that version's events with `ordinal <= ordinal_watermark` and
`head_hash` is the `event_hash` of the last of them, or 64 zeros for a version
with none. For an empty non-governance chain, `length` is 0 and `head_hash`
is `""`.

`period_fence` holds `period_from` and `period_to` (the package dates, ISO
8601), `from_watermark`, `from_checkpoint_id`, `to_watermark`,
`to_checkpoint_id` and `snapshot_built_at` (when the fence was drawn). The fence is the ordinal range `from_watermark < ordinal
<= to_watermark`:

- `from_watermark` is the signed `ordinal_watermark` of the latest org-wide
  checkpoint (subject not starting `version:`, not quarantined) issued at or
  before `period_from`. With no such checkpoint, `from_checkpoint_id` is `""`
  and `from_watermark` is 0: the fence starts at the first event.
- `to_watermark` is the signed `ordinal_watermark` of the earliest org-wide
  checkpoint issued at or after `period_to`. With none when the snapshot was
  built, `to_checkpoint_id` is `""` and `to_watermark` is the highest ordinal
  at that moment.

The package dates are `created_at` values, which are not inside `event_hash`
and not in the tenant bundle, so they cannot be checked offline. The fence
can. It may include events written just outside the dates (between a fence
checkpoint and the period boundary); it cannot leave out an event written
inside them. The snapshot's `governance_events` is the in-period list: the
in-scope events whose `created_at` falls inside the dates, which is what the
package renders. In-scope events inside the fence but dated outside the period
are in a separate list, `governance_events_outside_period`, same row shape.
Together the two lists hold every in-scope event inside the fence. The fence
ends at the snapshot build, not at the seal: the snapshot is frozen when the
package goes to review.

#### 6.2.4 Signed, not checkable offline

The four non-governance heads are inside the signature, so they cannot be
changed after sealing. But this specification does not publish their hash
formulas and the tenant bundle does not carry their rows, so no verifier can
recompute them. **Rule 6.2.4 (MUST).** A verifier reports them as signed and
not checkable offline. It MUST NOT report them as verified. They do not fail
a bundle either. `audit_log` is not among them.

#### 6.2.5 Checking the record-wide fields (`--bundle-dir`)

For each package seal carrying `record_heads` or `period_fence` whose own
signature verified:

0. `record_heads.governance_events` is present. A record-wide seal without it
   fails; it is never read as "nothing to check".
1. For each `governance_events` entry, recompute `length` and `head_hash`
   from `events/<version_id>.jsonl` rows with `ordinal <= ordinal_watermark`.
2. Version-pinned (`scope.version_id` set): the list is exactly that version
   and the checkpoint's `version_id` is that version. Org-wide (both `""`):
   every version with a row at or below the watermark is listed.
   Model-pinned: the bundle does not map versions to models, so the list
   itself is not checked; each listed head still is.
3. `0 <= from_watermark <= to_watermark`, and every in-scope row with
   `from_watermark < ordinal <= to_watermark` has `ordinal <=
   ordinal_watermark`, so it is a leaf of this seal. (Not `to_watermark <=
   ordinal_watermark`: a version-scoped seal's watermark is that version's
   last ordinal, while the fence is drawn in org-wide ordinals.)
4. A named fence checkpoint is in the bundle, its signature verified, it is
   org-wide, its signed `ordinal_watermark` equals the fence value, and it
   was issued at or before `period_from` (lower) or at or after `period_to`
   (upper). An empty `from_checkpoint_id` requires `from_watermark` 0.

5. Upper end with no checkpoint (`to_checkpoint_id` is `""`): `to_watermark`
   is the highest ordinal at `snapshot_built_at`, which no signature bounds.
   `snapshot_built_at` must be present and not after the seal, and
   `to_watermark` must be at least the `ordinal_watermark` of every
   signature-verified org-wide checkpoint issued at or before
   `snapshot_built_at` (a lower value means the end was cut short). What
   cannot be checked offline is that no event written after the last such
   checkpoint and before the build was left out. **Rule 6.2.5 (MUST).** A
   verifier discloses this as not checkable offline and MUST NOT report the
   upper end as verified.

Steps 1-4 check that the named checkpoints are valid fence posts, not that
they are the closest ones. A looser fence only lists more events.

#### 6.2.6 Checking a snapshot against the fence (`--snapshot`)

With `--bundle-dir` and `--snapshot snapshot.json`:

1. SHA-256 the file's bytes (Rule 6.2.1) and find the package seal whose
   `snapshot_sha256` equals it. None, or one whose signature did not verify,
   is a failure.
2. The snapshot's `period_fence.from_watermark` and `to_watermark` equal the
   signed ones.
3. For every version in `record_heads.governance_events` (or the pinned
   version, or every version, when the seal has no heads), every row in
   `events/<version_id>.jsonl` with `from_watermark < ordinal <=
   to_watermark` appears in the snapshot's `governance_events` with the same
   `event_id` and `event_hash`, in `governance_events` or
   `governance_events_outside_period`.

A seal without `period_fence` gets step 1 only; the membership check is
reported as not checked.

---

## 7. Inclusion proof bundle

### 7.1 Fields

| Field | Type | Meaning |
|---|---|---|
| `checkpoint_id` | string | Which seal this proves membership in |
| `event_id` | string | Identifier of the event being proven |
| `issued_at` | string | Echo of the checkpoint's issue time (display only) |
| `subject` | string | Echo of the checkpoint's subject (display only) |
| `leaf_index` | integer | Position of the event's leaf, 0-based |
| `tree_size` | integer | Number of leaves in the tree |
| `leaf_input` | string | The event's `event_hash`, hex |
| `proof_path` | array of string | Sibling hashes, hex, leaf → root |
| `merkle_root` | string | Root the path must reproduce |
| `sth_body` | object | The signed checkpoint body (§6) |
| `checkpoint_signature` | string | Ed25519 signature over `canonical_bytes(sth_body)`, hex |
| `key_id` | string | Which signing key was used |
| `public_key_pem` | string | PEM public key (see §9 before trusting it) |
| `anchor` | object | Optional Rekor anchor (§10), informational only |
| `cosignatures` | array of object | Witness cosignatures over this checkpoint (§9.4). Unsigned; may be empty |
| `leaf_tree` | string | Optional. `access_log` when the leaf is a sealed read (§4.5); absent means a governance event |
| `access_event` | object | With `leaf_tree` = `access_log`: the sealed read's hashed fields plus `event_id` (§4.5) |
| `spec_version` | string | Optional. The spec version this bundle was written to, `MAJOR.MINOR`; absent means `1.0` (§12.1) |
| `_verify_with`, `_how_it_works` | string | Human instructions. Display only; a verifier MUST ignore them. |

### 7.2 Verification

A conforming verifier MUST perform both checks and MUST fail if either fails.

**Check 1: Merkle inclusion.** Common preconditions, then one of two walks
selected by `sth_body.tree_version` (absent means 1; rule 5.3.3):

```
if tree_size == 0                      -> FAIL
if leaf_index < 0 or >= tree_size      -> FAIL
if tree_version not in {1, 2}          -> FAIL          (do not guess)
```

#### 7.2.1 `tree_version` 1

```
if len(proof_path) != expected_depth   -> FAIL          (rule 5.3.1)

computed = leaf_hash(bytes.fromhex(leaf_input))
idx = leaf_index
for sibling in proof_path:
    computed = node_hash(computed, sibling) if idx is even
               else node_hash(sibling, computed)
    idx = idx // 2

computed MUST equal bytes.fromhex(merkle_root)
```

#### 7.2.2 `tree_version` 2: RFC 6962 §2.1.1

No proof-depth precondition (rule 5.3.2). `tree_size` is threaded through the
walk instead: `sn` must reach exactly 0 as the path is consumed, so a path that
is too short leaves `sn != 0` and one that is too long trips `sn == 0` mid-walk.

```
fn = leaf_index
sn = tree_size - 1
r  = leaf_hash(bytes.fromhex(leaf_input))

for sibling in proof_path:
    if sn == 0                        -> FAIL     (path longer than the tree)
    if (fn is odd) or (fn == sn):
        r = node_hash(sibling, r)
        if fn is even:
            while fn != 0 and fn is even:
                fn = fn >> 1
                sn = sn >> 1
    else:
        r = node_hash(r, sibling)
    fn = fn >> 1
    sn = sn >> 1

sn MUST equal 0, and r MUST equal bytes.fromhex(merkle_root)
```

**Check 2: Ed25519 checkpoint signature.**

```
Ed25519_verify(public_key, bytes.fromhex(checkpoint_signature),
               canonical_bytes(sth_body))  MUST succeed
```

### 7.3 Binding the bundle to the signature

**Everything above `sth_body` in the bundle is unsigned.** `merkle_root`,
`tree_size`, `leaf_index`, `checkpoint_id`, `issued_at` and `subject` at the top
level are restatements for display; the Ed25519 signature covers `sth_body` and
nothing else.

**Rule 7.3.1 (MUST).** Before the inclusion check, `merkle_root` and `tree_size`
at the top level MUST equal `sth_body.merkle_root` and `sth_body.tree_size`, and
the inclusion check MUST use the values from `sth_body`.

**Rule 7.3.2 (MUST).** `tree_version` is not restated at the top level, and a
verifier MUST ignore it if some producer adds it there. It is read from
`sth_body` alone (rule 5.3.3). A `tree_version` an attacker can set is a
`tree_version` they will set.

Skipping this is a complete break of the proof bundle, not a nicety. A forger
keeps a genuine `sth_body` and its genuine, untouched signature, and supplies the
root, path and leaf of a tree they built themselves. The Merkle walk succeeds
against the attacker's own root; the signature verifies over the real body; the
verifier reports that an event which was never sealed is "cryptographically
proven to be part of" a real checkpoint.

This was found while writing this specification, against the reference
implementation, and fixed. It is recorded here because the class of mistake
(verifying a proof against a value the proof itself supplies) is easy to repeat
in a reimplementation, and because a format specification that hides its own
history is not worth reading. The regression test is
`tests/test_verifier.py::test_substituted_merkle_root_fails`.

**Residual limitation (v1, not fixed).** `checkpoint_id` is absent from
`sth_body`, so the identifier a bundle displays is not covered by any signature:
a genuine proof can be relabelled with a different `checkpoint_id` and still
verify. What is signed is `subject` and `issued_at`, which is what actually
identifies the seal. Fixing this means adding a field to the signed body, which
changes the canonical bytes and so applies only to newly issued checkpoints
(§12). A verifier displaying `checkpoint_id` SHOULD show `sth_body.issued_at`
and `sth_body.subject` alongside it, and treat those as the authoritative
identity.

---

## 8. Continuity certificate

Answers "did governance ever stop?" over a range of checkpoints. Self-contained:
it carries the public key for every `key_id` it references, so it verifies with
no network access.

### 8.1 Structure

```
{
  "statement":  { ... the signed claim ... },
  "signature_hex": "...",          Ed25519 over canonical_bytes(statement)
  "key_id": "...",
  "public_keys": { "<key_id>": { "pem": "...", "revoked": false } },
  "cosignatures": { "<checkpoint_id>": [ ... §9.4 ... ] },   unsigned
  "anchors":      { "<checkpoint_id>": { ... §10 ... } }     unsigned
}
```

Those four are the only top-level keys. Everything else, including
`certificate_version`, sits **inside** `statement` so that the signature
covers it.

`statement` contains:

| Field | Meaning |
|---|---|
| `certificate_version` | Format version, e.g. `"1.0"` |
| `issued_at` | When the certificate was composed, ISO 8601 UTC |
| `subject`, `period`, `claim` | Human-readable scope and claim text |
| `checkpoint_window` | The checkpoint range the statement covers |
| `checkpoint_count` | Number of checkpoints in the range |
| `checkpoints` | Ordered array of `{checkpoint_id, sth_body, signature_hex, key_id}` |
| `linkage` | Array of links joining consecutive checkpoints (§8.2) |
| `linkage_status` | `proven`, `not_applicable`, … |
| `linkage_unbroken` | Boolean claim |
| `links_proven` | Integer claim |
| `coverage` | Obligation and event counts (§8.3) |
| `coverage_gaps` | Quiet periods with recorded reasons |
| `gap_summary` | Counts by classification |
| `linkage_problems` | Why linkage is not established, when it is not |
| `excluded_v1_checkpoints` | Pre-Merkle checkpoints in range, excluded from linkage |
| `excluded_checkpoints` | Reasoned exclusions, including withholdings (§8.4) |

### 8.2 Linkage

For each consecutive pair, the earlier checkpoint's sealed head must be proven
to be a leaf of the later checkpoint's tree. That is what makes "governance
never stopped" a proof: the later seal demonstrably contains the earlier one's
final state, so the chain did not restart, fork, or lose history between seals.

A link carries `from_checkpoint_id`, `to_checkpoint_id`, `sealed_head`,
`merkle_root`, `tree_size`, `leaf_index`, `proof_path`, `provable`.

**Rule 8.2.1 (MUST).** Every value used in the inclusion check MUST be taken
from the checkpoints' `sth_body`, never from the link's own restatement of it.
A link is unsigned convenience data; a proof verified against its own
restatement shows only that the link is self-consistent, which a forger arranges
trivially. The link's copies MUST be compared against the signed bodies and any
disagreement MUST fail.

**Rule 8.2.2 (MUST).** `len(linkage)` MUST equal `len(checkpoints) - 1`.
Otherwise a certificate claiming ten checkpoints can ship an empty linkage array
and pass vacuously. Related: `linkage_status == "proven"` with fewer than two
checkpoints MUST fail, and `links_proven` greater than `len(checkpoints) - 1`
MUST fail.

**Rule 8.2.3 (MUST).** The link's `leaf_index` MUST equal
`earlier.sth_body.length - 1`, and `earlier.length` MUST NOT exceed
`later.tree_size`. A chain that shrank between seals is a broken chain, not a
continuous one.

### 8.3 Coverage

The certificate reports obligation counts and quiet periods. These are claims
made by the issuer, so a verifier MUST re-derive them from the signed bodies
rather than accept them:

- `coverage.sealed_event_count` MUST equal the closing checkpoint's signed `length`.
- `coverage.events_added_in_period` MUST equal closing `length` − opening `length`.
- Each `coverage.obligations_in_period[k]` MUST equal
  `closing.continuity.obligations[k] − opening.continuity.obligations[k]`.
- Each `coverage.obligations_closing[k]` MUST equal `closing.continuity.obligations[k]`.
- Every reported gap MUST appear in the closing checkpoint's signed
  `continuity.coverage_gaps`. A certificate may narrow gaps to its window; it
  MUST NOT invent one, and MUST NOT drop one the seal recorded.

Gaps are a normal feature of a real record. A quiet fortnight on a small model
book is ordinary operation and is classified `normal_cadence`, not a fault. A
verifier MUST display gaps even when every check passes.

### 8.4 Withheld checkpoints

`excluded_checkpoints` lists checkpoints inside the period that the certificate
does not certify, each with a `reason`. Entries look like:

```
{
  "checkpoint_id": "...",
  "issued_at": "...",
  "reason": "v1_no_merkle_root" | "not_reproducible" | "signature_not_verifiable",
  "detail": "one sentence for a human",
  "quarantine": {          only for signature_not_verifiable
    "declared_by": "...", "declared_at": "...",
    "operator_reason": "...", "verification_failure": "..."
  }
}
```

The first two reasons describe a checkpoint that cannot be linked or
re-derived. `signature_not_verifiable` describes one whose signature does not
check out at all: the issuer could not repair it, because checkpoints are
append-only, and removed it from the certified set under an attributable
declaration.

**Rule 8.4.1 (MUST).** A verifier MUST report `signature_not_verifiable`
entries separately from the other reasons, with the full `quarantine` record,
and MUST NOT present any part of that record as something it verified. The
withheld checkpoint is not in the bundle to check.

**Rule 8.4.2 (MUST).** A `signature_not_verifiable` entry MUST NOT name a
`checkpoint_id` that also appears in `statement.checkpoints`, and its
`quarantine` object MUST carry all four fields. A checkpoint withheld on paper
while still counted, or withheld by nobody, MUST fail.

**Rule 8.4.3 (MUST).** The verdict MUST still rest on the checkpoints the
certificate carries (a withholding neither fails the certificate nor is
excused by it), and a passing verdict MUST state that its range was reduced,
with the count. A proof over a narrower set is still a proof, but a reader must
not be able to mistake it for one over the whole period.

---

## 9. Keys, revocation, and the trust boundary

### 9.1 The boundary

A bundle carries its own public keys, which is what makes offline verification
possible. It is also the limit of what the bundle can prove on its own:

> **A self-contained bundle proves internal consistency, not authorship.**
> Anyone can sign a fabricated statement with a key they generated and ship the
> matching PEM. Every cryptographic check will pass.

Two ways to close it, and a verifier MUST make clear which one is in force:

1. **Pin the key.** Supply the public key out of band (`--pubkey`). Signatures
   must then verify under the supplied key, so a self-signed forgery fails.
2. **Compare fingerprints.** Print `hex(SHA256(base64-decoded PEM body))` for
   every key used and compare it against Coriqo's published keyring
   (`GET /api/v1/checkpoints/public-keys`).

A verifier that reports PASS without stating which keys were used, and where
they came from, is giving a misleading verdict. The reference implementation
prints the fingerprints and an explicit note whenever keys came from the bundle.

`testdata/` contains the assertion of this limit as an executable test
(`test_self_signed_forgery_passes_unpinned`) so that it stays a documented
property rather than an assumption.

### 9.2 Revocation

A key entry may carry `"revoked": true`. A signature under a revoked key is
often still mathematically valid, which is exactly why:

**Rule 9.2.1 (MUST).** A signature under a revoked key MUST fail verification,
loudly, even when the signature is valid.

**Rule 9.2.2 (MUST).** Pinning a key MUST NOT clear a revocation. Supplying a
PEM says "this is the right key", not "ignore the revocation". Dropping the flag
when a key is pinned would make key pinning a way to launder a revoked
attestation.

#### Signed revocation records

The `revoked` flag is unsigned metadata the issuer sets, and it carries no
date. So a verifier that sees it has to refuse everything the key ever signed,
which means a key compromised on Tuesday retroactively destroys years of honest
evidence the same key produced while it was still good. That is the wrong
answer, and it is the answer Rule 9.2.1 alone gives.

A **signed revocation record** fixes it by making the revocation dated and
checkable. A certificate `statement` MAY carry a `revocations` array; a tenant
record bundle (§13) carries the same array in `keys/keys.json`. A bundle with no
revocations needs no entry at all, and a verifier has nothing to check.

Each entry is the canonical body the signer signed, plus the detached signature:

| Field | Meaning |
|---|---|
| `type` | Always `"key.revocation"`. Domain separation; see Rule 9.2.5. |
| `tenant_schema` | The tenant whose key is being revoked. |
| `key_id` | The key being revoked. |
| `effective_at` | ISO-8601 UTC instant from which the key stops counting. |
| `reason` | One of `compromise`, `rotation`, `decommission`, `policy`. |
| `signed_by_key_id` | The key whose signature covers this record. |
| `signature_hex` | Ed25519 over `canonical_bytes(entry without signature_hex)`, made by `signed_by_key_id`. |

**Rule 9.2.3 (MUST).** Where a verified revocation record exists for a `key_id`,
an attestation signed under that key MUST fail verification if its `issued_at`
is at or after the record's `effective_at`, and MUST NOT fail on account of the
revocation if its `issued_at` is strictly before it.

`issued_at` MUST be read from the **signed** body (`sth_body.issued_at`), never
from an unsigned envelope field. Reading it from anywhere else would let a
forger back-date a checkpoint past a revocation by editing a value no signature
covers.

The reference implementation compares the two as strings, the same way it
already compares two checkpoints' `issued_at` for monotonicity. That is sound
only while both spell the UTC offset identically: `…T00:00:00+00:00` and
`…T00:00:00Z` are the same instant but not the same string, and `+` sorts
before `Z`, so a producer that emitted one form for revocations and the other
for checkpoints could tie-break wrongly at exactly equal instants. Coriqo emits
`+00:00` on both. This document does not yet pin a single form. This is a known gap,
carried to the same place §9.3's `prior_event_hash` gap is carried.

Where several verified records name the same `key_id`, the **earliest**
`effective_at` governs. Taking the latest would let anyone able to append a
record un-revoke the window between two dates and re-validate attestations an
earlier record had already excluded; taking the earliest means an appended
record can only ever tighten.

A certificate's own signature has no `issued_at` to compare, so a revocation of
the certificate's signing key fails the certificate outright. A certificate is
issued now, over a past range, by whoever currently holds the key, so it cannot
predate its own signer's revocation.

**Rule 9.2.4 (MUST NOT).** A verifier MUST NOT reconstruct the signed body from
a fixed field list. Take the entry as-is and remove only `signature_hex`. Same
reasoning as Rule 9.3.4: every other field is then covered, an unsigned field
cannot be stapled onto a genuine record, and a field added in a later version is
verified rather than silently ignored.

**Rule 9.2.5 (MUST).** The entry MUST carry `type` equal to `"key.revocation"`
inside the signed body, and its `signature_hex` MUST verify under
`signed_by_key_id`. A record that does not verify, names a signer whose public
key is unavailable, or carries the wrong `type` MUST fail the run. It MUST NOT
be skipped, and MUST NOT be downgraded to "no revocation known", which would
make a malformed record strictly better for a forger than an honest one.

The signer key is resolved **without** applying the revocation flag to it.
A self-revocation is signed by the key being revoked, necessarily (that is the
case where no successor exists), so applying the flag there would make the only
record capable of establishing a revocation impossible to check.

**Rule 9.2.6 (MUST).** Where no verified record exists for a `key_id`, Rule
9.2.1 applies unchanged: an unsigned `revoked: true` flag refuses every
attestation under that key, at any date. The flag has no date to bound the
distrust with, so the whole key is refused. The absence of a record is never
read as evidence that a key is live.

**Who signs a revocation.** The successor key when one exists, otherwise the
revoked key itself. The usual reason to revoke is compromise, and requiring the
compromised key to sign its own revocation would make the one action you most
need after a compromise the one action you can no longer perform. Self-signed
revocation is the weaker form, and honestly so: a signature by the revoked key
is evidence only if it was made while the key was still good, which is what
`effective_at` records. A verifier reports which form it saw and does not treat
them as equivalent.

**What this does not do.** `effective_at` is a signed claim about when a key
stopped being trustworthy, not proof of it. A holder who back-dates a revocation
can invalidate their own genuine attestations after the fact; the record shows
who asserted the date, not that it was true. External time (§10) is what would
bound that, and it is not bound here.

**Known gap: the signer's authority to revoke is not checked.** Rule 9.2.5
verifies that `signed_by_key_id` really made the signature. It does not
establish that this key was ever entitled to speak for `key_id`. On an unpinned
run, where §9.1 already warns the bundle only proves internal consistency,
anyone assembling a bundle can add a key of their own, plus a self-signed
revocation of the genuine signing key, and fail every checkpoint in it. The
result is denial, not forgery: this cannot make a false record verify, only a
true one fail. Pinning with `--keyring`/`--pubkey` closes it, because an
attacker's key is then not among the keys a revocation may be checked against.

Closing it properly means requiring that a revocation's signer be reachable
from the revoked key through a verified `succession` chain (§9.3), which is a
format change rather than a verifier change: it needs the certificate to carry
enough of the key history to walk. Carried to the same place §9.3's
`prior_event_hash` gap and the offset-format question are carried. Until then a
verifier SHOULD state, as the reference implementation does for keys generally,
that an unpinned run took its revocation records from the bundle itself.

### 9.3 Multiple keys, and key succession

A certificate's checkpoints can span more than one `key_id`. Two things produce
that: per-tenant signing keys with rotation, and a **custody transfer**: an
engagement moving from the validator that produced it to the bank that owns it,
where signing authority for the chain moves with it.

**Keyring pinning.** `--keyring` names one PEM per `key_id` (a directory of
`<key_id>.pem` files, or a JSON file mapping `key_id` to PEM text) instead of
the single unnamed PEM `--pubkey` supplies. The two combine: a named
`--keyring` entry wins for that `key_id`; `--pubkey` covers any `key_id`
`--keyring` does not name. A `key_id` covered by neither is refused, per §9.1
rule 1. The whole point of pinning is that an unlisted key does not fall back
to trusting the bundle's own copy of itself.

**Key succession.** A certificate `statement` MAY carry a `succession` array. A
certificate whose checkpoints share one `key_id` throughout needs no
`succession` entry at all, and a verifier has nothing to check.

Each entry is the canonical body the **outgoing** key signed, plus the detached
signature over it:

| Field | Meaning |
|---|---|
| `type` | Always `"key.succession"`. Domain separation; see Rule 9.3.3. |
| `tenant_schema` | The tenant whose chain is being handed over. |
| `outgoing_key_id` | The key giving the chain up; the key that signs this record. |
| `incoming_key_id` | The key receiving it. |
| `effective_at` | ISO-8601 UTC instant the handoff takes effect. |
| `prior_event_hash` | The chain head immediately before the succession event. |
| `reason` | Free text, e.g. `"custody_transfer"`. |
| `signature_hex` | Ed25519 over `canonical_bytes(record without signature_hex)`, made by `outgoing_key_id`. |

**Rule 9.3.1 (MUST).** A change of `key_id` between two consecutive checkpoints
in a certified range, with no `succession` entry naming that exact
`outgoing_key_id` → `incoming_key_id` pair, MUST fail verification. An
unexplained key change is not evidence the chain kept its own author; it is
exactly what a bundle stitched together from two unrelated signing keys would
also look like. `outgoing_key_id` MUST equal the `key_id` of the checkpoint
*before* the change and `incoming_key_id` the `key_id` of the one *after*: a
record naming some other pair explains some other handoff, and leaves this one
unexplained.

**Rule 9.3.2 (MUST).** The matching entry's `signature_hex` MUST verify as an
Ed25519 signature by `outgoing_key_id` over `canonical_bytes(entry)` with
`signature_hex` removed, resolving that key exactly as §9.1/§9.2 resolve any
other key (pinned PEM wins; an unpinned run falls back to the bundle's
`public_keys`). An absent or invalid signature MUST fail the certificate.

Without this rule the handoff is a claim by whoever assembled the bundle. A
party holding only the **incoming** key can take the outgoing party's genuine
signed checkpoints (a certificate is handed to examiners, so they are not
secret), append their own checkpoints under their own key, and assert the pair
themselves. Every other check in this specification passes on such a bundle:
the old checkpoints really were signed by the old key, the new ones really were
signed by the new key, and the Merkle links between them can be constructed by
the forger, since they control the later tree. The outgoing key's signature over
the record is the only thing that distinguishes a handoff from a hijacking.

The enclosing certificate signature (§8) does **not** supply this. After a
transfer the incoming holder is the party issuing certificates, so the
statement, `succession` array included, is signed by the incoming key by
design.

**Rule 9.3.3 (MUST).** The entry MUST carry `type` equal to `"key.succession"`,
inside the signed body. Without it, a signature the outgoing key made over some
*other* structure that happens to carry `outgoing_key_id` and `incoming_key_id`
fields could be replayed here as a handoff that party never authorised.

**Rule 9.3.4 (MUST NOT).** A verifier MUST NOT reconstruct the signed body from
a fixed field list. Take the entry as-is and remove only `signature_hex`. Every
other field is then covered by the signature, so an unsigned field cannot be
stapled onto a genuine record, and a field added in a later version is verified
rather than silently ignored.

### 9.3.5 Bundle-dir binding closes the replay gap: bound to a *signed* chain, not merely a self-consistent one

A bare certificate (§8, `--proof`/`--certificate`) never carries the
`governance_events` rows themselves, only the checkpoints and the
succession statement. That is exactly why the replay above works: nothing
in a certificate ties a genuine succession record to one specific chain,
so a bundle stitched from two chains that both once used the outgoing key
looks the same as an honest transfer.

A tenant record bundle (§13) is different: it carries
`events/<version_id>.jsonl` for the subject a version-scoped certificate
covers. Key rotation and custody
transfer both append the succession as a real `GovernanceEvent` (`action
= "key.succession"`) into that exact chain at the moment of the actual
handoff, with the same body the outgoing key signed (plus
`signature_hex`) sitting verbatim in the event's `notes`.

**A first draft of this rule proved too little, and a fabricated bundle
verified clean under it.** Matching a `key.succession` row in
`events/<version_id>.jsonl`, and confirming that file's own
`prev_hash`/`event_hash` chain re-derives cleanly (§13.4 step 4), only
proves the succession statement agrees with a row inside a file that
*hash-chains internally*, a file whose entire content the party
assembling the bundle controls. A forger can discard the real history,
write whatever events they like, paste a genuine signed succession
record's `notes` in verbatim, and re-chain `prev_hash`/`event_hash` from
genesis: every check that looks only at that file's internal consistency
passes such a forgery, because "hash-chains cleanly" and "is the history
that produced a signature" are different claims. **Chain-linked is not
signed-over**, and an earlier version of this section conflated the two.
A review found the flaw by running exactly this fabrication against this
repository's own fixture: three fabricated events plus the genuine
`key.succession` row pasted in verbatim, re-chained from genesis, passed
every check that stopped at chain-linkage.

**What actually ties `events/<version_id>.jsonl` to something a forger
cannot fabricate is §13.4's checkpoint signature.** Each checkpoint's
Ed25519 signature covers `merkle_root` inside `sth_body` (§6/§7.3): a
value the checkpoint's own signing key committed to at seal time, over
the exact ordinal-ordered leaf set that existed then. A forger without
that key can make their fabricated file hash-chain cleanly, but cannot
make its leaves reproduce a *pre-existing* signature's root; the two
would have to already agree before the signature was made.

**Two further rounds of chain-guard review found that "recompute the
root" alone still had two holes, each closed here.** First: the
recomputation was made conditional on the checkpoint's own `quarantine`
field (unsigned, operator-set metadata a forger can write freely), so a
forged bundle that added one JSON key (`"quarantine": {...}`) to its
fabricated checkpoint skipped recomputation entirely and verified clean.
Quarantine means "this checkpoint's *signature* is not to be trusted" (the
public key may genuinely be gone); it
has never meant "do not check whether the claimed root reproduces," and a
forger being able to switch off an integrity check by setting an unsigned
field is precisely the bug. Second: recomputing the root only proves the
*set of leaf hash strings* reproduces the signed value. It says nothing
about whether a given leaf's `event_hash` actually matches that event's
own content. A forger who leaves a genuine `event_hash`/`prev_hash`
untouched (so the root recomputes identically) but rewrites the
underlying event's `action`/`notes`, while marking that one row
`content_hash_verifiable: false` to dodge §13.4 step 4's own
(flag-gated) re-derivation, passed both the root check and a
succession-binding check that only compared parsed fields. Chain-linked
is not signed-over, and reproducing a root is not the same as reproducing
that root from CONTENT that still matches its own claimed hash.

**Rule 9.3.5a (MUST, `--bundle-dir` mode only, unconditional on
quarantine).** For every checkpoint in the bundle carrying a
`merkle_root`, regardless of that checkpoint's `quarantine` field, the
verifier MUST recompute the root from the ordinal-ordered `event_hash`
leaves in `events/*.jsonl` (a version-scoped checkpoint's leaves come only
from that version's file; an org_default checkpoint's, no `version_id`,
are every version's events combined, in one global ordinal order, per
the Coriqo server's checkpoint issuer) under the
tree construction the checkpoint declares (`tree_version` 1 or 2), and
compare it to the value inside that checkpoint's signed `sth_body`. A
mismatch MUST fail the bundle, distinctly from the chain-linkage failure
in step 4, and quarantine status MUST NOT suppress this check or its
failure.

**Rule 9.3.5b (MUST, `--bundle-dir` mode only).** A checkpoint's
recomputed-and-matching leaves count as trust-establishing evidence for
Rule 9.3.5c below only when that SAME checkpoint's own Ed25519 signature
also independently verified (§13.4 step 3). A quarantined or
signature-failed checkpoint whose root nonetheless recomputes correctly
proves nothing, since the party assembling the bundle controls both the
events file and this unsigned `merkle_root` field and can trivially make
them agree. The verifier accumulates a set of "trusted leaf hashes":
every `event_hash` that appears in the leaf range of at least one
checkpoint (version-scoped or org_default; either counts, per Rule 9.3.5a)
satisfying both this rule and 9.3.5a.

**Rule 9.3.5c (MUST, `--bundle-dir` mode only).** For every entry in a
version-scoped certificate's `statement.succession`, the bundle MUST
contain a `key.succession` event in `events/<version_id>.jsonl`, matched
first by the `outgoing_key_id`/`incoming_key_id` pair, satisfying ALL of:

1. its parsed `notes` agree with the signed record on every other field
   (`tenant_schema`, `effective_at`, `prior_event_hash`, `reason`,
   `type`);
2. its `event_hash`, recomputed from that row's OWN current content
   (**unconditionally, regardless of that row's `content_hash_verifiable`
   flag**), equals its stored `event_hash`. That flag discloses
   *historical* non-reproducibility (a seeded/legacy row predating the
   current hash formula); it is never a license to skip checking the one
   row a succession claim depends on, and treating it as one is exactly
   the second bypass described above;
3. that `event_hash` is a member of the trusted-leaf-hash set built under
   Rule 9.3.5b.

A succession record with no candidate event satisfying all three, or
whose only candidate(s) fail any one of them, MUST fail the bundle.
Checks 1 and 2 alone are insufficient even together: a forger can write a
correctly self-consistent, correctly-hashed, correctly field-matching
event that was simply never covered by any checkpoint's signed watermark
at all (appended past the last real seal). Check 3 is what requires the
event to have actually been part of a signature the outgoing party's key
(or the tenant's current key, for org_default) committed to.

**What a passing 9.3.5a/b/c set together prove, precisely:** the
`key.succession` event that matches the certificate's signed succession
record (1) is byte-for-byte the content that produced its own stored
hash, not content rewritten after the fact, and (2) is part of the exact
leaf set a checkpoint whose OWN signature independently verified
committed to at seal time, not merely part of a file that hash-chains
without contradiction, and not merely a well-formed row an unsigned
`quarantine` or `content_hash_verifiable` flag tried to wave through
uninspected. That is what makes the event's position in the chain
trustworthy rather than an unverified claim the bundle makes about
itself, and it is what closes the splice in §9.3's disclosure: B cannot
make a fabricated or repositioned chain reproduce A's or B's own
pre-existing signed root, under a signature that also independently
verifies, without holding the key that made it, and cannot rewrite an
event's content without its own re-derived hash disagreeing with what was
actually signed over.

This closes the gap **for `--bundle-dir` mode only**. `--proof` and
`--certificate` carry no `events/*.jsonl` to bind against, so the
disclosure below still applies to them unchanged. It also does not
extend beyond an unpinned bundle's inherent limit (§13.4 step 3's own
warning): a bundle verified without `--keyring`/`--pubkey` trusts the
keys it ships with itself, so a checkpoint "independently verifying"
under those same self-supplied keys still proves internal consistency,
not who issued it. Pin real keys to get the stronger claim.

**What this checker does not do**, deliberately, and what a reader must not
infer from a passing `key succession` line:

* It does **not** check `prior_event_hash` against anything, **in
  `--proof`/`--certificate` mode**. That leaves one real gap in those two
  modes. The value is signed, so it cannot be altered, but nothing in a bare
  certificate ties it to the checkpoints in the bundle, which makes a genuine
  record **replayable**: one real A → B handoff lets B present *any* chain A
  ever signed as a chain A gave them, by splicing B-signed checkpoints onto
  A's genuine ones and attaching the real record. Binding the two from the
  certificate alone is not possible: `prior_event_hash` is the chain head
  the succession event was appended after, while the last outgoing-key
  checkpoint seals a head that already includes that event, and any number of
  ordinary events can sit between the two, so requiring the two values to
  match would reject honest transfers. **This gap is closed in `--bundle-dir`
  mode** (see §9.3.5), because a tenant bundle carries the actual
  hash-chained `events/<version_id>.jsonl`, not just the certificate's
  claims about it. It is still open for `--proof` and `--certificate`,
  which never see that file; closing it there would need the certificate
  itself to carry the succession event's own position in the chain, which
  is a format change, not a verifier change.
* It does **not** check `effective_at` against the surrounding checkpoints'
  `issued_at`. A record signed today can name any effective date; the signature
  proves the outgoing key asserted it, not that it was true.
* It does **not** check who authorised the transfer on either side. There is no
  approver identity in the record, so a compromised outgoing key produces a
  succession that verifies. Key compromise is handled by revocation (§9.2), not
  here.
* It does **not** check that the incoming key was live, or that the outgoing
  key was not already revoked at `effective_at`; only the current revocation
  flags, via the checkpoint signature checks those keys also appear in.

What a passing check does prove, and no more: the party that held the outgoing
key signed a statement naming this successor. Which chain that statement was
meant for is not established here; see the `prior_event_hash` point above.

### 9.4 Witness cosignatures (PROVISIONAL)

A checkpoint may be cosigned. A **witness** (the organisation itself, an
audit firm, a bankers' league) generates its own Ed25519 keypair and hands
over only the public half, then signs **byte-for-byte the same
`canonical_bytes(sth_body)`** the checkpoint signature covers:

```
cosignature = Ed25519_sign(witness_private_key, canonical_bytes(sth_body))
```

It answers a question the checkpoint signature cannot. Coriqo signs on the
organisation's behalf and can reach that private key at sign time; it cannot
reach a witness's. So a cosignature is the one signature in a bundle Coriqo
could not have produced alone.

**This is additive and lives outside every signed body.** A cosignature is a
signature *over* `sth_body`, so cosignature metadata inside `sth_body` would
be circular as well as breaking. On a proof bundle it is the top-level
`cosignatures` array; on a certificate it is a top-level `cosignatures`
object keyed by `checkpoint_id`, a sibling of `statement` and never a member
of it. Both are unsigned, the same trust class as the restatements §7.3
warns about.

| Field | Type | Meaning |
|---|---|---|
| `witness_key_id` | string | The witness's public handle. This is the name a pinned PEM is filed under |
| `witness_label` | string \| null | Display name. Display only |
| `signature_hex` | string | Ed25519 over `canonical_bytes(sth_body)`, hex |
| `signed_at` | string \| null | ISO 8601 UTC. Display only; not covered by anything |
| `witness_relationship` | string | `self` \| `independent` \| `unknown`. A **claim**, see 9.4.2 |
| `revoked` | boolean | The issuer's claim that this witness key is no longer live |

**No witness public key appears in the bundle, by design.** §9.1 explains why
a bundle that carries its own key proves internal consistency and not
authorship. For a *witness* key there is no weaker-but-useful mode at all: a
witness key handed to you by the party being witnessed witnesses nothing. So
the key never travels with the bundle, and the reference implementation would
not use it if it did.

#### Rule 9.4.1 (MUST): pin, or report UNVERIFIED

A cosignature MUST be verified only against a public key supplied out of band
by the verifier's operator (`--witness-keyring` / `--witness-pubkey`, the same
two forms `--keyring` / `--pubkey` take for signing keys). A verifier MUST NOT
fall back to any key in the bundle, and MUST NOT fetch a witness key from
Coriqo at verify time. A cosignature checked against a key the witnessed
party supplied at verify time is not evidence.

A cosignature with no pinned key is **UNVERIFIED**. Never "verified", and
(the failure that matters) never rendered as though no cosignature existed.

#### Rule 9.4.2 (MUST): independence is never inferred from the bundle

`witness_relationship` is unsigned metadata produced by the party under
scrutiny. A verifier MUST NOT report a cosignature as independently witnessed
on the strength of that field alone; the operator must name the witness
(`--independent-witness <witness_key_id>`).

The label may only ever **downgrade**. A witness the bundle itself calls
`self` stays self-witnessed even when the operator declares it independent;
the disagreement is reported, and the weaker of the two claims stands.

Self-witnessing is a real and useful control: it means Coriqo cannot author
the organisation's history unnoticed. It is not third-party audit, and a
verifier that renders one as the other has answered the wrong question.

#### The four states

A verifier MUST distinguish, per checkpoint, and MUST NOT collapse any pair:

| State | When | Verdict effect |
|---|---|---|
| **no cosignature** | `cosignatures` absent or empty | none |
| **self-witnessed** | verifies under a pinned key; operator did not declare it independent | none |
| **independently witnessed** | verifies under a pinned key the operator declared independent | none |
| **UNVERIFIED** | present, but no key pinned for it, or `revoked: true` | none |

A cosignature that IS pinned and does NOT verify is a **hard failure**
(rule 9.4.3).

#### Rule 9.4.3 (MUST): fail closed on a cosignature that does not verify

If a witness key is pinned for a cosignature and the signature does not
verify under it, the verifier MUST fail, loudly. It MUST NOT downgrade to
UNVERIFIED, and MUST NOT keep a PASS verdict on the rest of the bundle.

A `cosignatures` field of an unexpected shape MUST also fail rather than be
skipped. A field an attacker can get ignored is a field an attacker will
malform.

#### Rule 9.4.4 (MUST NOT): a cosignature never rescues a checkpoint

The PASS/FAIL verdict on inclusion and on the checkpoint signature is
unchanged by any cosignature. Cosignatures are additive: a checkpoint is
complete and verifiable on Coriqo's own signature the moment it is issued.

#### Revocation, and why it differs from 9.2.1

`revoked: true` downgrades a cosignature to UNVERIFIED. It does **not** fail
the run, which is the opposite of rule 9.2.1 for signing keys. A signing key
is what the artifact rests on, so a revoked one poisons it; a cosignature is
additive, so failing the run would let revoking a witness retroactively break
every proof bundle issued while that witness was live. The claim goes away;
the checkpoint does not.

The asymmetry that keeps this safe: `revoked: true` is a downgrade and is
honoured. The **absence** of the flag is never read as evidence that a key is
live.

#### Why PROVISIONAL

Marked **PROVISIONAL** for the same reason §9.3 is: the shape of the record
that establishes a witness's independence does not exist yet. Today
independence is asserted by the operator on the command line, which is
honest (the operator is the one who knows where they got the key), but it is
not attestable, and two operators can reach different verdicts on the same
bundle. When a registry of witnesses with verifiable, signed provenance
lands, this section and the reference implementation should be tightened to
check it. Until then, "the operator pinned this key and vouched for it" is
the full extent of the independence claim, and the report says so.

---

### 9.5 Passkey countersignatures (PROVISIONAL)

A countersignature is a WebAuthn assertion by a person at the organisation,
made with their passkey when they signed in, over one checkpoint head. It is
the organisation's own signature over its record with a key the operator never
held, and it is additive in the same way as a witness cosignature (§9.4): it
never changes a checkpoint's verdict.

**9.5.1 Where it travels.** An inclusion proof bundle carries
`countersignatures`, a list; a continuity certificate carries
`countersignatures`, an object keyed by `checkpoint_id`. Both sit outside every
signed body. Each entry:

| field | meaning |
|---|---|
| `format` | `webauthn-countersign-v1` |
| `signer` | the person's username (display only, unsigned) |
| `key_fingerprint` | `sha256:` + hex SHA-256 of the key's SubjectPublicKeyInfo DER |
| `public_key_pem` | the passkey public key, as stored by the operator |
| `algorithm` | `es256`, `ed25519` or `rs256` |
| `rp_id` | the WebAuthn relying party id |
| `nonce` | hex, 16 random bytes |
| `authenticator_data`, `client_data_json`, `signature` | base64url, exactly as the browser returned them |

**9.5.2 The challenge.**
`challenge = SHA-256("coriqo-countersign-v1" || 0x0A || SHA-256(canonical_bytes(sth_body)) || nonce)`.

**9.5.3 Checking one entry.** A verifier MUST check, in order:
`client_data_json` parses as JSON with `type == "webauthn.get"` and
`challenge == base64url(challenge)` (no padding); `authenticator_data[0:32] ==
SHA-256(rp_id)`; flags byte `authenticator_data[32]` has UP (0x01) and UV
(0x04) set; and `signature` verifies over `authenticator_data ||
SHA-256(client_data_json)` under the key, per `algorithm` (ES256: ECDSA P-256
SHA-256, DER signature; RS256: PKCS#1 v1.5 SHA-256; Ed25519: raw).
`key_fingerprint` MUST equal the fingerprint of `public_key_pem`.

**9.5.4 Whose key.** The operator stores the passkey public keys, so a key
carried in the bundle shows only that the bundle is self-consistent. A
verifier SHOULD accept a pinned keyring from the organisation (the
`--countersign-keyring` file, `{fingerprint: PEM}`, `_`-prefixed keys
ignored) and report an entry as BANK-COUNTERSIGNED only when its key is
pinned there. An entry that is present and fails any check in 9.5.3 is a
failure, pinned or not.

**9.5.5 What it does not prove.** The operator serves the sign-in page, so
it could ask a person to countersign a forged head. It cannot rewrite a head
that was already countersigned without breaking the append-only consistency
that §5 and the public anchor (§10) check. Records sealed after the last
countersignature rest on the operator's signature and the anchor alone.

## 10. Public transparency-log anchor

A bundle may carry an `anchor` object recording publication of the signed tree
head to Sigstore Rekor, a public append-only log Coriqo does not operate.

| Field | Meaning |
|---|---|
| `status` | Anchor state |
| `rekor_uuid` | Entry UUID |
| `rekor_log_index` | Log index |
| `rekor_url` | Log base URL, default `https://rekor.sigstore.dev` |
| `anchored_at` | ISO 8601 UTC |

**The anchor is informational and MUST NOT affect the PASS/FAIL verdict.** The
offline checks stand alone; anchoring adds an independent witness that the
checkpoint existed no later than the log's `integratedTime`. A verifier that
fails because Rekor was unreachable has made offline verification conditional on
being online, which defeats the purpose.

To confirm an anchor manually: the Rekor entry is a `hashedrekord` whose
artifact SHA-256 equals `SHA256(canonical_bytes(sth_body))`, with a signature
and public key matching the bundle's.

### 10.1 Reported external time

`anchored_at` is Rekor's own `integratedTime` for the entry, carried into the
bundle at anchor time. It is external to Coriqo's app clock, which is the point of
anchoring at all: a server that cannot back-date its own checkpoints can still
be dishonest about issued_at unless something outside it corroborates a time.

A verifier MAY print this value (labelled `External time` for a single
checkpoint, or `Externally attested since <earliest>` across a certificate
covering several) as a convenience. This remains **reported, not verified**:
unless the verifier fetches and checks a Rekor inclusion or consistency proof
against the entry, `anchored_at` is exactly as trustworthy as the rest of the
bundle's own claims, that is, trustworthy conditional on the bundle not having
been tampered with, which is what the PASS/FAIL checks in §7.2/§9 establish
independently. Printing it does not, and MUST NOT, change the verdict; it is
strictly additional context alongside the manual-confirmation steps above.

### 10.2 A second, independent time source: RFC 3161 TSA

A checkpoint's `tsa` object (proof bundles) or a certificate's
`tsa_timestamps` map (keyed by `checkpoint_id`) may carry an RFC 3161
Time-Stamp Authority token: a second external time source, operated by a
different party than Sigstore Rekor, over the same artifact:

    artifact = SHA256(canonical_bytes(sth_body))

| Field | Meaning |
|---|---|
| `status` | `pending` \| `timestamped` \| `failed` \| `disabled` |
| `tsa_token` | base64-encoded DER `TimeStampResp` |
| `tsa_gen_time` | the TSA's own `genTime` for the token, ISO 8601 UTC |

**Two independent time sources are harder to fake in agreement than one.**
Rekor and a TSA are operated by different organisations with different
incentives; a checkpoint corroborated by both has two parties that would
have to collude (or be compromised) to produce a false early timestamp,
where one source alone requires only one.

**Verification, exactly like §10's Rekor anchor:**

1. Decode the DER `TimeStampResp` and its embedded `TimeStampToken`.
2. Recompute `SHA256(canonical_bytes(sth_body))` and confirm it equals the
   token's `messageImprint.hashedMessage` (with `hashAlgorithm` SHA-256). A
   mismatch means the token was minted over different bytes than this
   checkpoint's. It is reported, and MUST NOT be silently accepted.
3. Verify the token's CMS signature against its own embedded signing
   certificate (RSA/PKCS1v15 or ECDSA, dispatched on the certificate's key
   type; a general-purpose TSA may sign with either, and treating one as
   the other always fails).
4. **Optionally**, with `--tsa-ca <bundle>` (a PEM file of trusted CA
   certificates), confirm the signing certificate's own signature verifies
   under one of the pinned CAs (issuer-name + signature match; not a full
   RFC 5280 path-build to a root, OCSP, or CRL check; it is sufficient to confirm
   "this cert was issued by a CA the operator chose to trust" without
   pulling in a general PKI validation library for a check that, per the
   rule below, can never fail the run either way).

**The TSA timestamp is informational and MUST NOT affect the PASS/FAIL
verdict**, for the identical reason given in §10 for the Rekor anchor: the
offline checks stand alone, and a verifier that fails because a TSA (or its
CA bundle) was unavailable has made offline verification conditional on
network or configuration state, which defeats the purpose. Without
`--tsa-ca`, the tool reports "TSA token present, CA not pinned — not
verified" rather than either a false PASS or a verdict-affecting failure.

**Reported, not verified, same discipline as §10.1**: `tsa_gen_time` is the
TSA's own claim, corroborated only to the extent steps 1-4 above actually
ran (an unpinned CA leaves step 4 unconfirmed). A verifier MAY combine it
with Rekor's `anchored_at` and print the **earliest of the two that
verified** as the strongest single external-time claim the bundle supports
("Externally attested since <earliest>"). This is exactly the `min()`
this tool already applies
across multiple Rekor anchors in a certificate, extended across sources.

**Test vectors**: `testdata/proof_tsa.json` is `proof.json` plus a real
FreeTSA token minted over that exact bundle's `sth_body`, with the CA
certificate checked in at `testdata/tsa/freetsa_ca.pem`, MUST verify
(message imprint matches, signature valid, chains to the bundled CA).
`testdata/proof_tsa_tampered.json` is the same bundle with `sth_body.length`
incremented by one after the token was minted: the messageImprint
correctly reports MISMATCH, and the run still fails overall on the
resulting Ed25519 signature check (§7.2), never on the TSA mismatch alone.

---

## 11. Conformance

`testdata/` is the conformance corpus, regenerated by `tests/make_corpus.py`:

| File | Contents |
|---|---|
| `events.json` | A five-event chain, including a real 77-day quiet period |
| `proof.json` | Inclusion proof for event 2 under `tree_version` 1, MUST verify |
| `proof_v2.json` | Inclusion proof for event 4 under `tree_version` 2, MUST verify |
| `certificate.json` | Two-checkpoint continuity certificate, MUST verify |
| `pubkey.pem` | The corpus signing key: a test key, fixed seed, no relation to any Coriqo key |
| `proof_cosigned.json` | `proof.json` plus two genuine cosignatures (§9.4), one labelled `self`, one `independent`. Same `sth_body` and same `checkpoint_signature`, byte for byte |
| `proof_cosign_tampered.json` | The same bundle with one byte flipped in the self-witness signature. MUST fail under a pinned witness key |
| `certificate_cosigned.json` | `certificate.json` plus per-checkpoint `cosignatures` and `anchors`, outside `statement`. `cp-2026-q1` is deliberately left uncosigned |
| `witness_keyring/` | The two witness public keys, the operator's copy: test keys, fixed seeds |

The chain is five events on purpose. Five is not a power of two, so the two tree
constructions genuinely differ over it; at 2, 4 or 8 leaves they produce the
same root and the corpus would distinguish nothing (§5.2.2).

`proof_v2.json` proves the **last** leaf, whose RFC 6962 audit path is a single
hash where a five-leaf version-1 tree always needs three. It therefore fails
outright under Rule 5.3.1, which is the point: an implementation that applies
that rule to version 2 will reject this bundle, and will reject honest proofs in
production for the same reason.

`make_corpus.py` is written against this document rather than against Coriqo's
source, and imports nothing from Coriqo. It is a second implementation on
purpose: if it and `verify_proof.py` disagree, this specification is wrong or
incomplete, and `tests/test_verifier.py::test_corpus_regenerates_byte_for_byte`
is what catches that.

`proof_cosigned.json` and `proof.json` differ in exactly one top-level field.
That is the point: attaching a cosignature must not move one byte of what any
signature covers, so the two files carry the same `sth_body` and the same
`checkpoint_signature`, and the corpus asserts it
(`test_cosigned_bundle_carries_the_same_signed_body_as_the_uncosigned_one`).
`certificate_cosigned.json` makes the same claim for `statement`.

A conforming implementation MUST verify the clean corpus bundles, and MUST
reject every mutation in `tests/test_verifier.py`, currently forty-odd cases
covering leaf tampering, path reordering and truncation, key substitution,
revocation, checkpoint removal, vacuous linkage, backdating, coverage
overstatement, substituted Merkle roots, unknown and unsigned `tree_version`,
version-2 paths that are too short or too long, and the §9.4 cases: a
tampered cosignature under a pinned witness key, a cosignature whose key was
never pinned, a bundle asserting independence the operator did not, an
operator asserting independence the bundle contradicts, a revoked witness
key, and a malformed `cosignatures` field.

---

## 12. Stability

Frozen for the lifetime of v1; changing any of these breaks artifacts already
issued:

- `canonical_bytes` (§3)
- The event hash field set and construction (§4.2)
- `0x00` / `0x01` prefixes (§5.1), and each tree construction once issued
  against (version 1 and version 2 are both permanent, §5.2)
- Ed25519 over `canonical_bytes(sth_body)` (§6)

Additive changes are permitted: new optional fields may appear in bundles, and a
verifier MUST ignore fields it does not recognise rather than fail. Note that
adding a field to a **signed** object changes its canonical bytes, so new fields
inside `sth_body` or `statement` only appear in newly issued artifacts.

Known issue carried by v1, recorded here rather than silently dropped: the
unsigned `checkpoint_id` on proof bundles (§7.3). It is contained by fields that
*are* signed.

`cosignatures` and `anchors` are additive under this rule and add nothing to
any signed object: they are metadata about already-signed artifacts, and a
verifier written before they existed keeps verifying bundles that carry them.
The reverse is not true and is not meant to be: such a verifier reports "no
cosignature" for a cosigned chain, which is why rule 9.4.1 spells out that
UNVERIFIED and absent are different answers.

Two others have been fixed, and both are kept in this document rather than
deleted, because a verifier will still meet artifacts issued under them:

- **Leaf ordering** (§5.5), fixed from `ordering_version` 2. Checkpoints sealed
  under version 1 cannot be repaired retroactively and are marked
  non-reproducible.
- **The duplicating tree** (§5.3), fixed from `tree_version` 2, which uses
  RFC 6962's construction. Version-1 checkpoints are *not* marked
  non-reproducible: they reproduce exactly, under the construction they were
  sealed with. They simply cannot be recomputed as version 2, and are not.

### 12.1 Spec version

This document carries a version, `MAJOR.MINOR`, currently `1.1` (1.1 added §19). A JSON bundle
(inclusion proof, continuity certificate) states the version it was written to
in a top-level, unsigned `spec_version` string.

- **Absent** means `1.0`. Every bundle issued before the field existed is 1.0.
- **Same MAJOR, any MINOR**: a MINOR release only adds optional fields under the
  additive rule above. A verifier MUST check the bundle as normal and ignore the
  fields it does not know.
- **Different MAJOR**: a MAJOR release may change what an existing field means.
  A verifier MUST refuse to return PASS or FAIL for it, and MUST say which
  version the file declares and which version the verifier implements, so the
  reader knows to get a newer verifier rather than read the refusal as tamper.
- **Not `MAJOR.MINOR`**: refused the same way.

`spec_version` is unsigned on purpose. It only decides whether a verifier runs
at all; a forger who edits it can make a verifier refuse, never make it pass.
Every check after it is still anchored to the signed bodies.

The reference verifier prints `UNSUPPORTED SPEC VERSION: ...` and exits 1.

---

## 13. Tenant record bundle

A tenant that stops using Coriqo is entitled to leave with its record intact
and independently verifiable. DORA Art. 28 and the 2023 interagency
third-party guidance both require a documented exit for a critical ICT
vendor. This section defines that export: a single directory (optionally
zipped) that reproduces everything a continuity certificate and an
inclusion-proof bundle already prove piecemeal, plus the full leaf set
neither one carries, so nothing about verifying it depends on Coriqo still
running or still existing.

Format version: `tenant_bundle_v1`.

### 13.1 Layout

```
manifest.json
checkpoints/<checkpoint_id>.json
events/<version_id>.jsonl
access_events.jsonl                  (only when a read has been sealed, §4.5)
keys/keys.json
audit_log.jsonl
documents/manifest.json
documents/<document_id>              (only with --include-blobs, under the size cap)
verify_proof.py
SPEC.md
README.txt
```

### 13.2 `manifest.json`

```json
{
  "format": "tenant_bundle_v1",
  "tenant": "<tenant slug>",
  "generated_at": "<ISO 8601>",
  "subjects": ["org_default", "version:<id>", ...],
  "counts": {
    "checkpoints": <int>, "events": <int>, "keys": <int>,
    "audit_log_rows": <int>, "documents": <int>
  },
  "files": { "<relative path>": "<sha256 hex>", ... },
  "continuity_certificate": { ... full signed certificate bundle, §9 shape,
                               subject "org_default", unbounded range ... }
}
```

`files` covers every other file in the bundle by relative path, sha256 of
its bytes on disk, including `checkpoints/*.json`, `events/*.jsonl`,
`keys/keys.json`, `audit_log.jsonl`, and `documents/manifest.json`. A bundle
with a file missing from this map, or a map entry whose hash disagrees with
the file on disk, fails verification outright: an examiner must not be able
to trim or substitute a file without the manifest itself flagging it.

The `continuity_certificate` field is the reason a trimmed `manifest.json`
still gets caught even though the map lives in the same unsigned file it
describes: it is a full, Ed25519-signed continuity certificate (§9 bundle
shape) over the *whole* history for `org_default` (`from`/`to` omitted), so
every checkpoint the bundle claims to carry must also appear inside this
signed statement's `checkpoints` list, or verification fails. A manifest
edited to drop a checkpoint (or a whole event range) after the fact either
leaves the certificate's checkpoint list inconsistent with what's on disk
(caught by 13.4 step 2) or requires forging a new Ed25519 signature, which
requires the private key.

### 13.3 Other files

- `checkpoints/<checkpoint_id>.json`: the full `CheckpointOut` body for
  every checkpoint sealed for this tenant: signature, `merkle_root`,
  `tree_size`, `tree_version`, `ordering_version`, cosignatures, anchor
  fields (`anchor_status`, `rekor_uuid`, `rekor_log_index`, `anchored_at`),
  and `quarantine` when declared.
- `events/<version_id>.jsonl`: every `governance_events` row for that
  model version, one JSON object per line, in `ordinal` order (the total,
  append-only order the Merkle trees are built over, never `seq` or
  `created_at` alone, per §5.5). Each line carries every field
  `compute_governance_event_hash` hashes (`seq`, `actor`, `action`,
  `model_version_id`, `from_status`, `to_status`, `notes`, `prev_hash`,
  `oversight` when present) plus `event_id`, `event_hash`, `ordinal`, and
  `content_hash_verifiable`.
- `access_events.jsonl`: every sealed read (§4.5), one JSON object per
  line in `ordinal` order: the twelve hashed fields plus `event_id`,
  `ordinal` and `event_hash`. Present only when at least one read has been
  sealed; `manifest.json.counts.access_events` then gives the row count.
- `keys/keys.json`: every public key this tenant's checkpoints were ever
  signed under: `key_id`, PEM, `revoked` / `revoked_at`, `superseded_by`,
  and any `key.succession` GovernanceEvent notes payload for that key_id
  (the same verbatim shape §9.3 certificates embed), plus a `revocations`
  array of signed revocation records in the §9.2 shape, the same array a
  certificate carries at `statement.revocations`, so a bundle directory and
  a certificate are read by one implementation and cannot be judged
  differently.
- `audit_log.jsonl`: every `audit_log` row, one per line, ordered by
  `seq`, with free-text fields (`metadata_`, `user_agent`) passed through
  the Coriqo server's redaction step (the same redaction the rest of the product
  applies before free text leaves the tenant boundary).
- `documents/manifest.json`: `document_id`, `title`, `sha256`, `size_bytes`
  for every `documents` row, whether or not blobs are included.
- `verify_proof.py`, `SPEC.md`: byte-identical copies of the reference
  verifier and this specification, at the version the bundle was produced
  under, so verification needs nothing fetched over a network.
- `README.txt`: plain-language instructions for a bank's auditor: run
  `python verify_proof.py --bundle-dir .` from inside the bundle, with no
  network access and no Coriqo account.

### 13.4 Verification (`verify_proof.py --bundle-dir <path>`)

In order, stopping at the first failure:

1. Recompute the sha256 of every file `manifest.json.files` names and
   compare; any mismatch or missing file is a hard failure.
2. Verify `manifest.json.continuity_certificate` exactly as `--certificate`
   already does (§9), then confirm every checkpoint under `checkpoints/`
   appears in the certificate's `checkpoints` list (or its
   `excluded_checkpoints`, quarantined and disclosed). A checkpoint present
   on disk but absent from both is untrusted content smuggled past the
   signature and fails the bundle.
3. Verify each `checkpoints/<id>.json` signature under the key named in
   `keys/keys.json` when `--keyring` is not given (a warning, exactly as
   unpinned single-proof verification already warns) or under `--keyring`
   when given.
4. For each `events/<version_id>.jsonl`, recompute `event_hash` for every
   `content_hash_verifiable` row and confirm `prev_hash` linkage across the
   whole file in `ordinal` order, then confirm each checkpoint's
   `head_hash`/`merkle_root` for that subject is reproducible from the
   corresponding leaf range in the file.

4d. When `access_events.jsonl` is present or any checkpoint carries
   `access_log`: recompute every sealed read's hash, check each subject's
   `seq`/`prev_hash` links and that ordinals increase, then recompute each
   checkpoint's signed `access_log` root and size from the rows with
   `ordinal <= ordinal_watermark`. A root that does not reproduce fails; a
   root that reproduces under a checkpoint whose signature did not verify
   proves nothing and also fails. Reads after the newest signed watermark are
   reported as awaiting the next checkpoint.

5. For each package seal with record-wide fields (§6.2.3), recompute its
   governance-event heads and check its period fence (§6.2.5); report its
   other heads as signed, not checkable offline (§6.2.4). With `--snapshot`,
   also run §6.2.6.

Verdict wording is the existing house style: `CONTINUITY VERIFIED` when
every checkpoint the tenant issued is covered end to end, `CONTINUITY
VERIFIED OVER A REDUCED RANGE` when one or more checkpoints were excluded
under a disclosed quarantine but everything else
checks out, and a labelled failure otherwise. Quarantine disclosure in
`excluded_checkpoints` is carried into the bundle unchanged: a reduced
range is reported, never hidden.

### 13.5 Known limits

- `--include-blobs` is opt-in and capped by size; a bundle produced without
  it carries `documents/manifest.json` (id, title, sha256, size) but not
  the underlying files. An auditor can confirm what existed and its hash,
  not read the content, unless blobs were explicitly requested.
- A `v1` checkpoint (no `merkle_root`) or a checkpoint sealed under
  `ordering_version` 1 is bundled as-is and reported non-reproducible, the
  same distinction §12 already draws for a certificate; this bundle format
  does not retroactively fix either.

---

## 14. Global head log

Every tenant's Merkle chain lives in its own Postgres schema. Nothing outside
that schema records what a tenant's chain looked like at any given moment,
so a bank shown one chain and an examiner shown a different one for the same
subject could not detect the split from inside the product. `sth_hash` is
the same value Rekor already receives (`SHA256(canonical STH body)`), and
until now the only way to catch a split was both parties independently
checking Rekor for the same hash. This section adds a second, Coriqo-run
mechanism: a cross-tenant, append-only log of every issued checkpoint's
`sth_hash`, with RFC 6962 §2.1.2 consistency proofs between any two points in
its history.

### 14.1 What the log carries

One entry per checkpoint, across every tenant:

    seq              global, gapless sequence number
    tenant_id        public.tenants.tenant_id — NEVER a schema name or slug
    subject_hash     sha256(subject) — the subject string itself is tenant data
    checkpoint_id
    sth_hash         sha256(canonical STH body) — identical to what Rekor receives
    tree_size
    issued_at
    prev_entry_hash  entry_hash of the previous row (GENESIS "0"*64 for seq 0)
    entry_hash       sha256(canonical form of the fields above)

The log leaks no tenant identity to an unauthenticated reader: `tenant_id` is
an opaque id, and `subject_hash`/`sth_hash` are one-way. A reader who already
holds the plaintext subject or STH body (a bank, or an examiner the bank gave
it to) can confirm a match; nobody else learns anything from the log alone.

A separate Merkle tree (RFC 6962, tree_version 2; §5.3 of this document) is
built over `entry_hash` values in `seq` order. Periodically (see the
`checkpoint-head-log-seal` schedule), Coriqo signs a "log head" (the tree's
current root plus `tree_size`) under the deployment's GLOBAL key (never a
per-tenant key, since this asset spans every tenant) and best-effort anchors
it to Rekor, exactly as a tenant STH is anchored.

### 14.2 Public routes

    GET /api/v1/public/head-log/entries/{sth_hash}
    GET /api/v1/public/head-log/consistency?from_size=&to_size=

Both are unauthenticated and rate-limited. The first returns the entry for a
given `sth_hash` plus an inclusion proof against the latest signed head (or
the entry alone, with `log_head`/`inclusion_proof` both `null`, if the entry
exists but no head has been signed over it yet; see §14.3 on how a verifier
must report that). The second returns an RFC 6962 §2.1.2 consistency proof
between two log sizes, proving the smaller is an unmodified prefix of the
larger. This is what lets a bank (who saw the log at size `m` last week) and an
examiner (who sees it at size `n` today) confirm they are looking at
append-only extensions of the SAME log, not two different logs.

### 14.3 Verifying with `verify_proof.py`

    --head-log-proof PATH   [--expect-head STH_HASH] [--pubkey PEM | --keyring DIR]

`PATH` is a JSON file shaped like the `entries/{sth_hash}` response above.
The verifier checks:

1. If `--expect-head` is given, that the entry's own `sth_hash` matches it.
   This is the check that catches a split view: a bank hands an examiner an
   `sth_hash`, and the examiner passes that same hash here as `--expect-head`
   against whatever proof the bank (or Coriqo) hands them next. A mismatch
   means the examiner was shown a different checkpoint than the one named.
2. The inclusion proof, against the signed head's `root_hash` (RFC 6962
   §2.1.1, the same construction and code path as every other Merkle proof
   in this file).
3. The signed head's own Ed25519 signature, when a key for its `key_id` is
   pinned via `--pubkey`/`--keyring`. Without a pinned key this step is
   skipped and reported as such; the inclusion check alone still proves
   internal consistency, not who signed the head.

Verdicts: `PASS` ("public log agrees"), `FAIL` ("NOT in public log": a
forged entry, a forged proof, or an `--expect-head` mismatch), or
`NOT CHECKED` when the entry exists but no signed head covers it yet.
**`NOT CHECKED` must never be rendered or counted as a pass**. It means the
periodic seal has not caught up, not that the entry is verified.

### 14.4 In a tenant bundle (§13)

A tenant bundle built after this feature ships carries `head_log/`:

    head_log/entries.jsonl   this tenant's entries only, in seq order
    head_log/head.json       the latest signed log head at export time

`verify_proof.py --bundle-dir` extends its checks with one more, when
`head_log/` is present. Every `checkpoints/<id>.json` in the bundle must have
a matching `head_log/entries.jsonl` row by `checkpoint_id` (else: NOT IN
PUBLIC LOG, a hard failure). A bundle built with no `head_log/` at all
(issued before the head log existed, or exported before the tenant's first head-log entry) is reported
`NOT CHECKED` for this step and does not affect the bundle's overall verdict.

#### 14.4.1 Per-entry inclusion proofs

The signed head's root is over **every tenant's** entries (§14.1), and a
bundle carries only one tenant's, so the root cannot be rebuilt from the
bundle. (An earlier revision of this section required exactly that. It could
only pass on a log holding a single tenant, and was replaced by the check
below.) Instead, each entry line carries one more field:

    inclusion_proof   {"leaf_index": int, "tree_size": int,
                       "proof_path": [hex, ...]}   or   null

`inclusion_proof` is the RFC 6962 §2.1.1 audit path for leaf `seq` in the
tree over the first `tree_size` entry_hash values of the whole log, in seq
order: the tree `head.json` signs (tree_version 2, §5.3; leaf =
SHA-256(0x00 ‖ entry_hash bytes)). It is the same shape the public
`entries/{sth_hash}` route returns under `inclusion_proof` (§14.2), with
`proof_path` ordered leaf to root. It is `null` for an entry whose `seq` is
at or beyond `head.tree_size`, which the head was signed before.

For each entry the verifier:

1. Recomputes `entry_hash` from the entry's own fields, as §14.1 defines
   it: SHA-256 over the canonical JSON (sorted keys, no whitespace, UTF-8)
   of `seq, tenant_id, subject_hash, checkpoint_id, sth_hash, tree_size,
   issued_at, prev_entry_hash`. A mismatch is a FAIL.
2. If `seq < head.tree_size`: requires `inclusion_proof` with
   `leaf_index == seq` and `tree_size == head.tree_size`, and walks
   `proof_path` from the **recomputed** entry_hash to `head.root_hash`. A
   missing proof, a proof for another leaf or tree size, or a path that does
   not reproduce the root is a FAIL.
3. If `seq >= head.tree_size`: reports the entry **not yet checkable
   (issued after the latest signed head)**. This is shown, never counted as
   a pass, and is not a failure. It clears once the hourly head-log seal
   covers it and the bundle is exported again.

The head's signature is checked as in §14.3 step 3, when a key for its
`key_id` is pinned via `--keyring`/`--pubkey`. `PASS` ("public log agrees")
requires at least one entry verified by step 2, no FAIL from steps 1-2, and
no signature failure. If every entry is beyond the head, the step is
`NOT CHECKED`. `prev_entry_hash` links are not checked here: a single
tenant's entries are not contiguous in the log. The consistency route
(§14.2) is how to check that one head extends another.

---

## 15. Reporting a problem

A defect in this specification, or in `verify_proof.py`, is worth telling us
about: `bounty@coriqo.io`.

That includes a verifier that reports PASS on input it should reject, a rule
here that does not match what the reference implementation does, and any
ambiguity that led you to build something incompatible. A specification nobody
can implement from is not a specification.

---

## 16. Trust Repair claims (`--trust-repair`)

A sealed package can state, per remediation article, how a finding was closed and what the
determination method was. This section defines how those statements are checked against the
tenant bundle (§13). A verifier written from this text alone must reach the same verdicts.

Invocation: `verify_proof.py --bundle-dir <dir> --snapshot <snapshot.json> --trust-repair`. The
bundle is first verified exactly as §13.4 requires. If it does not verify, no claim is checked.

### 16.1 Inputs

From `snapshot.json`:

- `remediation_status.articles[]`: each with `finding_id`, `number`, and `finding` (may be null):
  `status`, `occurrence_count` (integer), `repeats` (array of earlier finding ids), `retest`
  (null or `{execution_id, result, evidence_verified}`), `closure` (null or `{basis, strength}`, plus `held_back` when the tenant's minimum applied),
  `sealed_steps[]` of `{to, ref}`.
- `assurance_determination` (optional): `method` (an object with a `sha256` member) and
  `method_seal_ref` (string or null).

From the bundle: every row of `events/*.jsonl`, indexed by `event_id`.

### 16.2 A ref

A ref is `<event_id>:<event_hash>`. It resolves when the bundle holds a row with that
`event_id`, the §12 event hash recomputed from the row equals both the ref's hash and the row's
`event_hash`, and `notes` parses as a JSON object. Otherwise the claim fails.

### 16.3 Claims

For each article whose `finding` is an object:

1. **Closure follows from the stated retest.** With `passed` = `retest.result == "pass"`:
   an open finding (`status` not in `resolved`, `accepted_risk`, `examiner_closed`) must state no
   closure; `accepted_risk` must read `risk_accepted` / `none`; `examiner_closed` must read
   `examiner` / `independent`; `resolved` with `passed` and `evidence_verified == true` must read
   `retest_verified` / `independent`; every other `resolved` closure must read strength
   `management` with basis `retest_waived`, `retest_unverified` or `management_signoff`, and when
   `passed` and `evidence_verified == false` the basis must be `retest_waived` or `retest_unverified`.
   Whether `evidence_verified` is true is inside the package signature and is reported
   *signed, not checkable offline*.
2. **Repeat count.** `occurrence_count` equals `len(repeats) + 1`.
3. **Sealed steps.** If `sealed_steps` is empty and the finding is closed, report *not covered*
   (the step was recorded before closures were sealed on a checkpoint-covered chain); this is a
   disclosure, not a failure. Otherwise every step's ref must resolve (16.2), its notes must carry
   `finding_id` equal to the article's and `to` equal to the step's `to`, the steps' `ordinal`
   values must strictly increase in listed order, and the last step's `to` must equal `status`.
4. **Retest matches the sealed closure.** When the finding has a `retest` and a step with `to ==
   "resolved"`, the last such event's notes `retest_execution_id` and `retest_result` must equal the
   package's `retest.execution_id` and `retest.result`.

For `assurance_determination.method`, when present:

5. **Method hash.** `sha256` equals the SHA-256 hex of the JSON encoding of the method object
   without its `sha256` member, with keys sorted, separators `,` and `:`, and non-ASCII escaped
   (`ensure_ascii` true, unlike §5).
6. **Method sealed.** When `method_seal_ref` is null, report *not covered*. Otherwise it must
   resolve (16.2) and its notes `method_sha256` must equal `sha256`.

7. **Evidence origins (context).** When an article carries `evidence_origins` (an object of class
   name to integer count), report it as *signed context*. It says how the evidence was checked on
   arrival (for example `signed_push`: the sender proved it holds the connection's secret). It is
   never a pass or a fail, and never a statement that the evidence is true.

8. **Held back follows the minimum.** `remediation_status.closure_min_origin` is absent (off) or one of
   `signed_push`, `keyed_push`, `pulled_with_credentials`; any other value fails. Class strength, strongest
   first: `signed_push`, `keyed_push`, `pulled_with_credentials`, `file_upload`. An article is *weak* when its
   `evidence_origins` hold a nonzero count for a class weaker than the minimum, or for any class not in that
   list (an unrecorded origin cannot meet the bar); an article with no events is not weak. Closures are per
   finding, so the weak set of a finding is every article with that `finding_id` that is weak. Then:
   with no minimum, no closure may carry `held_back`; with a minimum, a closure that carries `held_back`
   must read strength `management`, name `min_origin` equal to the minimum, have a nonempty weak set, and,
   when `held_back.articles` is present, list exactly the `article_id` values of the weak set; and a closure
   that reads `independent` must have an empty weak set. A held-back closure keeps its original basis
   (`retest_verified` or `examiner`) with strength `management`; claim 1 reads it as the independent closure
   it was, and claim 8 decides whether the hold was lawful. A tampered package that drops `held_back` to
   look independent, or invents one, fails here.

### 16.4 Verdicts and exit status

Each claim reports one of: verified, not covered, signed but not checkable offline, signed context, failed. Any
failed claim exits 1 (`EXIT_TAMPER`). Not-covered and offline lines never fail a run and never
read as a pass.

### 16.5 What this does not show

A verified claim shows that the package's statements match events that were sealed in order and
were not changed since. It does not show that the retest was a good test, that the evidence is true,
or that the finding was the right finding. Records from before closures were sealed on a covered
chain carry no refs and are reported as not covered; they are never backfilled.

## 17. E-signature records (`--esign`)

A signature request that Coriqo sent and collected leaves two sealed records (§13.3 evidence
records): `signature_sent` and `signature_completed`. This section defines how the downloadable
bundle for one request is read and checked. A verifier written from this text alone must reach
the same verdicts.

Invocation: `verify_proof.py --esign <PATH> [--pubkey P | --keyring K] [--esign-roots PEM]`.
`PATH` is the zip from `GET /api/v1/esign/requests/{id}/bundle` (the checked files are the
entries under `esign/`; `README.txt`, `verify_proof.py` and `SPEC.md` at the root are ignored), or
a folder that holds those files directly (a folder that holds an `esign/` folder is also accepted).
A package's Trust Repair proof zip carries one such folder per signed request at
`esign/<request_id>/`. Given that zip (or its unzipped folder), the verifier checks every
`esign/<request_id>/` that holds a `records/` folder, one after another, each exactly as a
single bundle; `--esign esign/<request_id>` checks one. The run's exit code follows 17.3. When `esign/records/` exists,
the input is a single request and nested folders are not looked for.

### 17.1 Layout

```
esign/request.json                       display only, unsigned
esign/sent.pdf                           the stamped bytes sent (H0)
esign/signed.pdf                         the signed PDF collected
esign/audit_trail.pdf | audit_trail.json | certificate.pdf     when held
esign/records/signature_sent.json
esign/records/signature_completed.json
```

Each `records/*.json` is `{record, event, proof}`:

- `record`: `id`, `record_type`, `schema_version`, `payload` (object), `content_hash`, `effective_at`.
- `event`: the governance event that sealed the record, with the fields its hash commits to
  (`seq`, `actor`, `action`, `version_id` as the `model_version_id` of §12, `from_status`,
  `to_status`, `notes`, `prev_hash`, and `oversight` when present), plus `event_id` and
  `event_hash`. Spelling and normalisation follow §13.3 (a NULL `from_status` or `notes` is `""`).
  For a sealed record, `oversight` is `{"evidence_seal": {record_id, record_type, schema_version,
  content_hash, effective_at}}`.
- `proof`: an inclusion proof bundle exactly as §7.1, or `null` when no checkpoint covered the
  event when the bundle was made.

Payload fields used below: `signature_sent` has `request_id`, `sent_sha256`, `source_sha256`;
`signature_completed` has `request_id`, `verdict`, `signed_sha256`, `sent_sha256`, `source_sha256`
(optional), `sent_record_id`, `audit_trail_pdf_sha256`, `audit_trail_json_sha256`,
`certificate_sha256` (each optional, present only when that file was held), and `checks`
(the seven sealed lines, each `{key, status, label, detail}`).

`request.json` is never read for any check. A verifier MUST NOT trust it.

### 17.2 Checks

Checks 1 to 3 run once for each record. Output is one line per check, per record where marked.

1. **Content hash.** `sha256(canonical_bytes(record.payload))` (§3) equals `record.content_hash`.
2. **Sealed in its event.** `event.oversight.evidence_seal` exists and its `record_id`,
   `record_type` and `content_hash` equal the record's, and the event hash recomputed per §4.2
   (with the §12 field set) equals `event.event_hash`. Both parts must hold.
3. **Under a signed checkpoint.** A `null` proof is **not covered**, never a failure. Otherwise
   all of these must hold, and any miss fails: `proof.event_id` equals `event.event_id`;
   `proof.leaf_input` equals `event.event_hash`; `proof.merkle_root` and `proof.tree_size` equal
   the values in `proof.sth_body`; the §7.2 inclusion walk succeeds under the `tree_version` of
   `sth_body`; the `sth_body` signature verifies (§6.1, §7.2 check 2). The key is the pinned one
   when `--pubkey` or `--keyring` is given (refusing to fall back to the bundle's key, as §9.1
   requires); with no pin, the `public_key_pem` in the proof is used and the line says the key
   was not pinned.
4. **The records belong together.** `signature_sent.request_id` equals
   `signature_completed.request_id`; `signature_completed.sent_record_id` equals
   `signature_sent` `record.id`; `sent_sha256` is present and equal in both; when
   `signature_completed.source_sha256` is present it equals the sent record's.
5. **Files hash to their sealed hashes.** `sent.pdf` to the sent record's `sent_sha256`;
   `signed.pdf` to `signed_sha256`; `audit_trail.pdf`, `audit_trail.json` and `certificate.pdf` to
   `audit_trail_pdf_sha256`, `audit_trail_json_sha256` and `certificate_sha256`. A sealed hash whose
   file is absent fails. A file present with no sealed hash fails. Any other file under `esign/`
   except `request.json` and the two record files also fails ("nothing seals it"): an extra file is
   never ignored, because an unsealed file in an evidence folder is how a swap is hidden.
6. **The signed PDF names this request.** `signed.pdf` carries `/CoriqoRef` in its Info dictionary
   equal to `request_id` and `/CoriqoSourceSha256` equal to the sent record's `source_sha256`.
   Needs a PDF reader (`pypdf`); without it the line is **signed, not checkable offline**. A file
   that cannot be read as a PDF fails.
7. **PAdES signatures.** Needs a PDF signature validator (`pyhanko`); without it the line is
   **signed, not checkable offline**. Every embedded signature and document timestamp must be
   intact and valid (integrity only; no certificate is trusted by this part). Every signature but
   the last may be followed only by changes at or below form-filling level and must not break its
   own change rules; the last must cover the whole file, or be followed only by validation data
   added after it (a PAdES-LTA tail). No signature, an encrypted file, or an unreadable file fails.
   With `--esign-roots`, a second line judges the last signer certificate (skipping document
   timestamps from the end; a file holding only document timestamps has no signer certificate and
   this line fails) against those roots, offline, requiring revocation data from the file's own
   security store; it is **verified** when the certificate is trusted and **failed** otherwise.
   Without `--esign-roots`, the sealed `certificate_trust` line is shown as **signed context** and
   no trust is claimed.
8. **Sealed verdict and lines.** `signature_completed.verdict` and each sealed check line are
   shown as **signed context**. They record what Coriqo concluded at collection time. They are
   never a pass or a failure here.

### 17.3 Verdicts and exit status

Each line reports one of: verified, not covered, signed but not checkable offline, signed
context, failed (the words of §16.4).

| Exit | Meaning |
|---|---|
| 0 | No line failed, every record is under a signed checkpoint, and the checkpoint signature was checked under a key the reader pinned (`--pubkey` or `--keyring`). Not-checkable lines never fail a run and never read as a pass. |
| 1 | At least one line failed. |
| 2 | No line failed, but check 3 is not covered for at least one record ("not anchored"). Without a signed checkpoint the records only agree with each other: someone who rewrote the records, their events and the files together would pass every other check, so this is never reported as verified. Also 2 when every check passed but no key was pinned ("not pinned"): the key inside the bundle proves only that the bundle agrees with itself, since a forger can sign their own checkpoint. |
| 3 | The input is not a readable bundle (not a zip or folder, no `esign/` files, a record file that is not `{record, event, proof}`, a `record_type` that does not match its file name, an unreadable `--pubkey`, `--keyring` or `--esign-roots`), `signature_sent.json` is missing, or `signature_completed.json` is missing. The last case prints "nothing signed to verify yet": the request had not been signed and collected (or had ended without a signature) when the bundle was made, so there is no signed document to check. |

A request whose records exist but were never put under a checkpoint exits 2 with check 3
reported as not covered and the run reported as not anchored. Download the bundle again after
the next checkpoint. For a package proof zip, the run's exit is 1 if any request failed, else 3 if
any is malformed, else 2 if any is not anchored, else 0.

### 17.4 What this does not show

That the person named is the person who signed. That is the signing service's authentication, at
the level recorded in `signers[].auth_method`, and nothing more. A verified bundle shows that
these bytes were signed, that Coriqo sealed the record of them, and that neither changed after the
checkpoint. It does not show that the document is correct, that the signer should have signed it,
or, without `--esign-roots`, that the signer's certificate chains to an authority you trust.
A record sealed by an earlier build may lack payload fields this section names; a missing one
is a failed line, not a skipped one.

## 18. Agent decisions (`--trace`)

An AI agent's decision is recorded as a decision trace and sealed, at the moment it is
recorded, as an `agent_decision` event on the agent's mandate version chain (§4). The trace
proof file, from `GET /api/v1/agents/{agent_id}/traces/{trace_id}/proof`, lets a reader
check one decision without the rest of the chain.

### 18.1 File

```
{
  "kind": "coriqo_decision_trace_proof",
  "format_version": 1,
  "trace": { trace_id, agent_id, version_id, input_hash, output, output_hash,
             tool_calls, grounding_refs, event_hash, occurred_at },
  "event": { event_id, version_id, seq, actor, action, from_status, to_status,
             notes, prev_hash, event_hash [, oversight] },
  "proof": <an inclusion proof bundle, §7>
}
```

`event` holds exactly the fields its event hash commits to (§13.3 spelling). `proof` is the
inclusion proof for that event under the newest signed checkpoint that covers it. The server
returns no file (HTTP 409) until a checkpoint covers the decision.

A reader may add `"inputs"` to `trace`: the original inputs, which Coriqo does not keep.

`trace.content_purged` is true when the bank deleted the decision's content under a retention
purge. The output and tool calls are then gone, their lines are *not covered*, and a run that
otherwise passes reports "hashes only, not fully verified" and exits 2, never 0: the flag is
not sealed, so a file that withholds its content looks the same as a real purge. The flag is unsigned, so it counts only when
`output` and `tool_calls` are both null, as a real purge leaves them. A file that sets the flag
but still carries an output or tool calls fails the "purge claim" check, and its content is
re-hashed as if the flag were absent.

### 18.2 What is hashed

`H(v)` is `hex(SHA256(canonical_bytes(v)))`, with §3's rules applied to any JSON value (a
string, list or object): sorted keys, no whitespace, UTF-8, non-ASCII characters not escaped.

| Hash | Over |
|---|---|
| `input_hash` | `H(inputs)`, the inputs the agent was given |
| `output_hash` | `H(output)`, the output exactly as recorded (usually a string) |
| `tool_calls_hash` | `H(tool_calls)`, the list in recorded order. Each entry is `{step, tool, args_hash, result_hash, ...}`; raw arguments and results are hashed on arrival and never stored |

The event's `notes` is the canonical JSON string of
`{trace_id, agent_id, input_hash, output_hash, grounding_refs, tool_calls_hash}`. Because
`notes` is inside the event hash, the event commits to the agent, the hashes and the tool
calls' order. Decisions sealed before `tool_calls_hash` was added carry neither it nor
`agent_id`; decisions sealed before 2026-10-15 carry no `agent_id`.

### 18.3 Checks

1. **Output.** `H(trace.output)` equals `trace.output_hash`. If `trace.inputs` is present,
   `H(trace.inputs)` equals `trace.input_hash`; if absent, the inputs line is *not covered*.
2. **The event names this decision.** `event.action` is `agent_decision`, `event.version_id`
   equals `trace.version_id`, and `notes.trace_id` equals `trace.trace_id`.
3. **The event commits to the trace.** `notes.input_hash`, `notes.output_hash` and
   `notes.grounding_refs` equal the trace's. If `notes.tool_calls_hash` is present it equals
   `H(trace.tool_calls)`; if absent, the tool-calls line is *not covered*. If `notes.agent_id`
   is present it equals `trace.agent_id`; if absent, the agent line is *not covered* and the
   agent shown in the header is marked as not checked.
4. **Event hash.** The event hash recomputed per §13.3 equals `event.event_hash`, which
   equals `trace.event_hash`.
5. **Inclusion.** `proof.event_id` is `event.event_id`, `proof.leaf_input` is
   `event.event_hash`, `merkle_root` and `tree_size` match `sth_body`, the path verifies
   (§7.2), and the checkpoint signature verifies (§6) under the reader's pinned key.

### 18.4 Exit status

| Exit | Meaning |
|---|---|
| 0 | No check failed and the checkpoint signature verified under a pinned key (`--pubkey` or `--keyring`). |
| 1 | A check failed: the record does not match what was sealed. |
| 2 | No check failed, but either no key was pinned (the signature was checked with the key inside the file), or the file says the content was purged, so only the sealed hashes were checked. |
| 3 | The file is not a decision-trace proof, or a required field is missing. |

### 18.5 What a pass proves, and what it does not

A pass shows that this output, these tool calls in this order, these grounding references,
and (when supplied) these inputs are the ones Coriqo sealed for this decision when it was
recorded, and that the sealed event is under a checkpoint signed by the key you pinned.
Editing the output, reordering a tool call, or rewriting the event afterwards fails a check.

It does not show that the decision was right, that the agent stayed inside its mandate (§19 checks that), or
that the agent reported its inputs and tool calls honestly: the seal covers what the agent
sent. It does not show the tool calls' raw arguments or results, only their hashes. Without
the original inputs it checks only that an input hash was sealed. `occurred_at` is not sealed
and is shown for reference only.

---

## 19. Recorded tool calls against the sealed mandate (added in 1.1)

This section answers one question offline: did the tool calls an agent recorded stay inside
the mandate that was in force when it recorded them? The mandate format is `MANDATE_SPEC.md`
(`coriqo.mandate/v1`). Everything checked here is a sealed event under a signed checkpoint.

### 19.1 What is sealed

Two things are added to the agent's mandate version chain (§18):

- A **`mandate_snapshot`** event. Its `notes` is the canonical JSON of
  `{agent_id, mandate_sha256, document}`. `document` is the mandate in force, in the
  normalised form of `MANDATE_SPEC.md` §6.1, and `mandate_sha256` is `H(document)`, which is
  the mandate's document hash (`MANDATE_SPEC.md` §6). A verifier hashes `document` exactly as
  given and does not normalise it again. Coriqo seals a snapshot before the first decision
  recorded under a mandate, and again whenever the mandate in force changes. A decision
  recorded under an unchanged mandate seals no snapshot.
- Two keys in every `agent_decision` event's `notes`:
  - `mandate_sha256`: the document hash of the mandate in force when the decision was
    recorded;
  - `decision_seq`: the decision's position, from 1, among the `agent_decision` events on the
    same version chain. It is assigned while the chain is locked for the append, so two
    decisions never share a number and no number is skipped.

Decisions sealed before 1.1 carry neither key.

### 19.2 The `mandate_check` block

```
"mandate_check": {
  "format_version": 1,
  "mandates":  [ { "event": <event>, "proof": <inclusion proof, §7> } ],
  "decisions": [ { "trace_id", "tool_calls", "event": <event>, "proof": <inclusion proof> } ]
}
```

Each `event` holds exactly the fields its event hash commits to, in the §13.3 spelling, and
each `proof` is that event's inclusion proof under a signed checkpoint. The block itself is
not signed; every entry in it is anchored by its own proof.

The block appears in two places:

- in a decision-trace proof (§18), with `mandates` only. The decision checked is the file's
  own decision.
- at the top level of an inclusion proof bundle (§7), with both lists. Coriqo's public sample
  bundle is one.

Both are additive under §12: a verifier written before 1.1 ignores the block.

### 19.3 Checks

1. **Each mandate.** `event.action` is `mandate_snapshot`; the event hash recomputes (§13.3);
   the proof verifies under a signed checkpoint (§18.3 step 5); `notes.document` is an
   object whose `spec` is `coriqo.mandate/v1` and whose `tools` has `allowed` (a list of
   names, or null) and `prohibited` (a list of names); and `H(notes.document)` equals
   `notes.mandate_sha256`. Any of these failing fails the check.
2. **Each decision in the block.** `event.action` is `agent_decision`; the event hash
   recomputes; the proof verifies; `notes.trace_id` equals `trace_id`; and, when `tool_calls`
   is not null and `notes.tool_calls_hash` is present, `H(tool_calls)` equals it. Any of these
   failing fails the check.
3. **Pairing.** A decision is evaluated when its tool calls are sealed (`tool_calls` not null
   and `notes.tool_calls_hash` present), `notes.mandate_sha256` is present, and a mandate that
   passed step 1 has that hash, sits on the same `version_id`, and names the same `agent_id`
   when the decision's notes name one. Any other decision is *not covered*, and the verifier
   says why: no mandate hash (recorded before 1.1), no matching mandate in the file, or tool
   calls purged or never sealed.
4. **Sequence.** Group the decisions that carry `decision_seq` by `version_id`. A number
   carried by two decisions fails the check. Numbers missing between the lowest and the
   highest are reported as gaps. A gap is not a failure, since a file may carry a selection,
   but it means those decisions were not checked. A verifier finds gaps from the sorted
   distinct numbers and reports the first ten, never by walking the range: a file can name
   decision 1 and decision 10^12.
5. **Every entry belongs to this file** (steps 1 and 2 apply it to each entry). The entry's
   `proof.sth_body.subject` equals the subject of the file's own checkpoint, or is exactly
   `version:<event.version_id>`; any other value, a missing one included, fails. When the
   reader pinned no key, the entry's `public_key_pem` and `sth_body.key_id` are the file's
   own checkpoint key: the reader is told that key was used, and an entry signed under any
   other key would borrow that statement. With a pinned key or keyring, each entry verifies
   under it instead. An `event_id` or `trace_id` that appears twice in the block (or repeats
   the file's own decision in a decision-trace proof) fails, so no call is counted twice.

### 19.4 The rule

For each entry of a decision's `tool_calls` that is an object with a non-empty `tool`:

- it is **outside the mandate** if `tool` is in `tools.prohibited`;
- otherwise, it is outside the mandate if `tools.allowed` is not null and `tool` is not in it.

An empty `allowed` list permits no tool. An entry without a tool name is not counted. This
is the rule Coriqo applies when the decision arrives, so the verifier and Coriqo's own
record of flagged decisions agree.

### 19.5 Output

The verifier prints the number of decisions checked, how many sealed entries verified under
a signed checkpoint, the line `K of N recorded tool calls fell outside the sealed mandate`
(N counts the calls of evaluated decisions only), each call outside the mandate with its
`trace_id`, `step`, `tool` and the reason, and the sequence gaps. An inclusion-proof run
repeats the `K of N` line under `RESULT: VERIFIED`.

### 19.6 Exit status

The exit codes of §18.4 and §7 are unchanged. A failed check in §19.3 is a failed record:
exit 1 for `--trace`, `RESULT: VERIFICATION FAILED` for an inclusion proof. Calls outside the
mandate are **not** a failed record: the record is intact, and it shows the agent went
outside its mandate. *Not covered* lines do not change the exit code; read them.

### 19.7 What this proves, and what it does not

A run with no failed check shows that each counted call is one sealed with its decision, and
that the mandate it was compared against is the one Coriqo sealed as in force when that
decision was recorded, both under a signed checkpoint.

It does not show that the agent reported every call it made: the seal covers what the agent
sent. It does not show that the runtime enforced the mandate: in `shadow` mode a call
outside the mandate is recorded but not stopped. Budgets, step limits and delegation are not
checked in 1.1. `K of N` is a count over this file; it is not a statement about any law,
regulation or framework.

Conformance corpus: `testdata/mandate_check/`, regenerated by
`tests/make_mandate_check_corpus.py`. `cases.json` gives each file's mode, exit code and
`K of N` line; `tests/test_mandate_check.py` adds the mutations a verifier must reject.

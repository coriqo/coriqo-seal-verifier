# Coriqo mandate file (`coriqo.mandate.yaml`): specification v1.1

Spec version: **1.1**. A file states the version it was written to in its
`spec` field (§3).

v1.1 adds one optional field, `stop_grace_s` (§4.7). A v1.0 file is a valid
v1.1 file and keeps its document hash.

Author: Abdulrafiu Rabiu, Coriqo. Licensed under the Apache License, Version 2.0.

A mandate says what one AI agent may do: which tools it may call, how many
steps and how much money a run may use, whether it may hand work to another
agent, and what happens when it tries something outside those limits. This
document defines the file that carries a mandate, so that an agent runtime, a
CI check, a gateway or an auditor can read the same mandate without asking
Coriqo.

- `mandate.schema.json` is the JSON Schema (draft 2020-12).
- `mandate_format.py` is the reference reader. Where it and this document
  disagree, this document is wrong and should be corrected.
- `testdata/mandate/` is the conformance corpus (§8).

---

## 1. What the file is, and what it is not

The file is a statement of limits. It is not proof that an agent stayed inside
them. Proof comes from the sealed record of what the agent did, checked with
`verify_proof.py` (see `SPEC.md`).

Coriqo holds the mandate a named person approved. The file is how that mandate
leaves Coriqo (export) and how a mandate kept in a repository comes back in
(import). Importing a file proposes a change; it takes effect only when a
second person approves it in Coriqo.

Enforcement happens in code the customer runs (the agent runtime, the
`coriqo-agents` SDK). Coriqo's service is never in the path of a tool call.

## 2. Encoding

A file is YAML 1.2 or JSON (JSON is valid YAML), UTF-8, at most 256 KB. A
reader loads YAML with a safe loader: no tags, no object construction. The
conventional name is `coriqo.mandate.yaml`.

The top level is a mapping. Field names are lowercase. Order does not matter.

## 3. Versions, and the promise that goes with them

`spec` is required and reads `coriqo.mandate/v1`, or `coriqo.mandate/v1.N`
for a later revision of v1.

Within v1, Coriqo will not remove a field, rename one, change a default, or
change what a value means. A later v1 revision may add optional fields only.
Anything else is v2.

A field added in a later v1 revision has no default. Left out, it means "not
set", and it is left out of the normalised document (§6.1), so a file that
does not use it hashes the same under every v1 revision. A file that uses one
should declare the revision that added it (for example `coriqo.mandate/v1.1`),
so that an older reader warns about it instead of refusing it.

A reader:

1. refuses a file whose major version it does not know, and says which
   version the file is;
2. for a file of a v1 revision newer than its own, warns about each field it
   does not know and ignores it;
3. for a file of its own revision or older, refuses unknown fields, so a
   misspelt field fails instead of silently meaning nothing.

Top-level fields whose names start with `x-` are extensions. A reader keeps or
ignores them and never refuses a file because of them. They are not part of
the document hash.

## 4. Fields

"Absent" below is what a reader that enforces from the file alone does when
the field is left out. §5 covers a system that already holds a mandate.

A field with no default (`environment`, `mandate`, `tools.allowed`,
`max_steps_per_run`, `max_cost_usd`, `stop_grace_s`) may also be written as `null`, which
states "not set" explicitly. Export writes it that way.

PyYAML and other YAML 1.1 loaders read a bare `off`, `on`, `yes` or `no` as a
boolean. Write `"off"` in quotes.

### 4.1 Identity

| Field | Type | Required | Meaning |
|---|---|---|---|
| `agent.name` | string, 1–256 | yes | The agent's name. |
| `agent.id` | string, 1–64 | no | The agent's id in Coriqo. Export writes it. |
| `agent.external_id` | string, 1–256 | no | The id the agent's own system uses. |
| `environment` | `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` | no | Where this mandate applies, for example `production`. |
| `mandate` | string, up to 20,000 | no | The written mandate, in plain words. |

### 4.2 Mode and staleness

| Field | Values | Absent | Meaning |
|---|---|---|---|
| `mode` | `shadow`, `enforce` | `shadow` | `shadow` records each call that falls outside the mandate and blocks nothing. `enforce` applies `on_violation`. |
| `on_stale_snapshot` | `fail_open`, `fail_closed` | `fail_open` | What the runtime does when its cached copy of the mandate is older than `max_staleness_s`: allow calls, or refuse them. |
| `max_staleness_s` | integer, 30–86400 | `300` | How long a cached copy may be trusted, in seconds. |
| `on_violation` | `deny`, `deny_and_halt_run`, `alert_only` | `deny` | Under `enforce`: refuse the call; refuse it and end the run; or allow it and raise an alert. |

### 4.3 Tools

| Field | Type | Absent | Meaning |
|---|---|---|---|
| `tools.allowed` | list of strings | no allow-list | The only tools the agent may call. An empty list means no tool at all. |
| `tools.prohibited` | list of strings | `[]` | Tools the agent may never call, whatever else is allowed. |

A tool may not appear in both lists. Lists hold at most 500 names of 1–256
characters each. Order and duplicates carry no meaning.

### 4.4 Budgets

| Field | Type | Absent | Meaning |
|---|---|---|---|
| `max_steps_per_run` | integer, 1–1,000,000 | no limit | Most tool calls or steps in one run. |
| `max_cost_usd` | number, above 0, at most 999999.999999, no more than 6 decimal places | no limit | Most a run may spend, in US dollars. |

### 4.5 Delegation

| Field | Values | Absent | Meaning |
|---|---|---|---|
| `delegation.policy` | `none`, `attenuated` | `none` | Whether the agent may hand work to another agent. `attenuated`: only with a scope no wider than its own. |
| `delegation.max_depth` | integer, 0–20 | `3` | How many hand-offs deep a chain may go. |

### 4.6 Output inspection

| Field | Values | Absent |
|---|---|---|
| `output_inspection.instruction_like` | `off`, `flag` | `off` |
| `output_inspection.secrets` | `off`, `flag`, `redact` | `off` |
| `output_inspection.pii` | `off`, `flag`, `redact` | `off` |

A reader validates and stores these switches; acting on them is the
runtime's job. When a runtime acts on them, `flag` records a tool result that looks like an instruction, a secret
or personal data; `redact` also removes it before the agent sees it. Flagging
is detection by pattern. It does not prevent prompt injection, and nothing
reading this file may claim that it does.

### 4.7 Stopping on suspension (v1.1)

| Field | Type | Absent | Meaning |
|---|---|---|---|
| `stop_grace_s` | integer, 1–600 | the runtime's own default | When the agent is suspended, how many seconds each worker the runtime started (for example an MCP server) has to stop on its own after it is asked to, before the runtime ends it. |

A runtime that stops workers asks first (on POSIX, SIGTERM) and ends a worker
still running when the grace period is over (SIGKILL). With the field absent
the runtime uses its own setting; `coriqo-mcp`'s default is 5 seconds.

## 5. Importing into a system that already holds a mandate

When a file is imported into Coriqo, a field the file leaves out keeps the
value Coriqo already holds. Only the fields the file states can change. This is
why export always writes every v1.0 field, with `null` where one is not set:
an exported file, imported again, proposes no change. A field added after
v1.0 is written only when set; an export that leaves it out still proposes no
change, because the field then keeps the value held, which is "not set".

A file whose `agent.id` is set must name the agent it is imported into. A file
without `agent.id` must have the agent's exact name.

## 6. Document hash

The document hash identifies a mandate across systems. It is the lowercase hex
SHA-256 of the canonical JSON (§6.2) of the normalised document (§6.1).

### 6.1 Normalised document

Every field of §4, with the "Absent" value filled in, in this shape:

```json
{
  "spec": "coriqo.mandate/v1",
  "agent": {"name": "...", "id": null, "external_id": null},
  "environment": null,
  "mandate": null,
  "mode": "shadow",
  "on_stale_snapshot": "fail_open",
  "max_staleness_s": 300,
  "tools": {"allowed": null, "prohibited": []},
  "max_steps_per_run": null,
  "max_cost_usd": null,
  "delegation": {"policy": "none", "max_depth": 3},
  "output_inspection": {"instruction_like": "off", "secrets": "off", "pii": "off"},
  "on_violation": "deny"
}
```

- `spec` is always `coriqo.mandate/v1`, whatever revision the file declared.
- `mandate`: CRLF and CR become LF, trailing whitespace is removed; empty
  becomes `null`.
- Tool lists are sorted by code point with duplicates removed. An absent
  `allowed` stays `null`, which is different from `[]`.
- `max_cost_usd` becomes a decimal string with no exponent and no trailing
  zeros: `1.50` is `"1.5"`, `10` is `"10"`.
- Fields added after v1.0 (`stop_grace_s`) appear only when set: a file that
  leaves one out, or writes it as `null`, has no such key in the normalised
  document. Set, it is written as the file states it, after the
  `on_violation` key in the shape above (key order does not change the hash,
  §6.2). This is what keeps every v1.0 document's hash unchanged.
- `x-` fields, and fields a reader ignored under §3 rule 2, are left out.

A reader of an older revision drops fields a newer one hashes, so compare
hashes only between readers of the same revision.

### 6.2 Canonical JSON

Keys sorted by code point, separators `,` and `:` with no spaces, non-ASCII
characters written as UTF-8 rather than escaped. This is the same rule as
`SPEC.md` §3.

## 7. Where Coriqo stores each field

For implementers reading Coriqo exports. Field names on the left are the
file's; on the right, Coriqo's agent record.

| File | Coriqo |
|---|---|
| `mode: shadow` / `enforce` | mandate enforcement `observe` / `enforce` |
| `on_stale_snapshot` | `enforcement_posture` |
| `max_staleness_s` | `max_staleness_s` |
| `tools.allowed` | `allowed_tools` |
| `max_steps_per_run` | `max_run_steps` |
| `max_cost_usd` | `max_run_cost_usd` |
| `delegation.policy`, `delegation.max_depth` | `delegation_policy`, `max_delegation_depth` |
| `tools.prohibited` | stored on the approved mandate, sent to the runtime in its mandate snapshot, and checked by Coriqo's own authorize and decision-scope checks (a call to a prohibited tool is outside the mandate even with no allow-list) |
| `environment`, `on_violation`, `output_inspection` | stored on the approved mandate and sent to the runtime in its mandate snapshot; acting on them is the runtime's job |
| `stop_grace_s` | `stop_grace_s`, stored on the approved mandate and sent in the runtime's mandate snapshot only when set; acting on it is the runtime's job |

Coriqo's own default for an agent registered without a file is `enforce`,
not `shadow`. Export writes the value Coriqo holds, so a file exported from
Coriqo always says which one applies.

Export writes `stop_grace_s` only when it is set, and then declares
`coriqo.mandate/v1.1`. An export of a mandate that never set it is the same
v1 file it was before v1.1.

## 8. Conformance

`testdata/mandate/cases.json` lists every file in the corpus. A conforming
reader:

- accepts each `valid` file, with the listed document hash and number of
  warnings;
- refuses each `invalid` file with an error that names the listed field.

Two rules cannot be written in JSON Schema: a tool in both lists (§4.3) and
`max_cost_usd` precision (§4.4). `schema_agrees: false` marks the cases where
the schema alone reaches a different verdict.

Run the corpus:

```
python -m pytest tests/test_mandate_format.py -q
```

Check one file:

```
python mandate_format.py coriqo.mandate.yaml --hash
```

Exit 0 valid, 1 invalid (each problem printed with its field), 2 the file
could not be read.

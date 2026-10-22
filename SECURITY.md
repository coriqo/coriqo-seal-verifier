# Security policy

## A record that verifies after it was changed

That is the open challenge: <https://coriqo.io/break-the-seal.html>. Change what a sealed
bundle says and get this verifier to pass it anyway, then send it to **bounty@coriqo.io**.
We publish every break we confirm, under your name, and record the fix in `SPEC.md`. There is
no prize money.

The same goes for a rule in `SPEC.md` that the code does not follow, or a gap in the
specification that let you build a verifier that disagrees with this one.

## Anything else in the verifier

A crash on crafted input, a file written outside the folder you pointed it at, a key read
from somewhere you did not choose: report it privately, not in a public issue.

- GitHub: [open a private advisory](https://github.com/coriqo/coriqo-seal-verifier/security/advisories/new)
  on this repository.
- Email: **security@coriqo.io**.

Include the version (`python verify_proof.py --version`), the file or steps that reproduce
it, and what it lets someone do. We acknowledge the report, keep you told while we fix it,
and agree the disclosure date with you.

## Reported elsewhere

The Coriqo service itself, and the SDK that sends records to it: security@coriqo.io.

## Supported versions

The latest tagged release. Fixes are not backported.

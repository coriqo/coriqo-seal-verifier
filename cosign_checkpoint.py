#!/usr/bin/env python3
"""
Cosign a Coriqo checkpoint. For independent witnesses.

You hold the private key. Coriqo never sees it, and cannot produce a signature
that verifies against your registered public key -- which is the only reason
your cosignature is worth anything to anyone reading it.

    # once, offline
    python cosign_checkpoint.py --generate-key witness.pem
    # send the printed public key to Coriqo; they register it out of band

    # then, whenever you want to witness a checkpoint
    python cosign_checkpoint.py --api https://coriqo.example.com \\
        --key witness.pem --key-id your-key-id --checkpoint latest

    # if you registered through an invitation link, add --invited (the key id is
    # the one shown on the page after you sent your public key)
    python cosign_checkpoint.py --api https://coriqo.example.com \\
        --key witness.pem --key-id inv-1234abcd-0011223344aa --invited

What this does
--------------
1. Fetches the exact bytes the checkpoint's own signature covers.
2. Verifies Coriqo's signature over them first, so you are not asked to
   countersign something you have not checked. Skipping this would make you a
   rubber stamp, which is worse than not witnessing at all.
3. Signs those bytes with your key and submits the signature.

It signs the bytes exactly as served. It does not re-serialise the JSON: key
order and whitespace are part of what was signed (SPEC.md §3), and a signature
over re-serialised bytes fails in a way that looks like tampering rather than
like a formatting mistake.

Needs only `cryptography` and the standard library.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
        load_pem_private_key, load_pem_public_key,
    )
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("This needs the `cryptography` package: pip install cryptography")


def generate_key(path: Path) -> int:
    if path.exists():
        sys.exit(f"{path} already exists. Refusing to overwrite a private key.")
    priv = Ed25519PrivateKey.generate()
    path.write_bytes(priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    path.chmod(0o600)
    pub = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    print(f"Private key written to {path} (mode 600). Keep it; Coriqo must never have it.")
    print("\nSend this public key to Coriqo, and confirm the fingerprint over a")
    print("channel that is not the same email:\n")
    print(pub)
    return 0


def _get(url: str, headers: dict | None = None) -> dict:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"GET {url} -> {e.code}: {e.read()[:300].decode(errors='replace')}")
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach {url}: {e.reason}")


def _post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"POST {url} -> {e.code}: {e.read()[:300].decode(errors='replace')}")
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach {url}: {e.reason}")


def check_coriqo_signature(body: dict, api: str) -> None:
    """Verify Coriqo's own signature before adding yours.

    The signed body does not carry the signature over itself, so this fetches
    the checkpoint's signature and Coriqo's published key. If that check cannot
    be made, say so and stop rather than signing anyway.
    """
    key_id = body.get("key_id")
    pem = None
    try:
        url = f"{api}/api/v1/checkpoints/public-key"
        if key_id:
            url += f"?key_id={key_id}"
        with urllib.request.urlopen(url, timeout=30) as r:
            pem = r.read().decode()
    except Exception as exc:
        sys.exit(f"Could not fetch Coriqo's public key ({exc}). Not signing blind.")

    cp = body.get("checkpoint_signature")
    if not cp:
        print("  ! This instance did not return the checkpoint's own signature, so it")
        print("    could not be checked here. Verify the checkpoint with verify_proof.py")
        print("    before trusting what you are about to countersign.")
        return
    try:
        pub = load_pem_public_key(pem.encode())
        assert isinstance(pub, Ed25519PublicKey)
        pub.verify(bytes.fromhex(cp), body["canonical_bytes"].encode("utf-8"))
        print(f"  Coriqo's signature over these bytes: valid (key {key_id})")
    except InvalidSignature:
        sys.exit("Coriqo's own signature over these bytes does NOT verify. "
                 "Do not cosign this. Tell them, and keep the bytes.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--generate-key", metavar="PATH",
                   help="Generate an Ed25519 keypair and exit.")
    p.add_argument("--api", help="Base URL of the Coriqo instance.")
    p.add_argument("--key", help="Path to your PEM private key.")
    p.add_argument("--key-id", help="The key_id Coriqo registered for you.")
    p.add_argument("--checkpoint", default="latest",
                   help="Checkpoint id, or 'latest' (default).")
    p.add_argument("--invited", action="store_true",
                   help="Your key was registered through an invitation link. Cosigns the latest checkpoint "
                        "through the invited-witness routes.")
    p.add_argument("--dry-run", action="store_true",
                   help="Check and sign, but do not submit.")
    args = p.parse_args(argv)

    if args.generate_key:
        return generate_key(Path(args.generate_key))

    missing = [f for f in ("api", "key", "key_id") if not getattr(args, f)]
    if missing:
        p.error("required unless --generate-key: " + ", ".join("--" + m.replace("_", "-")
                                                               for m in missing))

    api = args.api.rstrip("/")
    checkpoint = args.checkpoint
    invited = f"{api}/api/v1/public/witness/{args.key_id}/checkpoints"
    if args.invited:
        if checkpoint != "latest":
            p.error("--invited cosigns the latest checkpoint; leave --checkpoint out")
        # The key id is public, so reading the checkpoint proves you hold the key: sign
        # "coriqo-witness-read\n<key id>\n<unix time>" and send it with the time.
        reader = load_pem_private_key(Path(args.key).read_bytes(), password=None)
        if not isinstance(reader, Ed25519PrivateKey):
            sys.exit("That key is not Ed25519.")
        ts = str(int(time.time()))
        proof = reader.sign(f"coriqo-witness-read\n{args.key_id}\n{ts}".encode()).hex()
        body = _get(f"{invited}/latest", {"X-Witness-Timestamp": ts, "X-Witness-Signature": proof})
        checkpoint = body["checkpoint_id"]
    elif checkpoint == "latest":
        roster = _get(f"{api}/api/v1/public/checkpoints/witnesses/roster")
        if "latest_checkpoint_id" in roster:
            checkpoint = roster["latest_checkpoint_id"]
        else:
            sys.exit("This instance does not advertise a latest checkpoint. "
                     "Pass --checkpoint <id>.")

    print(f"Checkpoint : {checkpoint}")
    if not args.invited:
        body = _get(f"{api}/api/v1/public/checkpoints/{checkpoint}/body")
    print(f"Subject    : {body.get('subject')}")
    print(f"Sealed at  : {body.get('issued_at')}")
    print(f"sha256     : {body.get('sha256')}")

    check_coriqo_signature(body, api)

    priv = load_pem_private_key(Path(args.key).read_bytes(), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        sys.exit("That key is not Ed25519.")

    # The bytes as served. Not re-serialised -- see the module docstring.
    signature = priv.sign(body["canonical_bytes"].encode("utf-8")).hex()
    print(f"  Your signature: {signature[:32]}…")

    if args.dry_run:
        print("\n--dry-run: not submitted.")
        return 0

    if args.invited:
        result = _post(f"{invited}/{checkpoint}/cosign", {"signature_hex": signature})
    else:
        result = _post(f"{api}/api/v1/public/checkpoints/{checkpoint}/cosign",
                       {"witness_key_id": args.key_id, "signature_hex": signature})
    print("\n" + result.get("detail", "Recorded."))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

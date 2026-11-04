# TSA trust anchors

Pass one of these to `verify_proof.py --tsa-ca` to check that a checkpoint's
RFC 3161 timestamp token chains to a CA you trust.

Without `--tsa-ca`, the verifier reports:

    TSA token present, CA not pinned — not verified

The token's own signature and its message imprint are still checked. What is
missing is any assurance that the certificate which signed it belongs to the
authority it claims to be.

## Why the anchor is pinned by the VERIFIER, not by Coriqo

The same reason a witness key is: the party being audited must not be the party
that decides which timestamps are trustworthy. Coriqo requests the token and
stores it; the examiner chooses the trust anchor and checks the chain. A
server-side setting would be Coriqo vouching for its own evidence.

(Note that `the Coriqo server` still declares a `TSA_CA_BUNDLE` setting and
`the Coriqo server` still defines `tsa_ca_bundle_path()`. Both are
**inert**: nothing calls that function. Setting the env var changes no
behaviour. It is a leftover from an earlier design, not a knob to reach for.)

## digicert_trusted_root_g4.pem

Self-signed root, valid to 2038-01-15.

    subject/issuer  C=US, O=DigiCert Inc, OU=www.digicert.com,
                    CN=DigiCert Trusted Root G4
    SHA-256         55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:
                    F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88

**Provenance:** copied from the container's own distribution trust store
(`/etc/ssl/certs/DigiCert_Trusted_Root_G4.pem`), not downloaded, so it carries
the Debian ca-certificates package's vetting rather than a fetch from a URL
someone pasted. Verify the fingerprint above against any independent copy
before relying on it; that is cheaper than trusting this file.

**Verified to be the right anchor** for `http://timestamp.digicert.com`: a live
token from that endpoint embeds

    leaf          DigiCert SHA256 RSA4096 Timestamp Responder 2026 1
    intermediate  DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1
    root          DigiCert Trusted Root G4

and `openssl verify -CAfile digicert_trusted_root_g4.pem` returns OK on that
chain.

## Other endpoints that work

`http://timestamp.sectigo.com` and `http://time.certum.pl` both answer this
client correctly. They chain to their own roots, so pinning either needs that
root here instead.

None of the three is an **eIDAS-qualified** timestamp. If a European bank asks
for a qualified timestamp specifically, that is a paid service from Certum,
SwissSign or Sectigo, a commercial decision, not a configuration change.

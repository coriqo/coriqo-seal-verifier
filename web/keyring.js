// Coriqo's published signing keys, for the in-browser verifier.
//
// Each entry is the SHA-256 of the key's DER-encoded public key, the same value
// the verifier prints under "Key". A bundle that passes every integrity check
// only shows as issued by Coriqo when its key is listed here.
//
// Kept in git, not in a deploy variable, so every change to the trusted key
// goes through review and shows in history. To check a value, fetch
// GET /api/v1/checkpoints/public-keys from the product API and hash the DER of
// public_key_pem. Move a retired or compromised key to the revoked list; never
// just delete it, or files signed with it stop reading as a known Coriqo key.

window.CORIQO_PUBLISHED_FINGERPRINTS = [
  'cd93fe9775fd3d555a60d6903b309335af49c65a8b9b5727134dc31059f0ebc4' // coriqo-v1
];

window.CORIQO_REVOKED_FINGERPRINTS = [];

// The ids of the keys above. An organisation's own signing key can never reuse
// one of these (enrolment refuses it), so a file naming one of these ids but
// carrying a different key is a mismatch, not an organisation's own key.
window.CORIQO_PUBLISHED_KEY_IDS = ['coriqo-v1'];

# Truly Imagined record formats

The formats Truly Imagined publishes, as a stranger needs them to check a record without us. Each is named and
versioned (`ti-seal-v1`, `ti-bundle-v1`, ...). **A format is never reinterpreted.** A change of shape is a new
name, and a verifier that meets a name it does not know refuses it rather than guessing.

`src/h2a/` in this repository is the reference implementation: the same code Truly Imagined's own /verify runs,
copied byte for byte and checked for drift on every change to it. `oracle/oracle.mjs` is a second, independent
implementation of the checks below. Where this document and the code disagree, it is a bug; tell us.

## Conventions

- **Hashes** are SHA-256, written as 64 lowercase hexadecimal characters.
- **Canonical JSON** is RFC 8785 (JCS): object keys sorted by UTF-16 code unit, no whitespace, numbers in their
  shortest round-trip form.
- **The payload policy** (what a sealed payload may contain): plain objects, arrays, strings, booleans, `null`, and
  integers between -(2^53 - 1) and 2^53 - 1. No fractions (a decimal is sent as a string), no `-0`, no sparse
  arrays, no key named `__proto__`. A payload outside the policy is never sealed, and a verifier refuses one.
- **Signatures** are ECDSA P-256 with SHA-256 (ES256), encoded as the raw 64 bytes `r || s` (not DER), then
  base64url without padding.
- **Keys** are identified by the SHA-256 of their DER (SPKI) public key. The alias inside a record is a label and
  is not signed: never choose a key because a record names it. Take keys from `kilbowie/ti-anchors` `keys/` or
  `trulyimagined.com/trust`.
- **Timestamps** are RFC 3161 tokens from DigiCert and FreeTSA over a record's entry hash. Check them against
  each authority's own root, from the authority.

## ti-seal-v1: a record

| Field | Meaning |
| --- | --- |
| `chain_pos` | Its position in the chain: 0 for the first record, then consecutive with no gaps. |
| `scheme` | `ti-seal-v1`. |
| `subject_type` | What the record is about: `chain`, `anchor`, `protocol`, `policy`, `verification`, `work`, `account`. |
| `subject_hash` | SHA-256 of the subject's identifier (as text). Records about one subject share it; the identifier itself is never published. |
| `payload` | What was sealed: the event's body plus `scheme`, `subject_type` and `subject_hash`, which must equal the fields of the same names. Its shape per event is in `schemas/events/<event>.schema.json`. |
| `payload_hash` | SHA-256 of the payload's canonical JSON, as UTF-8. |
| `prev_hash` | The entry hash of the record at `chain_pos - 1`; 64 zeros for the first record. |
| `entry_hash` | SHA-256 of the text `prev_hash` followed by `payload_hash` (128 hexadecimal characters, as ASCII). |
| `sig` | ES256 signature over the 32 bytes of `entry_hash` (hex-decoded). |
| `key_alias` | The signing key's alias. Not signed; see Conventions. |

A record **checks out** when every one of these holds: the fields are well formed; the payload is within the
policy and its three bound fields match; `prev_hash` is the previous record's entry hash; both hashes recompute;
and the signature verifies against a key you already trust. If the issuer has said a key is **not relied on from
chain position N** (see Keys), a record that key signed at N or later does not check out, though its signature is
good. Records are never re-signed.

The events, and what each body carries, are listed on `trulyimagined.com/trust`. A body never holds a name, an
email address, a title, a file name or an unhashed identifier.

## ti-bundle-v1: everything needed to check one record

Served at `trulyimagined.com/api/verify/<seal id>`, which any page may read, and downloadable from /verify.

| Field | Meaning |
| --- | --- |
| `bundle_version` | `ti-bundle-v1`. |
| `issued_at` | When it was served. Not evidence of anything. |
| `seal` | The record (ti-seal-v1). |
| `prev_entry_hash` | The entry hash of the record before it, so the link can be checked from the bundle alone. |
| `stamps` | Each timestamp token: `tsa`, `token_base64` (the full DER TimeStampResp) and `tsa_time` (the time as we read it, unverified: check the token). |
| `anchor` | The earliest weekly anchor covering the record, or `null` if none does yet: `anchor_key`, `merkle_scheme`, `head_pos`, `head_hash`, `merkle_root`, `leaf_index` (= `chain_pos`), `tree_size` (= `head_pos + 1`), `proof` (the RFC 6962 audit path, bottom first), `seal_id` of the anchor's own record, and `publications` (where it has been published so far). |

The bundle never carries the issuer key: a bundle that brought its own key would prove nothing. The served bundle
also carries `ti_verdict`, `key_is_published` and `related_records`, which are our own word and are not part of
the format; a verifier ignores them.

## ti-anchor-v1: a weekly anchor

Published each Monday to `kilbowie/ti-anchors` at `anchors/<anchor_key>.json`, and to storage under a ten-year
compliance lock, byte for byte the same.

| Field | Meaning |
| --- | --- |
| `anchor_version` | `ti-anchor-v1`. |
| `anchor_key` | The ISO week the anchor was sealed in, such as `2026-W38`. It covers the whole chain up to that moment. |
| `merkle_scheme` | `rfc6962-sha256`. |
| `head_pos`, `head_hash` | The last record covered, and its entry hash. |
| `merkle_root` | The root of the Merkle tree over every entry hash from position 0 to `head_pos`. |
| `sealed_at` | When the anchor's own record was made. |
| `seal` | That record (an `anchor.published` ti-seal-v1 at `head_pos + 1`), whose payload names the same key, head and root. |
| `entry_hashes` | Every entry hash from position 0 to `head_pos`, in order, so anyone can rebuild the root. |

**The tree** is RFC 6962's: a leaf is SHA-256 of the byte `0x00` followed by the 32 bytes of an entry hash; an inner
node is SHA-256 of `0x01`, its left child and its right child; and a tree of n leaves splits at the largest power of
two below n. A later anchor's `entry_hashes` extends an earlier one's unchanged: history that changed between two
anchors shows as a difference here.

## ti-records-v1: the records an anchor newly covers

Exported beside each anchor (`records/<anchor_key>.json`), so the chain survives the loss of our database.
`anchor_key`, `from_pos` and `to_pos` (just after the previous anchor's head, to this anchor's head),
`prev_entry_hash` (the entry hash before `from_pos`), and `records` (ti-seal-v1, in order). Together the files are the
whole chain; each checks on its own, and each record must sit at its position in the anchor's `entry_hashes`.

## ti-stamps-v1: the timestamp tokens for an anchor's records

Exported a week after the anchor (`stamps/<anchor_key>.json`), once the tokens have had time to arrive. `anchor_key`,
`from_pos` and `to_pos` as for its records file; `stamps`, each `chain_pos`, `entry_hash`, `tsa` and `token` (base64
DER); and `unstamped`, every position in the range that has no token. Each token's imprint is its record's entry
hash; check its signature with `openssl ts -verify -digest <entry_hash> -sha256 -in <token>` and the authority's root.

## ti-export-v1: a member's own records

What a member downloads from their vault: `format` (`ti-export-v1`), `exported_at`, `creator_ref` (the per-account
reference every `work.created` record of theirs carries), `creator_key` (the secret that shows `creator_ref` is
theirs; it never appears anywhere public), `records` (ti-bundle-v1), `files` (each file those records sealed, with its
`sha256`), and `part` (`index`, `count`, `as_of_chain_pos`, `records_total`) when a large vault comes in parts. Each
part checks on its own. `issuer_key_pem` is a convenience: take the key from ti-anchors or /trust instead.

## ti-evidence-v1: one record, packed to be checked without us

Made in the visitor's browser on trulyimagined.com/verify ("Download the evidence pack"), one JSON file:
`evidence_version` (`ti-evidence-v1`), `made_at`, `readme` (how to use it), `bundle` (the ti-bundle-v1, unchanged),
`key` (`alias`, its `sha256` fingerprint and where to fetch it; never the key itself), `timestamp_authorities` (each
root's name, `root_source` and `root_sha256`; never the root itself), `anchor` (`anchor_key`, `public_url`,
`merkle_root`, or `null`), and `ots` (the anchor's OpenTimestamps proof; `null` until anchors carry one).
`ti-verify bundle <pack>` checks the bundle inside.

## Keys

Rotation is driven by events, not by a calendar. If a key is withdrawn after a compromise, the issuer says so in
`kilbowie/ti-anchors` `keys/LOG.md`, naming the key's fingerprint and the chain position from which its records are
not relied on. Every record before that position stands. `ti-verify --untrusted-from <N>` applies it.

## Event schemas

`schemas/events/<event>.schema.json` (JSON Schema 2020-12) describes each event's whole sealed payload, with
`additionalProperties: false` throughout: a field that is not in the schema is not in a record. They are generated
from the lists the sealing code itself checks against, and a test in Truly Imagined's repository fails if a schema
here and the code disagree.

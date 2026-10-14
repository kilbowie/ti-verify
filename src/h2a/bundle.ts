// The verification bundle: everything a stranger needs to check one seal, and nothing that identifies
// anybody. TI serves it from /api/verify/<seal id>; the browser verifier, the server and the offline
// openssl path all read this same shape, so a downloaded bundle verifies years later without TI.
//
// What a bundle does and does not carry:
//   - the seal itself, and the entry hash of the seal before it, so the link can be recomputed;
//   - the RFC 3161 timestamp tokens, as base64 DER, to be checked offline against the TSAs' own roots;
//   - `tsa_time` as TI read it, which this code does NOT verify: it is a convenience, not evidence;
//   - the earliest anchor covering this seal, whether or not it has been published yet (its
//     `publications` say where it has), with the audit path proving the seal is inside that anchor's
//     Merkle root. A seal sealed since the last anchor has no anchor yet.
// The issuer public key is deliberately absent. A bundle that carried its own key would prove nothing:
// verifiers take the key from /trust or from the published repo.

import { verifyEntryHashInclusion } from "./merkle.js";
import { GENESIS_PREV_HASH, isSha256Hex, type SealRecord } from "./seal.js";
import { verifySeal, type IssuerKey, type KeyTrust, type Verdict } from "./verify.js";

/** The only Merkle scheme this bundle version carries (D1). */
export const MERKLE_SCHEME = "rfc6962-sha256";

export const BUNDLE_VERSION = "ti-bundle-v1";

export interface BundleStamp {
  tsa: string;
  /** Full DER TimeStampResp, base64. */
  token_base64: string;
  /** genTime as TI parsed it. Unverified here: check it offline with the openssl commands on /verify. */
  tsa_time: string | null;
}

export interface BundleAnchor {
  /**
   * The ISO week the anchor was sealed in, e.g. "2026-W38": each Monday's anchor covers the whole chain up to
   * that moment, so mostly the week before. Names the file in the public anchor repo.
   */
  anchor_key: string;
  merkle_scheme: string;
  /** Chain position of the last seal in the anchored tree, so tree_size is head_pos + 1. */
  head_pos: number;
  head_hash: string;
  merkle_root: string;
  /** Leaf index of this seal in that tree: its chain_pos. */
  leaf_index: number;
  tree_size: number;
  /** RFC 6962 audit path, bottom first, lowercase hex. */
  proof: string[];
  /** The anchor.published seal, verifiable in its own right at /verify. */
  seal_id: string;
  /** Where this anchor has been published. Empty until the first publication succeeds. */
  publications: { target: string; ref: string }[];
}

export interface SealBundle {
  bundle_version: string;
  /** When TI served this bundle. Not evidence of anything: the seal's own timestamps are. */
  issued_at: string;
  seal: SealRecord;
  /** entry_hash of the seal at chain_pos - 1; 64 zeros at position 0. */
  prev_entry_hash: string;
  stamps: BundleStamp[];
  /**
   * The earliest anchor covering this seal (published or not; see its `publications`), or null if it has not
   * been anchored yet. The earliest, because it is the first commitment to the record, with the strongest date.
   */
  anchor: BundleAnchor | null;
}

/**
 * Verifies a bundle against an issuer key the caller already trusts: the seal's payload hash, its link
 * to the seal before it, its signature, and, when the bundle carries an anchor, that the seal is inside
 * that anchor's published Merkle root.
 *
 * What it still does not do is tell you the anchor was published. Take the root from the public anchor
 * repo, not from this bundle, and compare: the bundle's own copy is TI's word for it.
 */
export async function verifyBundle(bundle: SealBundle, key: IssuerKey, trust: KeyTrust = {}): Promise<Verdict> {
  if (bundle?.bundle_version !== BUNDLE_VERSION) {
    return { ok: false, failure: "malformed", detail: `unsupported bundle version ${JSON.stringify(bundle?.bundle_version)}` };
  }
  if (!isSha256Hex(bundle.prev_entry_hash)) {
    return { ok: false, failure: "malformed", detail: "prev_entry_hash is not 64 lowercase hex characters" };
  }
  if (bundle.seal?.chain_pos === 0 && bundle.prev_entry_hash !== GENESIS_PREV_HASH) {
    return { ok: false, failure: "prev_hash_mismatch", detail: "the first seal in a chain must follow the all-zero hash" };
  }
  const verdict = await verifySeal(bundle.seal, key, bundle.prev_entry_hash, trust);
  if (!verdict.ok || !bundle.anchor) return verdict;
  return verifyBundleAnchor(bundle.seal, bundle.anchor);
}

/** Checks that a seal sits where the anchor says it does, inside the anchor's Merkle root. */
export async function verifyBundleAnchor(seal: SealRecord, anchor: BundleAnchor): Promise<Verdict> {
  if (anchor.merkle_scheme !== MERKLE_SCHEME) {
    return { ok: false, failure: "malformed", detail: `unsupported Merkle scheme ${JSON.stringify(anchor.merkle_scheme)}` };
  }
  if (!isSha256Hex(anchor.merkle_root) || !isSha256Hex(anchor.head_hash)) {
    return { ok: false, failure: "malformed", detail: "anchor hashes are not 64 lowercase hex characters" };
  }
  if (anchor.tree_size !== anchor.head_pos + 1 || anchor.leaf_index !== seal.chain_pos) {
    return { ok: false, failure: "anchor_head_mismatch", detail: "the anchor does not describe this seal's position" };
  }
  const included = await verifyEntryHashInclusion(
    seal.entry_hash,
    anchor.leaf_index,
    anchor.tree_size,
    anchor.proof,
    anchor.merkle_root,
  );
  return included
    ? { ok: true }
    : { ok: false, failure: "anchor_inclusion", detail: "this record is not inside the anchor's Merkle root" };
}

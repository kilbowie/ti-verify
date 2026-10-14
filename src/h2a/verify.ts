// Verifier core. Zero runtime dependencies and no Node APIs: WebCrypto only, so this module and
// everything it imports run unchanged in a browser, and a stranger can audit the whole path.
// A dependency test fails CI if anything reachable from here imports outside packages/h2a/src.
//
// Every function returns a verdict instead of throwing, so the UI can say precisely what failed.

import { fromBase64, fromBase64Url, fromHex, type Bytes } from "./bytes.js";
import { SealPayloadError } from "./canonical.js";
import { ES256_SIGNATURE_BYTES, looksLikeDer } from "./ecdsa.js";
import { entryHashesRoot } from "./merkle.js";
import { GENESIS_PREV_HASH, TI_SEAL_V1, computeSealHashes, isSha256Hex, type SealRecord } from "./seal.js";

export type VerifyFailure =
  | "malformed"
  | "unknown_scheme"
  | "payload_policy"
  | "payload_binding"
  | "payload_hash_mismatch"
  | "prev_hash_mismatch"
  | "entry_hash_mismatch"
  | "signature_der"
  | "signature_malformed"
  | "signature_invalid"
  | "chain_position"
  | "anchor_head_mismatch"
  | "anchor_root_mismatch"
  | "anchor_inclusion"
  | "key_untrusted";

export type Verdict = { ok: true } | { ok: false; failure: VerifyFailure; detail: string };

/** A WebCrypto public key. Derived from crypto.subtle so it resolves under both DOM and Node type definitions. */
export type IssuerKey = Awaited<ReturnType<typeof crypto.subtle.importKey>>;

/**
 * What the verifier is told about a key beyond the key itself (D185, ROADMAP2 S5.9). Keys are rotated when
 * something happens, not on a calendar, and a record is never re-signed: if a key is compromised, its
 * issuer says publicly from which chain position its records are not relied on. A record signed there or
 * later then fails as `key_untrusted`, even though its signature checks out, and every record before it
 * stands. Absent or null, the key is relied on throughout.
 */
export interface KeyTrust {
  untrustedFromChainPos?: number | null;
}

const pass: Verdict = { ok: true };
const fail = (failure: VerifyFailure, detail: string): Verdict => ({ ok: false, failure, detail });

/** Imports an ECDSA P-256 public key from SPKI PEM, as published on /trust. */
export async function importIssuerKey(spkiPem: string): Promise<IssuerKey> {
  const match = /-----BEGIN PUBLIC KEY-----([\s\S]+?)-----END PUBLIC KEY-----/.exec(spkiPem);
  if (!match) throw new Error("importIssuerKey: expected a PEM PUBLIC KEY block");
  const spki = fromBase64(match[1]!);
  return crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, [
    "verify",
  ]);
}

/**
 * Verifies one seal against the issuer key and the entry_hash of the seal before it
 * (GENESIS_PREV_HASH for chain_pos 0). Dispatches on scheme (D11).
 */
export async function verifySeal(seal: SealRecord, key: IssuerKey, expectedPrevHash: string, trust: KeyTrust = {}): Promise<Verdict> {
  if (seal.scheme !== TI_SEAL_V1) return fail("unknown_scheme", `unsupported scheme ${JSON.stringify(seal.scheme)}`);
  const verdict = await verifyTiSealV1(seal, key, expectedPrevHash);
  // Checked last: a record that fails on its own terms says so first, and only a sound record signed after
  // the key was withdrawn is reported as untrusted.
  const from = trust.untrustedFromChainPos;
  if (verdict.ok && typeof from === "number" && seal.chain_pos >= from) {
    return fail("key_untrusted", `signed at chain position ${seal.chain_pos}; this key is not relied on from position ${from}`);
  }
  return verdict;
}

async function verifyTiSealV1(seal: SealRecord, key: IssuerKey, expectedPrevHash: string): Promise<Verdict> {
  for (const field of ["subject_hash", "payload_hash", "prev_hash", "entry_hash"] as const) {
    if (!isSha256Hex(seal[field])) return fail("malformed", `${field} is not 64 lowercase hex characters`);
  }
  if (typeof seal.payload !== "object" || seal.payload === null || Array.isArray(seal.payload)) {
    return fail("malformed", "payload is not an object");
  }
  for (const field of ["scheme", "subject_type", "subject_hash"] as const) {
    if (seal.payload[field] !== seal[field]) {
      return fail("payload_binding", `payload.${field} does not match the seal's ${field}`);
    }
  }
  if (seal.prev_hash !== expectedPrevHash) {
    return fail("prev_hash_mismatch", "prev_hash is not the entry_hash of the previous seal");
  }

  let hashes;
  try {
    hashes = await computeSealHashes(seal.payload, seal.prev_hash);
  } catch (error) {
    if (error instanceof SealPayloadError) return fail("payload_policy", error.message);
    throw error;
  }
  if (hashes.payloadHash !== seal.payload_hash) {
    return fail("payload_hash_mismatch", "payload does not hash to payload_hash");
  }
  if (hashes.entryHash !== seal.entry_hash) {
    return fail("entry_hash_mismatch", "entry_hash is not sha256(prev_hash ‖ payload_hash)");
  }

  let sig: Bytes;
  try {
    sig = fromBase64Url(seal.sig);
  } catch {
    return fail("signature_malformed", "sig is not unpadded base64url");
  }
  if (looksLikeDer(sig)) {
    return fail("signature_der", "sig is DER-encoded; ti-seal-v1 requires raw 64-byte r‖s (H2A ADR-014)");
  }
  if (sig.length !== ES256_SIGNATURE_BYTES) {
    return fail("signature_malformed", `sig is ${sig.length} bytes; expected ${ES256_SIGNATURE_BYTES}`);
  }
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    sig,
    fromHex(seal.entry_hash),
  );
  return valid ? pass : fail("signature_invalid", "signature does not verify against the issuer key");
}

/**
 * Verifies a contiguous run of seals in chain order. With no options, the run must start at the
 * genesis seal; to verify a later segment, pass the chain position and prev_hash it starts from.
 */
export async function verifyChain(
  seals: readonly SealRecord[],
  key: IssuerKey,
  from: { chainPos: number; prevHash: string } = { chainPos: 0, prevHash: GENESIS_PREV_HASH },
  trust: KeyTrust = {},
): Promise<Verdict & { verified: number }> {
  let prevHash = from.prevHash;
  for (const [i, seal] of seals.entries()) {
    const expectedPos = from.chainPos + i;
    if (seal.chain_pos !== expectedPos) {
      return { ...fail("chain_position", `expected chain_pos ${expectedPos}, found ${seal.chain_pos}`), verified: i };
    }
    const verdict = await verifySeal(seal, key, prevHash, trust);
    if (!verdict.ok) return { ...verdict, detail: `chain_pos ${seal.chain_pos}: ${verdict.detail}`, verified: i };
    prevHash = seal.entry_hash;
  }
  return { ...pass, verified: seals.length };
}

export interface AnchorRecord {
  head_pos: number;
  head_hash: string;
  merkle_root: string;
}

/**
 * Verifies an anchor against the entry hashes of seals 0..head_pos, in chain order. The entry hashes
 * should come from a chain that verifyChain has accepted; this checks only the anchor's own claims.
 */
export async function verifyAnchor(anchor: AnchorRecord, entryHashes: readonly string[]): Promise<Verdict> {
  if (!isSha256Hex(anchor.merkle_root) || !isSha256Hex(anchor.head_hash)) {
    return fail("malformed", "anchor hashes are not 64 lowercase hex characters");
  }
  if (!entryHashes.every(isSha256Hex)) return fail("malformed", "entry hashes are not 64 lowercase hex characters");
  if (entryHashes.length !== anchor.head_pos + 1 || entryHashes[anchor.head_pos] !== anchor.head_hash) {
    return fail("anchor_head_mismatch", `anchor head ${anchor.head_pos} does not match the chain supplied`);
  }
  const root = await entryHashesRoot(entryHashes);
  return root === anchor.merkle_root ? pass : fail("anchor_root_mismatch", "Merkle root does not match the entry hashes");
}

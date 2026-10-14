// The ti-seal-v1 scheme (D11): what a seal is, and how its hashes are derived. The sealer uses these
// functions to build seals; the verifier uses the same functions to recompute them.
//
//   payload        a JSON object satisfying the D5 policy, which MUST contain
//                    scheme        "ti-seal-v1"
//                    subject_type  equal to the seal's subject_type
//                    subject_hash  equal to the seal's subject_hash
//                  so the signature covers them: they cannot be relabelled after sealing.
//   payload_hash   hex SHA-256 of the RFC 8785 canonical payload bytes
//   prev_hash      entry_hash of the seal at chain_pos - 1; 64 zeros at chain_pos 0
//   entry_hash     hex SHA-256 of the UTF-8 bytes of (prev_hash ‖ payload_hash), both as lowercase hex
//   sig            ES256 (ECDSA P-256, SHA-256) over the 32 raw bytes of entry_hash, as raw r‖s,
//                  base64url. Equivalent to AWS KMS Sign with MessageType RAW over those 32 bytes.

import { canonicalSealBytes } from "./canonical.js";
import { sha256Hex } from "./hash.js";

export const TI_SEAL_V1 = "ti-seal-v1";
export const SEAL_SCHEMES = [TI_SEAL_V1] as const;
export type SealScheme = (typeof SEAL_SCHEMES)[number];

export const GENESIS_PREV_HASH = "0".repeat(64);

/** A seal as exported in a verification bundle. Field names match the database columns. */
export interface SealRecord {
  chain_pos: number;
  scheme: string;
  subject_type: string;
  subject_hash: string;
  payload: Record<string, unknown>;
  payload_hash: string;
  prev_hash: string;
  entry_hash: string;
  sig: string;
  key_alias: string;
}

export interface SealHashes {
  payloadBytes: Uint8Array;
  payloadHash: string;
  entryHash: string;
}

/** Canonicalises the payload under the D5 policy and derives payload_hash and entry_hash. */
export async function computeSealHashes(payload: unknown, prevHash: string): Promise<SealHashes> {
  if (!isSha256Hex(prevHash)) throw new Error("prev_hash must be 64 lowercase hex characters");
  const payloadBytes = canonicalSealBytes(payload);
  const payloadHash = await sha256Hex(payloadBytes);
  const entryHash = await sha256Hex(prevHash + payloadHash);
  return { payloadBytes, payloadHash, entryHash };
}

export function isSha256Hex(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

// ES256 signature encoding (H2A ADR-014 §2, D8). A seal's signature is the fixed-width 64-byte
// concatenation r‖s (RFC 7518 §3.4), carried as base64url. Never DER.
//
// AWS KMS returns DER, so the sealer converts once, at that boundary, with derToRaw. The verifier
// never converts the other way: a DER signature is refused, as the H2A reference verifier refuses it,
// so that one signature has exactly one accepted spelling.
//
// Interface after h2a-protocol reference/verifier/src/jcs.ts (Apache-2.0, see ../NOTICE); the parser
// is rewritten for Uint8Array and made strict (definite short-form lengths, minimal positive INTEGERs,
// no trailing bytes).

import { concatBytes, type Bytes } from "./bytes.js";

const COORD = 32;
export const ES256_SIGNATURE_BYTES = 2 * COORD;

/** DER SEQUENCE { INTEGER r, INTEGER s } from a P-256 ECDSA signer, to raw 64-byte r‖s. */
export function derToRaw(der: Uint8Array): Bytes {
  let i = 0;
  const byte = (): number => {
    if (i >= der.length) throw new Error("derToRaw: truncated signature");
    return der[i++]!;
  };
  if (byte() !== 0x30) throw new Error("derToRaw: expected SEQUENCE");
  const seqLen = byte();
  // A P-256 signature is at most 72 bytes, so its lengths always use DER's short form.
  if (seqLen & 0x80 || i + seqLen !== der.length) throw new Error("derToRaw: bad SEQUENCE length");
  const readInt = (): Uint8Array => {
    if (byte() !== 0x02) throw new Error("derToRaw: expected INTEGER");
    const len = byte();
    if (len === 0 || len > COORD + 1 || i + len > der.length) throw new Error("derToRaw: bad INTEGER length");
    const value = der.subarray(i, i + len);
    i += len;
    if (value[0]! & 0x80) throw new Error("derToRaw: negative INTEGER");
    if (len > 1 && value[0] === 0 && !(value[1]! & 0x80)) throw new Error("derToRaw: non-minimal INTEGER");
    const unpadded = value[0] === 0 && len > 1 ? value.subarray(1) : value;
    if (unpadded.length > COORD) throw new Error("derToRaw: INTEGER wider than 32 bytes");
    const out = new Uint8Array(COORD);
    out.set(unpadded, COORD - unpadded.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  if (i !== der.length) throw new Error("derToRaw: trailing bytes");
  return concatBytes(r, s);
}

/** Raw 64-byte r‖s to DER. Only for interop tests and for openssl, which wants DER. */
export function rawToDer(raw: Uint8Array): Bytes {
  if (raw.length !== ES256_SIGNATURE_BYTES) {
    throw new Error(`rawToDer: expected ${ES256_SIGNATURE_BYTES} bytes, got ${raw.length}`);
  }
  const derInt = (coord: Uint8Array): Uint8Array => {
    let start = 0;
    while (start < coord.length - 1 && coord[start] === 0) start++;
    let value = coord.subarray(start);
    if (value[0]! & 0x80) value = concatBytes(new Uint8Array([0]), value);
    return concatBytes(new Uint8Array([0x02, value.length]), value);
  };
  const r = derInt(raw.subarray(0, COORD));
  const s = derInt(raw.subarray(COORD));
  return concatBytes(new Uint8Array([0x30, r.length + s.length]), r, s);
}

/** True if the bytes look like a DER signature rather than raw r‖s; used to give a precise refusal. */
export function looksLikeDer(sig: Uint8Array): boolean {
  return sig.length !== ES256_SIGNATURE_BYTES && sig[0] === 0x30;
}

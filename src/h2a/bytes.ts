// Byte encodings the verifier needs, written against Uint8Array so the same code runs in Node and
// in the browser. Node's Buffer is deliberately not used anywhere in this package.

/** Bytes backed by a plain ArrayBuffer, which is what WebCrypto accepts. */
export type Bytes = Uint8Array<ArrayBuffer>;

const encoder = new TextEncoder();

export function utf8(text: string): Bytes {
  return encoder.encode(text);
}

export function concatBytes(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Lowercase hex only: the chain stores hashes as lowercase hex, and a second spelling of the same hash is a bug. */
export function fromHex(hex: string): Bytes {
  if (!/^(?:[0-9a-f]{2})*$/.test(hex)) throw new Error("fromHex: expected lowercase hex of even length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** RFC 4648 §5 base64url, unpadded. */
export function toBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]!;
    if (i + 1 < bytes.length) out += B64URL[(n >> 6) & 63]!;
    if (i + 2 < bytes.length) out += B64URL[n & 63]!;
  }
  return out;
}

/** Strict unpadded base64url: rejects padding, the standard alphabet's + and /, and non-canonical trailing bits. */
export function fromBase64Url(text: string): Bytes {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    throw new Error("fromBase64Url: not unpadded base64url");
  }
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let bits = 0;
  let value = 0;
  let o = 0;
  for (const ch of text) {
    value = (value << 6) | B64URL.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (value >> bits) & 0xff;
    }
  }
  if ((value & ((1 << bits) - 1)) !== 0) throw new Error("fromBase64Url: non-canonical trailing bits");
  return out;
}

/** Standard padded base64 (RFC 4648 §4), for PEM bodies and KMS output. */
export function fromBase64(text: string): Bytes {
  const body = text.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(body) || body.length % 4 !== 0) throw new Error("fromBase64: not base64");
  return fromBase64Url(body.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"));
}

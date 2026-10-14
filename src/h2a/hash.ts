// SHA-256 through WebCrypto, which Node 22 and every current browser provide as globalThis.crypto.

import { toHex, utf8, type Bytes } from "./bytes.js";

export async function sha256(data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(data)));
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  return toHex(await sha256(typeof data === "string" ? utf8(data) : data));
}

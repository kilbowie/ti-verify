// RFC 8785 JSON Canonicalization Scheme (H2A ADR-014), plus TI's seal payload policy (D5).
//
// Ported from h2a-protocol reference/verifier/src/jcs.ts at commit 61e1ca84869adb917435575a8175313ac823a304,
// Copyright Kilbowie, licensed under the Apache License 2.0 (see ../NOTICE and ../LICENSES/Apache-2.0.txt).
// Changes from the original: returns Uint8Array instead of Buffer so it runs in browsers; strict-mode
// index typing; the ES256 helpers moved to ecdsa.ts; the seal payload policy below is new.
//
// Why the original is correct, in one line: JavaScript's JSON.stringify already emits RFC 8785
// numbers and strings, so the only work is key ordering, done by sorting an ARRAY of keys with the
// default comparator (UTF-16 code units as unsigned integers, RFC 8785 §3.2.3). Never rebuild an
// object from sorted entries: integer-like keys would jump to the front and undo the sort.

import { utf8 } from "./bytes.js";

/** RFC 8785 canonical JSON. Throws on values JSON cannot represent. */
export function jcs(value: unknown): string {
  const out = serialize(value);
  if (out === undefined) throw new Error("jcs: value is not representable as JSON");
  return out;
}

/** The UTF-8 bytes to hash or sign. Signatures are over bytes, not strings. */
export function jcsBytes(value: unknown): Uint8Array {
  return utf8(jcs(value));
}

function serialize(v: unknown): string | undefined {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      // NaN and Infinity have no JSON form. JSON.stringify would emit "null", silently giving two
      // different values the same bytes.
      if (!Number.isFinite(v)) throw new Error(`jcs: ${String(v)} has no JSON representation`);
      return JSON.stringify(v);
    case "string":
      return JSON.stringify(v);
    case "object":
      break;
    default:
      return undefined; // undefined, function, symbol: dropped by JSON, so dropped here
  }

  if (Array.isArray(v)) {
    return "[" + v.map((e) => serialize(e) ?? "null").join(",") + "]";
  }
  if (typeof (v as { toJSON?: unknown }).toJSON === "function") {
    return serialize((v as { toJSON: () => unknown }).toJSON());
  }

  const obj = v as Record<string, unknown>;
  const parts: string[] = [];
  for (const key of Object.keys(obj).sort()) {
    const encoded = serialize(obj[key]);
    if (encoded === undefined) continue;
    parts.push(JSON.stringify(key) + ":" + encoded);
  }
  return "{" + parts.join(",") + "}";
}

// ---------------------------------------------------------------------------------------------
// Seal payload policy (D5). JCS accepts any JSON; a seal payload accepts less, so that the bytes a
// verifier recomputes cannot depend on how some other language prints a float, and so nothing JCS
// would silently drop or coerce can reach a signature:
//   - strings, booleans, null, safe integers (|n| <= 2^53 - 1), arrays, and plain objects only;
//   - no floats, no -0, no NaN or Infinity: decimals travel as strings;
//   - no undefined, functions, symbols, bigints, Dates or other objects with toJSON;
//   - no sparse arrays;
//   - no "__proto__" key: valid JSON, but ordinary JavaScript object handling (assignment, many
//     clone and merge helpers) silently drops it, so an independent verifier could recompute
//     different bytes and reject a genuine seal.
// ---------------------------------------------------------------------------------------------

export class SealPayloadError extends Error {
  constructor(
    readonly path: string,
    reason: string,
  ) {
    super(`seal payload ${path}: ${reason}`);
    this.name = "SealPayloadError";
  }
}

/** Throws SealPayloadError, naming the offending path, unless the value satisfies the D5 policy. */
export function assertSealPayload(value: unknown): asserts value is Record<string, unknown> {
  if (!isPlainObject(value)) throw new SealPayloadError("$", "must be a plain object");
  check(value, "$", new Set());
}

/** Canonical bytes of a seal payload: the D5 policy, then RFC 8785. */
export function canonicalSealBytes(payload: unknown): Uint8Array {
  assertSealPayload(payload);
  return jcsBytes(payload);
}

function check(v: unknown, path: string, seen: Set<object>): void {
  if (v === null || typeof v === "string" || typeof v === "boolean") return;
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new SealPayloadError(path, `${String(v)} is not a safe integer; send decimals as strings`);
    if (Object.is(v, -0)) throw new SealPayloadError(path, "-0 is not allowed");
    return;
  }
  if (typeof v !== "object") throw new SealPayloadError(path, `${typeof v} is not allowed`);
  if (seen.has(v)) throw new SealPayloadError(path, "circular reference");
  seen.add(v);
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) {
      if (!(i in v)) throw new SealPayloadError(`${path}[${i}]`, "sparse arrays are not allowed");
      check(v[i], `${path}[${i}]`, seen);
    }
  } else if (isPlainObject(v)) {
    for (const key of Object.keys(v)) {
      if (key === "__proto__") throw new SealPayloadError(`${path}.__proto__`, "the __proto__ key is not allowed");
      check(v[key], `${path}.${key}`, seen);
    }
  } else {
    throw new SealPayloadError(path, "only plain objects and arrays are allowed");
  }
  seen.delete(v);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

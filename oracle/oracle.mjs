#!/usr/bin/env node
// The independent oracle (ROADMAP2 S5.5, D179): a second verifier that shares no code with the first. It
// imports nothing from src/ or from Truly Imagined: its own RFC 8785 canonical JSON, node:crypto for SHA-256
// and ECDSA, its own RFC 6962 Merkle tree (written from the RFC's recursive definition, not as the first
// verifier builds it), and the OpenSSL command line for timestamp tokens. When the two verifiers agree, a
// mistake would have to be made twice, in two different ways.
//
//   node oracle/oracle.mjs --key <issuer.pem> [--tsa-root <root.pem>]... [--anchor <anchor.json>]...
//                          <bundle.json | https://trulyimagined.com/api/verify/<seal id>>...
//
// Exit 0 when every bundle checks out, 1 when any does not, 2 on bad usage.
import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const GENESIS = "0".repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
const sha256 = (data) => createHash("sha256").update(data).digest();

/** RFC 8785 for the values a seal payload may hold: null, booleans, strings, safe integers, arrays, objects. */
export function canonical(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error(`payload number ${value} is outside the seal policy`);
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    // Keys in UTF-16 code unit order, which is what Array.prototype.sort does with strings.
    const keys = Object.keys(value).sort();
    if (keys.includes("__proto__")) throw new Error("payload key __proto__ is outside the seal policy");
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  throw new Error(`payload value of type ${typeof value} is outside the seal policy`);
}

/** RFC 6962 §2.1, as written: MTH of n leaves splits at the largest power of two below n. */
export function merkleTreeHash(leaves) {
  if (leaves.length === 0) return sha256(Buffer.alloc(0));
  if (leaves.length === 1) return sha256(Buffer.concat([Buffer.from([0x00]), leaves[0]]));
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  return sha256(Buffer.concat([Buffer.from([0x01]), merkleTreeHash(leaves.slice(0, k)), merkleTreeHash(leaves.slice(k))]));
}

/** RFC 6962 §2.1.1: rebuild the root from one leaf and its audit path, bottom first. */
export function rootFromPath(leaf, index, size, path) {
  if (index >= size) return null;
  let hash = sha256(Buffer.concat([Buffer.from([0x00]), leaf]));
  let fn = index;
  let sn = size - 1;
  for (const sibling of path) {
    if (sn === 0) return null;
    if (fn % 2 === 1 || fn === sn) {
      hash = sha256(Buffer.concat([Buffer.from([0x01]), sibling, hash]));
      while (fn % 2 === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      hash = sha256(Buffer.concat([Buffer.from([0x01]), hash, sibling]));
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 ? hash : null;
}

function signatureOk(entryHash, sig, key) {
  const raw = Buffer.from(sig.replaceAll("-", "+").replaceAll("_", "/"), "base64");
  if (raw.length !== 64) return false;
  try {
    return verify("sha256", Buffer.from(entryHash, "hex"), { key, dsaEncoding: "ieee-p1363" }, raw);
  } catch {
    return false;
  }
}

/** A seal's own claims: its fields, its hashes, its link and its signature. */
export function checkSeal(seal, prevHash, key) {
  for (const field of ["subject_hash", "payload_hash", "prev_hash", "entry_hash"]) if (!HEX64.test(seal[field] ?? "")) return `${field} is not 64 lowercase hex`;
  if (seal.scheme !== "ti-seal-v1") return `unknown scheme ${seal.scheme}`;
  const payload = seal.payload;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return "payload is not an object";
  for (const field of ["scheme", "subject_type", "subject_hash"]) if (payload[field] !== seal[field]) return `payload.${field} differs from the seal's`;
  if (seal.prev_hash !== prevHash) return "prev_hash is not the previous record's entry hash";
  let payloadHash;
  try {
    payloadHash = sha256(Buffer.from(canonical(payload), "utf8")).toString("hex");
  } catch (error) {
    return error.message;
  }
  if (payloadHash !== seal.payload_hash) return "payload does not hash to payload_hash";
  if (sha256(Buffer.from(seal.prev_hash + seal.payload_hash, "utf8")).toString("hex") !== seal.entry_hash) return "entry_hash is not sha256(prev_hash || payload_hash)";
  if (!signatureOk(seal.entry_hash, seal.sig ?? "", key)) return "signature does not verify against the key given";
  return null;
}

function opensslAvailable() {
  try {
    execFileSync("openssl", ["version"], { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

/** OpenSSL's verdict on one token: the -digest form, with the token's own certificates as -untrusted. */
function opensslStamp(tokenBase64, entryHash, rootPath) {
  const dir = mkdtempSync(join(tmpdir(), "ti-oracle-"));
  try {
    const tsr = join(dir, "token.tsr");
    writeFileSync(tsr, Buffer.from(tokenBase64, "base64"));
    execFileSync("openssl", ["ts", "-reply", "-in", tsr, "-token_out", "-out", join(dir, "token.tok")], { stdio: "pipe" });
    execFileSync("openssl", ["pkcs7", "-inform", "DER", "-in", join(dir, "token.tok"), "-print_certs", "-out", join(dir, "certs.pem")], { stdio: "pipe" });
    const out = execFileSync("openssl", ["ts", "-verify", "-digest", entryHash, "-sha256", "-in", tsr, "-CAfile", rootPath, "-untrusted", join(dir, "certs.pem")], { stdio: "pipe" }).toString();
    return out.includes("Verification: OK");
  } catch {
    return false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Every check the oracle can make on one bundle; an empty list of problems means it checks out. */
export function checkBundleIndependently(bundle, options) {
  const problems = [];
  const key = createPublicKey(options.keyPem);
  if (bundle?.bundle_version !== "ti-bundle-v1") return [`unknown bundle_version ${bundle?.bundle_version}`];
  const seal = bundle.seal;
  if (seal.chain_pos === 0 && bundle.prev_entry_hash !== GENESIS) problems.push("the first record must follow the all-zero hash");
  const sealProblem = checkSeal(seal, bundle.prev_entry_hash, key);
  if (sealProblem) problems.push(`record: ${sealProblem}`);

  if (bundle.anchor) {
    const a = bundle.anchor;
    if (a.leaf_index !== seal.chain_pos || a.tree_size !== a.head_pos + 1) problems.push("anchor: does not describe this record's position");
    const root = rootFromPath(Buffer.from(seal.entry_hash, "hex"), a.leaf_index, a.tree_size, (a.proof ?? []).map((h) => Buffer.from(h, "hex")));
    if (!root || root.toString("hex") !== a.merkle_root) problems.push("anchor: the audit path does not lead to the anchor's root");
  }
  for (const anchor of options.anchors ?? []) {
    if (anchor.anchor_key !== bundle.anchor?.anchor_key && !(anchor.head_pos >= seal.chain_pos)) continue;
    const hashes = anchor.entry_hashes ?? [];
    if (hashes[seal.chain_pos] !== seal.entry_hash) problems.push(`anchor file ${anchor.anchor_key}: does not hold this record`);
    if (merkleTreeHash(hashes.map((h) => Buffer.from(h, "hex"))).toString("hex") !== anchor.merkle_root) problems.push(`anchor file ${anchor.anchor_key}: its hashes do not rebuild its root`);
    const anchorProblem = checkSeal(anchor.seal, anchor.head_hash, key);
    if (anchorProblem) problems.push(`anchor file ${anchor.anchor_key}: its seal: ${anchorProblem}`);
    if (bundle.anchor?.anchor_key === anchor.anchor_key && bundle.anchor.merkle_root !== anchor.merkle_root) problems.push(`anchor file ${anchor.anchor_key}: a different root from the bundle's`);
  }
  if ((options.tsaRoots ?? []).length > 0) {
    if (!opensslAvailable()) problems.push("timestamps: openssl is not available to check them");
    else
      for (const stamp of bundle.stamps ?? []) {
        if (!options.tsaRoots.some((root) => opensslStamp(stamp.token_base64, seal.entry_hash, root))) problems.push(`timestamp ${stamp.tsa}: OpenSSL does not verify it against the roots given`);
      }
  }
  return problems;
}

async function main(argv) {
  const options = { anchors: [], tsaRoots: [] };
  const sources = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--key") options.keyPem = readFileSync(argv[++i], "utf8");
    else if (arg === "--tsa-root") options.tsaRoots.push(argv[++i]);
    else if (arg === "--anchor") options.anchors.push(JSON.parse(readFileSync(argv[++i], "utf8")));
    else sources.push(arg);
  }
  if (!options.keyPem || sources.length === 0) {
    console.error("usage: oracle.mjs --key <issuer.pem> [--tsa-root <root.pem>]... [--anchor <anchor.json>]... <bundle.json | URL>...");
    return 2;
  }
  let failed = 0;
  for (const source of sources) {
    const bundle = source.startsWith("https://") ? await (await fetch(source)).json() : JSON.parse(readFileSync(source, "utf8"));
    const problems = checkBundleIndependently(bundle, options);
    if (problems.length === 0) console.log(`OK    ${source}: chain position ${bundle.seal.chain_pos}`);
    else {
      failed += 1;
      console.log(`FAIL  ${source}`);
      for (const problem of problems) console.log(`      - ${problem}`);
    }
  }
  return failed === 0 ? 0 : 1;
}

// Run as a command; imported by the tests, it only exports.
if (process.argv[1]?.endsWith("oracle.mjs")) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}

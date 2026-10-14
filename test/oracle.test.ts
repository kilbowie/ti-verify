// The independent oracle agrees with ti-verify on the genesis record, refuses what ti-verify refuses, and its
// Merkle tree (from RFC 6962's recursive definition) gives the verifier's roots and paths at every size.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
// @ts-expect-error -- plain JavaScript on purpose: the oracle shares no code, and no types, with the verifier.
import { canonical, checkBundleIndependently, merkleTreeHash, rootFromPath } from "../oracle/oracle.mjs";
import { entryHashProof, entryHashesRoot, jcs } from "../src/h2a/index.js";

const fixture = (name: string) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
const text = (name: string) => readFileSync(fixture(name), "utf8");
const genesis = () => JSON.parse(text("genesis-bundle.json"));
const options = { keyPem: text("h2a-issuer-v1.pub.pem"), anchors: [JSON.parse(text("anchor-2026-W38.json"))], tsaRoots: [fixture("digicert-root.pem"), fixture("freetsa-root.pem")] };

describe("the oracle", () => {
  test("finds nothing wrong with the genesis record, its public anchor and its timestamps", () => {
    expect(checkBundleIndependently(genesis(), options)).toEqual([]);
  });

  test("finds what ti-verify finds", () => {
    const edited = genesis();
    edited.seal.payload.chain = "someone-else";
    expect(checkBundleIndependently(edited, options).join("\n")).toMatch(/payload does not hash to payload_hash/);
    const resigned = genesis();
    resigned.seal.sig = resigned.seal.sig.replace(/^./, (c: string) => (c === "A" ? "B" : "A"));
    expect(checkBundleIndependently(resigned, options).join("\n")).toMatch(/signature does not verify/);
    const unlinked = genesis();
    unlinked.prev_entry_hash = "11".repeat(32);
    expect(checkBundleIndependently(unlinked, options).join("\n")).toMatch(/all-zero hash|prev_hash/);
  });

  test("its canonical JSON is RFC 8785's, as the verifier writes it", () => {
    const value = { b: [1, "two", { "é": null, a: true }], a: " \n", "€": -5, z: {} };
    expect(canonical(value)).toBe(jcs(value));
    expect(canonical(genesis().seal.payload)).toBe(jcs(genesis().seal.payload));
  });

  test("its Merkle tree gives the verifier's root and audit paths at every size from 1 to 40", async () => {
    for (let size = 1; size <= 40; size += 1) {
      const hashes = Array.from({ length: size }, (_, i) => (i * 7919 + size).toString(16).padStart(64, "0"));
      const leaves = hashes.map((hash) => Buffer.from(hash, "hex"));
      const root = await entryHashesRoot(hashes);
      expect(merkleTreeHash(leaves).toString("hex"), `size ${size}`).toBe(root);
      for (let index = 0; index < size; index += 1) {
        const path = (await entryHashProof(hashes, index)).map((hash) => Buffer.from(hash, "hex"));
        expect(rootFromPath(leaves[index], index, size, path)?.toString("hex"), `size ${size}, leaf ${index}`).toBe(root);
      }
    }
  });
});

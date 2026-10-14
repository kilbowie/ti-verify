// ti-verify over the genesis record (the golden fixture: the prod chain's position 0, its W38 anchor as the
// public repository holds it, and both authorities' tokens), and the ways it must fail.
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { checkBundle } from "../src/check.js";
import { certificateDer } from "../src/tsa.js";

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));
const text = (name: string) => readFileSync(here(`./fixtures/${name}`), "utf8");
const genesis = () => JSON.parse(text("genesis-bundle.json"));
const anchor = () => JSON.parse(text("anchor-2026-W38.json"));
const KEY = text("h2a-issuer-v1.pub.pem");
const ROOTS = [certificateDer(text("digicert-root.pem")), certificateDer(text("freetsa-root.pem"))];

async function* chunks(data: string) {
  yield new TextEncoder().encode(data);
}

describe("the genesis record", () => {
  test("checks out: the record, its anchor from the public repository, and both timestamps", async () => {
    const report = await checkBundle({ bundle: genesis(), keyPem: KEY, anchor: anchor(), tsaRoots: ROOTS });
    expect(report.lines.map((line) => [line.check, line.status])).toEqual([
      ["record", "pass"],
      ["anchor", "pass"],
      ["timestamp digicert", "pass"],
      ["timestamp freetsa", "pass"],
    ]);
    expect(report.ok).toBe(true);
    expect(report.lines[2]!.detail).toBe("2026-09-16T15:18:24.000Z");
  });

  test("fails an edited record, another key, or a key withdrawn from its position", async () => {
    const edited = genesis();
    edited.seal.payload.chain = "someone-else";
    expect((await checkBundle({ bundle: edited, keyPem: KEY })).lines[0]).toMatchObject({ status: "fail", detail: expect.stringMatching(/^payload_hash_mismatch/) });
    const other = execFileSync("openssl", ["ecparam", "-name", "prime256v1", "-genkey", "-noout"]);
    const otherPub = execFileSync("openssl", ["ec", "-pubout"], { input: other }).toString();
    expect((await checkBundle({ bundle: genesis(), keyPem: otherPub })).lines[0]).toMatchObject({ status: "fail", detail: expect.stringMatching(/^signature_invalid/) });
    expect((await checkBundle({ bundle: genesis(), keyPem: KEY, untrustedFrom: 0 })).lines[0]).toMatchObject({ status: "fail", detail: expect.stringMatching(/^key_untrusted/) });
  });

  test("fails an anchor that does not hold it, or whose root was changed", async () => {
    const moved = anchor();
    moved.entry_hashes[0] = "ab".repeat(32);
    expect((await checkBundle({ bundle: genesis(), keyPem: KEY, anchor: moved })).lines[1]).toMatchObject({ status: "fail", detail: expect.stringMatching(/does not hold this record/) });
    const rerooted = anchor();
    rerooted.merkle_root = "cd".repeat(32);
    expect((await checkBundle({ bundle: genesis(), keyPem: KEY, anchor: rerooted })).lines[1]).toMatchObject({ status: "fail" });
  });

  test("fails a timestamp checked against the wrong authority's root", async () => {
    const report = await checkBundle({ bundle: genesis(), keyPem: KEY, tsaRoots: [ROOTS[0]!] });
    expect(report.lines.find((line) => line.check === "timestamp freetsa")).toMatchObject({ status: "fail", detail: expect.stringMatching(/does not chain/) });
    expect(report.ok).toBe(false);
  });

  test("an evidence pack is checked as the bundle it holds", async () => {
    const pack = { evidence_version: "ti-evidence-v1", bundle: genesis() };
    expect((await checkBundle({ bundle: pack, keyPem: KEY })).ok).toBe(true);
  });

  test("a file is checked against the record's own hash, and genesis names none", async () => {
    expect((await checkBundle({ bundle: genesis(), keyPem: KEY, file: chunks("anything") })).lines[1]).toMatchObject({ check: "file", status: "fail", detail: "this record does not name a file" });
  });
});

describe("the command", () => {
  const cli = here("../dist/cli.js");
  const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });

  test("exits 0 when every check passes, 1 when one fails, 2 when it cannot run", () => {
    const fixtures = (name: string) => here(`./fixtures/${name}`);
    const ok = run("bundle", fixtures("genesis-bundle.json"), "--key", fixtures("h2a-issuer-v1.pub.pem"), "--anchor", fixtures("anchor-2026-W38.json"), "--tsa-root", fixtures("digicert-root.pem"), "--tsa-root", fixtures("freetsa-root.pem"));
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain("OK: every check passed.");
    expect(run("bundle", fixtures("genesis-bundle.json"), "--key", fixtures("h2a-issuer-v1.pub.pem"), "--untrusted-from", "0").status).toBe(1);
    expect(run("bundle", fixtures("genesis-bundle.json")).status).toBe(2);
    expect(run("bundle", fixtures("missing.json"), "--key", fixtures("h2a-issuer-v1.pub.pem")).status).toBe(2);
    const json = run("bundle", fixtures("genesis-bundle.json"), "--key", fixtures("h2a-issuer-v1.pub.pem"), "--json");
    expect(JSON.parse(json.stdout)).toMatchObject({ ok: true, lines: [{ check: "record", status: "pass" }] });
  });
});

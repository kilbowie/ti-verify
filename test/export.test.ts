// `ti-verify export`: a creator's export (ti-export-v1) checked as the Sealer's own script checks it, then each
// anchor its records name against the copy of the public repository given. The genesis record and its W38
// anchor are real; a record that seals a file is signed here with a key made for the test.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "vitest";
import { checkExport } from "../src/check.js";
import { GENESIS_PREV_HASH, TI_SEAL_V1, computeSealHashes, creatorRefOf, sha256Hex, toBase64Url, type SealBundle } from "../src/h2a/index.js";

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));
const text = (name: string) => readFileSync(here(`./fixtures/${name}`), "utf8");
const genesis = (): SealBundle => JSON.parse(text("genesis-bundle.json"));
const KEY = text("h2a-issuer-v1.pub.pem");
const W38 = () => JSON.parse(text("anchor-2026-W38.json"));
const noFiles = async () => null;

const exportOf = (records: SealBundle[], files: object[] = []) => ({ format: "ti-export-v1", records, files });

describe("the genesis record as an export", () => {
  test("checks out, and its anchor is the one published", async () => {
    const report = await checkExport({ parts: [exportOf([genesis()])], keyPem: KEY, hashFile: noFiles, anchorFile: (key) => (key === "2026-W38" ? W38() : null) });
    expect(report.lines.map((line) => [line.check, line.status])).toEqual([
      ["export", "pass"],
      ["anchor 2026-W38", "pass"],
    ]);
    expect(report.ok).toBe(true);
  });

  test("fails when the anchor is not in the copy given, or the copy is not the one published", async () => {
    const absent = await checkExport({ parts: [exportOf([genesis()])], keyPem: KEY, hashFile: noFiles, anchorFile: () => null });
    expect(absent.lines[1]).toMatchObject({ check: "anchor 2026-W38", status: "fail", detail: "not in the copy of the public repository given" });
    const altered = W38();
    altered.merkle_root = "cd".repeat(32);
    const report = await checkExport({ parts: [exportOf([genesis()])], keyPem: KEY, hashFile: noFiles, anchorFile: () => altered });
    expect(report.lines[1]).toMatchObject({ status: "fail", detail: "its record hashes do not rebuild its root" });
    expect(report.ok).toBe(false);
  });

  test("fails a file the export lists that no record sealed", async () => {
    const report = await checkExport({ parts: [exportOf([genesis()], [{ kind: "version", filename: "a.txt", size_bytes: 1, sha256: "ab".repeat(32) }])], keyPem: KEY, hashFile: noFiles });
    expect(report.lines.map((line) => line.detail)).toEqual([`a.txt: no record in this export sealed the fingerprint ${"ab".repeat(32)}`, "a.txt: not found in the files folder, so it could not be checked"]);
  });
});

describe("the command", () => {
  const cli = here("../dist/cli.js");
  const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
  const dir = mkdtempSync(join(tmpdir(), "ti-verify-export-"));
  const files = join(dir, "files");
  const contents = "the work itself\n";

  beforeAll(async () => {
    // One record that seals a file, signed with a key made here, and the creator key that produced its creator_ref.
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const spki = Buffer.from(await crypto.subtle.exportKey("spki", pair.publicKey)).toString("base64");
    writeFileSync(join(dir, "key.pem"), `-----BEGIN PUBLIC KEY-----\n${spki.replace(/(.{64})/g, "$1\n").trim()}\n-----END PUBLIC KEY-----\n`);
    const creatorKey = "22".repeat(32);
    const sha256 = await sha256Hex(contents);
    const payload = { event: "version.sealed", scheme: TI_SEAL_V1, subject_type: "version", subject_hash: "cd".repeat(32), sha256, creator_ref: await creatorRefOf(creatorKey) };
    const { payloadHash, entryHash } = await computeSealHashes(payload, GENESIS_PREV_HASH);
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, Buffer.from(entryHash, "hex"));
    const record: SealBundle = {
      bundle_version: genesis().bundle_version,
      issued_at: "2026-10-14T00:00:00.000Z",
      seal: { chain_pos: 0, scheme: TI_SEAL_V1, subject_type: "version", subject_hash: payload.subject_hash, payload, payload_hash: payloadHash, prev_hash: GENESIS_PREV_HASH, entry_hash: entryHash, sig: toBase64Url(new Uint8Array(sig)), key_alias: "test" },
      prev_entry_hash: GENESIS_PREV_HASH,
      stamps: [],
      anchor: null,
    };
    const entry = { kind: "version", filename: "work.txt", size_bytes: Buffer.byteLength(contents), sha256 };
    writeFileSync(join(dir, "seals.json"), JSON.stringify({ ...exportOf([record], [entry]), creator_key: creatorKey, creator_ref: payload.creator_ref }));
    writeFileSync(join(dir, "escape.json"), JSON.stringify({ ...exportOf([record], [{ ...entry, filename: "../outside.txt" }]) }));
    mkdirSync(files);
    writeFileSync(join(files, "work.txt"), contents);
    writeFileSync(join(dir, "outside.txt"), contents);
  }, 120_000);

  test("exits 0 when every file matches the record that sealed it, 1 when one does not", () => {
    const ok = run("export", join(dir, "seals.json"), "--files", files, "--key", join(dir, "key.pem"));
    expect(ok.stdout).toContain("PASS  export: 1 records, each signed by the key given (0 inside an anchor); 1 files match the fingerprints they were sealed under");
    expect(ok.status).toBe(0);
    writeFileSync(join(files, "work.txt"), "the work, changed\n");
    const changed = run("export", join(dir, "seals.json"), "--files", files, "--key", join(dir, "key.pem"));
    expect(changed.status).toBe(1);
    expect(changed.stdout).toMatch(/work\.txt: this copy hashes to [0-9a-f]{64}, which is not the/);
    writeFileSync(join(files, "work.txt"), contents);
  });

  test("reads nothing outside the files folder, whatever name the export gives", () => {
    const escaped = run("export", join(dir, "escape.json"), "--files", files, "--key", join(dir, "key.pem"));
    expect(escaped.status).toBe(1);
    expect(escaped.stdout).toContain("../outside.txt: not found in the files folder");
  });

  test("checks the anchors against a folder of the public repository's anchors, and exits 2 without --files", () => {
    const anchors = here("./fixtures");
    writeFileSync(join(dir, "genesis.json"), JSON.stringify(exportOf([genesis()])));
    const withAnchors = (folder: string) => run("export", join(dir, "genesis.json"), "--files", files, "--key", here("./fixtures/h2a-issuer-v1.pub.pem"), "--anchors", folder);
    // The fixture is named anchor-2026-W38.json, so a folder laid out as ti-anchors' anchors/ is made for it.
    const published = join(dir, "anchors");
    mkdirSync(published);
    writeFileSync(join(published, "2026-W38.json"), readFileSync(join(anchors, "anchor-2026-W38.json")));
    const ok = withAnchors(published);
    expect(ok.stdout).toContain("PASS  anchor 2026-W38: published with root");
    expect(ok.status).toBe(0);
    expect(withAnchors(anchors).status).toBe(1);
    expect(run("export", join(dir, "genesis.json"), "--key", here("./fixtures/h2a-issuer-v1.pub.pem")).status).toBe(2);
  });
});

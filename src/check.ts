// What `ti-verify bundle` and `ti-verify export` check, as functions the CLI and the tests share. Each check either passes, fails
// with a reason, or was not asked for. Nothing here contacts anyone: every input is a file you supply.
import {
  entryHashesRoot,
  importIssuerKey,
  sha256Stream,
  verifyBundle,
  verifySeal,
  verifyVaultExportParts,
  type FileHasher,
  type SealBundle,
  type VaultExportFile,
} from "./h2a/index.js";
import { verifyStamp } from "./tsa.js";

export interface CheckInput {
  /** The bundle, as parsed JSON: from trulyimagined.com/api/verify/<seal id>, downloaded on /verify, or an evidence pack holding one. */
  bundle: unknown;
  /** The issuer's public key, PEM, taken from ti-anchors keys/ or trulyimagined.com/trust, never from the bundle. */
  keyPem: string;
  /** The file the record is about, read as it streams, if you have it. */
  file?: AsyncIterable<Uint8Array>;
  /** An anchor file from the public repository (kilbowie/ti-anchors anchors/<week>.json) that covers the record. */
  anchor?: unknown;
  /** Root certificates (DER) of the timestamp authorities, taken from the authorities themselves. */
  tsaRoots?: readonly Uint8Array[];
  /** The chain position from which this key is not relied on, if its issuer has said so (see their keys/LOG.md). */
  untrustedFrom?: number | null;
}

export interface CheckLine {
  check: string;
  status: "pass" | "fail";
  detail?: string;
}

export interface Report {
  ok: boolean;
  lines: CheckLine[];
}

interface AnchorFile {
  anchor_key?: string;
  head_pos?: number;
  head_hash?: string;
  merkle_root?: string;
  entry_hashes?: string[];
  seal?: SealBundle["seal"];
}

const hex64 = /^[0-9a-f]{64}$/;

/** The record's own word for which bytes it names: a version's file, or a piece of evidence. */
export function fileHashOf(bundle: SealBundle): string | null {
  const payload = (bundle.seal?.payload ?? {}) as Record<string, unknown>;
  const hash = typeof payload.sha256 === "string" ? payload.sha256 : typeof payload.evidence_sha256 === "string" ? payload.evidence_sha256 : null;
  return hash && hex64.test(hash) ? hash : null;
}

/**
 * What is wrong with an anchor file as the public repository holds it, or null: its own hashes must rebuild its
 * root and end at its head, and its own seal must be signed by the key and say what the file says.
 */
async function anchorFileProblem(anchor: AnchorFile, key: Awaited<ReturnType<typeof importIssuerKey>>, untrustedFrom: number | null): Promise<string | null> {
  const hashes = Array.isArray(anchor?.entry_hashes) ? anchor.entry_hashes : [];
  if (typeof anchor?.head_pos !== "number" || typeof anchor.merkle_root !== "string" || !anchor.seal) return "not an anchor file";
  if (hashes.length !== anchor.head_pos + 1 || hashes[anchor.head_pos] !== anchor.head_hash) return "its hash list does not end at its head";
  if ((await entryHashesRoot(hashes)) !== anchor.merkle_root) return "its record hashes do not rebuild its root";
  const sealed = await verifySeal(anchor.seal, key, anchor.head_hash!, { untrustedFromChainPos: untrustedFrom });
  if (!sealed.ok) return `its own seal does not verify: ${sealed.detail}`;
  const said = anchor.seal.payload as Record<string, unknown>;
  if (said.merkle_root !== anchor.merkle_root || said.head_pos !== anchor.head_pos || said.head_hash !== anchor.head_hash) return "its fields differ from what its seal signed";
  return null;
}

export async function checkBundle(input: CheckInput): Promise<Report> {
  const lines: CheckLine[] = [];
  const pass = (check: string, detail?: string) => lines.push(detail ? { check, status: "pass", detail } : { check, status: "pass" });
  const fail = (check: string, detail: string) => lines.push({ check, status: "fail", detail });
  // An evidence pack (ti-evidence-v1) holds the bundle unchanged; check that.
  const given = input.bundle as { evidence_version?: string; bundle?: unknown };
  const bundle = (given?.evidence_version === "ti-evidence-v1" ? given.bundle : input.bundle) as SealBundle;
  const key = await importIssuerKey(input.keyPem);

  // 1. The record itself: its content, its link to the record before it, its signature, and, when the bundle
  //    carries one, that it sits inside its anchor's Merkle root.
  const verdict = await verifyBundle(bundle, key, { untrustedFromChainPos: input.untrustedFrom ?? null });
  if (verdict.ok) pass("record", `chain position ${bundle.seal.chain_pos}, signed by the key given${bundle.anchor ? `, inside the anchor for ${bundle.anchor.anchor_key}` : ""}`);
  else fail("record", `${verdict.failure}: ${verdict.detail}`);

  // 2. The file, hashed as it is read.
  if (input.file) {
    const expected = fileHashOf(bundle);
    const got = await sha256Stream(input.file);
    if (!expected) fail("file", "this record does not name a file");
    else if (got === expected) pass("file", `SHA-256 ${got}`);
    else fail("file", `its SHA-256 is ${got}; the record names ${expected}`);
  }

  // 3. The anchor as the public repository holds it: it covers the record, its own hashes rebuild its root, and
  //    its own seal is signed by the key and says what the file says.
  if (input.anchor !== undefined) {
    const anchor = input.anchor as AnchorFile;
    const pos = bundle.seal?.chain_pos;
    const holds = typeof pos === "number" && Array.isArray(anchor?.entry_hashes) && anchor.entry_hashes[pos] === bundle.seal.entry_hash;
    const problem = await anchorFileProblem(anchor, key, input.untrustedFrom ?? null);
    if (problem === "not an anchor file") fail("anchor", problem);
    else if (!holds || anchor.head_pos! < pos) fail("anchor", `it does not hold this record at chain position ${pos}`);
    else if (problem) fail("anchor", problem);
    else if (bundle.anchor && bundle.anchor.anchor_key === anchor.anchor_key && bundle.anchor.merkle_root !== anchor.merkle_root) fail("anchor", "the bundle's copy of this anchor has a different root");
    else pass("anchor", `${anchor.anchor_key}: root ${anchor.merkle_root}, holds this record, signed by the key given`);
  }

  // 4. Each timestamp, against the roots given.
  if (input.tsaRoots) {
    const stamps = Array.isArray(bundle.stamps) ? bundle.stamps : [];
    if (stamps.length === 0) fail("timestamps", "the bundle carries no timestamp tokens");
    for (const stamp of stamps) {
      const token = Uint8Array.from(atob(stamp.token_base64), (c) => c.charCodeAt(0));
      const result = await verifyStamp({ token, entryHash: bundle.seal.entry_hash, prevHash: bundle.prev_entry_hash, payloadHash: bundle.seal.payload_hash, roots: input.tsaRoots });
      if (result.ok) pass(`timestamp ${stamp.tsa}`, result.genTime.toISOString());
      else fail(`timestamp ${stamp.tsa}`, result.detail);
    }
  }

  return { ok: lines.every((line) => line.status === "pass"), lines };
}

export interface ExportInput {
  /** Every part of one export, as parsed JSON: seals.json, or seals-part-1-of-3.json and the rest. */
  parts: unknown[];
  /** The issuer's public key, PEM, taken from ti-anchors keys/ or trulyimagined.com/trust, never from the export. */
  keyPem: string;
  /** Hashes a downloaded file by the name the export gives it, or answers null when it is not there. */
  hashFile: FileHasher;
  /** Reads anchors/<anchor key>.json from a copy of the public repository, or answers null when it is not there. */
  anchorFile?: (anchorKey: string) => unknown;
  untrustedFrom?: number | null;
}

/**
 * A creator's export: every record, every file and the creator key, as the verifier core checks them; then, when
 * a copy of the public anchor repository is given, every anchor the records name against the one published,
 * which is the one thing the export cannot show by itself.
 */
export async function checkExport(input: ExportInput): Promise<Report> {
  const lines: CheckLine[] = [];
  const key = await importIssuerKey(input.keyPem);
  const untrustedFrom = input.untrustedFrom ?? null;
  const parts = input.parts as VaultExportFile[];

  const verdict = await verifyVaultExportParts(parts, key, input.hashFile, { untrustedFromChainPos: untrustedFrom });
  const across = parts.length > 1 ? ` across ${parts.length} parts` : "";
  if (verdict.ok) {
    lines.push({ check: "export", status: "pass", detail: `${verdict.records} records${across}, each signed by the key given (${verdict.anchored} inside an anchor); ${verdict.files} files match the fingerprints they were sealed under` });
  } else {
    for (const problem of verdict.problems) lines.push({ check: "export", status: "fail", detail: problem });
  }

  if (input.anchorFile) {
    const byAnchor = new Map<string, SealBundle[]>();
    for (const bundle of parts.flatMap((part) => part?.records ?? [])) {
      if (!bundle?.anchor) continue;
      byAnchor.set(bundle.anchor.anchor_key, [...(byAnchor.get(bundle.anchor.anchor_key) ?? []), bundle]);
    }
    for (const [anchorKey, bundles] of [...byAnchor].sort(([a], [b]) => a.localeCompare(b))) {
      const check = `anchor ${anchorKey}`;
      const anchor = input.anchorFile(anchorKey) as AnchorFile | null;
      const problem = anchor === null ? "not in the copy of the public repository given" : await anchorFileProblem(anchor, key, untrustedFrom);
      const missing = problem ? null : bundles.find((b) => anchor!.entry_hashes![b.seal.chain_pos] !== b.seal.entry_hash);
      if (problem) lines.push({ check, status: "fail", detail: problem });
      else if (missing) lines.push({ check, status: "fail", detail: `the published anchor does not hold the record at chain position ${missing.seal.chain_pos}` });
      else if (bundles.some((b) => b.anchor!.merkle_root !== anchor!.merkle_root)) lines.push({ check, status: "fail", detail: "the export's copy of this anchor has a different root from the one published" });
      else lines.push({ check, status: "pass", detail: `published with root ${anchor!.merkle_root}, holding the ${bundles.length} record${bundles.length === 1 ? "" : "s"} that name it` });
    }
  }

  return { ok: lines.length > 0 && lines.every((line) => line.status === "pass"), lines };
}

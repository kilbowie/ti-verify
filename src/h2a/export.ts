// Checking a creator's export (ti-export-v1) with no database and no TI (D38, copy C6). Here, in the verifier
// core, so the public ti-verify runs exactly what the Sealer's own script does (ROADMAP2 S5.5).
//
// What it proves, given the issuer key the caller supplies (never the one inside the file):
//   - every record's payload hash, link and signature, and its inclusion in the anchor it names;
//   - that every file on disk hashes to the fingerprint the record sealed it under;
//   - that every file the export lists is present, and every record that sealed a file has one listed;
//   - that the creator key in the export produces the creator_ref those records carry (D32);
//   - for an export in parts (ROADMAP2 S5.10), that the parts are one export, every one of them is here,
//     and between them they hold the number of records they say.
//
// What it cannot prove is that an anchor was published: take the root from the public anchor repository
// and compare. The export's own copy is TI's word for it.
import { verifyBundle, type SealBundle } from "./bundle.js";
import { fromHex, toHex, utf8 } from "./bytes.js";
import type { IssuerKey, KeyTrust } from "./verify.js";

export const VAULT_EXPORT_FORMAT = "ti-export-v1";
export const CREATOR_REF_CONTEXT = "ti-creator-v1";

export interface ExportFileEntry {
  kind: string;
  filename: string;
  size_bytes: number;
  sha256: string;
  /** TI's own id for the record, for looking it up at /verify. Not what a file is matched by. */
  seal_id?: string;
  work_title?: string;
  seq?: number | null;
}

export interface ExportPartInfo {
  index: number;
  count: number;
  as_of_chain_pos: number;
  records_total: number;
}

export interface VaultExportFile {
  format?: string;
  creator_ref?: string;
  creator_key?: string;
  /** Absent from an export made before parts existed, which is the whole of it. */
  part?: ExportPartInfo;
  records?: SealBundle[];
  files?: ExportFileEntry[];
}

/** Reads one file and returns its SHA-256, or null when it is not there. */
export type FileHasher = (filename: string) => Promise<{ sha256: string; sizeBytes: number } | null>;

export interface ExportVerdict {
  ok: boolean;
  records: number;
  anchored: number;
  files: number;
  problems: string[];
}

const SHA256_HEX = /^[0-9a-f]{64}$/;
const KEY_HEX = SHA256_HEX;

/** creator_ref = HMAC-SHA256(creator_key, "ti-creator-v1"), lowercase hex (D32). */
export async function creatorRefOf(creatorKey: string): Promise<string> {
  if (!KEY_HEX.test(creatorKey)) throw new Error("creator key must be 64 lowercase hex characters");
  const key = await crypto.subtle.importKey("raw", fromHex(creatorKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(CREATOR_REF_CONTEXT))));
}

/** The content fingerprint a record sealed, whichever kind of record it is. */
function sealedHashOf(bundle: SealBundle): string | null {
  const payload = bundle.seal?.payload as { sha256?: unknown; evidence_sha256?: unknown } | undefined;
  const value = payload?.sha256 ?? payload?.evidence_sha256;
  return typeof value === "string" && SHA256_HEX.test(value) ? value : null;
}

export async function verifyVaultExport(exported: VaultExportFile, key: IssuerKey, hashFile: FileHasher, trust: KeyTrust = {}): Promise<ExportVerdict> {
  const problems: string[] = [];
  if (exported?.format !== VAULT_EXPORT_FORMAT) {
    return { ok: false, records: 0, anchored: 0, files: 0, problems: [`unsupported export format ${JSON.stringify(exported?.format)}`] };
  }

  const records = exported.records ?? [];
  const files = exported.files ?? [];
  let anchored = 0;

  for (const bundle of records) {
    const name = `the record at chain position ${bundle?.seal?.chain_pos ?? "?"}`;
    const verdict = await verifyBundle(bundle, key, trust);
    if (!verdict.ok) problems.push(`${name}: ${verdict.failure} — ${verdict.detail}`);
    if (bundle?.anchor) anchored += 1;
  }

  // A bundle names no seal id, so a file is matched to the record that vouches for it by the fingerprint
  // itself: the record sealed this hash, and this file has it. That is the claim the export makes.
  const sealedHashes = new Set<string>();
  for (const bundle of records) {
    const hash = sealedHashOf(bundle);
    if (hash) sealedHashes.add(hash);
  }

  let checked = 0;
  for (const file of files) {
    if (!SHA256_HEX.test(file.sha256)) {
      problems.push(`${file.filename}: the export's fingerprint for it is not 64 lowercase hex characters`);
    } else if (!sealedHashes.has(file.sha256)) {
      problems.push(`${file.filename}: no record in this export sealed the fingerprint ${file.sha256}`);
    }
    const found = await hashFile(file.filename);
    if (!found) {
      problems.push(`${file.filename}: not found in the files folder, so it could not be checked`);
      continue;
    }
    checked += 1;
    if (found.sha256 !== file.sha256) {
      problems.push(`${file.filename}: this copy hashes to ${found.sha256}, which is not the ${file.sha256} that was sealed`);
    }
    if (found.sizeBytes !== file.size_bytes) {
      problems.push(`${file.filename}: this copy is ${found.sizeBytes} bytes, and ${file.size_bytes} were sealed`);
    }
  }

  // A record that sealed a file, with no file listed against it, means the export is incomplete.
  const listed = new Set(files.map((file) => file.sha256));
  for (const hash of sealedHashes) {
    if (!listed.has(hash)) problems.push(`a record sealed the fingerprint ${hash}, and the export lists no file with it`);
  }

  if (exported.creator_key) {
    let computed: string | undefined;
    try {
      computed = await creatorRefOf(exported.creator_key);
    } catch (error) {
      problems.push(`creator key: ${(error as Error).message}`);
    }
    if (computed && exported.creator_ref && computed !== exported.creator_ref) {
      problems.push("creator key: it does not produce the creator_ref in this export");
    }
    for (const bundle of records) {
      const ref = (bundle?.seal?.payload as { creator_ref?: unknown } | undefined)?.creator_ref;
      if (typeof ref === "string" && computed && ref !== computed) {
        problems.push(`the record at chain position ${bundle.seal.chain_pos}: its creator_ref is not the one this creator key produces`);
      }
    }
  }

  return { ok: problems.length === 0, records: records.length, anchored, files: checked, problems };
}

/**
 * Checks an export that comes in parts: first that the parts are one whole (the same creator, the same chain
 * position, every index from 1 to the count exactly once, the records they say, in chain order), then each
 * part as verifyVaultExport does. One file with no part information is an export from before parts, and is
 * checked as it always was.
 */
export async function verifyVaultExportParts(parts: VaultExportFile[], key: IssuerKey, hashFile: FileHasher, trust: KeyTrust = {}): Promise<ExportVerdict> {
  if (parts.length === 1 && !parts[0]?.part) return verifyVaultExport(parts[0]!, key, hashFile, trust);
  const problems: string[] = [];
  const empty = { ok: false, records: 0, anchored: 0, files: 0 };
  if (parts.length === 0) return { ...empty, problems: ["no export files given"] };
  if (parts.some((p) => !p?.part)) return { ...empty, problems: ["a file without part information was given with others: give the parts of one export"] };

  const first = parts[0]!.part!;
  for (const p of parts) {
    const info = p.part!;
    if (p.creator_ref !== parts[0]!.creator_ref) problems.push(`part ${info.index}: a different creator_ref from the first part, so it is from another account's export`);
    if (info.as_of_chain_pos !== first.as_of_chain_pos || info.count !== first.count || info.records_total !== first.records_total) {
      problems.push(`part ${info.index}: from a different export (as of chain position ${info.as_of_chain_pos}, ${info.count} parts, ${info.records_total} records; the first part says ${first.as_of_chain_pos}, ${first.count}, ${first.records_total}). Download every part again from one visit to the export page`);
    }
  }
  const indexes = parts.map((p) => p.part!.index);
  for (let index = 1; index <= first.count; index++) {
    const seen = indexes.filter((i) => i === index).length;
    if (seen === 0) problems.push(`part ${index} of ${first.count} is missing`);
    if (seen > 1) problems.push(`part ${index} of ${first.count} was given ${seen} times`);
  }
  for (const index of indexes) if (!Number.isInteger(index) || index < 1 || index > first.count) problems.push(`part ${index} is not one of 1 to ${first.count}`);

  const ordered = [...parts].sort((a, b) => a.part!.index - b.part!.index);
  const positions = ordered.flatMap((p) => (p.records ?? []).map((bundle) => bundle?.seal?.chain_pos));
  if (positions.length !== first.records_total) problems.push(`the parts hold ${positions.length} records between them, and say they hold ${first.records_total}`);
  for (let i = 1; i < positions.length; i++) {
    if (!(positions[i]! > positions[i - 1]!)) {
      problems.push(`the records are not in chain order across the parts at chain position ${positions[i]}: a record is repeated or out of place`);
      break;
    }
  }
  const late = positions.find((pos) => typeof pos === "number" && pos > first.as_of_chain_pos);
  if (late !== undefined) problems.push(`a record at chain position ${late} is later than the export's ${first.as_of_chain_pos}`);

  const totals = { records: 0, anchored: 0, files: 0 };
  for (const p of ordered) {
    const verdict = await verifyVaultExport(p, key, hashFile, trust);
    totals.records += verdict.records;
    totals.anchored += verdict.anchored;
    totals.files += verdict.files;
    for (const problem of verdict.problems) problems.push(`part ${p.part!.index} of ${first.count}: ${problem}`);
  }
  return { ok: problems.length === 0, ...totals, problems };
}

#!/usr/bin/env node
// ti-verify: check a Truly Imagined record without relying on Truly Imagined.
//
//   ti-verify bundle <bundle.json> --key <issuer.pem> [--file <path>] [--anchor <anchor.json>]
//                    [--tsa-root <root.pem>]... [--untrusted-from <chain position>] [--json]
//   ti-verify export <seals.json> [<more parts>...] --files <folder> --key <issuer.pem> [--anchors <folder>]
//                    [--untrusted-from <chain position>] [--json]
//
// Exit codes: 0 every check asked for passed; 1 a check failed; 2 the command or an input could not be read.
import { accessSync, constants, createReadStream, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { checkBundle, checkExport, type CheckInput, type Report } from "./check.js";
import { sha256Stream } from "./h2a/index.js";
import { certificateDer } from "./tsa.js";

const USAGE = `usage: ti-verify bundle <bundle.json> --key <issuer.pem> [--file <path>] [--anchor <anchor.json>]
                        [--tsa-root <root.pem>]... [--untrusted-from <chain position>] [--json]
       ti-verify export <seals.json> [<more parts>...] --files <folder> --key <issuer.pem> [--anchors <folder>]
                        [--untrusted-from <chain position>] [--json]`;

function usage(message: string): never {
  console.error(`ti-verify: ${message}\n${USAGE}`);
  process.exit(2);
}

function read(path: string, what: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    usage(`cannot read ${what} ${path}`);
  }
}

function json(path: string, what: string): unknown {
  try {
    return JSON.parse(read(path, what));
  } catch {
    usage(`${what} ${path} is not JSON`);
  }
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

interface Flags {
  inputs: string[];
  key?: string;
  file?: string;
  anchor?: string;
  files?: string;
  anchors?: string;
  roots: string[];
  untrusted?: string;
  json: boolean;
}

function parse(args: string[], allowed: readonly string[]): Flags {
  const flags: Flags = { inputs: [], roots: [], json: false };
  for (let i = 0; i < args.length; i += 1) {
    const flag = args[i]!;
    if (!flag.startsWith("--")) {
      flags.inputs.push(flag);
      continue;
    }
    if (!allowed.includes(flag)) usage(`unknown option ${flag}`);
    const value = () => args[++i] ?? usage(`${flag} needs a value`);
    if (flag === "--key") flags.key = value();
    else if (flag === "--file") flags.file = value();
    else if (flag === "--anchor") flags.anchor = value();
    else if (flag === "--files") flags.files = value();
    else if (flag === "--anchors") flags.anchors = value();
    else if (flag === "--tsa-root") flags.roots.push(value());
    else if (flag === "--untrusted-from") flags.untrusted = value();
    else if (flag === "--json") flags.json = true;
  }
  return flags;
}

function untrustedFrom(flags: Flags): number | null {
  const untrusted = flags.untrusted === undefined ? null : Number(flags.untrusted);
  if (untrusted !== null && (!Number.isSafeInteger(untrusted) || untrusted < 0)) usage("--untrusted-from takes a chain position");
  return untrusted;
}

function requireKey(flags: Flags): string {
  if (!flags.key) usage("--key is required: the issuer's public key, from ti-anchors keys/ or trulyimagined.com/trust");
  return read(flags.key, "key");
}

async function bundle(flags: Flags): Promise<Report> {
  if (flags.inputs.length !== 1) usage("expected: bundle <bundle.json>");
  const input: CheckInput = { bundle: json(flags.inputs[0]!, "bundle"), keyPem: requireKey(flags), untrustedFrom: untrustedFrom(flags) };
  if (flags.file) {
    try {
      accessSync(flags.file, constants.R_OK);
      if (!statSync(flags.file).isFile()) throw new Error("not a file");
    } catch {
      usage(`cannot read file ${flags.file}`);
    }
    input.file = createReadStream(flags.file) as AsyncIterable<Uint8Array>;
  }
  if (flags.anchor) input.anchor = json(flags.anchor, "anchor");
  if (flags.roots.length > 0) {
    try {
      input.tsaRoots = flags.roots.map((path) => certificateDer(read(path, "TSA root")));
    } catch {
      usage("a --tsa-root is not a PEM certificate");
    }
  }
  return checkBundle(input);
}

async function exported(flags: Flags): Promise<Report> {
  if (flags.inputs.length === 0) usage("expected: export <seals.json> [<more parts>...]");
  const files = flags.files;
  const anchors = flags.anchors;
  if (!files || !isDirectory(files)) usage("--files is required: the folder you downloaded your files into, each under the name the export gives it");
  if (anchors && !isDirectory(anchors)) usage(`cannot read the anchors folder ${anchors}`);
  return checkExport({
    parts: flags.inputs.map((path) => json(path, "export")),
    keyPem: requireKey(flags),
    untrustedFrom: untrustedFrom(flags),
    hashFile: async (filename) => {
      // A name the export gives is a name, never a path: nothing outside the folder is read.
      if (/[/\\]/.test(filename) || filename === "." || filename === "..") return null;
      const path = join(files, filename);
      try {
        const stat = statSync(path);
        if (!stat.isFile()) return null;
        return { sha256: await sha256Stream(createReadStream(path) as AsyncIterable<Uint8Array>), sizeBytes: stat.size };
      } catch {
        return null;
      }
    },
    ...(anchors && {
      anchorFile: (anchorKey: string) => {
        if (!/^[0-9]{4}-W[0-9]{2}$/.test(anchorKey)) return null;
        try {
          return JSON.parse(readFileSync(join(anchors, `${anchorKey}.json`), "utf8"));
        } catch {
          return null;
        }
      },
    }),
  });
}

const COMMANDS = {
  bundle: { run: bundle, options: ["--key", "--file", "--anchor", "--tsa-root", "--untrusted-from", "--json"] },
  export: { run: exported, options: ["--key", "--files", "--anchors", "--untrusted-from", "--json"] },
} as const;

async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;
  if (command !== "bundle" && command !== "export") usage("expected a command: bundle or export");
  const flags = parse(args, COMMANDS[command].options);
  let report: Report;
  try {
    report = await COMMANDS[command].run(flags);
  } catch (error) {
    usage(error instanceof Error ? error.message : String(error));
  }
  if (flags.json) console.log(JSON.stringify(report, null, 2));
  else {
    for (const line of report.lines) console.log(`${line.status === "pass" ? "PASS" : "FAIL"}  ${line.check}${line.detail ? `: ${line.detail}` : ""}`);
    console.log(report.ok ? "OK: every check passed." : "FAILED: at least one check did not pass.");
  }
  return report.ok ? 0 : 1;
}

main(process.argv.slice(2)).then((code) => process.exit(code));

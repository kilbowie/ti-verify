# ti-verify

Check a [Truly Imagined](https://trulyimagined.com) evidence record without relying on Truly Imagined.

A Truly Imagined record says that a file existed in a given form by a given date, and that a verified person's
account added it. It is not a ruling on who made or owns the work. This tool checks that a record is what it
claims to be, using only files you hold and keys you took from somewhere other than the record itself.

## What you need

- **The record's bundle**: from `https://trulyimagined.com/api/verify/<seal id>`, or the "Download bundle" button on
  `trulyimagined.com/verify`.
- **The issuer's public key**: `keys/h2a-issuer-v1.pub.pem` in [kilbowie/ti-anchors](https://github.com/kilbowie/ti-anchors),
  which should have the SHA-256 fingerprint `ba3f5cac86c94436a9b8430881b6e6305d2bd02e90d8208ff8f6f622355abc02`.
- Optionally: **the file** the record is about; **the anchor file** from ti-anchors (`anchors/<week>.json`); and **the
  timestamp authorities' root certificates**, taken from DigiCert and FreeTSA themselves. Their fingerprints are on
  `trulyimagined.com/trust` so you can compare.

## Use

```sh
git clone https://github.com/kilbowie/ti-verify && cd ti-verify
npm install
npm run build
node dist/cli.js bundle bundle.json --key h2a-issuer-v1.pub.pem \
  --file the-work.mp4 \
  --anchor 2026-W38.json \
  --tsa-root digicert-trusted-root-g4.pem --tsa-root freetsa-root.pem
```

Each check prints `PASS` or `FAIL` with its reason. Exit codes: **0** every check asked for passed; **1** a check
failed; **2** the command or an input could not be read. `--json` prints the report as JSON. `--untrusted-from <N>`
applies a key withdrawal the issuer has announced in ti-anchors `keys/LOG.md`.

What is checked:

1. **The record**: its content hashes to the values inside it, it links to the record before it, it is signed by
   the key you gave, and it sits inside its weekly anchor's Merkle root.
2. **The file** (`--file`): its SHA-256, computed as it is read, is the one the record names.
3. **The anchor** (`--anchor`): the published anchor holds the record, its own record hashes rebuild its root, and
   its own record is signed by the same key.
4. **The timestamps** (`--tsa-root`): each token stamps the record's hash and is signed by an authority whose
   certificate chains to a root you supplied, at the token's own time.

Nothing here contacts anyone.

## A whole export

A creator's export from `trulyimagined.com/vault/export` is a records file (`seals.json`, or for a large vault
`seals-part-1-of-3.json` and the rest) and the files themselves, downloaded into one folder under the names the
records file gives them.

```sh
git clone https://github.com/kilbowie/ti-anchors
node dist/cli.js export seals.json --files <the folder of files> \
  --key ti-anchors/keys/h2a-issuer-v1.pub.pem --anchors ti-anchors/anchors
```

For an export in parts, give every part in place of `seals.json`. What is checked:

1. **Every record**, as `bundle` checks one.
2. **Every file**: present, the size and SHA-256 a record sealed, and every file a record sealed listed.
3. **The creator key**: it produces the `creator_ref` the records carry, which is what shows they are one person's.
4. **The parts**: they are one export, all of them are here, and they hold the records they say.
5. **Each anchor** the records name (`--anchors`): the one published in ti-anchors rebuilds its root, is signed by
   the key, holds each of those records, and is the one the export carries. The export's own copy is the
   issuer's word; this is what makes it more.

## A second opinion

`oracle/oracle.mjs` makes the same checks with code it shares with nothing else here: its own canonical JSON,
Node's own cryptography, the RFC's own Merkle definition, and the OpenSSL command line for timestamps.

```sh
node oracle/oracle.mjs --key h2a-issuer-v1.pub.pem --anchor 2026-W38.json \
  --tsa-root digicert-trusted-root-g4.pem --tsa-root freetsa-root.pem bundle.json
```

If the two ever disagree, trust neither and tell us.

## The formats

`SPEC.md` describes every format Truly Imagined publishes, and `schemas/events/` each record's exact shape.

## Licence

Apache License 2.0 (`LICENSE`). `src/h2a/` includes code and test data from H2A Protocol under the same licence;
see `NOTICE`.

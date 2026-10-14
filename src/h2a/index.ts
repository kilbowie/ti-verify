// @ti/h2a: canonicalisation, seal hashing and the verifier core. Zero runtime dependencies; runs in
// Node and in browsers. Built on H2A conventions (ADR-014): RFC 8785 canonical JSON and raw r‖s ES256.
export { jcs, jcsBytes, assertSealPayload, canonicalSealBytes, SealPayloadError } from "./canonical.js";
export { sha256, sha256Hex } from "./hash.js";
export { derToRaw, rawToDer, looksLikeDer, ES256_SIGNATURE_BYTES } from "./ecdsa.js";
export {
  merkleRoot,
  entryHashesRoot,
  inclusionProof,
  verifyInclusion,
  entryHashProof,
  verifyEntryHashInclusion,
} from "./merkle.js";
export {
  TI_SEAL_V1,
  SEAL_SCHEMES,
  GENESIS_PREV_HASH,
  computeSealHashes,
  isSha256Hex,
  type SealScheme,
  type SealRecord,
  type SealHashes,
} from "./seal.js";
export {
  BUNDLE_VERSION,
  MERKLE_SCHEME,
  verifyBundle,
  verifyBundleAnchor,
  type SealBundle,
  type BundleStamp,
  type BundleAnchor,
} from "./bundle.js";
export {
  importIssuerKey,
  verifySeal,
  verifyChain,
  verifyAnchor,
  type AnchorRecord,
  type IssuerKey,
  type KeyTrust,
  type Verdict,
  type VerifyFailure,
} from "./verify.js";
export { toBase64Url, fromBase64Url, fromBase64, toHex, fromHex, utf8 } from "./bytes.js";
export { Sha256, sha256Stream } from "./sha256-stream.js";
export {
  VAULT_EXPORT_FORMAT,
  CREATOR_REF_CONTEXT,
  creatorRefOf,
  verifyVaultExport,
  verifyVaultExportParts,
  type VaultExportFile,
  type ExportFileEntry,
  type ExportPartInfo,
  type ExportVerdict,
  type FileHasher,
} from "./export.js";

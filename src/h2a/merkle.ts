// RFC 6962 §2.1 Merkle Tree Hash, the public anchor scheme (D1).
//
//   MTH({})       = SHA-256()
//   MTH({d0})     = SHA-256(0x00 ‖ d0)
//   MTH(D[0:n])   = SHA-256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n])),  k the largest power of two < n
//
// Built level by level, pairing left to right and promoting a trailing odd node unhashed, which gives
// the same root as the recursive definition. For an anchor, the leaves are the 32 raw bytes of each
// entry hash, in chain order from position 0.

import { bytesEqual, concatBytes, fromHex, toHex, type Bytes } from "./bytes.js";
import { sha256 } from "./hash.js";

const LEAF = new Uint8Array([0x00]);
const NODE = new Uint8Array([0x01]);

const leafHash = (leaf: Uint8Array): Promise<Bytes> => sha256(concatBytes(LEAF, leaf));
const nodeHash = (left: Uint8Array, right: Uint8Array): Promise<Bytes> => sha256(concatBytes(NODE, left, right));

/** One level up: pair left to right, promote a trailing odd node unchanged. */
async function nextLevel(level: readonly Bytes[]): Promise<Bytes[]> {
  const paired: Promise<Bytes>[] = [];
  for (let i = 0; i + 1 < level.length; i += 2) paired.push(nodeHash(level[i]!, level[i + 1]!));
  const promoted = level.length % 2 === 1 ? [level[level.length - 1]!] : [];
  return [...(await Promise.all(paired)), ...promoted];
}

export async function merkleRoot(leaves: readonly Uint8Array[]): Promise<Bytes> {
  if (leaves.length === 0) return sha256(new Uint8Array(0));
  let level = await Promise.all(leaves.map(leafHash));
  while (level.length > 1) level = await nextLevel(level);
  return level[0]!;
}

/** Merkle root, as lowercase hex, over entry hashes given as lowercase hex. */
export async function entryHashesRoot(entryHashes: readonly string[]): Promise<string> {
  return toHex(await merkleRoot(entryHashes.map(fromHex)));
}

// -------------------------------------------------------------------------------------------------
// Inclusion proofs (RFC 6962 §2.1.1). The audit path for leaf m is the sibling at each level on the
// way to the root: exactly what a holder needs to show their record is inside a published anchor,
// without publishing the whole tree and without asking TI to vouch for it.
// -------------------------------------------------------------------------------------------------

/** Sibling hashes from the leaf up to the root, bottom first. A single-leaf tree has an empty path. */
export async function inclusionProof(leaves: readonly Uint8Array[], index: number): Promise<Bytes[]> {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new Error(`inclusionProof: index ${index} is outside a tree of ${leaves.length} leaves`);
  }
  let level = await Promise.all(leaves.map(leafHash));
  let i = index;
  const path: Bytes[] = [];
  while (level.length > 1) {
    // No sibling only when this is a trailing odd node, which moves up unchanged.
    const sibling = i % 2 === 0 ? level[i + 1] : level[i - 1];
    if (sibling) path.push(sibling);
    level = await nextLevel(level);
    i >>= 1;
  }
  return path;
}

/**
 * Recomputes the root from a leaf and its audit path. Returns false rather than throwing: a failed
 * proof is an answer, not an error. The path must be exactly the right length, so a proof cannot be
 * padded with extra nodes that happen to fold to the same root.
 */
export async function verifyInclusion(
  leaf: Uint8Array,
  index: number,
  treeSize: number,
  path: readonly Uint8Array[],
  root: Uint8Array,
): Promise<boolean> {
  if (!Number.isInteger(index) || !Number.isInteger(treeSize) || index < 0 || treeSize < 1 || index >= treeSize) {
    return false;
  }
  if (path.some((node) => node.length !== 32) || root.length !== 32) return false;

  let hash: Bytes = await leafHash(leaf);
  let i = index;
  let size = treeSize;
  let used = 0;
  while (size > 1) {
    const promoted = i === size - 1 && size % 2 === 1;
    if (!promoted) {
      const sibling = path[used++];
      if (!sibling) return false;
      hash = i % 2 === 0 ? await nodeHash(hash, sibling) : await nodeHash(sibling, hash);
    }
    i >>= 1;
    size = Math.ceil(size / 2);
  }
  return used === path.length && bytesEqual(hash, root);
}

/** Audit path for the entry hash at `index`, as lowercase hex. */
export async function entryHashProof(entryHashes: readonly string[], index: number): Promise<string[]> {
  return (await inclusionProof(entryHashes.map(fromHex), index)).map(toHex);
}

/** Checks a hex audit path for one entry hash against a published Merkle root. */
export async function verifyEntryHashInclusion(
  entryHash: string,
  index: number,
  treeSize: number,
  path: readonly string[],
  root: string,
): Promise<boolean> {
  try {
    return await verifyInclusion(fromHex(entryHash), index, treeSize, path.map(fromHex), fromHex(root));
  } catch {
    // fromHex rejects anything that is not lowercase hex; a malformed proof does not verify.
    return false;
  }
}

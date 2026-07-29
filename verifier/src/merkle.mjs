/**
 * RFC 6962 Merkle inclusion verification (algorithm as restated in
 * RFC 9162 §2.1.3.2) — port of the Python reference in logsiegel/merkle.py.
 * The verifier only ever *checks* proofs; tree construction stays on the
 * writer side, so this module needs no tree-building code.
 */

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** SHA-256(0x00 || data) — domain-separated leaf hash. */
export async function leafHash(data) {
  const prefixed = new Uint8Array(data.length + 1);
  prefixed[0] = LEAF_PREFIX;
  prefixed.set(data, 1);
  return sha256(prefixed);
}

/** SHA-256(0x01 || left || right) — domain-separated interior node hash. */
export async function nodeHash(left, right) {
  const prefixed = new Uint8Array(1 + left.length + right.length);
  prefixed[0] = NODE_PREFIX;
  prefixed.set(left, 1);
  prefixed.set(right, 1 + left.length);
  return sha256(prefixed);
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Check that `leaf` is the leaf at `index` of the size-`size` tree with the
 * given `root` (RFC 9162 §2.1.3.2).
 *
 * @param {Uint8Array} leaf        leaf hash (already domain-separated)
 * @param {number} index           0-based leaf index
 * @param {number} size            tree size the root commits to
 * @param {Uint8Array[]} proof     audit path, leaf-to-root order
 * @param {Uint8Array} root        expected Merkle root
 * @returns {Promise<boolean>}
 */
export async function verifyInclusion(leaf, index, size, proof, root) {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size)) return false;
  if (index < 0 || index >= size) return false;

  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (!(fn & 1)) {
        while (fn !== 0 && !(fn & 1)) {
          fn >>>= 1;
          sn >>>= 1;
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn >>>= 1;
    sn >>>= 1;
  }
  return sn === 0 && equalBytes(r, root);
}

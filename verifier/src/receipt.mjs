/**
 * Receipt format: structural validation + hashing primitives.
 *
 * Verification runs in three stages; each stage only runs if the previous
 * one passed, and the verdict names the first failing stage:
 *   1. structure  — shape, types, hex fields, origin/seq consistency (here)
 *   2. signature  — Ed25519 over the checkpoint body           (M3)
 *   3. inclusion  — RFC 6962 audit path against the root        (M2)
 *
 * Stricter than the Python reference at stage 1 by design: malformed hex or
 * missing checkpoint fields are structure errors here, while Python folds
 * them into the signature/inclusion verdicts. The fixtures encode the
 * expected JS stage per case.
 */

import { canonicalBytes, bytesToHex, hexToBytes } from "./canonical.mjs";
import { leafHash, verifyInclusion } from "./merkle.mjs";

const SHA256_HEX_LEN = 64;
const ED25519_SIG_HEX_LEN = 128;

function isHex(value, length) {
  return typeof value === "string" && value.length === length && !/[^0-9a-f]/.test(value);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Validate the shape of a parsed receipt.
 * @returns {{ok: boolean, problems: {stage: string, code: string, message: string}[]}}
 */
export function checkStructure(receipt) {
  const problems = [];
  const fail = (code, message) => problems.push({ stage: "structure", code, message });

  if (!isPlainObject(receipt)) {
    fail("receipt_not_object", "receipt is not a JSON object");
    return { ok: false, problems };
  }
  if (typeof receipt.origin !== "string" || receipt.origin === "") {
    fail("origin_missing", "receipt.origin missing or empty");
  }
  if (!Number.isSafeInteger(receipt.seq) || receipt.seq < 0) {
    fail("seq_invalid", "receipt.seq is not a non-negative integer");
  }

  if (!isPlainObject(receipt.entry)) {
    fail("entry_not_object", "receipt.entry is not a JSON object");
  } else if (receipt.entry.seq !== receipt.seq) {
    fail("entry_seq_mismatch",
      `entry.seq (${receipt.entry.seq}) does not match receipt.seq (${receipt.seq})`);
  }

  const cp = receipt.checkpoint;
  if (!isPlainObject(cp)) {
    fail("checkpoint_not_object", "receipt.checkpoint is not a JSON object");
  } else {
    if (typeof cp.origin !== "string" || cp.origin === "") {
      fail("checkpoint_origin_missing", "checkpoint.origin missing or empty");
    }
    if (!Number.isSafeInteger(cp.size) || cp.size < 1) {
      fail("checkpoint_size_invalid", "checkpoint.size is not a positive integer");
    }
    if (!isHex(cp.root, SHA256_HEX_LEN)) {
      fail("checkpoint_root_invalid", "checkpoint.root is not a 64-char lowercase hex string");
    }
    if (typeof cp.ts !== "string" || cp.ts === "") {
      fail("checkpoint_ts_missing", "checkpoint.ts missing or empty");
    }
    if (!isHex(cp.sig, ED25519_SIG_HEX_LEN)) {
      fail("checkpoint_sig_invalid", "checkpoint.sig is not a 128-char lowercase hex string");
    }
    if (typeof receipt.origin === "string" && typeof cp.origin === "string" &&
        receipt.origin !== cp.origin) {
      fail("origin_mismatch",
        `receipt.origin (${receipt.origin}) does not match checkpoint.origin (${cp.origin})`);
    }
  }

  if (!Array.isArray(receipt.inclusion_proof)) {
    fail("proof_not_array", "receipt.inclusion_proof is not an array");
  } else {
    receipt.inclusion_proof.forEach((p, i) => {
      if (!isHex(p, SHA256_HEX_LEN)) {
        fail("proof_element_invalid",
          `inclusion_proof[${i}] is not a 64-char lowercase hex string`);
      }
    });
  }

  return { ok: problems.length === 0, problems };
}

/** Leaf hash of an entry object (canonical JSON bytes), as lowercase hex. */
export async function entryLeafHashHex(entry) {
  return bytesToHex(await leafHash(canonicalBytes(entry)));
}

export { leafHash };

/**
 * Stage 3: RFC 6962 inclusion — is the entry committed by the checkpoint's
 * root? Callers must run this only after `checkStructure` passed; the hex
 * fields and integer types are trusted here.
 * @returns {Promise<{ok: boolean, problems: {stage: string, code: string, message: string}[]}>}
 */
export async function checkInclusion(receipt) {
  const cp = receipt.checkpoint;
  const leaf = await leafHash(canonicalBytes(receipt.entry));
  const proof = receipt.inclusion_proof.map(hexToBytes);
  const ok = await verifyInclusion(leaf, receipt.seq, cp.size, proof, hexToBytes(cp.root));
  return {
    ok,
    problems: ok ? [] : [{
      stage: "inclusion",
      code: "inclusion_invalid",
      message: `inclusion proof invalid for entry ${receipt.seq}`,
    }],
  };
}

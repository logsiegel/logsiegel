/**
 * Orchestrator: run the three stages in order, stop at the first failure.
 * The verdict names the failing stage — that message is what a
 * non-technical examiner reads, so it must say *what* is broken, not just
 * that something is.
 */

import { checkStructure, checkInclusion } from "./receipt.mjs";
import { checkSignature, importPublicKey, splitKeyFile } from "./signature.mjs";

/**
 * @param {object} receipt   parsed receipt JSON
 * @param {CryptoKey} key    operator's Ed25519 public key (out-of-band!)
 * @returns {Promise<{
 *   ok: boolean,
 *   failedStage: "structure"|"signature"|"inclusion"|null,
 *   stages: {structure: object|null, signature: object|null, inclusion: object|null},
 *   problems: {stage: string, code: string, message: string}[],
 * }>}
 */
export async function verifyReceipt(receipt, key) {
  const stages = { structure: null, signature: null, inclusion: null };

  stages.structure = checkStructure(receipt);
  if (!stages.structure.ok) {
    return { ok: false, failedStage: "structure", stages, problems: stages.structure.problems };
  }

  stages.signature = await checkSignature(receipt, key);
  if (!stages.signature.ok) {
    return { ok: false, failedStage: "signature", stages, problems: stages.signature.problems };
  }

  stages.inclusion = await checkInclusion(receipt);
  if (!stages.inclusion.ok) {
    return { ok: false, failedStage: "inclusion", stages, problems: stages.inclusion.problems };
  }

  return { ok: true, failedStage: null, stages, problems: [] };
}

/**
 * Verify against a key file that may hold several keys (one per log, as
 * operators publish them). Key choice, in order:
 *   1. exactly one block labelled "Origin: <checkpoint.origin>" → that key,
 *      and its verdict stands (a bad signature there means the checkpoint
 *      was altered or forged, not that the key is wrong);
 *   2. otherwise the first key whose signature over the checkpoint verifies.
 * Every key in the file is a trust anchor the user chose, and the origin is
 * inside the signed body, so trying them all cannot mix up logs.
 * No key verifies → failedStage "key" (no matching key), never "changed".
 * @returns {Promise<object>} verifyReceipt result plus `spkiDer` of the key used
 */
export async function verifyReceiptWithKeyFile(receipt, keyInput) {
  const blocks = splitKeyFile(keyInput);
  const run = async (input) => {
    const { key, spkiDer } = await importPublicKey(input);
    return { ...(await verifyReceipt(receipt, key)), spkiDer };
  };
  if (blocks.length <= 1) return run(blocks.length ? blocks[0].pem : keyInput);

  const structure = checkStructure(receipt);
  const stages = { structure, signature: null, inclusion: null };
  if (!structure.ok) {
    return { ok: false, failedStage: "structure", stages, problems: structure.problems, spkiDer: null };
  }

  const labelled = blocks.filter((b) => b.origin === receipt.checkpoint.origin);
  if (labelled.length === 1) return run(labelled[0].pem);

  for (const b of blocks) {
    const { key } = await importPublicKey(b.pem);
    if ((await checkSignature(receipt, key)).ok) return run(b.pem);
  }
  const problems = [{
    stage: "key",
    code: "no_matching_key",
    message: `none of the ${blocks.length} keys in the key file verifies this checkpoint`,
  }];
  stages.signature = { ok: false, problems };
  return { ok: false, failedStage: "key", stages, problems, spkiDer: null };
}

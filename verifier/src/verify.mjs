/**
 * Orchestrator: run the three stages in order, stop at the first failure.
 * The verdict names the failing stage — that message is what a
 * non-technical examiner reads, so it must say *what* is broken, not just
 * that something is.
 */

import { checkStructure, checkInclusion } from "./receipt.mjs";
import { checkSignature } from "./signature.mjs";

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

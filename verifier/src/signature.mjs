/**
 * Stage 2: Ed25519 signature over the canonical checkpoint body
 * {origin, root, size, ts} — the operator's attestation of a log state.
 *
 * Key input accepts what operators actually hand out: the PEM public key
 * file (`keys/signing_key.pub`) or base64/raw SPKI DER. WebCrypto carries
 * the Ed25519 implementation; no crypto code of our own.
 */

import { canonicalBytes, bytesToHex, hexToBytes } from "./canonical.mjs";

const PEM_BODY = /-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----/;
const ED25519_SPKI_LEN = 44; // 12-byte algorithm prefix + 32-byte raw key

function base64ToBytes(b64) {
  const bin = atob(b64.replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Extract SPKI DER bytes from PEM text, base64, or pass DER through. */
export function spkiFromInput(input) {
  if (input instanceof Uint8Array) return input;
  if (typeof input !== "string" || input.trim() === "") {
    throw new TypeError("public key: expected PEM text, base64, or DER bytes");
  }
  const pem = input.match(PEM_BODY);
  const der = base64ToBytes(pem ? pem[1] : input);
  if (der.length !== ED25519_SPKI_LEN) {
    throw new TypeError(
      `public key: expected ${ED25519_SPKI_LEN}-byte Ed25519 SPKI, got ${der.length} bytes`);
  }
  return der;
}

/**
 * @returns {Promise<{key: CryptoKey, spkiDer: Uint8Array}>}
 * Throws with a clear message when the runtime lacks WebCrypto Ed25519.
 */
export async function importPublicKey(input) {
  const spkiDer = spkiFromInput(input);
  let key;
  try {
    key = await crypto.subtle.importKey("spki", spkiDer, { name: "Ed25519" }, true, ["verify"]);
  } catch (err) {
    throw new Error(`Ed25519 key import failed (browser too old?): ${err.message}`);
  }
  return { key, spkiDer };
}

/** Same short fingerprint the Python side prints: ed25519:<sha256(raw)[:16]>. */
export async function keyFingerprint(spkiDer) {
  const raw = spkiDer.slice(-32);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
  return "ed25519:" + bytesToHex(digest).slice(0, 16);
}

/**
 * Verify the checkpoint signature. Run only after `checkStructure` passed.
 * @returns {Promise<{ok: boolean, problems: {stage: string, code: string, message: string}[]}>}
 */
export async function checkSignature(receipt, key) {
  const cp = receipt.checkpoint;
  const body = { origin: cp.origin, size: cp.size, root: cp.root, ts: cp.ts };
  const ok = await crypto.subtle.verify(
    "Ed25519", key, hexToBytes(cp.sig), canonicalBytes(body));
  return {
    ok,
    problems: ok ? [] : [{
      stage: "signature",
      code: "signature_invalid",
      message: "checkpoint signature invalid",
    }],
  };
}

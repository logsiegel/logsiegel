import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { checkStructure } from "../src/receipt.mjs";
import { importPublicKey, keyFingerprint, spkiFromInput, checkSignature } from "../src/signature.mjs";
import { verifyReceipt } from "../src/verify.mjs";

const fixtures = JSON.parse(readFileSync(
  fileURLToPath(new URL("../fixtures/receipts.json", import.meta.url)), "utf8"));

const keyFor = async (c) =>
  (await importPublicKey((c.public_key_override ?? fixtures.public_key).spki_der_b64)).key;

// Python always evaluates the signature first, so its report is a complete
// ground truth for this stage: parity for every structure-passing case.
for (const c of fixtures.cases.filter((c) => checkStructure(c.receipt).ok)) {
  const expected = !c.python_report.problems.includes("checkpoint signature invalid");
  test(`signature parity: ${c.name} (expect ${expected})`, async () => {
    const result = await checkSignature(c.receipt, await keyFor(c));
    assert.equal(result.ok, expected);
  });
}

test("PEM and base64 SPKI inputs yield the same key", async () => {
  const pem = spkiFromInput(fixtures.public_key.pem);
  const b64 = spkiFromInput(fixtures.public_key.spki_der_b64);
  assert.deepEqual(pem, b64);
});

test("key fingerprint has the Python shape", async () => {
  const { spkiDer } = await importPublicKey(fixtures.public_key.pem);
  assert.match(await keyFingerprint(spkiDer), /^ed25519:[0-9a-f]{16}$/);
});

test("garbage key input is rejected with a clear error", () => {
  assert.throws(() => spkiFromInput("not a key"), /public key|invalid/i);
  assert.throws(() => spkiFromInput(""), TypeError);
});

// End-to-end: the orchestrator's verdict must land on exactly the stage the
// fixture predicts, for all 18 cases.
for (const c of fixtures.cases) {
  test(`verdict: ${c.name} → ${c.expect_stage}`, async () => {
    const result = await verifyReceipt(c.receipt, await keyFor(c));
    assert.equal(result.ok, c.expect_stage === "ok");
    assert.equal(result.failedStage, c.expect_stage === "ok" ? null : c.expect_stage);
  });
}

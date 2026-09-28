import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { splitKeyFile } from "../src/signature.mjs";
import { verifyReceiptWithKeyFile } from "../src/verify.mjs";

const fixtures = JSON.parse(readFileSync(
  fileURLToPath(new URL("../fixtures/receipts.json", import.meta.url)), "utf8"));
const receipt = fixtures.cases.find((c) => c.name === "valid_seq7_size13").receipt;
const goodPem = fixtures.public_key.pem.trim();

async function otherPem() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const der = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const b64 = btoa(String.fromCharCode(...der));
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
}

// Same layout as a published key list: header prose, then labelled blocks.
function keyList(blocks) {
  return "Operator key list\n\n" + blocks.map(({ origin, pem }) =>
    "------------------------------\n" +
    (origin ? `Origin:         ${origin}\nFingerabdruck:  ed25519:0000000000000000\n\n` : "") +
    pem + "\n").join("\n");
}

const tamperEntry = (r) => {
  const t = structuredClone(r);
  t.entry.attrs["nachtraeglich_geaendert"] = true;
  return t;
};

test("splitKeyFile reads blocks and their Origin labels", async () => {
  const text = keyList([{ origin: "a/1", pem: await otherPem() }, { origin: null, pem: goodPem }]);
  const blocks = splitKeyFile(text);
  assert.equal(blocks.length, 2);
  assert.equal(blocks[0].origin, "a/1");
  assert.equal(blocks[1].origin, null);
});

test("single key file verifies as before", async () => {
  const r = await verifyReceiptWithKeyFile(receipt, fixtures.public_key.pem);
  assert.equal(r.ok, true);
  assert.equal(r.failedStage, null);
});

test("bare base64 key still accepted", async () => {
  const r = await verifyReceiptWithKeyFile(receipt, fixtures.public_key.spki_der_b64);
  assert.equal(r.ok, true);
});

test("key list, matching key labelled by origin at position 3 → valid", async () => {
  const text = keyList([
    { origin: "x/one", pem: await otherPem() },
    { origin: "x/two", pem: await otherPem() },
    { origin: receipt.checkpoint.origin, pem: goodPem },
  ]);
  const r = await verifyReceiptWithKeyFile(receipt, text);
  assert.equal(r.ok, true);
  assert.equal(btoa(String.fromCharCode(...r.spkiDer)), fixtures.public_key.spki_der_b64);
});

test("key list without labels, matching key at position 2 → valid by trial", async () => {
  const text = keyList([{ pem: await otherPem() }, { pem: goodPem }, { pem: await otherPem() }]);
  const r = await verifyReceiptWithKeyFile(receipt, text);
  assert.equal(r.ok, true);
  assert.equal(btoa(String.fromCharCode(...r.spkiDer)), fixtures.public_key.spki_der_b64);
});

test("key list without the matching key → no matching key, not 'changed'", async () => {
  const text = keyList([{ origin: "x/one", pem: await otherPem() }, { pem: await otherPem() }]);
  const r = await verifyReceiptWithKeyFile(receipt, text);
  assert.equal(r.ok, false);
  assert.equal(r.failedStage, "key");
  assert.equal(r.problems[0].code, "no_matching_key");
});

test("tampered entry with key list → inclusion failure (content changed)", async () => {
  const text = keyList([{ origin: "x/one", pem: await otherPem() }, { origin: receipt.checkpoint.origin, pem: goodPem }]);
  const r = await verifyReceiptWithKeyFile(tamperEntry(receipt), text);
  assert.equal(r.ok, false);
  assert.equal(r.failedStage, "inclusion");
});

test("tampered checkpoint, key labelled for its origin → signature failure, not 'no key'", async () => {
  const text = keyList([{ origin: "x/one", pem: await otherPem() }, { origin: receipt.checkpoint.origin, pem: goodPem }]);
  const t = structuredClone(receipt);
  t.checkpoint.size += 1;
  const r = await verifyReceiptWithKeyFile(t, text);
  assert.equal(r.ok, false);
  assert.equal(r.failedStage, "signature");
});

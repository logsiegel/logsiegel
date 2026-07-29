import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { checkStructure, checkInclusion } from "../src/receipt.mjs";
import { verifyInclusion, leafHash, nodeHash } from "../src/merkle.mjs";
import { canonicalBytes } from "../src/canonical.mjs";

const fixtures = JSON.parse(readFileSync(
  fileURLToPath(new URL("../fixtures/receipts.json", import.meta.url)), "utf8"));

// Parity with the Python reference: every case where the structure stage
// passes must reach the exact inclusion verdict the exporter recorded.
for (const c of fixtures.cases.filter((c) => checkStructure(c.receipt).ok)) {
  test(`inclusion parity: ${c.name} (expect ${c.expect_inclusion})`, async () => {
    const result = await checkInclusion(c.receipt);
    assert.equal(result.ok, c.expect_inclusion);
    if (!result.ok) {
      assert.equal(result.problems[0].stage, "inclusion");
    }
  });
}

test("single-leaf tree: leaf is the root, empty proof", async () => {
  const leaf = await leafHash(canonicalBytes({ seq: 0 }));
  assert.equal(await verifyInclusion(leaf, 0, 1, [], leaf), true);
  assert.equal(await verifyInclusion(leaf, 0, 1, [leaf], leaf), false,
    "surplus proof elements must be rejected");
});

test("two-leaf tree built by hand verifies both leaves", async () => {
  const a = await leafHash(canonicalBytes({ seq: 0 }));
  const b = await leafHash(canonicalBytes({ seq: 1 }));
  const root = await nodeHash(a, b);
  assert.equal(await verifyInclusion(a, 0, 2, [b], root), true);
  assert.equal(await verifyInclusion(b, 1, 2, [a], root), true);
  assert.equal(await verifyInclusion(a, 1, 2, [b], root), false,
    "leaf presented at the wrong index must fail");
});

test("index >= size fails without touching the proof", async () => {
  const leaf = await leafHash(canonicalBytes({ seq: 0 }));
  assert.equal(await verifyInclusion(leaf, 3, 2, [], leaf), false);
  assert.equal(await verifyInclusion(leaf, -1, 2, [], leaf), false);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { checkStructure, entryLeafHashHex, leafHash } from "../src/receipt.mjs";
import { canonicalBytes } from "../src/canonical.mjs";

const fixtures = JSON.parse(readFileSync(
  fileURLToPath(new URL("../fixtures/receipts.json", import.meta.url)), "utf8"));

for (const c of fixtures.cases) {
  test(`structure: ${c.name} (expect ${c.expect_stage})`, () => {
    const result = checkStructure(c.receipt);
    if (c.expect_stage === "structure") {
      assert.equal(result.ok, false, "structure stage must reject this case");
    } else {
      assert.equal(result.ok, true,
        `structure stage must pass; problems: ${JSON.stringify(result.problems)}`);
    }
  });
}

for (const c of fixtures.cases.filter((c) => c.entry_leaf_hash_hex)) {
  test(`entry leaf hash parity: ${c.name}`, async () => {
    assert.equal(await entryLeafHashHex(c.receipt.entry), c.entry_leaf_hash_hex,
      "leaf hash over canonical entry bytes must match the Python reference");
  });
}

test("fixture sanity: every python-rejected case fails some JS stage too", () => {
  for (const c of fixtures.cases) {
    if (!c.python_report.ok) {
      assert.notEqual(c.expect_stage, "ok",
        `${c.name}: python rejects but fixture expects JS ok`);
    }
  }
});

test("leaf hash uses the 0x00 domain separator", async () => {
  const data = canonicalBytes({ a: 1 });
  const plain = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  const leaf = await leafHash(data);
  assert.notDeepEqual(leaf, plain);
});

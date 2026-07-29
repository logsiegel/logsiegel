import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { canonicalBytes, bytesToHex } from "../src/canonical.mjs";

const fixtures = JSON.parse(readFileSync(
  fileURLToPath(new URL("../fixtures/canonical_vectors.json", import.meta.url)), "utf8"));

for (const vector of fixtures.vectors) {
  test(`canonical vector: ${vector.name}`, async () => {
    const bytes = canonicalBytes(vector.value);
    assert.equal(bytesToHex(bytes), vector.canonical_utf8_hex,
      "canonical bytes must match the Python reference");

    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    assert.equal(bytesToHex(digest), vector.sha256_hex);
  });
}

test("floats are rejected", () => {
  assert.throws(() => canonicalBytes({ t: 0.25 }), TypeError);
});

test("astral keys sort by code point, not UTF-16 code units", () => {
  // U+FF21 (BMP) sorts before U+1D400 (astral) by code point; naive UTF-16
  // comparison puts the surrogate pair (0xD835…) first.
  const bytes = canonicalBytes({ "\u{1D400}": 1, "Ａ": 2 });
  const text = new TextDecoder().decode(bytes);
  assert.ok(text.indexOf("Ａ") < text.indexOf("\u{1D400}"));
});

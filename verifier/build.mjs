/**
 * Build the single-file browser verifier.
 *
 * Concatenates verifier/src/*.mjs (imports/exports stripped — the modules
 * form one flat scope with no name collisions) into the UI template and
 * writes verifier/dist/logsiegel-verifier.html. Inline module scripts run
 * from file:// — the artifact needs no server and no network.
 *
 * Then self-checks: the bundled code (not the source modules) must reach
 * the fixture verdict on every receipt case.
 *
 * Run:  node verifier/build.mjs
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));

const SOURCES = ["canonical.mjs", "merkle.mjs", "receipt.mjs", "signature.mjs", "verify.mjs"];

function flatten(code) {
  return code
    .replace(/^import .*$/gm, "")
    .replace(/^export \{[^}]*\};?$/gm, "")
    .replace(/^export (?=(async |function|const |class ))/gm, "");
}

const bundle = SOURCES
  .map((f) => `// --- ${f} ---\n` + flatten(readFileSync(here(`src/${f}`), "utf8")))
  .join("\n");

if (/^(import|export)\b/m.test(bundle)) {
  throw new Error("bundle still contains import/export statements — transform incomplete");
}

const template = readFileSync(here("ui/template.html"), "utf8");
const marker = "// %BUNDLE%";
if (!template.includes(marker)) throw new Error("template is missing the bundle marker");

mkdirSync(here("dist"), { recursive: true });
writeFileSync(here("dist/logsiegel-verifier.html"), template.replace(marker, bundle));

// -- self-check against the fixtures ----------------------------------------

writeFileSync(here("dist/bundle-test.mjs"),
  bundle + "\nexport { verifyReceipt, importPublicKey };\n");
const lib = await import(pathToFileURL(here("dist/bundle-test.mjs")));

const fixtures = JSON.parse(readFileSync(here("fixtures/receipts.json"), "utf8"));
let pass = 0;
for (const c of fixtures.cases) {
  const bundleB64 = (c.public_key_override ?? fixtures.public_key).spki_der_b64;
  const { key } = await lib.importPublicKey(bundleB64);
  const result = await lib.verifyReceipt(c.receipt, key);
  const expected = c.expect_stage === "ok" ? null : c.expect_stage;
  if (result.ok === (c.expect_stage === "ok") && result.failedStage === expected) {
    pass += 1;
  } else {
    console.error(`✗ ${c.name}: expected ${c.expect_stage}, got ${result.failedStage ?? "ok"}`);
  }
}
if (pass !== fixtures.cases.length) {
  throw new Error(`self-check failed: ${pass}/${fixtures.cases.length}`);
}
console.log(`dist/logsiegel-verifier.html written — self-check ${pass}/${fixtures.cases.length} verdicts match`);

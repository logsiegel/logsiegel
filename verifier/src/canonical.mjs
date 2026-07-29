/**
 * Canonical JSON — byte-identical to the Python reference:
 * json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
 *
 * Receipts commit to entries via SHA-256 over these exact bytes, so the two
 * implementations must agree on every byte. Scope is deliberately narrow:
 * entries contain null, booleans, integers, strings, arrays and objects —
 * floats are rejected rather than risking Python/JS formatting divergence.
 */

const encoder = new TextEncoder();

/** Python sorts keys by Unicode code point; JS String comparison uses UTF-16
 * code units, which disagrees for astral characters. Compare code points. */
function compareCodePoints(a, b) {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done && y.done) return 0;
    if (x.done) return -1;
    if (y.done) return 1;
    const cx = x.value.codePointAt(0);
    const cy = y.value.codePointAt(0);
    if (cx !== cy) return cx - cy;
  }
}

const SHORT_ESCAPES = new Map([
  ['"', '\\"'], ["\\", "\\\\"], ["\b", "\\b"], ["\f", "\\f"],
  ["\n", "\\n"], ["\r", "\\r"], ["\t", "\\t"],
]);

function escapeString(s) {
  let out = '"';
  for (const ch of s) {
    const short = SHORT_ESCAPES.get(ch);
    if (short !== undefined) {
      out += short;
    } else {
      const cp = ch.codePointAt(0);
      out += cp < 0x20 ? "\\u" + cp.toString(16).padStart(4, "0") : ch;
    }
  }
  return out + '"';
}

function serialize(value) {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value)) {
        throw new TypeError(`canonical JSON: only safe integers supported, got ${value}`);
      }
      return String(value);
    case "string":
      return escapeString(value);
    case "object":
      if (Array.isArray(value)) {
        return "[" + value.map(serialize).join(",") + "]";
      }
      return (
        "{" +
        Object.keys(value)
          .sort(compareCodePoints)
          .map((k) => escapeString(k) + ":" + serialize(value[k]))
          .join(",") +
        "}"
      );
    default:
      throw new TypeError(`canonical JSON: unsupported type ${typeof value}`);
  }
}

/** @returns {Uint8Array} UTF-8 bytes of the canonical form. */
export function canonicalBytes(value) {
  return encoder.encode(serialize(value));
}

export function bytesToHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || /[^0-9a-f]/.test(hex)) {
    throw new TypeError("invalid lowercase hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

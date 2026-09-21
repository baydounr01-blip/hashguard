/* The canonical encoding and the hashes built on it, for the browser.
 *
 * This is the second implementation of hashguard/canonical.py. It exists
 * because the console re-derives the invoice in the client's own browser,
 * using none of the operator's code -- which is worth nothing unless the two
 * implementations produce the same bytes for the same value, every time.
 *
 * It lives in its own file so that the file which runs in the browser is the
 * file the parity test hashes. A copy of the encoder maintained beside the
 * test would agree with the test and drift from the page, which is the one
 * failure mode this whole arrangement is meant to prevent. Node loads it
 * through tools/canonical_parity_node.js; console.html loads it before
 * console.js, both under script-src 'self'.
 *
 * Three rules are not obvious and each has a reason:
 *
 *  - No floats. A ledger whose numbers are floats is a ledger with two
 *    readings, and a billing dispute that turns on the last bit of a mantissa
 *    is one nobody can settle.
 *
 *  - No integer outside +-(2^53 - 1). JavaScript parses 9007199254740993 as
 *    9007199254740992; a record holding such a value would hash differently in
 *    the browser and the console could never verify it. Refusing it makes
 *    parity a property rather than a hope. The bound is four orders of
 *    magnitude above any real HashGuard quantity: 2^53 watt-hours is 9 PWh,
 *    and 2^53 micro-euro is nine billion euro.
 *
 *  - Keys sorted by code point, not by UTF-16 code unit. Python sorts strings
 *    by code point; Array.prototype.sort compares UTF-16 code units, and the
 *    two disagree whenever a key above U+FFFF meets one in U+E000..U+FFFF --
 *    a surrogate pair's lead unit (0xD800..0xDBFF) sorts *below* U+E000, so
 *    JavaScript would put the astral key first and Python would not.
 */

"use strict";

(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;            // Node, for the parity test
  } else {
    root.HashGuardCanonical = api;   // the browser
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  const SPEC = "hashguard-ledger/2";
  const MAX_SAFE = 9007199254740991;   // 2^53 - 1

  function canonicalError(message) {
    const error = new Error(message);
    error.name = "CanonicalError";
    return error;
  }

  /* Compare two strings by Unicode code point, as Python's `sorted` does.
     Iterating a JavaScript string with for..of yields code points, so this
     needs no surrogate arithmetic of its own. */
  function byCodePoint(a, b) {
    const left = Array.from(a);
    const right = Array.from(b);
    const shared = Math.min(left.length, right.length);
    for (let i = 0; i < shared; i++) {
      const x = left[i].codePointAt(0);
      const y = right[i].codePointAt(0);
      if (x !== y) return x < y ? -1 : 1;
    }
    return left.length - right.length;
  }

  function canonical(value, path) {
    const here = path || "$";
    if (value === null || typeof value === "boolean" || typeof value === "string") {
      return JSON.stringify(value);
    }
    if (typeof value === "number") {
      if (!Number.isInteger(value)) {
        throw canonicalError(
          here + ": floats are not canonical; carry the quantity as an integer " +
          "in a declared minor unit"
        );
      }
      if (value > MAX_SAFE || value < -MAX_SAFE) {
        throw canonicalError(
          here + ": " + value + " is outside +-(2^53 - 1), where JavaScript and " +
          "Python stop agreeing on which integer this is"
        );
      }
      // -0 is a number JSON.stringify writes as "0"; Python writes 0 for the
      // integer 0 too, so the two agree. Stated here because it looks like a
      // trap and is not one.
      return JSON.stringify(value === 0 ? 0 : value);
    }
    if (typeof value === "bigint") {
      throw canonicalError(here + ": bigint has no canonical encoding; it would not survive JSON");
    }
    if (Array.isArray(value)) {
      return "[" + value.map((item, i) => canonical(item, here + "[" + i + "]")).join(",") + "]";
    }
    if (typeof value === "object") {
      const keys = Object.keys(value).sort(byCodePoint);
      return (
        "{" +
        keys
          .map((k) => JSON.stringify(k) + ":" + canonical(value[k], here + "." + k))
          .join(",") +
        "}"
      );
    }
    throw canonicalError(here + ": type " + typeof value + " has no canonical encoding");
  }

  /* ---- hashes ---- */

  function subtle() {
    const web = typeof crypto !== "undefined" ? crypto : undefined;
    if (!web || !web.subtle) {
      throw new Error("WebCrypto is not available here");
    }
    return web.subtle;
  }

  async function sha256(bytes) {
    return new Uint8Array(await subtle().digest("SHA-256", bytes));
  }

  async function sha256d(bytes) {
    return sha256(await sha256(bytes));
  }

  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  function toHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function fromHex(text) {
    if (typeof text !== "string" || text.length !== 64 || !/^[0-9a-f]+$/.test(text)) return null;
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(text.substr(i * 2, 2), 16);
    return out;
  }

  const encoder = new TextEncoder();

  function canonicalBytes(value) {
    return encoder.encode(canonical(value));
  }

  async function taggedHash(tag, bytes) {
    return sha256d(concat(await sha256(encoder.encode(tag)), bytes));
  }

  async function recordHash(record) {
    return taggedHash(SPEC + "/record", canonicalBytes(record));
  }

  async function nodeHash(left, right) {
    return taggedHash(SPEC + "/node", concat(left, right));
  }

  return {
    SPEC,
    MAX_SAFE,
    byCodePoint,
    canonical,
    canonicalBytes,
    sha256,
    sha256d,
    concat,
    toHex,
    fromHex,
    encoder,
    taggedHash,
    recordHash,
    nodeHash,
  };
});

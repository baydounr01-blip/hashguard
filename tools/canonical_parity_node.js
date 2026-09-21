#!/usr/bin/env node
/* Run web/canonical.js under Node and report what it produces.
 *
 * The file loaded here is the file the browser loads. Not a copy, not a port:
 * the same bytes on disk, required directly. A copy maintained beside the test
 * would agree with the test and drift from the page, which is the one failure
 * this whole arrangement exists to prevent.
 *
 * It reads a JSON job on stdin and writes a JSON answer on stdout:
 *
 *   {"encode": [<value>, ...]}   -> {"results": [{"canonical": "...",
 *                                                 "record_hash": "..."} | {"error": "..."}]}
 *
 * An entry that cannot be encoded comes back as an error rather than taking
 * the process down, because "this value is refused" is one of the things the
 * parity test needs to compare between the two implementations.
 */

"use strict";

const path = require("path");

const canonicalJs = path.join(__dirname, "..", "web", "canonical.js");
const HG = require(canonicalJs);

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

async function main() {
  const raw = await readStdin();
  let job;
  try {
    job = JSON.parse(raw);
  } catch (error) {
    process.stdout.write(JSON.stringify({ fatal: `stdin is not JSON: ${error.message}` }));
    process.exitCode = 2;
    return;
  }

  const results = [];
  for (const value of job.encode || []) {
    try {
      const encoded = HG.canonical(value);
      const digest = await HG.recordHash(value);
      results.push({ canonical: encoded, record_hash: HG.toHex(digest) });
    } catch (error) {
      results.push({ error: `${error.name}: ${error.message}` });
    }
  }

  // Key ordering is asserted separately: comparing a *sort* rather than a
  // whole encoding is what localises a failure to the comparator instead of
  // leaving a diff of two long strings to read.
  const sorted = (job.sort || []).map((keys) => keys.slice().sort(HG.byCodePoint));

  process.stdout.write(
    JSON.stringify({
      node: process.versions.node,
      max_safe: HG.MAX_SAFE,
      results,
      sorted,
    })
  );
}

main().catch((error) => {
  process.stdout.write(JSON.stringify({ fatal: `${error.name}: ${error.message}` }));
  process.exitCode = 1;
});

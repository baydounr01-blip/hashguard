/* HashGuard console.
 *
 * Two rules govern this file.
 *
 * 1. Nothing from the agent is ever assigned to innerHTML. Miner names, alert
 *    text and payment references all originate in a config file, and v1 built
 *    its alert list by string-concatenating them into innerHTML -- a stored XSS
 *    with the agent token sitting in localStorage next to it (AUDIT-11/13).
 *    Everything here goes through textContent on nodes built with
 *    createElement, and the token lives in sessionStorage.
 *
 * 2. The console verifies the invoice itself. It re-derives the record hashes,
 *    walks each inclusion proof to the sealed Merkle root, checks that each
 *    seal is SHA256d(prev_seal || merkle_root), checks that the seals chain,
 *    and redoes the fee arithmetic in integers -- in the client's own browser,
 *    with WebCrypto, using none of the operator's code. That works only because
 *    the ledger contains no floating point: integers and strings serialise
 *    identically in Python and JavaScript, so both sides hash the same bytes.
 */

"use strict";

const SPEC = "hashguard-ledger/2";
const POLL_MS = 10000;

let AGENT = sessionStorage.getItem("hg_agent") || "";
let TOKEN = sessionStorage.getItem("hg_token") || "";
let pollTimer = null;
let lastStatus = null;
let calibrationBuilt = false;
const calState = {};

/* ───────────────────────── crypto ───────────────────────── */

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
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

/* The canonical encoding, matching hashguard/canonical.py exactly: keys sorted,
   no insignificant whitespace, UTF-8, and no floats anywhere. */
function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("the canonical form admits no floats");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  throw new Error("value has no canonical encoding");
}

const encoder = new TextEncoder();

async function taggedHash(tag, bytes) {
  return sha256d(concat(await sha256(encoder.encode(tag)), bytes));
}

async function recordHash(record) {
  return taggedHash(SPEC + "/record", encoder.encode(canonical(record)));
}

async function nodeHash(left, right) {
  return taggedHash(SPEC + "/node", concat(left, right));
}

async function verifyInclusion(leaf, proof, root) {
  if (!leaf || !root) return false;
  const index = Number(proof.index);
  const count = Number(proof.leaf_count);
  if (!(index >= 0 && index < count)) return false;
  let depth = 0;
  let width = count;
  while (width > 1) {
    width = Math.ceil(width / 2);
    depth++;
  }
  if (proof.path.length !== depth) return false;
  let cursor = leaf;
  for (const step of proof.path) {
    const sibling = fromHex(step.hash);
    if (!sibling) return false;
    cursor = step.side === "L" ? await nodeHash(sibling, cursor) : await nodeHash(cursor, sibling);
  }
  return toHex(cursor) === toHex(root);
}

const GENESIS_PROMISE = sha256d(encoder.encode("hashguard/v2/genesis"));

/* ───────────────────────── DOM helpers ───────────────────── */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function setEmpty(node, message) {
  clear(node);
  node.appendChild(el("div", "empty", message));
}

function eur(micro) {
  const value = Number(micro) / 1e6;
  return (value < 0 ? "-" : "") + "€" + Math.abs(value).toFixed(2);
}

/* ───────────────────────── transport ─────────────────────── */

async function api(path, options) {
  if (!AGENT) throw new Error("no agent configured");
  const response = await fetch(AGENT + path, {
    ...(options || {}),
    headers: {
      "X-HashGuard-Token": TOKEN,
      "Content-Type": "application/json",
      ...((options || {}).headers || {}),
    },
  });
  if (response.status === 401) throw new Error("the agent rejected this token");
  if (response.status === 429) {
    const retry = response.headers.get("Retry-After") || "?";
    throw new Error(`rate limited; retry in ${retry}s`);
  }
  if (!response.ok && response.status !== 207) throw new Error("HTTP " + response.status);
  return response.json();
}

/* ───────────────────────── connection ────────────────────── */

function openSettings() {
  document.getElementById("agentUrl").value = AGENT;
  document.getElementById("agentTok").value = TOKEN;
  document.getElementById("connErr").textContent = "";
  document.getElementById("settings").classList.remove("hidden");
}

function closeSettings() {
  document.getElementById("settings").classList.add("hidden");
}

async function connect() {
  const url = document.getElementById("agentUrl").value.trim().replace(/\/+$/, "");
  const token = document.getElementById("agentTok").value.trim();
  const error = document.getElementById("connErr");
  if (!/^https?:\/\//.test(url)) {
    error.textContent = "The agent URL must start with http:// or https://";
    return;
  }
  const previous = [AGENT, TOKEN];
  AGENT = url;
  TOKEN = token;
  try {
    await api("/status");
  } catch (problem) {
    [AGENT, TOKEN] = previous;
    error.textContent = "Could not connect: " + problem.message;
    return;
  }
  sessionStorage.setItem("hg_agent", AGENT);
  sessionStorage.setItem("hg_token", TOKEN);
  closeSettings();
  start();
}

function signOut() {
  sessionStorage.removeItem("hg_agent");
  sessionStorage.removeItem("hg_token");
  AGENT = "";
  TOKEN = "";
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
  openSettings();
}

/* ───────────────────────── polling ───────────────────────── */

function start() {
  poll();
  if (!pollTimer) pollTimer = setInterval(poll, POLL_MS);
}

async function poll() {
  if (!AGENT) return;
  const dot = document.getElementById("connDot");
  try {
    const status = await api("/status");
    lastStatus = status;
    dot.classList.add("ok");
    render(status);
    renderLedger();
  } catch (problem) {
    dot.classList.remove("ok");
    document.getElementById("curtailReason").textContent =
      "No connection to the agent (" + problem.message + "). Your miners keep running on their own.";
  }
}

/* ───────────────────────── rendering ─────────────────────── */

function zColour(z, alertZ, criticalZ) {
  if (z === null || z === undefined || !isFinite(z)) return "var(--dead)";
  if (z < -criticalZ) return "var(--bad)";
  if (z < -alertZ) return "var(--warn)";
  return "var(--ok)";
}

function median(values) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function render(status) {
  document.getElementById("farmName").textContent = status.farm || "—";
  document.getElementById("lastTs").textContent = status.ts
    ? new Date(status.ts).toLocaleTimeString()
    : "";

  const banner = document.getElementById("curtailBanner");
  const action = (status.curtailment && status.curtailment.action) || "—";
  banner.className = action === "PAUSE" ? "pause" : "mine";
  document.getElementById("curtailAction").textContent = action === "PAUSE" ? "PAUSED" : "MINING";
  document.getElementById("curtailReason").textContent =
    (status.curtailment && status.curtailment.reason) || "";

  const telemetry = status.telemetry || {};
  const corroboration = document.getElementById("corroboration");
  if (action === "PAUSE" && telemetry.baseline_gh) {
    const dark = Math.max(
      0,
      Math.min(100, ((telemetry.baseline_gh - telemetry.observed_gh) / telemetry.baseline_gh) * 100)
    );
    corroboration.textContent = `telemetry: ${dark.toFixed(0)}% of the farm is dark`;
  } else if (action === "PAUSE") {
    corroboration.textContent = "telemetry: no baseline yet — this pause is not yet billable";
  } else {
    corroboration.textContent = "";
  }

  renderRack(status);
  renderPrices(status);
  renderAlerts(status);
  renderCalibration(status);
}

function renderRack(status) {
  const rack = document.getElementById("rack");
  const thresholds = status.thresholds || { z_alert: 2.5, z_critical: 4 };
  const miners = status.miners || {};
  const names = Object.keys(miners).sort();
  if (!names.length) {
    setEmpty(rack, "The agent sees no miners. Check config.json, or start it with --demo.");
    document.getElementById("totalTh").textContent = "";
    return;
  }
  const all = [];
  names.forEach((name) =>
    (miners[name].boards || []).forEach((board) => all.push(board.hashrate_gh))
  );
  const med = median(all);
  const mad = median(all.map((v) => Math.abs(v - med)));
  const sigma = 1.4826 * mad || 1;

  clear(rack);
  let totalTh = 0;
  names.forEach((name) => {
    const column = el("div", "miner");
    (miners[name].boards || []).forEach((board) => {
      totalTh += board.hashrate_gh / 1000;
      const z = (board.hashrate_gh - med) / sigma;
      const cell = el("div", "board", (board.hashrate_gh / 1000).toFixed(0) + "T");
      cell.style.background = zColour(z, thresholds.z_alert, thresholds.z_critical);
      cell.title =
        `${name} board ${board.idx} · z=${z.toFixed(1)}σ` +
        (board.temp_max ? ` · ${board.temp_max.toFixed(0)}°C` : "");
      column.appendChild(cell);
    });
    column.appendChild(el("div", "mname", name));
    rack.appendChild(column);
  });
  document.getElementById("totalTh").textContent = totalTh ? `Σ ${totalTh.toFixed(0)} TH/s` : "";
}

function renderPrices(status) {
  const chart = document.getElementById("priceChart");
  const meta = document.getElementById("priceMeta");
  const prices = status.prices_ppm || {};
  const hours = Object.keys(prices)
    .map(Number)
    .sort((a, b) => a - b);
  const breakeven = (status.breakeven_ppm_per_kwh || 0) / 1e6;

  if (hours.length < 2) {
    setEmpty(chart, "No hourly curve (fixed price source).");
    meta.textContent = breakeven
      ? `Break-even ${breakeven.toFixed(3)} €/kWh · fixed price source`
      : "";
    return;
  }
  clear(chart);
  const values = hours.map((h) => prices[h] / 1e6);
  const maximum = Math.max(...values, breakeven) * 1.15 || 1;
  const nowHour = new Date().getHours();
  hours.forEach((hour) => {
    const value = prices[hour] / 1e6;
    const bar = el("div", "pbar " + (value > breakeven ? "expensive" : "cheap"));
    if (hour === nowHour) bar.classList.add("now");
    bar.style.height = Math.max(3, (value / maximum) * 120) + "px";
    bar.title = `${String(hour).padStart(2, "0")}:00 · ${value.toFixed(3)} €/kWh`;
    chart.appendChild(bar);
  });
  const line = el("div");
  line.id = "beLine";
  line.style.bottom = (breakeven / maximum) * 120 + "px";
  line.appendChild(el("span", null, "break-even " + breakeven.toFixed(3)));
  chart.appendChild(line);

  const profitable = values.filter((v) => v <= breakeven).length;
  meta.textContent =
    `${profitable} of ${values.length} hours profitable today · ` +
    `break-even ${breakeven.toFixed(3)} €/kWh`;
}

function renderAlerts(status) {
  const container = document.getElementById("alerts");
  const alerts = (status.alerts || []).slice().reverse();
  if (!alerts.length) {
    setEmpty(container, "No alerts. Silence is information too.");
    return;
  }
  clear(container);
  alerts.forEach((alert) => {
    const card = el("div", "alert " + alert.severity + (alert.open ? "" : " closed"));
    const head = el("div", "ahead");
    head.appendChild(el("span", null, `${alert.severity} · ${alert.metric} · z=${alert.z}σ`));
    head.appendChild(el("span", null, new Date(alert.ts).toLocaleTimeString()));
    card.appendChild(head);

    const message = el("div", "amsg");
    message.appendChild(el("b", null, alert.target));
    message.appendChild(document.createTextNode(" — " + alert.message));
    card.appendChild(message);

    if (alert.open) {
      const buttons = el("div", "abtns");
      const real = el("button", "btn-real", "Real failure");
      real.addEventListener("click", () => sendFeedback(alert.id, true));
      const bogus = el("button", "btn-false", "False alarm");
      bogus.addEventListener("click", () => sendFeedback(alert.id, false));
      buttons.append(real, bogus);
      card.appendChild(buttons);
    } else {
      const footer = el("div", "ahead");
      footer.style.marginTop = "6px";
      footer.appendChild(
        el("span", null, `Marked ${alert.feedback === "real" ? "real" : "false"} — threshold recalibrated`)
      );
      card.appendChild(footer);
    }
    container.appendChild(card);
  });
}

async function sendFeedback(id, real) {
  try {
    await api("/feedback", { method: "POST", body: JSON.stringify({ alert_id: id, real }) });
    poll();
  } catch (problem) {
    window.alert("Could not send feedback: " + problem.message);
  }
}

/* ───────────────────────── the ledger ────────────────────── */

let currentStatement = null;

async function renderLedger() {
  const container = document.getElementById("ledger");
  try {
    const statement = await api("/savings");
    currentStatement = statement;
    const totals = statement.totals || {};
    clear(container);

    if (statement.mode === "advisory") {
      const note = el(
        "div",
        "empty",
        "Advisory mode: these savings are measured and shown, but nothing is billed until execution is enabled."
      );
      note.style.color = "var(--warn)";
      container.appendChild(note);
    }

    const rows = [
      ["Month", statement.month, ""],
      ["Sealed days", String((statement.days || []).length), ""],
      ["Gross measured savings", eur(totals.gross_net_saving_micro_eur), ""],
      ["Billable after corroboration", eur(totals.billable_net_saving_micro_eur), ""],
      ["Operator fee (" + (statement.fee_bp || 0) / 100 + "%)", eur(totals.fee_micro_eur), "total"],
      ["You keep", eur(totals.client_keeps_micro_eur), "keep"],
    ];
    rows.forEach(([label, value, kind]) => {
      const row = el("div", "stat-row" + (kind ? " " + kind : ""));
      row.appendChild(el("span", null, label));
      row.appendChild(el("span", "v", value));
      container.appendChild(row);
    });

    const corroboration = statement.corroboration || {};
    const verdictRow = el("div", "stat-row");
    verdictRow.appendChild(el("span", null, "Corroboration"));
    const verdictWrap = el("span");
    verdictWrap.appendChild(el("span", "verdict " + (corroboration.verdict || ""), corroboration.verdict || "—"));
    verdictRow.appendChild(verdictWrap);
    container.appendChild(verdictRow);

    if (corroboration.claimed_wh) {
      const ratio = (corroboration.billable_wh / corroboration.claimed_wh) * 100;
      container.appendChild(
        el(
          "div",
          "small muted",
          `${ratio.toFixed(1)}% of claimed energy was witnessed by the hashrate telemetry ` +
            `and is therefore billable.`
        )
      );
    }
  } catch (problem) {
    setEmpty(container, "No statement available (" + problem.message + ").");
  }
}

/* ── verification, in this browser, using none of the operator's code ── */

async function verifyStatement() {
  const output = document.getElementById("verifyOutput");
  const summary = document.getElementById("verifySummary");
  clear(output);
  summary.className = "hidden";

  if (!currentStatement) {
    setEmpty(output, "Load a statement first.");
    return;
  }
  const statement = currentStatement;
  const failures = [];
  const notes = [];

  function check(ok, label, why) {
    const row = el("div", "check " + (ok ? "pass" : "fail"));
    row.appendChild(el("span", "mark", ok ? "OK" : "XX"));
    const body = el("div");
    body.appendChild(el("div", null, label));
    if (why) body.appendChild(el("div", "why", why));
    row.appendChild(body);
    output.appendChild(row);
    if (!ok) failures.push(label);
    return ok;
  }
  function note(text) {
    const row = el("div", "check note");
    row.appendChild(el("span", "mark", "--"));
    row.appendChild(el("div", null, text));
    output.appendChild(row);
    notes.push(text);
  }

  check(statement.spec === SPEC, "The statement uses a spec version this console knows");

  // 1. The seals chain, day to day. A statement covers one month, so its first
  //    day usually chains to a seal from the month before: a real link, but not
  //    checkable from this document alone.
  const genesis = toHex(await GENESIS_PROMISE);
  let expectedPrev = null;
  const days = statement.days || [];
  for (const day of days) {
    const prev = fromHex(day.prev_seal);
    const root = fromHex(day.merkle_root);
    if (!check(!!prev && !!root, `${day.day}: seal carries well-formed digests`)) continue;
    const computed = toHex(await sha256d(concat(prev, root)));
    check(
      computed === day.seal_hash,
      `${day.day}: seal_hash = SHA256d(prev_seal ‖ merkle_root)`,
      "the same construction that chains Bitcoin block headers"
    );
    if (expectedPrev === null) {
      if (day.prev_seal === genesis) {
        check(true, `${day.day}: chains to the genesis seal`);
      } else {
        note(
          `${day.day} chains to a seal from before this statement. That link is real, but to ` +
            "follow the chain back further you need the previous month's statement."
        );
      }
    } else {
      check(
        day.prev_seal === expectedPrev,
        `${day.day}: chains to the previous sealed day`,
        "a day inserted, removed or reordered would break this link"
      );
    }
    expectedPrev = day.seal_hash;
  }
  if (!days.length) note("No sealed days in this month yet — nothing to verify.");

  // 2. Every sampled record really is inside the day it claims.
  const roots = {};
  const counts = {};
  days.forEach((day) => {
    roots[day.day] = fromHex(day.merkle_root);
    counts[day.day] = Number(day.leaf_count);
  });
  for (const item of statement.proofs || []) {
    let leaf = null;
    try {
      leaf = await recordHash(item.record);
    } catch (problem) {
      check(false, `seq ${item.record && item.record.seq}: record is canonically encodable`, problem.message);
      continue;
    }
    if (!check(toHex(leaf) === item.leaf, `seq ${item.record.seq}: record hashes to its stated leaf`)) {
      continue;
    }
    // A tree whose last leaf is duplicated shares its root (CVE-2012-2459), so
    // the proof must also claim the size the seal committed to.
    if (
      !check(
        Number(item.proof.leaf_count) === counts[item.day],
        `seq ${item.record.seq}: proof describes the tree size the seal committed to`,
        `proof says ${item.proof.leaf_count} records, the seal says ${counts[item.day]}`
      )
    ) {
      continue;
    }
    const ok = await verifyInclusion(leaf, item.proof, roots[item.day]);
    check(
      ok,
      `seq ${item.record.seq} (${item.day}): proven to sit under that day's sealed root`,
      `${item.proof.path.length} hashes of audit path against ${item.proof.leaf_count} records`
    );
  }
  if (!(statement.proofs || []).length) note("This statement carries no inclusion proofs to sample.");

  // 3. The money. Integers only, so this is exact.
  const totals = statement.totals || {};
  const billable = Number(totals.billable_net_saving_micro_eur || 0);
  const fee = Number(totals.fee_micro_eur || 0);
  const keeps = Number(totals.client_keeps_micro_eur || 0);
  const feeBp = Number(statement.fee_bp || 0);
  const expectedFee = billable > 0 ? Math.floor((billable * feeBp) / 10000) : 0;
  check(fee === expectedFee, `The fee is exactly ${feeBp / 100}% of billable savings, rounded down`);
  check(fee + keeps === billable, "Fee plus what you keep equals billable savings, to the micro-euro");
  check(billable > 0 || fee === 0, "A month that did not save money is not billed");

  const corroboration = statement.corroboration || {};
  check(
    Number(corroboration.billable_wh || 0) <= Number(corroboration.corroborated_wh || 0),
    "No line bills more energy than the hashrate telemetry witnessed"
  );
  if (corroboration.verdict === "OVERCLAIMED" || corroboration.verdict === "UNCORROBORATED") {
    note(
      `Corroboration verdict is ${corroboration.verdict}: the ledger claimed savings the telemetry ` +
        "does not support. The cap was applied and you were not charged for them, but ask what happened."
    );
  }

  // 4. Signatures. Ed25519 verification needs a library this page does not load,
  //    so say so rather than implying a check that did not happen.
  const device = statement.device || {};
  if (device.verifiable_by_third_party) {
    note(
      `Seals are ed25519-signed by device ${device.device_id}. This page checks structure and ` +
        "arithmetic; run tools/hashguard_verify.py to also check the signatures."
    );
  } else {
    note(
      "Seals are HMAC-signed, which only a holder of the shared secret can check. " +
        "Install 'cryptography' on the agent for ed25519 keys that a third party can audit."
    );
  }

  summary.className = "verify-summary " + (failures.length ? "bad" : "ok");
  clear(summary);
  if (failures.length) {
    summary.appendChild(
      el("b", null, `${failures.length} check${failures.length > 1 ? "s" : ""} failed.`)
    );
    summary.appendChild(
      document.createTextNode(
        " Do not pay this statement until it is explained. Nothing above was computed by the " +
          "operator: your browser re-derived every hash from the statement itself."
      )
    );
  } else {
    summary.appendChild(el("b", null, "Every check passed."));
    summary.appendChild(
      document.createTextNode(
        " Your browser re-derived every hash in this statement using WebCrypto and none of the " +
          "operator's code. For the full check against the raw records, run tools/hashguard_verify.py."
      )
    );
  }
}

/* ───────────────────────── calibration ───────────────────── */

const CAL_FIELDS = [
  {
    section: "Detection engine",
    items: [
      { path: "qtmp.z_alert", label: "Alert threshold (σ, farm-wide rate)", min: 1.5, max: 6, step: 0.1 },
      { path: "qtmp.z_critical", label: "Critical threshold (σ)", min: 2, max: 8, step: 0.1 },
      { path: "qtmp.persistence", label: "Consecutive polls before alerting", min: 1, max: 20, step: 1 },
      { path: "qtmp.min_samples", label: "Samples before a board is judged", min: 3, max: 240, step: 1 },
      { path: "qtmp.fan_temp_alert", label: "Fan effort vs temperature (σ)", min: 1, max: 5, step: 0.1 },
    ],
  },
  {
    section: "Curtailment",
    items: [
      { path: "curtailment.hashrate_th", label: "Hashrate per machine (TH/s)", min: 1, max: 1000, step: 1 },
      { path: "curtailment.power_kw", label: "Power per machine (kW)", min: 0.1, max: 20, step: 0.05 },
      { path: "curtailment.hashprice_usd_th_day", label: "Hashprice ($/TH/day)", min: 0.001, max: 1, step: 0.001 },
      { path: "curtailment.fixed_price_eur_kwh", label: "Fixed price (€/kWh)", min: 0, max: 2, step: 0.005 },
      { path: "curtailment.network_cost_eur_kwh", label: "Grid fees (€/kWh)", min: 0, max: 1, step: 0.005 },
      { path: "curtailment.margin", label: "Margin required over break-even", min: 0, max: 0.5, step: 0.01 },
    ],
  },
  {
    section: "Feedback loop",
    items: [{ path: "adaptive.target_precision", label: "Target alert precision", min: 0.3, max: 0.95, step: 0.05 }],
  },
];

function getPath(object, path) {
  return path.split(".").reduce((node, key) => (node == null ? undefined : node[key]), object);
}

function decimals(step) {
  const parts = String(step).split(".");
  return parts.length > 1 ? parts[1].length : 0;
}

async function renderCalibration(status) {
  if (calibrationBuilt) return;
  const body = document.getElementById("calBody");
  let config;
  try {
    config = await api("/config");
  } catch (problem) {
    setEmpty(body, "Could not read the agent's configuration (" + problem.message + ").");
    return;
  }
  calibrationBuilt = true;
  clear(body);
  const writable = new Set(config._writable_from_console || []);

  CAL_FIELDS.forEach((group) => {
    const items = group.items.filter((item) => writable.has(item.path));
    if (!items.length) return;
    const wrap = el("div", "cal-section");
    wrap.appendChild(el("h3", null, group.section));
    items.forEach((field) => {
      const current = getPath(config, field.path);
      const value = current === undefined ? field.min : Number(current);
      calState[field.path] = value;

      const row = el("div", "cal-row");
      const left = el("div");
      left.appendChild(el("label", null, field.label));
      const slider = document.createElement("input");
      slider.type = "range";
      slider.min = field.min;
      slider.max = field.max;
      slider.step = field.step;
      slider.value = value;
      slider.setAttribute("aria-label", field.label);
      const readout = el("div", "val", value.toFixed(decimals(field.step)));
      slider.addEventListener("input", () => {
        calState[field.path] = parseFloat(slider.value);
        readout.textContent = parseFloat(slider.value).toFixed(decimals(field.step));
      });
      left.appendChild(slider);
      row.append(left, readout);
      wrap.appendChild(row);
    });
    body.appendChild(wrap);
  });

  const advertised = el(
    "div",
    "small muted",
    "The agent decides what is settable from here. Tokens, price sources, relay " +
      "addresses, file paths and the fee are not on that list: they are changed by " +
      "editing config.json on the farm machine."
  );
  advertised.style.marginTop = "14px";
  body.appendChild(advertised);
}

async function saveCalibration() {
  const patch = {};
  Object.entries(calState).forEach(([path, value]) => {
    const [head, tail] = path.split(".");
    patch[head] = patch[head] || {};
    patch[head][tail] = value;
  });
  const message = document.getElementById("saveMsg");
  try {
    const result = await api("/config", { method: "POST", body: JSON.stringify(patch) });
    if (result.rejected && result.rejected.length) {
      message.style.color = "var(--warn)";
      message.textContent = `Applied ${result.applied.length}; refused: ${result.rejected.join("; ")}`;
    } else {
      message.style.color = "var(--ok)";
      message.textContent = `Saved to the agent (${result.applied.length} settings).`;
      setTimeout(() => (message.textContent = ""), 4000);
    }
    poll();
  } catch (problem) {
    message.style.color = "var(--bad)";
    message.textContent = "Save failed: " + problem.message;
  }
}

/* ───────────────────────── wiring ────────────────────────── */

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btnConnection").addEventListener("click", openSettings);
  document.getElementById("btnSignOut").addEventListener("click", signOut);
  document.getElementById("btnCancel").addEventListener("click", closeSettings);
  document.getElementById("btnConnect").addEventListener("click", connect);
  document.getElementById("btnVerify").addEventListener("click", verifyStatement);
  document.getElementById("btnSaveCal").addEventListener("click", saveCalibration);
  document.getElementById("agentTok").addEventListener("keydown", (event) => {
    if (event.key === "Enter") connect();
  });

  if (AGENT && TOKEN) {
    closeSettings();
    start();
  } else {
    openSettings();
  }
});

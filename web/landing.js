/* The hero simulation on the landing page.
 *
 * A five-machine farm on a synthetic price curve: it pauses when the hour costs
 * more than it earns, and one board drifts away from its siblings until the
 * engine notices. Everything shown is computed here in the page; nothing is
 * fetched, and there is no real farm behind it.
 *
 * In its own file so the page needs no inline script and can keep script-src 'self'.
 */

"use strict";

const BREAKEVEN = 0.098;
const MINERS = 5;
const BOARDS = 3;
const KW = 3.05;
const TH = 100;
const HASHPRICE = 0.045;
const EURUSD = 1.08;

const prices = Array.from({ length: 24 }, (_, hour) =>
  Number(
    (
      0.07 +
      0.055 * Math.sin(((hour - 4) / 24) * 2 * Math.PI + 1.2) +
      0.04 * Math.max(0, Math.sin((hour - 19) / 3))
    ).toFixed(3)
  )
);

let hour = 0;
let tick = 0;
let saved = 0;
let sealedRecords = 0;

const hashrates = Array.from({ length: MINERS }, () =>
  Array.from({ length: BOARDS }, () => 100 + Math.random() * 4 - 2)
);

const rackEl = document.getElementById("simRack");
const cells = [];
for (let m = 0; m < MINERS; m++) {
  const column = document.createElement("div");
  column.className = "sm";
  for (let b = 0; b < BOARDS; b++) {
    const cell = document.createElement("div");
    cell.className = "sb";
    column.appendChild(cell);
    cells.push(cell);
  }
  rackEl.appendChild(column);
}

const priceEl = document.getElementById("simPrices");
const maxPrice = Math.max(...prices);
const bars = prices.map((price) => {
  const bar = document.createElement("div");
  bar.className = "sp " + (price > BREAKEVEN ? "exp" : "cheap");
  bar.style.height = Math.max(4, (price / maxPrice) * 64) + "px";
  priceEl.appendChild(bar);
  return bar;
});
const breakevenLine = document.createElement("div");
breakevenLine.id = "simBe";
breakevenLine.style.bottom = (BREAKEVEN / maxPrice) * 64 + "px";
priceEl.appendChild(breakevenLine);

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

function step() {
  tick++;
  if (tick % 3 === 0) hour = (hour + 1) % 24;
  const price = prices[hour];
  const paused = price > BREAKEVEN;

  const flat = [];
  hashrates.forEach((machine, mi) =>
    machine.forEach((value, bi) => {
      let next = value + (Math.random() - 0.5) * 1.6;
      if (mi === 3 && bi === 1) next -= 0.05;
      hashrates[mi][bi] = next;
      flat.push(next);
    })
  );

  const med = median(flat);
  const mad = median(flat.map((v) => Math.abs(v - med))) * 1.4826 || 1;
  let alerted = false;
  cells.forEach((cell, index) => {
    const z = (flat[index] - med) / mad;
    cell.style.opacity = paused ? 0.35 : 1;
    cell.style.background = z < -4 ? "#E4573D" : z < -2.5 ? "#F2A33C" : "#4CB782";
    if (z < -3.5) alerted = true;
  });

  document.getElementById("simAlert").textContent = alerted
    ? "⚠  machine 04, board 2 is drifting below its siblings — degradation, weeks before it fails"
    : "";

  const badge = document.getElementById("simBadge");
  badge.className = paused ? "pause" : "mine";
  badge.textContent = paused ? "PAUSED — the hour costs more than it earns" : "MINING";

  bars.forEach((bar, index) => bar.classList.toggle("now", index === hour));

  if (paused && tick % 3 === 0) {
    const electricity = KW * MINERS * price;
    const forgone = ((TH * HASHPRICE) / EURUSD / 24) * MINERS;
    saved += Math.max(0, electricity - forgone);
    document.getElementById("simSave").textContent = "net savings: €" + saved.toFixed(2);
  }
  sealedRecords++;
  document.getElementById("simLedger").textContent =
    sealedRecords + " records sealed · chain intact";
  document.getElementById("simClock").textContent = String(hour).padStart(2, "0") + ":00";
}

step();
if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
  setInterval(step, 1400);
}

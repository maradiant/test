"use strict";

const RISK_NUM = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const RISK_COLOR = {
  LOW: getVar("--low"),
  MEDIUM: getVar("--medium"),
  HIGH: getVar("--high"),
  CRITICAL: getVar("--critical"),
};

function getVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#5b8cff";
}

const els = {
  scenario: document.getElementById("scenario"),
  scenarioDesc: document.getElementById("scenario-desc"),
  ticks: document.getElementById("ticks"),
  ticksVal: document.getElementById("ticks-val"),
  seed: document.getElementById("seed"),
  council: document.getElementById("council"),
  councilBanner: document.getElementById("council-banner"),
  councilCol: document.getElementById("council-col"),
  runBtn: document.getElementById("run-btn"),
  results: document.getElementById("results"),
  error: document.getElementById("error"),
  chart: document.getElementById("chart"),
  timelineBody: document.querySelector("#timeline tbody"),
  audit: document.getElementById("audit"),
  toggleAudit: document.getElementById("toggle-audit"),
  sSession: document.getElementById("s-session"),
  sScenario: document.getElementById("s-scenario"),
  sTicks: document.getElementById("s-ticks"),
  sPeak: document.getElementById("s-peak"),
  sRotations: document.getElementById("s-rotations"),
  sQuarantine: document.getElementById("s-quarantine"),
};

let scenarios = [];

async function loadScenarios() {
  const res = await fetch("/api/scenarios");
  const data = await res.json();
  scenarios = data.scenarios;
  els.scenario.innerHTML = scenarios
    .map((s) => `<option value="${s.name}">${s.name}</option>`)
    .join("");
  updateScenarioDesc();
}

function updateScenarioDesc() {
  const found = scenarios.find((s) => s.name === els.scenario.value);
  els.scenarioDesc.textContent = found ? found.description : "";
}

els.scenario.addEventListener("change", updateScenarioDesc);
els.ticks.addEventListener("input", () => {
  els.ticksVal.textContent = els.ticks.value;
});

els.toggleAudit.addEventListener("click", () => {
  const hidden = els.audit.classList.toggle("hidden");
  els.toggleAudit.textContent = hidden ? "Show raw audit JSON" : "Hide raw audit JSON";
});

els.runBtn.addEventListener("click", runSimulation);

async function runSimulation() {
  els.runBtn.disabled = true;
  els.runBtn.textContent = "Running…";
  els.error.classList.add("hidden");
  try {
    const body = {
      scenario: els.scenario.value,
      ticks: parseInt(els.ticks.value, 10),
      seed: els.seed.value === "" ? null : parseInt(els.seed.value, 10),
      council: els.council.checked,
    };
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Simulation failed");
    render(data);
  } catch (err) {
    els.error.textContent = "Error: " + err.message;
    els.error.classList.remove("hidden");
  } finally {
    els.runBtn.disabled = false;
    els.runBtn.textContent = "▶ Run simulation";
  }
}

function render(data) {
  els.results.classList.remove("hidden");
  const decisions = data.decisions;

  const peak = decisions.reduce(
    (acc, d) => (RISK_NUM[d.risk_level] > RISK_NUM[acc] ? d.risk_level : acc),
    "LOW"
  );
  const rotations = decisions.filter((d) => d.rotated).length;
  const quarantined = decisions.some((d) => d.quarantined);

  els.sSession.textContent = data.session_id;
  els.sScenario.textContent = data.scenario;
  els.sTicks.textContent = data.ticks;
  els.sPeak.innerHTML = badge(peak);
  els.sRotations.textContent = rotations;
  els.sQuarantine.innerHTML = quarantined
    ? `<span class="badge critical">YES</span>`
    : `<span class="badge low">NO</span>`;

  renderCouncilBanner(data);
  drawChart(decisions);
  drawTimeline(decisions, !!data.council);
  els.audit.textContent = JSON.stringify(data.audit, null, 2);
}

function renderCouncilBanner(data) {
  const on = !!data.council;
  els.councilCol.classList.toggle("hidden", !on);
  if (!on) {
    els.councilBanner.classList.add("hidden");
    return;
  }
  const decisions = data.decisions;
  const reviews = decisions.filter((d) => d.council && d.council.human_review_required).length;
  const guardrails = new Set();
  decisions.forEach((d) => (d.council?.triggered_guardrails || []).forEach((g) => guardrails.add(g)));
  const advisors = (decisions[0] && decisions[0].council && decisions[0].council.advisors) || [];
  const chips = advisors
    .map((a) => `<span class="chip">${a.name}: ${a.risk_level}${a.requires_quarantine ? " ⚠Q" : ""}</span>`)
    .join("");
  els.councilBanner.innerHTML = `
    <h3>Multi-model security council active — LLMs advise, MARVIN governs</h3>
    <div>Independent advisors review identical telemetry; a deterministic governance
    engine makes every final decision. Ticks flagged for human review:
    <strong class="${reviews ? "review-flag" : ""}">${reviews}</strong>.
    Guardrails triggered: <strong>${[...guardrails].join(", ") || "none"}</strong>.</div>
    <div class="advisor-chips">${chips}</div>`;
  els.councilBanner.classList.remove("hidden");
}

function badge(level) {
  return `<span class="badge ${level.toLowerCase()}">${level}</span>`;
}

function drawChart(decisions) {
  const W = 1000;
  const H = 240;
  const padL = 44;
  const padR = 20;
  const padT = 16;
  const padB = 28;
  const innerW = W - padL - padR;
  const innerH = H - padT - padB;
  const n = decisions.length;

  const x = (i) => padL + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW);
  const y = (score) => padT + innerH - score * innerH;

  let gridlines = "";
  for (let g = 0; g <= 4; g++) {
    const gy = padT + innerH - (g / 4) * innerH;
    gridlines += `<line x1="${padL}" y1="${gy}" x2="${W - padR}" y2="${gy}" stroke="#283357" stroke-width="1"/>`;
    gridlines += `<text x="${padL - 8}" y="${gy + 4}" fill="#8b96b8" font-size="10" text-anchor="end">${(g / 4).toFixed(2)}</text>`;
  }

  const linePts = decisions.map((d, i) => `${x(i)},${y(d.risk_score)}`).join(" ");
  const areaPts = `${padL},${padT + innerH} ${linePts} ${x(n - 1)},${padT + innerH}`;

  const dots = decisions
    .map((d, i) => {
      const color = RISK_COLOR[d.risk_level] || "#5b8cff";
      const r = d.quarantined ? 6 : 4;
      return `<circle cx="${x(i)}" cy="${y(d.risk_score)}" r="${r}" fill="${color}" stroke="#0b1020" stroke-width="1.5">
        <title>tick ${d.tick} — ${d.risk_level} (${d.risk_score.toFixed(2)})</title>
      </circle>`;
    })
    .join("");

  const xlabels = decisions
    .map((d, i) =>
      n <= 20 || i % Math.ceil(n / 20) === 0
        ? `<text x="${x(i)}" y="${H - 8}" fill="#8b96b8" font-size="10" text-anchor="middle">${d.tick}</text>`
        : ""
    )
    .join("");

  els.chart.innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
      <defs>
        <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#5b8cff" stop-opacity="0.35"/>
          <stop offset="100%" stop-color="#5b8cff" stop-opacity="0"/>
        </linearGradient>
      </defs>
      ${gridlines}
      <polygon points="${areaPts}" fill="url(#areaGrad)"/>
      <polyline points="${linePts}" fill="none" stroke="#5b8cff" stroke-width="2.5" stroke-linejoin="round"/>
      ${dots}
      ${xlabels}
    </svg>`;
}

function drawTimeline(decisions, withCouncil) {
  els.timelineBody.innerHTML = "";
  const colspan = withCouncil ? 8 : 7;
  decisions.forEach((d) => {
    const tr = document.createElement("tr");
    const keyClass =
      d.key_action === "quarantine"
        ? "key-quarantine"
        : d.key_action === "rotate"
        ? "key-rotate"
        : "key-hold";
    const councilCell = withCouncil
      ? `<td class="council-cell">${councilSummaryText(d.council)}</td>`
      : "";
    tr.innerHTML = `
      <td>${d.tick}</td>
      <td>${badge(d.risk_level)}</td>
      <td>${d.risk_score.toFixed(2)}</td>
      <td class="policy">${d.policy}</td>
      <td class="${keyClass}">${d.key_action}</td>
      ${councilCell}
      <td>${d.next_action}</td>
      <td><button class="expand-btn" title="Explain">+</button></td>`;
    const detail = document.createElement("tr");
    detail.className = "detail hidden";
    detail.innerHTML = `<td colspan="${colspan}">
      <strong>Telemetry:</strong> ${escapeHtml(d.telemetry_summary)}<br/>
      <strong>Why:</strong> ${escapeHtml(d.explanation)}<br/>
      <strong>Keys:</strong> ${escapeHtml(d.key_reason)}
      ${d.active_key_id ? ` &nbsp;|&nbsp; <span class="mono">active=${d.active_key_id}</span>` : ""}
      ${d.reauth ? ` &nbsp;|&nbsp; <strong>reauth required</strong>` : ""}
      ${councilDetail(d.council)}
    </td>`;
    tr.querySelector(".expand-btn").addEventListener("click", (e) => {
      const open = detail.classList.toggle("hidden");
      e.target.textContent = open ? "+" : "−";
    });
    els.timelineBody.appendChild(tr);
    els.timelineBody.appendChild(detail);
  });
}

function councilSummaryText(council) {
  if (!council) return "-";
  const votes = council.risk_level_votes || {};
  const v = Object.entries(votes)
    .map(([k, n]) => `${k.slice(0, 4)}:${n}`)
    .join(" ");
  const flags = [];
  if (council.quarantine_votes) flags.push(`Q${council.quarantine_votes}`);
  if (council.human_review_required) flags.push("REVIEW");
  return `${v}${flags.length ? " " + flags.join(" ") : ""}`;
}

function councilDetail(council) {
  if (!council) return "";
  const advisors = (council.advisors || [])
    .map(
      (a) =>
        `${a.name}=${a.risk_level}${a.requires_quarantine ? "(Q)" : ""}@${a.confidence}`
    )
    .join(", ");
  const guardrails = (council.triggered_guardrails || []).join(", ") || "none";
  return `<br/><strong>Council:</strong> ${escapeHtml(advisors)}
    &nbsp;|&nbsp; guardrails: ${escapeHtml(guardrails)}
    &nbsp;|&nbsp; severity: ${escapeHtml(council.audit_severity || "-")}`;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

loadScenarios();

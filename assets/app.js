"use strict";

const state = { data: null, view: "overview", selected: null };
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatUtc(value, seconds = false) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value || "—");
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "UTC",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: seconds ? "2-digit" : undefined,
    hour12: false,
  }).format(date).replace(",", "");
}

function badge(value) {
  const labels = { high: "High", medium: "Medium", true_positive: "악성" };
  return `<span class="badge ${escapeHtml(value)}">${escapeHtml(labels[value] || value)}</span>`;
}

function incidentRow(item, compact = false) {
  const name = `<div class="incident-name"><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.id)} · Sigma Alert ${item.alert_count}개</small></div>`;
  if (compact) {
    return `<tr data-incident="${escapeHtml(item.id)}"><td>${name}</td><td class="host">${escapeHtml(item.host)}</td><td>${formatUtc(item.timestamp)}</td><td>${badge(item.severity)}</td><td>${badge(item.verdict)}</td><td><button class="row-button" type="button" aria-label="사건 열기">＋</button></td></tr>`;
  }
  return `<tr data-incident="${escapeHtml(item.id)}"><td>${badge(item.severity)}</td><td>${name}</td><td class="host">${escapeHtml(item.host)}</td><td>${formatUtc(item.timestamp)}</td><td>${item.alert_count}개</td><td>${badge(item.verdict)}</td><td><button class="row-button" type="button" aria-label="사건 열기">＋</button></td></tr>`;
}

function bindIncidentRows(root) {
  $$('[data-incident]', root).forEach((row) => row.addEventListener("click", () => openIncident(row.dataset.incident)));
}

function renderOverview() {
  const meta = state.data.meta;
  $("#metricAlerts").textContent = meta.raw_alerts;
  $("#metricIncidents").textContent = meta.malicious_incidents;
  $("#metricHosts").textContent = 1;
  $("#metricCoverage").textContent = `${Math.round(meta.evidence_process_coverage * 100)}%`;
  $("#navAlertCount").textContent = meta.raw_alerts;
  const ordered = [...state.data.incidents].sort((left, right) => new Date(left.timestamp) - new Date(right.timestamp));
  const maxRisk = Math.max(...ordered.map((item) => item.risk_score));
  $("#flowChart").innerHTML = ordered.map((item) => {
    const height = Math.max(28, Math.round((item.risk_score / maxRisk) * 165));
    return `<button class="flow-column" type="button" data-incident="${escapeHtml(item.id)}" title="${escapeHtml(item.title)} · Risk ${item.risk_score}"><span class="flow-bar-wrap"><i class="flow-bar" style="height:${height}px"></i></span><span class="flow-time">${escapeHtml(formatUtc(item.timestamp).slice(-5))}</span></button>`;
  }).join("");
  bindIncidentRows($("#flowChart"));
  const recent = [...ordered].reverse();
  $("#recentTable").innerHTML = recent.map((item) => incidentRow(item, true)).join("");
  bindIncidentRows($("#recentTable"));
}

function renderIncidents() {
  const query = $("#alertSearch").value.trim().toLowerCase();
  const severity = $("#severityFilter").value;
  const filtered = state.data.incidents.filter((item) => {
    const text = `${item.id} ${item.title} ${item.host} ${item.summary} ${item.rules.join(" ")}`.toLowerCase();
    return (!query || text.includes(query)) && (severity === "all" || item.severity === severity);
  });
  $("#incidentCount").textContent = filtered.length;
  $("#incidentTable").innerHTML = filtered.map((item) => incidentRow(item)).join("");
  $("#alertEmpty").classList.toggle("hidden", filtered.length > 0);
  bindIncidentRows($("#incidentTable"));
}

function evidenceItems() {
  return state.data.incidents.flatMap((incident) => incident.timeline.map((event) => ({
    ...event,
    incident_id: incident.id,
    host: incident.host,
  }))).sort((left, right) => new Date(left.timestamp) - new Date(right.timestamp));
}

function renderEvidence() {
  const query = $("#evidenceSearch").value.trim().toLowerCase();
  const filtered = evidenceItems().filter((item) => `${item.event_code} ${item.title} ${item.detail} ${item.incident_id}`.toLowerCase().includes(query));
  $("#evidenceCount").textContent = `${filtered.length}개 이벤트`;
  $("#evidenceList").innerHTML = filtered.length ? filtered.map((item) => `<button class="evidence-row" type="button" data-incident="${escapeHtml(item.incident_id)}"><time class="evidence-time">${escapeHtml(formatUtc(item.timestamp, true))} UTC</time><span class="event-code">Event ${escapeHtml(item.event_code)}</span><span class="evidence-detail"><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.detail)}</small></span></button>`).join("") : `<div class="empty-state">조건에 맞는 증거 이벤트가 없습니다.</div>`;
  bindIncidentRows($("#evidenceList"));
}

function showView(name, updateHash = true) {
  const valid = ["overview", "alerts", "evidence", "about"];
  state.view = valid.includes(name) ? name : "overview";
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `${state.view}View`));
  $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === state.view));
  $("#sidebar").classList.remove("open");
  if (state.view === "alerts") renderIncidents();
  if (state.view === "evidence") renderEvidence();
  if (updateHash) history.replaceState(null, "", `#${state.view}`);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function listSection(title, items) {
  if (!items?.length) return "";
  return `<section class="detail-section"><h3>${escapeHtml(title)}</h3><ul class="detail-list">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></section>`;
}

function openIncident(id) {
  const item = state.data.incidents.find((incident) => incident.id === id);
  if (!item) return;
  state.selected = item;
  $("#drawerId").textContent = item.id;
  $("#drawerTitle").textContent = item.title;
  const timeline = item.timeline.map((event) => `<div class="timeline-item"><span class="timeline-dot"></span><div class="timeline-card"><time>${escapeHtml(formatUtc(event.timestamp, true))} UTC · Event ${escapeHtml(event.event_code)}</time><strong>${escapeHtml(event.title)}</strong><small>${escapeHtml(event.detail)}</small></div></div>`).join("");
  $("#drawerContent").innerHTML = `
    <section class="incident-hero">
      <div class="incident-hero-top"><div>${badge(item.verdict)}<h3>${escapeHtml(item.summary)}</h3><p>Sigma Alert ${item.alert_count}개와 정적 증거 타임라인을 바탕으로 구성된 SET01 조사 결과입니다.</p></div><div class="risk"><span><strong>${item.risk_score}</strong><small>RISK SCORE</small></span></div></div>
      <div class="incident-meta"><div><span>호스트</span><strong>${escapeHtml(item.host)}</strong></div><div><span>발생 시각</span><strong>${escapeHtml(formatUtc(item.timestamp, true))} UTC</strong></div><div><span>원본 Alert</span><strong>${item.alert_count}개</strong></div></div>
    </section>
    <section class="detail-section"><h3>탐지 정보</h3><div class="tag-list">${[...item.rules, ...item.techniques].map((value) => `<span class="tag">${escapeHtml(value)}</span>`).join("")}</div></section>
    <section class="detail-section"><h3>관련 로그 타임라인</h3><div class="timeline">${timeline}</div></section>
    ${listSection("확인된 근거", item.findings)}
    ${listSection("분석 한계", item.limitations)}
    ${listSection("권고 대응", item.recommendations)}
    <section class="detail-section"><div class="drawer-actions"><button id="downloadReport" class="download-button" type="button"><svg><use href="#i-download"/></svg>HTML 보고서 내보내기</button></div></section>`;
  $("#downloadReport").addEventListener("click", () => downloadReport(item));
  $("#drawerBackdrop").classList.remove("hidden");
  $("#incidentDrawer").classList.remove("hidden");
  $("#incidentDrawer").setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
}

function closeDrawer() {
  $("#drawerBackdrop").classList.add("hidden");
  $("#incidentDrawer").classList.add("hidden");
  $("#incidentDrawer").setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
  state.selected = null;
}

function reportList(title, values) {
  return `<section><h2>${escapeHtml(title)}</h2><ul>${values.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></section>`;
}

function reportHtml(item) {
  const timeline = item.timeline.map((event) => `<li><time>${escapeHtml(formatUtc(event.timestamp, true))} UTC · Event ${escapeHtml(event.event_code)}</time><strong>${escapeHtml(event.title)}</strong><p>${escapeHtml(event.detail)}</p></li>`).join("");
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(item.id)} IRIS 보고서</title><style>body{margin:0;background:#eef2f2;color:#182328;font-family:Arial,sans-serif;line-height:1.7}main{width:min(980px,calc(100% - 32px));margin:30px auto;padding:42px;background:white;border:1px solid #d9e2e3}header{padding-bottom:22px;border-bottom:2px solid #173e42}h1{margin:0 0 12px;font-size:28px}h2{margin:36px 0 14px;padding-bottom:8px;border-bottom:1px solid #dde4e5;font-size:18px}.meta{color:#63747b;font-size:13px}.verdict{display:inline-block;margin-top:14px;padding:5px 10px;color:#9f2f39;background:#f7e8ea;border-radius:99px;font-weight:bold}ul{padding-left:22px}.timeline{display:grid;gap:10px;list-style:none;padding:0}.timeline li{padding:14px;background:#f6f8f8;border:1px solid #e0e7e8}.timeline time,.timeline strong{display:block}.timeline time{color:#718087;font-family:Consolas,monospace;font-size:12px}.timeline strong{margin-top:5px}.timeline p{margin:5px 0 0;color:#52636a}footer{margin-top:36px;padding-top:14px;border-top:1px solid #dde4e5;color:#718087;font-size:12px}@media(max-width:650px){main{width:100%;margin:0;padding:26px 18px;border:0}}</style></head><body><main><header><h1>${escapeHtml(item.title)}</h1><div class="meta">${escapeHtml(item.id)} · ${escapeHtml(item.host)} · ${escapeHtml(formatUtc(item.timestamp, true))} UTC</div><span class="verdict">AI 악성 판정 · Risk ${item.risk_score}</span></header><section><h2>요약</h2><p>${escapeHtml(item.summary)}</p></section><section><h2>관련 로그 타임라인</h2><ol class="timeline">${timeline}</ol></section>${reportList("확인된 근거", item.findings)}${reportList("분석 한계", item.limitations)}${reportList("권고 대응", item.recommendations)}<footer>IRIS static demo · SET01 · DEDALE dataset 기반 비식별 예시</footer></main></body></html>`;
}

function downloadReport(item) {
  const blob = new Blob([reportHtml(item)], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${item.id}.html`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  toast("HTML 보고서를 생성했습니다.");
}

function toast(message) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.remove("hidden");
  clearTimeout(element._timer);
  element._timer = setTimeout(() => element.classList.add("hidden"), 2600);
}

function bindEvents() {
  $$("[data-view]").forEach((element) => element.addEventListener("click", () => showView(element.dataset.view)));
  $("#alertSearch").addEventListener("input", renderIncidents);
  $("#severityFilter").addEventListener("change", renderIncidents);
  $("#evidenceSearch").addEventListener("input", renderEvidence);
  $("#globalSearch").addEventListener("input", (event) => {
    $("#alertSearch").value = event.target.value;
    showView("alerts");
  });
  $("#menuButton").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  $("#drawerClose").addEventListener("click", closeDrawer);
  $("#drawerBackdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeDrawer(); });
  window.addEventListener("hashchange", () => showView(location.hash.slice(1), false));
}

async function initialize() {
  bindEvents();
  try {
    const response = await fetch("data/set01.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    state.data = await response.json();
    renderOverview();
    renderIncidents();
    renderEvidence();
    showView(location.hash.slice(1) || "overview", false);
  } catch (error) {
    document.querySelector("main").innerHTML = `<div class="empty-state">정적 데모 데이터를 불러오지 못했습니다: ${escapeHtml(error.message)}</div>`;
  }
}

document.addEventListener("DOMContentLoaded", initialize);


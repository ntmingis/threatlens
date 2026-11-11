/* ThreatLens UI. All server data is rendered with textContent / DOM nodes, never as HTML. */
"use strict";
const API = "/api/scanner";
const $ = (s) => document.querySelector(s);

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v; else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n;
}
async function api(path, opts) {
  const r = await fetch(API + path, opts);
  let body = null;
  try { body = await r.json(); } catch (_) { /* non-JSON */ }
  if (!r.ok) throw new Error((body && body.error && body.error.message) || `Request failed (HTTP ${r.status})`);
  return body;
}
const label = (v) => String(v).replaceAll("_", " ");
const fmtBytes = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`;
const fmtDate = (v) => new Date(typeof v === "number" ? v * 1000 : v).toLocaleString();

/* ---------- tabs ---------- */
const tabs = [...document.querySelectorAll("[role=tab]")];
function show(name) {
  for (const t of tabs) {
    const on = t.dataset.tab === name;
    t.setAttribute("aria-selected", on); t.tabIndex = on ? 0 : -1;
    $("#panel-" + t.dataset.tab).hidden = !on;
  }
  $("#report").hidden = true;
  if (name === "history") loadHistory();
}
tabs.forEach((t, i) => {
  t.addEventListener("click", () => show(t.dataset.tab));
  t.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const n = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    n.focus(); show(n.dataset.tab);
  });
});

/* ---------- capabilities ---------- */
async function loadCaps() {
  const ul = $("#caps");
  try {
    const c = await api("/capabilities");
    $("#maxmb").textContent = c.max_upload_mb;
    const av = c.engines.clamav.status;
    const items = [
      ["ClamAV: " + label(av), av === "READY" ? "ok" : "warn"],
      ["PDF / Office / ZIP analysis: ready", "ok"],
      ["VirusTotal: " + label(c.providers.virustotal), c.providers.virustotal === "CONFIGURED" ? "ok" : "off"],
      ["Safe Browsing: " + label(c.providers.google_safe_browsing), c.providers.google_safe_browsing === "CONFIGURED" ? "ok" : "off"],
      ["URL fetch: off by design", "off"],
    ];
    ul.replaceChildren(...items.map(([t, k]) => el("li", {}, el("span", { class: "dot " + k }), t)));
  } catch (e) { ul.replaceChildren(el("li", { class: "err", text: "Backend is not reachable: " + e.message })); }
}

/* ---------- file scan ---------- */
const drop = $("#drop"), fileInput = $("#file");
drop.addEventListener("click", () => fileInput.click());
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); } });
for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); });
for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); });
drop.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) scanFile(f); });
fileInput.addEventListener("change", () => { if (fileInput.files[0]) scanFile(fileInput.files[0]); fileInput.value = ""; });

function setStatus(name, state, pct, msg, cls) {
  $("#file-status").hidden = false;
  $("#fs-name").textContent = name;
  const s = $("#fs-state"); s.textContent = state; s.className = "pill " + (cls || "v-INCONCLUSIVE");
  const bar = $("#fs-bar"); if (pct == null) bar.removeAttribute("value"); else bar.value = pct;
  $("#fs-msg").textContent = msg || "";
}
function scanFile(file) {
  $("#report").hidden = true;
  setStatus(file.name, "UPLOADING", 0, `${fmtBytes(file.size)} · sending to the scanner`);
  const fd = new FormData(); fd.append("file", file);
  const xhr = new XMLHttpRequest();
  xhr.open("POST", API + "/files");
  xhr.upload.onprogress = (e) => { if (e.lengthComputable) setStatus(file.name, "UPLOADING", Math.round(e.loaded / e.total * 100), `${fmtBytes(e.loaded)} of ${fmtBytes(e.total)}`); };
  xhr.onerror = () => setStatus(file.name, "FAILED", 0, "Upload failed: the scanner could not be reached.", "v-MALICIOUS");
  xhr.onload = () => {
    let body = null; try { body = JSON.parse(xhr.responseText); } catch (_) { /* ignore */ }
    if (xhr.status !== 202 || !body) return setStatus(file.name, "REJECTED", 0, (body && body.error && body.error.message) || `Upload rejected (HTTP ${xhr.status})`, "v-MALICIOUS");
    poll(file.name, body.job_id, Date.now());
  };
  xhr.send(fd);
}
async function poll(name, jobId, t0) {
  try {
    const j = await api("/jobs/" + jobId);
    const secs = Math.round((Date.now() - t0) / 1000);
    if (j.status === "QUEUED" || j.status === "RUNNING") {
      setStatus(name, j.status, null, `Static analysis in progress · ${secs}s`);
      return setTimeout(() => poll(name, jobId, t0), 700);
    }
    if (j.status === "FAILED") return setStatus(name, "FAILED", 0, j.error || "The scan failed. No result is available.", "v-MALICIOUS");
    setStatus(name, "COMPLETED", 100, `Finished in ${secs}s`, "v-CLEAN_WITHIN_CHECKED_SCOPE");
    renderReport(await api("/reports/" + j.report_id));
  } catch (e) { setStatus(name, "FAILED", 0, e.message, "v-MALICIOUS"); }
}

/* ---------- URL scan ---------- */
$("#url-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("#url-msg"), btn = e.target.querySelector("button"); msg.textContent = "";
  const url = $("#url").value.trim();
  if (!url) { msg.textContent = "Enter a URL to analyse."; return; }
  btn.disabled = true; $("#report").hidden = true;
  try {
    renderReport(await api("/urls", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) }));
  } catch (err) { msg.textContent = err.message; } finally { btn.disabled = false; }
});

/* ---------- history ---------- */
$("#hist-form").addEventListener("submit", (e) => { e.preventDefault(); loadHistory(); });
async function loadHistory() {
  const p = new URLSearchParams();
  if ($("#hist-q").value.trim()) p.set("q", $("#hist-q").value.trim());
  if ($("#hist-v").value) p.set("verdict", $("#hist-v").value);
  const tb = $("#hist tbody");
  try {
    const { items } = await api("/history?" + p);
    $("#hist-empty").hidden = items.length > 0;
    tb.replaceChildren(...items.map((r) => el("tr", {},
      el("td", { text: fmtDate(r.created) }), el("td", { text: r.kind }),
      el("td", {}, el("div", { class: "mono", text: r.name || "" }), r.sha256 ? el("small", { class: "muted mono", text: r.sha256 }) : null),
      el("td", {}, el("span", { class: "pill v-" + r.verdict, text: label(r.verdict) })),
      el("td", { class: "actions" },
        el("button", { class: "btn ghost sm", type: "button", text: "View", onclick: async () => renderReport(await api("/reports/" + r.id)) }), " ",
        el("button", { class: "btn danger sm", type: "button", text: "Delete", "aria-label": "Delete report for " + (r.name || r.id), onclick: () => removeReport(r.id) })))));
  } catch (e) { tb.replaceChildren(el("tr", {}, el("td", { colspan: 5, class: "err", text: e.message }))); }
}
async function removeReport(id) {
  try { await api("/reports/" + id, { method: "DELETE" }); } catch (e) { /* already gone */ }
  $("#report").hidden = true;
  if (!$("#panel-history").hidden) loadHistory();
}

/* ---------- report ---------- */
function kv(pairs) {
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of pairs) {
    if (v == null || v === "") continue;
    dl.append(el("dt", { text: k }), el("dd", { text: typeof v === "object" ? JSON.stringify(v) : String(v) }));
  }
  return dl;
}
const card = (title, body, full) => el("section", { class: "card" + (full ? " full" : "") }, el("h3", { text: title }), body);
const list = (items) => el("ul", { class: "plain" }, items.map((t) => el("li", { text: t })));

function renderReport(r) {
  const box = $("#report"), t = r.target, isFile = r.kind === "file";
  const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const findings = [...r.findings].sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);
  const exportJson = () => {
    const a = el("a", { href: URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" })), download: `threatlens-${r.report_id}.json` });
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  const head = el("div", { class: "verdict v-" + r.verdict },
    el("div", { class: "target mono", text: isFile ? t.filename : t.normalized_url }),
    el("h2", { class: "v-" + r.verdict, text: label(r.verdict) }),
    r.verdict_reasons.map((x) => el("p", { text: x })),
    el("div", { class: "tools" },
      el("button", { class: "btn ghost sm", type: "button", text: "Export JSON", onclick: exportJson }),
      el("button", { class: "btn danger sm", type: "button", text: "Delete report", onclick: () => removeReport(r.report_id) })));

  const target = isFile
    ? kv([["File name", t.filename], ["Size", fmtBytes(t.size_bytes)], ["Detected format", t.format], ["Detected MIME", t.mime],
          ["Claimed extension", t.claimed_extension ? "." + t.claimed_extension : "(none)"],
          ["Extension matches", t.extension_matches_content == null ? "not checked" : t.extension_matches_content ? "yes" : "NO"],
          ["SHA-256", t.sha256], ["Scanned", fmtDate(r.created_at)],
          ["Seen before", (r.previous_reports_same_hash || []).length ? `${r.previous_reports_same_hash.length} earlier report(s) with this hash` : "no"]])
    : kv([["Submitted", t.submitted_url], ["Normalised", t.normalized_url], ["Hostname", t.host],
          ["Shown as", t.host_unicode !== t.host ? t.host_unicode : null], ["Registrable domain", t.registrable_domain],
          ["HTTPS", t.https ? "yes" : "no"], ["Port", t.port], ["IP literal", t.ip_literal],
          ["DNS", t.dns ? (t.dns.ips ? t.dns.ips.join(", ") : t.dns.error) : "not resolved"], ["Scanned", fmtDate(r.created_at)]]);

  const fbox = el("div", {});
  if (!findings.length) fbox.append(el("p", { class: "muted", text: "No findings from the checks that ran." }));
  for (const x of findings) {
    fbox.append(el("article", { class: "finding" },
      el("header", {}, el("span", { class: "pill s-" + x.severity, text: x.severity }), el("h4", { text: x.title }),
        el("span", { class: "src mono", text: `${x.source} · confidence ${x.confidence}` })),
      x.description ? el("p", { text: x.description }) : null,
      Object.keys(x.evidence || {}).length ? el("div", { class: "ev" }, kv(Object.entries(x.evidence).map(([k, v]) => [label(k), v]))) : null));
  }
  const eng = el("div", { class: "eng" });
  for (const e of r.engines) {
    const cls = e.status === "COMPLETED" ? "v-CLEAN_WITHIN_CHECKED_SCOPE" : e.status === "SKIPPED" || e.status === "NOT_CONFIGURED" ? "v-INCONCLUSIVE" : "v-SUSPICIOUS";
    eng.append(el("span", { class: "pill " + cls, text: label(e.status) }),
      el("div", {}, e.name, el("small", { text: [e.detail, e.version, e.duration_ms != null ? e.duration_ms + " ms" : null].filter(Boolean).join(" · ") })));
  }
  const grid = el("div", { class: "grid" }, card(isFile ? "File" : "URL", target), card("Engines", eng));
  grid.append(card(`Findings (${findings.length})`, fbox, true));
  const pdf = r.analysis && r.analysis.pdf;
  if (pdf && Object.keys(pdf).length) grid.append(card("PDF metadata", kv([["Pages", pdf.page_count], ["Encrypted", pdf.encrypted ? "yes" : "no"], ["Title", pdf.title],
    ["Author", pdf.author], ["Creator", pdf.creator], ["Producer", pdf.producer], ["Created", pdf.creation_date], ["Modified", pdf.modification_date],
    ["Form fields", pdf.is_form ? "yes" : "no"], ["Embedded files", (pdf.embedded_files || []).join(", ")], ["Extracted text", pdf.extracted_text_chars != null ? pdf.extracted_text_chars + " characters" : null]])));
  const ind = r.indicators || {};
  if ((ind.urls || []).length) {
    const tb = el("tbody", {}, ind.urls.map((u) => el("tr", {}, el("td", { text: u.page != null ? "p. " + u.page : (u.part || "") }),
      el("td", { class: "mono", text: u.url }), el("td", { text: u.displayed_text || "" }), el("td", { text: u.found_as || "" }))));
    grid.append(card(`Extracted links (${ind.urls.length}) · shown as text, not clickable`, el("div", { class: "tablewrap" },
      el("table", {}, el("thead", {}, el("tr", {}, ["Where", "Destination", "Displayed text", "Found as"].map((h) => el("th", { text: h })))), tb)), true));
  }
  const other = [["Email addresses", ind.emails], ["Phone numbers", ind.phones]].filter(([, v]) => (v || []).length);
  if (other.length) grid.append(card("Other indicators", kv(other.map(([k, v]) => [k, v.join(", ")]))));
  grid.append(card("Recommendations", r.recommendations.length ? list(r.recommendations) : el("p", { class: "muted", text: "None." })));
  if (r.engines_not_available.length) grid.append(card("Engines not available", list(r.engines_not_available)));
  if ((r.items_skipped || []).length) grid.append(card("Not inspected", list(r.items_skipped)));
  box.replaceChildren(head, grid, el("p", { class: "disclaimer", text: r.disclaimer + (r.retention ? " " + r.retention : "") }));
  box.hidden = false; box.focus({ preventScroll: true }); box.scrollIntoView({ behavior: "smooth", block: "start" });
}

loadCaps();

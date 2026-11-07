"use strict";
const $ = (s, r = document) => r.querySelector(s);
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v; else if (k === "text") e.textContent = v;
    else if (k.startsWith("data-") || k.startsWith("aria-") || k === "role") e.setAttribute(k, v); else e[k] = v;
  }
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
async function api(path, body) {
  const opt = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const r = await fetch(path, opt);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
  return j;
}
function busy(btn, on, label) { btn.disabled = on; if (label) btn.textContent = label; }
function setStatus(node, text, isErr, spin) {
  node.replaceChildren();
  if (!text) return;
  node.append(isErr ? el("span", { class: "err", text }) : el("span", {}, spin ? el("span", { class: "spin", "aria-hidden": "true" }) : null, text));
}

/* ---- theme ---- */
const root = document.documentElement;
function curTheme() { return root.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"); }
function applyTheme(t) { root.dataset.theme = t; $("#theme").textContent = t === "dark" ? "Light mode" : "Dark mode"; try { localStorage.setItem("sentinel-theme", t); } catch (e) {} }
try { const t = localStorage.getItem("sentinel-theme"); if (t) root.dataset.theme = t; } catch (e) {}
$("#theme").textContent = curTheme() === "dark" ? "Light mode" : "Dark mode";
$("#theme").onclick = () => applyTheme(curTheme() === "dark" ? "light" : "dark");

/* ---- tabs ---- */
const tabs = [...document.querySelectorAll("[role=tab]")];
function selectTab(t, focus) {
  for (const x of tabs) {
    const on = x === t;
    x.setAttribute("aria-selected", on); x.tabIndex = on ? 0 : -1;
    document.getElementById(x.getAttribute("aria-controls")).hidden = !on;
  }
  if (focus) t.focus();
  if (t.id === "tab-hist") loadHistory();
}
tabs.forEach((t, i) => {
  t.onclick = () => selectTab(t);
  t.onkeydown = e => {
    const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (d) { e.preventDefault(); selectTab(tabs[(i + d + tabs.length) % tabs.length], true); }
    if (e.key === "Home") { e.preventDefault(); selectTab(tabs[0], true); }
    if (e.key === "End") { e.preventDefault(); selectTab(tabs[tabs.length - 1], true); }
  };
});

/* ---- renderers ---- */
const SEV = ["critical", "high", "medium", "low", "info"];
const badge = s => el("span", { class: "badge sev-" + s, text: s });

function renderScan(env) {
  const d = env.data, box = el("div");
  box.append(el("div", { class: "chips" },
    el("span", { class: "chip", text: d.address }),
    el("span", { class: "chip", text: d.open_count + " open / " + d.ports_scanned + " scanned" }),
    el("span", { class: "chip", text: Math.round(d.elapsed_ms) + " ms" })));
  if (!d.open_ports.length) { box.append(el("div", { class: "empty", text: "No open ports found." })); return box; }
  const t = el("table", { class: "stack" },
    el("thead", {}, el("tr", {}, ["Port", "Service", "RTT", "Banner"].map(h => el("th", { scope: "col", text: h })))),
    el("tbody", {}, d.open_ports.map(p => el("tr", {},
      el("td", { "data-label": "Port", class: "mono", text: p.port }),
      el("td", { "data-label": "Service" }, badge2(p.service)),
      el("td", { "data-label": "RTT", text: p.rtt_ms + " ms" }),
      el("td", { "data-label": "Banner", class: "mono", text: p.banner || "-" })))));
  box.append(el("div", { class: "tablewrap" }, t));
  return box;
}
function badge2(text) { return el("span", { class: "badge sev-ok", text }); }

function fmtTs(ts) { return ts ? new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC" : ""; }

function renderLogs(env) {
  const d = env.data, box = el("div");
  const chips = el("div", { class: "chips" });
  for (const s of SEV) chips.append(el("span", { class: "badge sev-" + s }, s + ": " + d.counts[s]));
  chips.append(el("span", { class: "chip", text: d.lines_parsed + " lines parsed, " + d.lines_ignored + " ignored" }));
  box.append(chips);
  if (!d.findings.length) { box.append(el("div", { class: "empty", text: "No anomalies detected." })); return box; }
  for (const s of SEV) {
    const items = d.findings.filter(f => f.severity === s);
    if (!items.length) continue;
    const g = el("section", { class: "group", "aria-label": s + " findings" }, el("h3", {}, badge(s), items.length + (items.length === 1 ? " finding" : " findings")));
    for (const f of items) g.append(el("div", { class: "finding" },
      el("span", { class: "chip", text: f.type }),
      el("div", {}, el("div", { text: f.summary }),
        el("div", { class: "meta" }, [f.ip && "source " + f.ip, f.line && "line " + f.line, fmtTs(f.timestamp)].filter(Boolean).join(" | ")))));
    box.append(g);
  }
  return box;
}

/* ---- scan ---- */
const presets = { common: "common", "1-1024": "1-1024", "1-10000": "1-10000" };
$("#s-preset").onchange = e => { if (presets[e.target.value]) $("#s-ports").value = presets[e.target.value]; else $("#s-ports").focus(); };
$("#s-ports").oninput = () => { const v = $("#s-ports").value.trim(); $("#s-preset").value = presets[v] ? v : "custom"; };
$("#scan-form").onsubmit = async e => {
  e.preventDefault();
  const btn = $("#s-run"); busy(btn, true); $("#s-out").replaceChildren();
  setStatus($("#s-status"), "Scanning 127.0.0.1...", false, true);
  try {
    const env = await api("/api/scan", { ports: $("#s-ports").value, timeout_ms: +$("#s-timeout").value || 400, banner: $("#s-banner").checked });
    setStatus($("#s-status"), env.summary + (env.report ? " - saved as " + env.report : ""));
    $("#s-out").replaceChildren(renderScan(env));
  } catch (err) { setStatus($("#s-status"), err.message, true); }
  busy(btn, false);
};

/* ---- logs ---- */
const SAMPLE = [
  ...Array.from({ length: 8 }, (_, i) => `Nov  3 09:10:${String(5 + i * 6).padStart(2, "0")} web01 sshd[2211]: Failed password for ${i % 2 ? "invalid user admin" : "root"} from 203.0.113.45 port ${40000 + i} ssh2`),
  "Nov  3 09:11:20 web01 sshd[2211]: Accepted password for root from 203.0.113.45 port 40100 ssh2",
  '198.51.100.9 - - [10/Oct/2023:13:30:01 +0000] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 512 "-" "sqlmap"',
  '198.51.100.9 - - [10/Oct/2023:13:30:04 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 1840 "-" "curl/8"',
  '198.51.100.9 - - [10/Oct/2023:13:30:09 +0000] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 900 "-" "curl/8"',
  '198.51.100.9 - - [10/Oct/2023:13:30:12 +0000] "GET /.env HTTP/1.1" 404 120 "-" "curl/8"',
].join("\n");
$("#l-sample").onclick = () => { $("#l-text").value = SAMPLE; $("#l-text").focus(); };
$("#l-file").onchange = async e => {
  const f = e.target.files[0]; if (!f) return;
  if (f.size > 4 * 1024 * 1024) { setStatus($("#l-status"), "File too large (max 4 MB).", true); return; }
  $("#l-text").value = await f.text();
  setStatus($("#l-status"), "Loaded " + f.name + " (" + Math.ceil(f.size / 1024) + " KB)");
};
$("#l-run").onclick = async () => {
  const text = $("#l-text").value;
  if (!text.trim()) { setStatus($("#l-status"), "Paste or upload a log first.", true); $("#l-text").focus(); return; }
  const btn = $("#l-run"); busy(btn, true); $("#l-out").replaceChildren();
  setStatus($("#l-status"), "Analyzing...", false, true);
  try {
    const env = await api("/api/logscan", { text, bf_threshold: +$("#l-thr").value || 5, bf_window: +$("#l-win").value || 300 });
    setStatus($("#l-status"), env.summary + (env.report ? " - saved as " + env.report : ""));
    $("#l-out").replaceChildren(renderLogs(env));
  } catch (err) { setStatus($("#l-status"), err.message, true); }
  busy(btn, false);
};

/* ---- passwords ---- */
const pw = $("#pw"); let pwTimer = 0, pwSeq = 0;
$("#pw-show").onclick = e => { const show = pw.type === "password"; pw.type = show ? "text" : "password"; e.target.textContent = show ? "Hide" : "Show"; e.target.setAttribute("aria-pressed", show); };
function resetPw() {
  $("#meter").dataset.score = ""; $("#meter").setAttribute("aria-label", "Strength meter");
  $("#pw-label").replaceChildren(el("span", { class: "muted", text: "Start typing to see feedback." })); $("#pw-detail").replaceChildren();
}
pw.oninput = () => {
  clearTimeout(pwTimer);
  if (!pw.value) { pwSeq++; resetPw(); return; }
  pwTimer = setTimeout(async () => {
    const seq = ++pwSeq;
    try {
      const r = await api("/api/audit", { password: pw.value });
      if (seq !== pwSeq) return;
      const sevClass = ["critical", "high", "medium", "low", "ok"][r.score];
      $("#meter").dataset.score = r.score;
      $("#meter").setAttribute("aria-label", "Strength: " + r.label);
      $("#pw-label").replaceChildren(el("span", { class: "badge sev-" + sevClass, text: r.label }), " ",
        el("span", { class: "muted small", text: r.entropy_bits + " bits | offline crack time: " + r.crack_time }));
      const d = $("#pw-detail"); d.replaceChildren();
      if (r.patterns.length) d.append(el("h3", { text: "Patterns found", class: "mt12" }), el("ul", { class: "plain" }, r.patterns.map(p => el("li", { text: p }))));
      if (r.feedback.length) d.append(el("h3", { text: "Suggestions", class: "mt12" }), el("ul", { class: "plain" }, r.feedback.map(p => el("li", { text: p }))));
    } catch (err) { $("#pw-label").replaceChildren(el("span", { class: "err", text: err.message })); }
  }, 150);
};

/* ---- history ---- */
async function loadHistory() {
  const list = $("#h-list"); setStatus($("#h-status"), "Loading...", false, true);
  try {
    const { reports } = await api("/api/reports");
    setStatus($("#h-status"), "");
    list.replaceChildren();
    if (!reports.length) { list.append(el("li", { class: "empty", text: "No reports yet. Run a scan or analyze a log." })); return; }
    for (const r of reports) {
      const b = el("button", { type: "button", text: "View", "aria-label": "View " + r.name });
      b.onclick = () => viewReport(r.name);
      list.append(el("li", {}, el("span", { class: "badge sev-low", text: r.kind }),
        el("div", { class: "grow" }, el("div", { text: r.summary }), el("div", { class: "muted small mono", text: r.generated_at + " | " + r.name })), b));
    }
  } catch (err) { setStatus($("#h-status"), err.message, true); }
}
async function viewReport(name) {
  try {
    const env = await api("/api/reports/" + encodeURIComponent(name));
    $("#h-title").textContent = env.kind + " report - " + env.generated_at;
    const body = $("#h-body"); body.replaceChildren();
    if (env.kind === "scan") body.append(renderScan(env));
    else if (env.kind === "logscan") body.append(renderLogs(env));
    else body.append(el("pre", { class: "json", text: JSON.stringify(env.data, null, 2) }));
    $("#h-view").hidden = false; $("#h-view").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) { setStatus($("#h-status"), err.message, true); }
}
$("#h-refresh").onclick = loadHistory;

api("/api/version").then(v => { $("#ver").textContent = "v" + v.version; }).catch(() => {});

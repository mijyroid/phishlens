// PhishLens UI. All email-derived values are rendered with textContent, never
// innerHTML, because the content being analyzed is attacker-controlled.
"use strict";

const $ = (id) => document.getElementById(id);

const VERDICTS = {
  low_risk: { label: "Low risk", color: "var(--ok)" },
  suspicious: { label: "Suspicious", color: "var(--medium)" },
  likely_phishing: { label: "Likely phishing", color: "var(--critical)" },
};

const FLAG_LABELS = {
  text_mismatch: "Text ≠ destination",
  ip_host: "IP address",
  userinfo_trick: "@ trick",
  lookalike: "Look-alike domain",
  punycode: "Punycode",
  dangerous_scheme: "Script link",
  form: "Form",
  shortener: "Shortener",
  suspicious_tld: "Risky TLD",
  http: "No HTTPS",
  many_subdomains: "Many subdomains",
};

let activeTab = "paste";
let selectedFile = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function setTab(tab) {
  activeTab = tab;
  document.querySelectorAll(".tab").forEach((btn) => {
    const on = btn.dataset.tab === tab;
    btn.classList.toggle("active", on);
    btn.setAttribute("aria-selected", String(on));
  });
  $("panel-paste").classList.toggle("hidden", tab !== "paste");
  $("panel-upload").classList.toggle("hidden", tab !== "upload");
}

function showError(message) {
  const box = $("error");
  box.textContent = message;
  box.classList.toggle("hidden", !message);
}

async function runAnalysis() {
  showError("");
  let request;
  if (activeTab === "upload") {
    if (!selectedFile) return showError("Choose an .eml file first.");
    const form = new FormData();
    form.append("file", selectedFile);
    request = fetch("/api/analyze/file", { method: "POST", body: form });
  } else {
    const raw = $("raw").value;
    if (!raw.trim()) return showError("Paste the email source first.");
    request = fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw }),
    });
  }

  const button = $("analyze");
  button.disabled = true;
  button.textContent = "Analyzing…";
  try {
    const res = await request;
    if (!res.ok) {
      let message = `Analysis failed (${res.status}).`;
      try {
        const data = await res.json();
        if (typeof data.detail === "string") message = data.detail;
      } catch {
        const text = await res.text().catch(() => "");
        if (text) message = text;
      }
      return showError(message);
    }
    render(await res.json());
  } catch {
    showError("Couldn't reach the server. Check your connection and try again.");
  } finally {
    button.disabled = false;
    button.textContent = "Analyze email";
  }
}

function render(report) {
  const verdict = VERDICTS[report.verdict] || VERDICTS.suspicious;

  const card = $("verdict-card");
  card.className = `card verdict-card ${report.verdict}`;
  const gauge = $("gauge");
  gauge.style.setProperty("--pct", report.score);
  gauge.style.setProperty("--color", verdict.color);
  $("score").textContent = report.score;
  $("verdict-label").textContent = verdict.label;
  $("verdict-label").style.color = verdict.color;
  $("explanation").textContent = report.explanation;
  $("explanation-source").textContent =
    report.explanation_source === "llm" ? "Explanation written by AI from the findings below." : "";

  renderSummary(report.email);
  renderFindings(report.findings);
  renderLinks(report.links);
  renderAttachments(report.attachments);
  renderIntel(report.intel);

  $("results").classList.remove("hidden");
  card.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderSummary(email) {
  const dl = $("summary");
  dl.replaceChildren();
  const from = email.from_address
    ? `${email.from_display ? email.from_display + " " : ""}<${email.from_address}>`
    : null;
  const rows = [
    ["From", from],
    ["Reply-To", email.reply_to],
    ["Subject", email.subject],
    ["Date", email.date],
  ];
  for (const [label, value] of rows) {
    if (!value) continue;
    dl.append(el("dt", null, label), el("dd", null, value));
  }
  if (!dl.children.length) dl.append(el("dt", null, "Headers"), el("dd", null, "None provided"));

  const auth = $("auth");
  auth.replaceChildren();
  for (const mech of ["spf", "dkim", "dmarc"]) {
    const result = email.auth[mech];
    let cls = "pill";
    if (result === "pass") cls += " pass";
    else if (result === "fail" || result === "permerror") cls += " fail";
    else if (result) cls += " warn";
    auth.append(el("span", cls, `${mech.toUpperCase()}: ${result || "n/a"}`));
  }
}

function renderFindings(findings) {
  const list = $("findings");
  list.replaceChildren();
  $("finding-count").textContent = `(${findings.length})`;
  if (!findings.length) {
    list.append(el("li", "muted", "No findings."));
    return;
  }
  for (const f of findings) {
    const item = el("li", "finding");
    item.append(el("span", `sev ${f.severity}`, f.severity));
    const body = el("div");
    body.append(el("p", "finding-title", f.title), el("p", "finding-detail", f.detail));
    if (f.evidence) body.append(el("code", "evidence", f.evidence));
    item.append(body);
    list.append(item);
  }
}

function renderLinks(links) {
  const tbody = $("links");
  tbody.replaceChildren();
  $("link-count").textContent = `(${links.length})`;
  if (!links.length) {
    const row = el("tr");
    const cell = el("td", "muted", "No links found.");
    cell.colSpan = 3;
    row.append(cell);
    tbody.append(row);
    return;
  }
  for (const link of links) {
    const row = el("tr");
    row.append(el("td", "url", link.url));
    row.append(el("td", null, link.text || "—"));
    const flags = el("td");
    if (link.flags.length) {
      for (const flag of link.flags) flags.append(el("span", "flag", FLAG_LABELS[flag] || flag));
    } else {
      flags.append(el("span", "flag clean", "No issues"));
    }
    row.append(flags);
    tbody.append(row);
  }
}

function renderAttachments(attachments) {
  const list = $("attachments");
  list.replaceChildren();
  if (!attachments.length) {
    list.append(el("li", "muted", "None"));
    return;
  }
  for (const a of attachments) {
    list.append(el("li", null, `${a.filename} · ${a.content_type} · ${formatBytes(a.size)}`));
  }
}

function renderIntel(intel) {
  const list = $("intel");
  list.replaceChildren();
  for (const source of intel) {
    const item = el("li");
    item.append(el("span", `status ${source.status}`, source.status), el("span", null, source.source));
    if (source.detail) item.append(el("div", "muted small", source.detail));
    list.append(item);
  }
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

async function loadSample(name) {
  showError("");
  try {
    const res = await fetch(`/api/samples/${encodeURIComponent(name)}`);
    if (!res.ok) throw new Error();
    $("raw").value = await res.text();
    setTab("paste");
    runAnalysis();
  } catch {
    showError("Couldn't load the sample.");
  }
}

function pickFile(file) {
  selectedFile = file || null;
  $("file-name").textContent = selectedFile ? selectedFile.name : "or drag it here";
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".tab").forEach((btn) => btn.addEventListener("click", () => setTab(btn.dataset.tab)));
  document.querySelectorAll("[data-sample]").forEach((btn) =>
    btn.addEventListener("click", () => loadSample(btn.dataset.sample))
  );
  $("analyze").addEventListener("click", runAnalysis);
  $("raw").addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") runAnalysis();
  });
  $("file").addEventListener("change", (e) => pickFile(e.target.files[0]));

  const zone = $("dropzone");
  ["dragenter", "dragover"].forEach((t) =>
    zone.addEventListener(t, (e) => { e.preventDefault(); zone.classList.add("dragging"); })
  );
  ["dragleave", "drop"].forEach((t) =>
    zone.addEventListener(t, (e) => { e.preventDefault(); zone.classList.remove("dragging"); })
  );
  zone.addEventListener("drop", (e) => pickFile(e.dataTransfer.files[0]));
});

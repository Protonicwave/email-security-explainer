"use strict";

// Every string from DNS or the server reaches the page through textContent or
// a text node, never as markup, so a TXT record cannot inject anything.

const REQUEST_TIMEOUT_MS = 90000;
const SVG_NS = "http://www.w3.org/2000/svg";
const SEVERITY_LABELS = { high: "High", medium: "Medium", low: "Low" };
const RECORD_LABELS = { spf: "SPF", dmarc: "DMARC" };
const VIEWS = ["intro", "checking", "stopped", "verdict", "records", "findings"];

const form = document.getElementById("check-form");
const input = document.getElementById("domain");
const button = document.getElementById("check-button");
const fieldError = document.getElementById("domain-error");

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function icon(pathData) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", pathData);
  for (const [name, value] of Object.entries({
    fill: "none", stroke: "currentColor", "stroke-width": "2",
    "stroke-linecap": "round", "stroke-linejoin": "round",
  })) path.setAttribute(name, value);
  svg.append(path);
  return svg;
}

const tick = () => {
  const svg = icon("M3 8.5 6.5 12 13 4");
  svg.classList.add("tick");
  return svg;
};

function show(...visible) {
  for (const id of VIEWS) document.getElementById(id).hidden = !visible.includes(id);
}

function showFieldError(message) {
  fieldError.textContent = message;
  fieldError.hidden = !message;
  input.setAttribute("aria-invalid", message ? "true" : "false");
}

function setBusy(isBusy) {
  button.disabled = isBusy;
  button.textContent = isBusy ? "Checking…" : "Check domain";
}

function domainText(domain) {
  return element("span", "domain-name", domain);
}

// A title with the domain set apart, so a long domain can wrap on its own.
function titleWithDomain(title, domain) {
  const at = title.indexOf(domain);
  if (at < 0) return [document.createTextNode(title)];
  return [
    document.createTextNode(title.slice(0, at)),
    domainText(domain),
    document.createTextNode(title.slice(at + domain.length)),
  ];
}

function proof(number) {
  const badge = element("span", "proof", String(number));
  badge.setAttribute("aria-hidden", "true");
  return badge;
}

function findingLink(className, finding) {
  const link = element("a", className);
  link.href = `#finding-${finding.number}`;
  link.dataset.sev = finding.severity;
  link.dataset.finding = String(finding.number);
  link.style.setProperty("--order", String(finding.number - 1));
  return link;
}

function renderSpan(span, findingsByNumber) {
  switch (span.kind) {
    case "version":
      return element("span", "version", span.text);
    case "absent":
      return element("span", "absent", span.text);
    case "mark": {
      const finding = findingsByNumber.get(span.finding);
      const link = findingLink("mark", finding);
      link.setAttribute("aria-label", `${span.text} (finding ${finding.number})`);
      link.append(span.text, proof(finding.number));
      return link;
    }
    case "caret": {
      const finding = findingsByNumber.get(span.finding);
      const link = findingLink("caret", finding);
      link.setAttribute("aria-label", `Missing here: ${finding.title} (finding ${finding.number})`);
      link.append(icon("M2 14 8 4l6 10"), proof(finding.number));
      return link;
    }
    default:
      return document.createTextNode(span.text);
  }
}

function renderLine(className, spans, findingsByNumber) {
  const line = element("p", className);
  for (const span of spans) line.append(renderSpan(span, findingsByNumber));
  return line;
}

function renderChain(view, findingsByNumber) {
  const { spf_chain: rows } = view.records;
  if (!rows.length && !view.spf_lookup_count) return null;
  const chain = element("div", "chain");
  for (const row of rows) {
    const chainRow = element("div", "chain-row");
    chainRow.append(element("span", "chain-from", row.via), renderLine("chain-value", row.spans, findingsByNumber));
    chain.append(chainRow);
  }
  const count = element("p", "chain-count");
  if (view.spf_lookup_count > view.max_spf_lookups) {
    count.append(element("strong", "", `More than ${view.max_spf_lookups}`), " DNS lookups needed across the include chain.");
  } else {
    count.append(element("strong", "", `${view.spf_lookup_count} of ${view.max_spf_lookups}`), " DNS lookups used across the include chain.");
  }
  chain.append(count);
  return chain;
}

function renderNotes(kind, findings) {
  const own = findings.filter((finding) => finding.record === kind);
  if (!own.length) {
    const clean = element("p", "record-clean");
    clean.append(tick(), "No problems found");
    return clean;
  }
  const notes = element("ul", "notes");
  notes.setAttribute("aria-label", `Marks on the ${RECORD_LABELS[kind]} record`);
  for (const finding of own) {
    const link = findingLink("", finding);
    link.append(proof(finding.number));
    if (finding.evidence !== null) link.append(element("span", "note-token", finding.evidence));
    link.append(element("span", "note-text", finding.title));
    const note = element("li", "note");
    note.append(link);
    notes.append(note);
  }
  return notes;
}

function renderRecord(kind, name, lines, chain, view, findingsByNumber) {
  const figure = element("figure", "record");
  figure.setAttribute("aria-labelledby", `${kind}-label`);
  const body = element("div");
  const where = element("div", "record-where");
  const label = element("span", "record-kind", RECORD_LABELS[kind]);
  label.id = `${kind}-label`;
  where.append(label, element("span", "record-name", `TXT at ${name}`));
  body.append(where);
  for (const spans of lines) body.append(renderLine("record-value", spans, findingsByNumber));
  if (chain) body.append(chain);
  figure.append(body, renderNotes(kind, view.findings));
  return figure;
}

function renderFinding(finding) {
  const item = element("li", "finding");
  item.id = `finding-${finding.number}`;
  item.dataset.sev = finding.severity;
  item.dataset.finding = String(finding.number);
  const body = element("div");
  const meta = element("p", "finding-meta");
  meta.append(
    element("span", "severity", SEVERITY_LABELS[finding.severity]),
    element("span", "finding-code", finding.code),
  );
  body.append(meta, element("h3", "", finding.title));
  if (finding.evidence !== null) {
    const quote = element("p");
    quote.append("Rests on ", element("code", "", finding.evidence), ` in your ${RECORD_LABELS[finding.record]} record.`);
    body.append(quote);
  }
  item.append(proof(finding.number), body);
  return item;
}

function renderTally(findings) {
  const tally = document.getElementById("tally");
  tally.replaceChildren();
  tally.hidden = !findings.length;
  for (const severity of Object.keys(SEVERITY_LABELS)) {
    const group = element("div", `is-${severity}`);
    const count = findings.filter((finding) => finding.severity === severity).length;
    group.append(element("dt", "", SEVERITY_LABELS[severity]), element("dd", "", String(count)));
    tally.append(group);
  }
}

// A finding, its mark in the record and its margin note light up together.
function linkFindings(root) {
  for (const node of root.querySelectorAll("[data-finding]")) {
    const linked = () => root.querySelectorAll(`[data-finding="${node.dataset.finding}"]`);
    const on = () => linked().forEach((other) => other.classList.add("is-linked"));
    const off = () => linked().forEach((other) => other.classList.remove("is-linked"));
    node.addEventListener("mouseenter", on);
    node.addEventListener("mouseleave", off);
    node.addEventListener("focusin", on);
    node.addEventListener("focusout", off);
  }
}

function renderAudit(view) {
  const findingsByNumber = new Map(view.findings.map((finding) => [finding.number, finding]));
  const now = new Date();
  const time = now.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  const date = now.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
  document.getElementById("fetched").textContent = `Records fetched from public DNS at ${time} on ${date}`;

  const title = document.getElementById("verdict-title");
  title.replaceChildren(...titleWithDomain(view.headline.title, view.domain), element("span", "then", view.headline.cause));
  renderTally(view.findings);

  const hasFindings = view.findings.length > 0;
  document.getElementById("records-title").textContent = hasFindings ? "Your records, marked up" : "Your records";
  document.getElementById("records-note").hidden = !hasFindings;
  const slip = document.getElementById("slip");
  slip.classList.remove("is-drawing");
  slip.replaceChildren(
    renderRecord("spf", view.domain, view.records.spf, renderChain(view, findingsByNumber), view, findingsByNumber),
    renderRecord("dmarc", `_dmarc.${view.domain}`, view.records.dmarc, null, view, findingsByNumber),
  );
  document.getElementById("finding-list").replaceChildren(...view.findings.map(renderFinding));
  linkFindings(document.getElementById("main"));

  show("verdict", "records", ...(hasFindings ? ["findings"] : []));
  // Reading layout restarts the animation for a second check of the same page.
  void slip.offsetWidth;
  slip.classList.add("is-drawing");
  title.focus();
}

function showStopped(titleNodes, reason, advice, canRetry) {
  document.getElementById("stopped-title").replaceChildren(...titleNodes);
  document.getElementById("stopped-reason").textContent = reason;
  const adviceNode = document.getElementById("stopped-advice");
  adviceNode.textContent = advice;
  adviceNode.hidden = !advice;
  document.getElementById("retry").hidden = !canRetry;
  show("stopped");
  document.getElementById("stopped-title").focus();
}

function asSentence(text) {
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

async function readError(response) {
  try {
    const payload = await response.json();
    return typeof payload.error === "string" ? payload.error : `HTTP ${response.status}`;
  } catch {
    return `HTTP ${response.status}`;
  }
}

async function check(domain) {
  showFieldError("");
  setBusy(true);
  document.getElementById("checking-domain").textContent = domain;
  show("checking");
  document.getElementById("checking-title").focus();
  let response;
  try {
    response = await fetch("/api/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    showStopped(
      [document.createTextNode("The page lost contact with esx.")],
      "No answer came back, so nothing was audited.",
      "Check that esx serve is still running in your terminal, then try again.",
      true,
    );
    return;
  } finally {
    setBusy(false);
  }
  if (response.ok) {
    const view = await response.json();
    input.value = view.domain;
    renderAudit(view);
    return;
  }
  const error = await readError(response);
  if (response.status === 400) {
    show("intro");
    showFieldError("That is not a domain name. Enter only the part after the @, such as example.com.");
    input.focus();
  } else if (response.status === 404) {
    showFieldError("This domain does not exist. Check the spelling.");
    showStopped(
      [domainText(domain), document.createTextNode(" does not exist.")],
      "DNS has no record of this name at all, so there are no SPF or DMARC records to audit.",
      "Check the spelling: the domain you send email from is the part after the @ in your address.",
      false,
    );
  } else if (response.status === 502) {
    showStopped(
      [document.createTextNode("The DNS lookup failed, so nothing was audited.")],
      asSentence(error),
      "A lookup that fails is not the same as a record that is missing, so this page shows no result rather than a wrong one.",
      true,
    );
  } else {
    showStopped([document.createTextNode("esx could not finish the check.")], asSentence(error), "", true);
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const domain = input.value.trim();
  if (!domain) {
    showFieldError("Enter the domain you send email from, such as example.com.");
    input.focus();
    return;
  }
  check(domain);
});

document.getElementById("retry").addEventListener("click", () => check(input.value.trim()));

"use strict";

// Every string from DNS or the server reaches the page through textContent or
// a text node, never as markup, so a TXT record cannot inject anything.

const REQUEST_TIMEOUT_MS = 90000;
// The server allows each model call two minutes and a repair round doubles
// the calls, so a slow answer can take several minutes.
const EXPLAIN_TIMEOUT_MS = 300000;
const SVG_NS = "http://www.w3.org/2000/svg";
const SEVERITY_LABELS = { high: "High", medium: "Medium", low: "Low" };
const RECORD_LABELS = { spf: "SPF", dmarc: "DMARC" };
const VIEWS = ["intro", "checking", "stopped", "verdict", "records", "findings", "method"];
const EXPLAIN_PARTS = ["steps", "summary", "explain-stopped"];
const PASSED_PATH = "M3 8.5 6.5 12 13 4";
const DROPPED_PATH = "M4 8h8";

// Each check takes the next number, and a reply for an earlier check is dropped,
// so a slow explanation cannot land on another domain's audit.
let checkNumber = 0;
let explainController = null;

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

const tick = (pathData = PASSED_PATH) => {
  const svg = icon(pathData);
  svg.classList.add("tick");
  return svg;
};

const plural = (count, one, many) => (count === 1 ? one : many);

// Tokens as bold text, separated by commas.
function strongList(tokens) {
  return tokens.flatMap((token, index) => (index ? [", ", element("strong", "", token)] : [element("strong", "", token)]));
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Text with each whole occurrence of `token` set as code: ptr is marked, but not
// the ptr inside ptr:mail.example.
function withCode(tag, className, text, token) {
  const node = element(tag, className);
  if (token === null) {
    node.textContent = text;
    return node;
  }
  const parts = text.split(new RegExp(`(?<![\\w:.=-])${escapeRegExp(token)}(?![\\w:=-])`));
  parts.forEach((part, index) => {
    if (index) node.append(element("code", "", token));
    if (part) node.append(part);
  });
  return node;
}

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
  const body = element("div", "finding-body");
  const meta = element("p", "finding-meta");
  meta.append(
    element("span", "severity", SEVERITY_LABELS[finding.severity]),
    element("span", "finding-code", finding.code),
  );
  body.append(meta, element("h3", "", finding.title));
  if (finding.evidence !== null) {
    const quote = element("p", "rests-on");
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

function showExplainPart(visible) {
  for (const id of EXPLAIN_PARTS) document.getElementById(id).hidden = id !== visible;
}

function step(text, status, detail = "") {
  const item = element("li", "step");
  item.dataset.status = status;
  const mark = element("span", "step-mark");
  mark.append(status === "done" ? tick() : element("span", "step-dot"));
  item.append(mark, element("span", "", text), element("span", "step-detail", detail));
  return item;
}

function showExplaining(view) {
  const count = view.findings.length;
  const lookups = view.spf_lookup_count > view.max_spf_lookups
    ? `over ${view.max_spf_lookups} lookups`
    : `${view.spf_lookup_count} of ${view.max_spf_lookups} lookups`;
  document.getElementById("steps").replaceChildren(
    step("Fetched records and followed SPF includes", "done", lookups),
    step("Audited against RFC 7208 and 7489", "done", `${count} ${plural(count, "finding", "findings")}`),
    step("Asking Claude to explain them", "active"),
    step("Checking each claim against your records", "waiting"),
  );
  showExplainPart("steps");
}

function showExplainStopped(title, reason, retryLabel, retry) {
  document.getElementById("explain-stopped-title").textContent = title;
  document.getElementById("explain-stopped-reason").textContent = reason;
  const button = document.getElementById("explain-retry");
  button.textContent = retryLabel;
  button.onclick = retry;
  showExplainPart("explain-stopped");
}

function showRecordsChanged(domain) {
  showExplainStopped(
    "Your records changed after the audit.",
    "The explanations were written for findings other than the ones shown, so they are left out. Check the domain again to audit the records as they are now.",
    "Check domain again",
    () => check(domain),
  );
}

function matchesAudit(explained, audited) {
  return explained.domain === audited.domain
    && explained.findings.length === audited.findings.length
    && explained.findings.every((entry, index) => entry.code === audited.findings[index].code
      && entry.evidence === audited.findings[index].evidence);
}

function renderSummary(view) {
  const summary = document.getElementById("summary");
  if (view.summary === null) {
    const tokens = view.summary_unsupported_tokens;
    summary.replaceChildren(
      element("span", "summary-by", "Claude’s summary was removed"),
      "It quoted ", ...strongList(tokens), `, which ${plural(tokens.length, "is", "are")} not in your records.`,
    );
  } else {
    summary.replaceChildren(element("span", "summary-by", "Claude’s summary"), view.summary);
  }
  showExplainPart(view.summary === "" ? null : "summary");
}

function checkedLine(isPassed, nodes) {
  const line = element("p", isPassed ? "checked" : "checked is-dropped");
  const text = element("span");
  text.append(...nodes);
  line.append(tick(isPassed ? PASSED_PATH : DROPPED_PATH), text);
  return line;
}

function renderExplained(entry, body) {
  const fix = withCode("p", "fix", entry.fix, entry.evidence);
  fix.prepend(element("span", "fix-label", "To fix"));
  body.append(withCode("p", "", entry.explanation, entry.evidence), fix);
  return checkedLine(true, entry.evidence === null
    ? ["Checked. Names this finding and quotes nothing that is not in your records."]
    : ["Checked. Quotes ", element("strong", "", entry.evidence), ", the value this finding rests on, and nothing that is not in your records."]);
}

function renderRemoved(entry, body) {
  const tokens = entry.unsupported_tokens;
  const isAre = plural(tokens.length, "is", "are");
  const withheld = element("div", "withheld");
  withheld.append(element("span", "withheld-title", "Explanation removed"));
  if (tokens.length) {
    withheld.append("Claude’s explanation named ", ...strongList(tokens), `, which ${isAre} not in your records. Claude was sent its answer back once with the problems listed, and this explanation still failed the check, so it was removed.`);
  } else {
    withheld.append("Claude gave no explanation of this finding that passed the claim check, even after it was sent its answer back once with the problems listed.");
  }
  withheld.append(" The finding stands: it comes from the auditor, not from Claude.");
  body.append(withheld);
  return checkedLine(false, tokens.length
    ? ["Failed the check after one retry. Named ", ...strongList(tokens), `, which ${isAre} not in your records.`]
    : ["Failed the check after one retry."]);
}

function renderMethod(view) {
  const explainedBy = document.getElementById("method-explained-by");
  const heldTo = document.getElementById("method-held-to");
  document.getElementById("method-held").hidden = view === null;
  document.getElementById("method").hidden = false;
  if (view === null) {
    explainedBy.textContent = "Nobody. With no findings there was nothing to explain, so Claude was not asked.";
    return;
  }
  explainedBy.replaceChildren(element("code", "", view.model), ", shown your records and the auditor’s findings and asked to write one plain explanation of each.");
  const total = view.findings.length;
  const passed = view.findings.filter((entry) => entry.explanation !== null).length;
  const extra = view.extra_claims_removed;
  heldTo.replaceChildren(
    element("strong", "", `${passed} of ${total}`),
    ` ${plural(total, "explanation", "explanations")} passed the claim check. Each one shown names a finding the audit made, quotes its record value exactly, and quotes no value that is not in your records.`,
  );
  // A clean first answer is shown as it came, so anything removed means the
  // answer had already been sent back once.
  if (passed < total || view.summary === null || extra > 0) {
    heldTo.append(" Claude’s first answer failed the check, so it was sent back once with the problems listed, and whatever still failed was removed.");
  }
  if (extra > 0) {
    heldTo.append(` ${extra} further ${plural(extra, "claim", "claims")} matched no finding on this page and ${plural(extra, "was", "were")} removed.`);
  }
}

function setFindingsHeading(isExplained) {
  document.getElementById("findings-title").textContent = isExplained ? "What each problem lets someone do" : "What the audit found";
  document.getElementById("findings-note").textContent = isExplained
    ? "The auditor decided what is wrong. Claude wrote the explanations, and each one was checked against your records before it reached this page."
    : "Fixed rules from RFC 7208 (SPF) and RFC 7489 (DMARC), run as code. No language model decides what is wrong.";
}

function renderExplanation(view) {
  renderSummary(view);
  for (const entry of view.findings) {
    const item = document.getElementById(`finding-${entry.number}`);
    const body = item.querySelector(".finding-body");
    body.querySelector(".rests-on")?.remove();
    item.append(entry.explanation === null ? renderRemoved(entry, body) : renderExplained(entry, body));
  }
  setFindingsHeading(true);
  renderMethod(view);
}

async function explainFindings(audited, number) {
  explainController = new AbortController();
  const signal = AbortSignal.any([explainController.signal, AbortSignal.timeout(EXPLAIN_TIMEOUT_MS)]);
  const askAgain = () => explainFindings(audited, number);
  showExplaining(audited);
  let response;
  let explained;
  try {
    response = await post("/api/explain", audited.domain, signal);
    explained = response.ok ? await response.json() : null;
  } catch (error) {
    if (number !== checkNumber) return;
    if (error.name === "TimeoutError") {
      showExplainStopped("Claude took too long to explain the findings.", `No answer came within ${EXPLAIN_TIMEOUT_MS / 60000} minutes.`, "Ask Claude again", askAgain);
    } else {
      showExplainStopped("The page lost contact with esx before the explanations arrived.", "Check that esx serve is still running in your terminal, then ask again.", "Ask Claude again", askAgain);
    }
    return;
  }
  if (number !== checkNumber) return;
  if (explained) {
    if (matchesAudit(explained, audited)) renderExplanation(explained);
    else showRecordsChanged(audited.domain);
    return;
  }
  const error = await readError(response);
  if (number !== checkNumber) return;
  if (response.status === 429) {
    showExplainStopped(
      "Claude is already explaining another check.",
      "esx writes one explanation at a time, which keeps the cost of the API bounded. Wait for the other check, in this tab or another, to finish, then ask again.",
      "Ask Claude again",
      askAgain,
    );
  } else if (response.status === 404 || response.status === 409) {
    showRecordsChanged(audited.domain);
  } else if (response.status === 502) {
    showExplainStopped("The explanations could not be written.", asSentence(error), "Ask Claude again", askAgain);
  } else {
    showExplainStopped("esx failed while writing the explanations.", asSentence(error), "Ask Claude again", askAgain);
  }
}

function renderAudit(view, number) {
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

  setFindingsHeading(false);

  show("verdict", "records", ...(hasFindings ? ["findings"] : ["method"]));
  // Reading layout restarts the animation for a second check of the same page.
  void slip.offsetWidth;
  slip.classList.add("is-drawing");
  title.focus();
  if (hasFindings) {
    explainFindings(view, number);
  } else {
    showExplainPart(null);
    renderMethod(null);
  }
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

function post(path, domain, signal) {
  return fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain }),
    signal,
  });
}

async function check(domain) {
  const number = ++checkNumber;
  explainController?.abort();
  showFieldError("");
  setBusy(true);
  document.getElementById("checking-domain").textContent = domain;
  show("checking");
  document.getElementById("checking-title").focus();
  let response;
  try {
    response = await post("/api/audit", domain, AbortSignal.timeout(REQUEST_TIMEOUT_MS));
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
    renderAudit(view, number);
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

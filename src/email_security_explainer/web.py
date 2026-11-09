"""Describe an audit for the web page: a headline, the records with each finding
marked on its token, and the findings in severity order. No I/O."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from email_security_explainer import dmarc, spf
from email_security_explainer.audit import DnsRecords, audit
from email_security_explainer.domain import DomainName
from email_security_explainer.findings import Finding, FindingCode, RecordKind, Severity

FINDING_TITLES: dict[FindingCode, str] = {
    FindingCode.SPF_MISSING: "No SPF record lists your mail servers",
    FindingCode.SPF_MULTIPLE: "More than one SPF record, so receivers use none",
    FindingCode.SPF_SYNTAX: "A term receivers cannot read breaks SPF",
    FindingCode.SPF_ALL_PASS: "Every server on the internet may send as you",
    FindingCode.SPF_ALL_NEUTRAL: "Unknown senders are neither allowed nor refused",
    FindingCode.SPF_NO_ALL: "Nothing says what to do with unknown senders",
    FindingCode.SPF_SOFTFAIL: "Unknown senders get a warning, not a refusal",
    FindingCode.SPF_PTR: "An outdated check receivers may skip",
    FindingCode.SPF_LOOKUP_LIMIT: "Too many DNS lookups break SPF",
    FindingCode.SPF_TARGET_UNUSABLE: "An include points at no usable SPF record",
    FindingCode.DMARC_MISSING: "No DMARC policy protects your domain",
    FindingCode.DMARC_MULTIPLE: "More than one DMARC record, so receivers use none",
    FindingCode.DMARC_SYNTAX: "A DMARC tag receivers cannot read",
    FindingCode.DMARC_POLICY_NONE: "Forged mail is delivered anyway",
    FindingCode.DMARC_PARTIAL_PCT: "The policy covers only part of the forged mail",
    FindingCode.DMARC_SUBDOMAIN_NONE: "Forged mail from subdomains is delivered",
    FindingCode.DMARC_NO_RUA: "Nobody receives the reports",
}

# The first cause present names why forged mail gets through. When DMARC does
# not enforce and no partial percentage explains it, one of the DMARC causes
# is always among the findings.
_OPEN_CAUSES = (
    (FindingCode.SPF_ALL_PASS, "Your SPF record lets every server on the internet send as you."),
    (
        FindingCode.DMARC_MISSING,
        "You publish no DMARC record, so inboxes are never told to refuse forged mail.",
    ),
    (
        FindingCode.DMARC_MULTIPLE,
        "You publish more than one DMARC record, so inboxes ignore all of them.",
    ),
    (FindingCode.DMARC_POLICY_NONE, "Your DMARC policy tells inboxes to deliver forged mail."),
    (FindingCode.DMARC_SYNTAX, "Your DMARC record has no valid policy, so inboxes ignore it."),
)
# RFC 7208 section 2.6.7: each of these is a permanent error, which receivers
# treat as a failed SPF check for every message.
_BROKEN_SPF_CAUSES = (
    (
        FindingCode.SPF_MISSING,
        "You publish no SPF record, so your mail passes only when it carries a DKIM signature.",
    ),
    (
        FindingCode.SPF_MULTIPLE,
        "You publish more than one SPF record, so every SPF check of your mail fails.",
    ),
    (
        FindingCode.SPF_SYNTAX,
        "Your SPF record has a term receivers cannot read, so every SPF check of your mail fails.",
    ),
    (
        FindingCode.SPF_LOOKUP_LIMIT,
        "Your SPF record needs more than 10 DNS lookups, so every SPF check of your mail fails.",
    ),
    (
        FindingCode.SPF_TARGET_UNUSABLE,
        "Your SPF record includes a domain with no usable SPF record, "
        "so every SPF check of your mail fails.",
    ),
)
_ALL_CODES = frozenset(
    {FindingCode.SPF_ALL_PASS, FindingCode.SPF_ALL_NEUTRAL, FindingCode.SPF_SOFTFAIL}
)
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Severity)}

SpanKind = Literal["version", "text", "mark", "caret", "absent"]


@dataclass(frozen=True, slots=True)
class Headline:
    title: str
    cause: str


@dataclass(frozen=True, slots=True)
class Span:
    """A run of record text. A `mark` is a token a finding rests on and a
    `caret` shows where something is missing; both carry the finding's number."""

    kind: SpanKind
    text: str
    finding: int | None = None

    def __post_init__(self) -> None:
        assert (self.finding is not None) == (self.kind in {"mark", "caret"}), self


Line = tuple[Span, ...]


@dataclass(frozen=True, slots=True)
class ChainRow:
    """An SPF record reached through `via`, an include or redirect term."""

    via: str
    spans: Line


@dataclass(frozen=True, slots=True)
class MarkedRecords:
    spf: tuple[Line, ...]
    spf_chain: tuple[ChainRow, ...]
    dmarc: tuple[Line, ...]


@dataclass(frozen=True, slots=True)
class FindingView:
    number: int
    code: FindingCode
    severity: Severity
    record: RecordKind
    evidence: str | None
    title: str


@dataclass(frozen=True, slots=True)
class AuditView:
    domain: str
    headline: Headline
    findings: tuple[FindingView, ...]
    records: MarkedRecords
    spf_lookup_count: int
    max_spf_lookups: int


def audit_view(records: DnsRecords) -> AuditView:
    findings = sorted(audit(records), key=lambda finding: _SEVERITY_RANK[finding.severity])
    is_dmarc_enforcing = dmarc.assess(records.dmarc_txt).is_enforcing
    return AuditView(
        domain=records.domain,
        headline=headline(records.domain, findings, is_dmarc_enforcing=is_dmarc_enforcing),
        findings=tuple(
            FindingView(
                number,
                finding.code,
                finding.severity,
                finding.record,
                finding.evidence,
                FINDING_TITLES[finding.code],
            )
            for number, finding in enumerate(findings, start=1)
        ),
        records=marked_records(records, findings),
        spf_lookup_count=spf.walk_lookups(records.apex_txt, records.spf_by_domain).lookup_count,
        max_spf_lookups=spf.MAX_SPF_LOOKUPS,
    )


def headline(
    domain: DomainName, findings: Sequence[Finding], *, is_dmarc_enforcing: bool
) -> Headline:
    """The worst thing the findings let happen, in the order: anyone can send
    as the domain, some forged mail gets through, subdomains are open, the
    owner's own mail may fail SPF, and otherwise forged mail is turned away."""
    evidence_by_code: dict[FindingCode, str | None] = {}
    for finding in findings:
        evidence_by_code.setdefault(finding.code, finding.evidence)
    is_partial = FindingCode.DMARC_PARTIAL_PCT in evidence_by_code
    if FindingCode.SPF_ALL_PASS in evidence_by_code or not (is_dmarc_enforcing or is_partial):
        cause = next((text for code, text in _OPEN_CAUSES if code in evidence_by_code), None)
        assert cause is not None, f"DMARC does not enforce, yet no finding says why: {findings}"
        return Headline(f"Anyone can send email as {domain}.", cause)
    if is_partial:
        return Headline(
            f"Some forged email as {domain} gets through.",
            f"Your DMARC record sets {evidence_by_code[FindingCode.DMARC_PARTIAL_PCT]}, "
            "so its policy covers only part of the mail that fails.",
        )
    if FindingCode.DMARC_SUBDOMAIN_NONE in evidence_by_code:
        return Headline(
            f"Anyone can send email as a subdomain of {domain}.",
            f"Your DMARC record sets {evidence_by_code[FindingCode.DMARC_SUBDOMAIN_NONE]}, "
            f"so inboxes deliver forged mail from addresses such as billing.{domain}.",
        )
    cause = next((text for code, text in _BROKEN_SPF_CAUSES if code in evidence_by_code), None)
    if cause is not None:
        return Headline(f"Your own email from {domain} may be refused.", cause)
    return Headline(
        f"Inboxes are told to turn away forged email as {domain}.",
        "The problems below are worth fixing, but none lets forged mail through."
        if findings
        else "The audit found no problems in SPF or DMARC.",
    )


def marked_records(records: DnsRecords, findings: Sequence[Finding]) -> MarkedRecords:
    """Split each record into spans, marking the token each finding rests on.

    Findings are numbered from 1 in the order given. A token is matched as a
    whole term, and each token carries at most one mark. A finding with no
    evidence gets a caret after the last record of its kind; evidence that
    matches no free token is left unmarked.
    """
    spf_lines = [_spf_spans(record) for record in spf.select_records(records.apex_txt)] or [
        [Span("absent", "No SPF record")]
    ]
    dmarc_lines = [_dmarc_spans(record) for record in dmarc.select_records(records.dmarc_txt)] or [
        [Span("absent", "No DMARC record")]
    ]
    chain = _chain(records)
    deciding_domains = _redirect_chain(records)
    for number, finding in enumerate(findings, start=1):
        own_lines = spf_lines if finding.record is RecordKind.SPF else dmarc_lines
        if finding.evidence is None:
            own_lines[-1].append(Span("caret", "", number))
            continue
        searched = list(own_lines)
        if finding.code is FindingCode.SPF_TARGET_UNUSABLE:
            searched += [spans for _domain, _via, spans in chain]
        elif finding.code in _ALL_CODES:
            searched += [spans for domain, _via, spans in chain if domain in deciding_domains]
        _mark_first_free_token(searched, finding.evidence, number)
    return MarkedRecords(
        spf=tuple(tuple(line) for line in spf_lines),
        spf_chain=tuple(ChainRow(via, tuple(spans)) for _domain, via, spans in chain),
        dmarc=tuple(tuple(line) for line in dmarc_lines),
    )


def _spf_spans(record: str) -> list[Span]:
    # Split as spf.parse_record does, on single spaces, keeping the spaces.
    version, *terms = record.split(" ")
    spans = [Span("version", version)]
    for term in terms:
        spans.append(Span("text", " "))
        if term:
            spans.append(Span("text", term))
    return spans


def _dmarc_spans(record: str) -> list[Span]:
    # Split as dmarc._parse_tags does: at semicolons, each tag without the
    # whitespace around it.
    version, separator, tags_text = record.partition(";")
    spans = [Span("version", version + separator)]
    for index, raw_segment in enumerate(tags_text.split(";") if separator else []):
        if index:
            spans.append(Span("text", ";"))
        tag = raw_segment.strip()
        leading = raw_segment[: len(raw_segment) - len(raw_segment.lstrip())]
        trailing = raw_segment[len(raw_segment.rstrip()) :] if tag else ""
        spans += [Span("text", text) for text in (leading, tag, trailing) if text]
    return spans


def _chain(records: DnsRecords) -> list[tuple[str, str, list[Span]]]:
    """The fetched include and redirect targets in the order a reader meets
    them, each once, as (domain, term that reached it, spans)."""
    rows: list[tuple[str, str, list[Span]]] = []
    seen: set[str] = set()
    pending = list(reversed(spf.followed_terms(records.apex_txt)))
    # Each fetched target is expanded once, so the loop ends after at most
    # len(spf_by_domain) expansions.
    while pending:
        term = pending.pop()
        target = spf.normalise_target(term.value)
        if target in seen or target not in records.spf_by_domain:
            continue
        seen.add(target)
        txt = records.spf_by_domain[target]
        lines = [_spf_spans(record) for record in spf.select_records(txt)]
        rows += [(target, term.text, line) for line in lines or [[Span("absent", "No SPF record")]]]
        pending += reversed(spf.followed_terms(txt))
    return rows


def _redirect_chain(records: DnsRecords) -> set[str]:
    """The targets reached from the apex through redirects alone: the records
    one of which holds the `all` that decides the SPF result."""
    domains: set[str] = set()
    txt = records.apex_txt
    for _ in range(spf.MAX_SPF_LOOKUPS + 1):
        redirect = next((term for term in spf.followed_terms(txt) if term.is_modifier), None)
        if redirect is None:
            break
        target = spf.normalise_target(redirect.value)
        domains.add(target)
        txt = records.spf_by_domain.get(target, ())
    return domains


def _mark_first_free_token(lines: Sequence[list[Span]], evidence: str, number: int) -> None:
    for line in lines:
        for index, span in enumerate(line):
            if span.kind == "text" and span.text == evidence:
                line[index] = Span("mark", evidence, number)
                return

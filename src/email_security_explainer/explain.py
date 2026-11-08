"""Ask Claude to explain the audit findings, then hold its answer to them."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import assert_never

import anthropic
import pydantic
from anthropic.types import JSONOutputFormatParam

from email_security_explainer import spf
from email_security_explainer.audit import DnsRecords
from email_security_explainer.claims import CheckReport, ClaimCheck, Verdict, check
from email_security_explainer.findings import Finding, FindingCode
from email_security_explainer.schema import Explanation

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_OUTPUT_TOKENS = 16000
REQUEST_TIMEOUT_SECONDS = 120.0
MAX_API_RETRIES = 2

_FINDINGS_TASK = """\
You explain email security problems to the owner of a domain who has never \
heard of SPF or DMARC. An automated auditor has already decided what is wrong; \
your job is to explain its findings, not to look for new ones.

Write one claim per finding, in the order given, and no others. Copy each \
finding's code and record exactly. Set quoted_value to the finding's evidence \
exactly as given, or null when the evidence is "none"."""

_RAW_RECORDS_TASK = """\
You explain email security problems to the owner of a domain who has never \
heard of SPF or DMARC. You are shown the domain's SPF and DMARC records; your \
job is to find which of the problems listed below they have, and explain each one.

Write one claim for each problem the records have, and none for a problem they \
do not have. Set record to the record the problem is in. Set quoted_value to \
the record token the problem rests on, copied exactly from the record, or null \
where the list says the token is null.

The problems, by code:"""

# The auditor's rules in words, so a model shown only the records is held to
# the same rulebook as the auditor rather than to its own idea of a problem.
_PROBLEM_BY_CODE = {
    FindingCode.SPF_MISSING: "no TXT record at the domain starts with v=spf1. Token: null.",
    FindingCode.SPF_MULTIPLE: "more than one TXT record starts with v=spf1. Token: null.",
    FindingCode.SPF_SYNTAX: "the SPF record has a term SPF syntax does not allow; one claim per "
    "such term. Token: the term. A missing, duplicated or malformed SPF record has no other "
    "SPF problem.",
    FindingCode.SPF_ALL_PASS: "the all term passes every sender: +all, or all with no "
    "qualifier. Token: the all term.",
    FindingCode.SPF_ALL_NEUTRAL: "the all term is ?all. Token: ?all.",
    FindingCode.SPF_NO_ALL: "the SPF record has neither an all term nor a redirect. Token: null.",
    FindingCode.SPF_SOFTFAIL: "the all term is ~all and DMARC does not enforce: DMARC is "
    "missing or duplicated, has no valid p tag, has p=none, or has pct below 100. Token: ~all.",
    FindingCode.SPF_PTR: "the SPF record uses the ptr mechanism; one claim per ptr term. "
    "Token: the term.",
    FindingCode.SPF_LOOKUP_LIMIT: "more than 10 DNS-querying terms (include, a, mx, ptr, "
    "exists, and redirect when the record has no all term) across the SPF record and every "
    "record it includes or redirects to. Token: null.",
    FindingCode.SPF_TARGET_UNUSABLE: "an include or redirect points at a domain without "
    "exactly one SPF record free of syntax errors. Token: the include or redirect term.",
    FindingCode.DMARC_MISSING: "no TXT record at _dmarc.<domain> starts with v=DMARC1. "
    "Token: null.",
    FindingCode.DMARC_MULTIPLE: "more than one DMARC record. Token: null. A missing or "
    "duplicated DMARC record has no other DMARC problem.",
    FindingCode.DMARC_SYNTAX: "a tag has no = or appears twice (token: the tag as written); "
    "p is not none, quarantine or reject (token: the p tag, or null when there is no p tag, "
    "and then the record has no other DMARC problem); pct is not a whole number from 0 to 100 "
    "(token: the pct tag); or sp is not one of the three policies (token: the sp tag).",
    FindingCode.DMARC_POLICY_NONE: "p=none. Token: the p tag.",
    FindingCode.DMARC_PARTIAL_PCT: "pct below 100 with p=quarantine or p=reject. Token: the "
    "pct tag.",
    FindingCode.DMARC_SUBDOMAIN_NONE: "sp=none with p=quarantine or p=reject. Token: the sp tag.",
    FindingCode.DMARC_NO_RUA: "the DMARC record has no rua tag. Token: null.",
}

_STYLE = """\
In each explanation, start from what an impersonator could do: send mail that \
appears to come from the domain and still reach inboxes. Explain the record's \
job in plain words the first time it comes up, for example "SPF, a list the \
domain publishes of the servers allowed to send its mail". Quote a record \
value such as ~all or p=none only if it appears in the records shown; do not \
mention values the records do not contain.

In each fix, say exactly what to change in the record. A fix may name values \
the records do not contain yet.

The summary is two or three sentences on how exposed the domain is overall. It \
quotes no record values.

Use UK English and plain sentences. No headings, lists or emphasis inside the \
text fields."""

SYSTEM_PROMPT = f"{_FINDINGS_TASK}\n\n{_STYLE}"
RAW_RECORDS_SYSTEM_PROMPT = "\n".join(
    [
        _RAW_RECORDS_TASK,
        *(f"- {code}: {problem}" for code, problem in _PROBLEM_BY_CODE.items()),
        "",
        _STYLE,
    ]
)

Generate = Callable[[str], Explanation]
"""Sends one request to a model and returns its explanation.

Raises ExplanationError when the model gives no explanation that fits the schema.
"""


class ExplanationError(Exception):
    """The model returned no explanation that fits the schema."""


@dataclass(frozen=True, slots=True)
class ExplainResult:
    """`explanation` keeps only the parts that passed the claim check; `report`
    is the check of the model's last answer before anything was dropped."""

    explanation: Explanation
    report: CheckReport


def explain(
    domain: str, findings: Sequence[Finding], records: DnsRecords, generate: Generate
) -> ExplainResult:
    """Explain `findings`, with one repair round if the first answer fails the check.

    Raises ExplanationError from `generate`.
    """
    request = findings_request(domain, findings, records)
    return check_and_repair(request, generate(request), findings, records, generate)


def check_and_repair(
    request: str,
    explanation: Explanation,
    findings: Sequence[Finding],
    records: DnsRecords,
    generate: Generate,
) -> ExplainResult:
    """Check `explanation`, the answer to `request`; if it fails, ask `generate`
    once to repair it, then drop whatever still fails.

    Raises ExplanationError from `generate`.
    """
    report = check(findings, explanation, records)
    if not report.is_clean:
        explanation = generate(_repair_request(request, explanation, report))
        report = check(findings, explanation, records)
    return ExplainResult(_passed_parts(explanation, report), report)


def claude_generator(
    client: anthropic.Anthropic, model: str, system_prompt: str = SYSTEM_PROMPT
) -> Generate:
    output_format = JSONOutputFormatParam(
        type="json_schema", schema=anthropic.transform_schema(Explanation)
    )

    def generate(request: str) -> Explanation:
        message = client.messages.create(
            model=model,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": request}],
            output_config={"format": output_format},
        )
        if message.stop_reason == "refusal":
            category = message.stop_details.category if message.stop_details else None
            raise ExplanationError(f"{model} declined to explain (category: {category})")
        if message.stop_reason != "end_turn":
            raise ExplanationError(f"{model} stopped before finishing: {message.stop_reason}")
        text = "".join(block.text for block in message.content if block.type == "text")
        try:
            return Explanation.model_validate_json(text)
        except pydantic.ValidationError as err:
            raise ExplanationError(f"{model} returned output that does not fit the schema") from err

    return generate


def findings_request(domain: str, findings: Sequence[Finding], records: DnsRecords) -> str:
    """The request to pair with SYSTEM_PROMPT: the records and the findings."""
    lines = [raw_records_request(domain, records), "", "Findings:"]
    lines += [
        f"{number}. {finding.code} ({finding.record} record, {finding.severity} severity), "
        f"evidence: {finding.evidence or 'none'}"
        for number, finding in enumerate(findings, start=1)
    ]
    if not findings:
        lines.append("none")
    return "\n".join(lines)


def raw_records_request(domain: str, records: DnsRecords) -> str:
    """The request to pair with RAW_RECORDS_SYSTEM_PROMPT: the records alone."""
    lines = [f"Domain: {domain}", "", "Records:"]
    lines += _record_lines(f"SPF at {domain}", spf.select_records(records.apex_txt))
    lines += _record_lines(f"DMARC at _dmarc.{domain}", records.dmarc_txt)
    for target, txt in sorted(records.spf_by_domain.items()):
        label = f"SPF at {target}, reached by include or redirect"
        lines += _record_lines(label, spf.select_records(txt))
    return "\n".join(lines)


def _record_lines(label: str, records: Sequence[str]) -> list[str]:
    return [f"{label}: {record}" for record in records] or [f"{label}: none"]


def _repair_request(request: str, explanation: Explanation, report: CheckReport) -> str:
    problems = [
        problem
        for number, claim_check in enumerate(report.claim_checks, start=1)
        if (problem := _claim_problem(number, claim_check)) is not None
    ]
    problems += [
        f"No claim explains {finding.code} with evidence {finding.evidence or 'none'}."
        for finding in report.missed
    ]
    if report.summary_unsupported_tokens:
        tokens = ", ".join(report.summary_unsupported_tokens)
        problems.append(f"The summary quotes {tokens}; the summary must quote no record values.")
    return "\n".join(
        [
            request,
            "",
            "Your previous answer was:",
            explanation.model_dump_json(),
            "",
            "A checker compared it with the findings and found these problems:",
            *(f"- {problem}" for problem in problems),
            "",
            "Return the whole explanation again with every problem fixed.",
        ]
    )


def _claim_problem(number: int, claim_check: ClaimCheck) -> str | None:
    claim = claim_check.claim
    prefix = f"Claim {number} ({claim.finding_code})"
    match claim_check.verdict:
        case Verdict.ACCEPTED:
            return None
        case Verdict.INVENTED:
            return f"{prefix} explains a problem the audit did not find. Remove it."
        case Verdict.WRONG_RECORD:
            return f"{prefix} names the {claim.record} record; this finding is about another."
        case Verdict.WRONG_DETAIL:
            return f"{prefix} quotes {claim.quoted_value!r}, which is not the finding's evidence."
        case Verdict.DUPLICATE:
            return f"{prefix} repeats a finding another claim already explains. Remove it."
        case Verdict.UNSUPPORTED_TOKEN:
            tokens = ", ".join(claim_check.unsupported_tokens)
            return f"{prefix} quotes {tokens}, which the records do not contain."
        case _:
            assert_never(claim_check.verdict)


def _passed_parts(explanation: Explanation, report: CheckReport) -> Explanation:
    return Explanation(
        summary="" if report.summary_unsupported_tokens else explanation.summary,
        claims=[
            claim_check.claim for claim_check in report.claim_checks if claim_check.is_accepted
        ],
    )

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
from email_security_explainer.findings import Finding
from email_security_explainer.schema import Explanation

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_OUTPUT_TOKENS = 16000
REQUEST_TIMEOUT_SECONDS = 120.0
MAX_API_RETRIES = 2

SYSTEM_PROMPT = """\
You explain email security problems to the owner of a domain who has never \
heard of SPF or DMARC. An automated auditor has already decided what is wrong; \
your job is to explain its findings, not to look for new ones.

Write one claim per finding, in the order given, and no others. Copy each \
finding's code and record exactly. Set quoted_value to the finding's evidence \
exactly as given, or null when the evidence is "none".

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
    request = _request(domain, findings, records)
    explanation = generate(request)
    report = check(findings, explanation, records)
    if not report.is_clean:
        explanation = generate(_repair_request(request, explanation, report))
        report = check(findings, explanation, records)
    return ExplainResult(_passed_parts(explanation, report), report)


def claude_generator(client: anthropic.Anthropic, model: str) -> Generate:
    output_format = JSONOutputFormatParam(
        type="json_schema", schema=anthropic.transform_schema(Explanation)
    )

    def generate(request: str) -> Explanation:
        message = client.messages.create(
            model=model,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=SYSTEM_PROMPT,
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


def _request(domain: str, findings: Sequence[Finding], records: DnsRecords) -> str:
    lines = [f"Domain: {domain}", "", "Records:"]
    lines += _record_lines(f"SPF at {domain}", spf.select_records(records.apex_txt))
    lines += _record_lines(f"DMARC at _dmarc.{domain}", records.dmarc_txt)
    for target, txt in sorted(records.spf_by_domain.items()):
        label = f"SPF at {target}, reached by include or redirect"
        lines += _record_lines(label, spf.select_records(txt))
    lines += ["", "Findings:"]
    lines += [
        f"{number}. {finding.code} ({finding.record} record, {finding.severity} severity), "
        f"evidence: {finding.evidence or 'none'}"
        for number, finding in enumerate(findings, start=1)
    ]
    if not findings:
        lines.append("none")
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

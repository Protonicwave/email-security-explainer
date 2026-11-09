"""Command-line entry point: `esx audit`, `esx explain`, `esx eval` and `esx case`."""

import argparse
import dataclasses
import io
import json
import sys
import textwrap
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import anthropic

from email_security_explainer.audit import audit
from email_security_explainer.claims import CheckReport, ClaimCheck
from email_security_explainer.dns_fetch import DnsLookupError, TxtLookup, fetch_records, lookup_txt
from email_security_explainer.domain import parse_domain
from email_security_explainer.evaluate import (
    ConditionSummary,
    Failure,
    Run,
    dump_case,
    evaluate,
    load_cases,
    score,
    summarise,
)
from email_security_explainer.explain import (
    DEFAULT_MODEL,
    MAX_API_RETRIES,
    RAW_RECORDS_SYSTEM_PROMPT,
    REQUEST_TIMEOUT_SECONDS,
    SYSTEM_PROMPT,
    ExplainResult,
    ExplanationError,
    Generate,
    claude_generator,
    explain,
)
from email_security_explainer.findings import Finding

EXIT_OK = 0
EXIT_FAILURE = 1
TEXT_WIDTH_CHARACTERS = 80
MAX_REPEATS = 10
DEFAULT_CASES_PATH = "cases/cases.json"
DEFAULT_RESULTS_PATH = "eval-results.jsonl"

GeneratorFactory = Callable[[str, str], Generate]
"""Builds a Generate from a model name and a system prompt."""


def _claude_generator_for(model: str, system_prompt: str) -> Generate:
    client = anthropic.Anthropic(timeout=REQUEST_TIMEOUT_SECONDS, max_retries=MAX_API_RETRIES)
    return claude_generator(client, model, system_prompt)


def main(
    argv: Sequence[str] | None = None,
    lookup: TxtLookup = lookup_txt,
    generator_for: GeneratorFactory = _claude_generator_for,
) -> int:
    for stream in (sys.stdout, sys.stderr):
        # Redirected output on Windows uses the ANSI code page, which cannot hold
        # every character a TXT record, a model's answer or a typed domain may contain.
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8")
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "eval":
            output = _evaluate(args, generator_for)
        elif args.command == "case":
            output = dump_case(fetch_records(parse_domain(args.domain), lookup))
        else:
            output = _audit_or_explain(args, lookup, generator_for)
    except (
        OSError,
        ValueError,
        DnsLookupError,
        ExplanationError,
        anthropic.AnthropicError,
    ) as err:
        print(f"esx: {err}", file=sys.stderr)
        return EXIT_FAILURE
    print(output)
    return EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="esx", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    audit_command = commands.add_parser("audit", help="list SPF and DMARC gaps for a domain")
    audit_command.add_argument("domain", help="domain to audit, such as example.com")
    audit_command.add_argument("--json", action="store_true", help="print findings as JSON")
    explain_command = commands.add_parser(
        "explain", help="explain a domain's SPF and DMARC gaps in plain English"
    )
    explain_command.add_argument("domain", help="domain to explain, such as example.com")
    _add_model_option(explain_command)
    eval_command = commands.add_parser(
        "eval", help="score explanations from three conditions on a case corpus"
    )
    eval_command.add_argument(
        "--cases", default=DEFAULT_CASES_PATH, help=f"case file (default: {DEFAULT_CASES_PATH})"
    )
    eval_command.add_argument(
        "--repeats",
        type=_repeat_count,
        default=1,
        help=f"times to run every case, 1 to {MAX_REPEATS} (default: 1)",
    )
    eval_command.add_argument(
        "--output",
        default=DEFAULT_RESULTS_PATH,
        help=f"where to write every run as JSON Lines (default: {DEFAULT_RESULTS_PATH})",
    )
    _add_model_option(eval_command)
    case_command = commands.add_parser(
        "case", help="print a domain's records as a case for the evaluation corpus"
    )
    case_command.add_argument("domain", help="domain to capture, such as example.com")
    return parser


def _add_model_option(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--model", default=DEFAULT_MODEL, help=f"Claude model to use (default: {DEFAULT_MODEL})"
    )


def _repeat_count(text: str) -> int:
    # Each repeat costs about three model calls per case, so the cap bounds the bill.
    if not (text.isascii() and text.isdigit() and 1 <= int(text) <= MAX_REPEATS):
        raise argparse.ArgumentTypeError(
            f"expected a whole number from 1 to {MAX_REPEATS}, got {text!r}"
        )
    return int(text)


def _audit_or_explain(
    args: argparse.Namespace, lookup: TxtLookup, generator_for: GeneratorFactory
) -> str:
    domain = parse_domain(args.domain)
    records = fetch_records(domain, lookup)
    findings = audit(records)
    if args.command == "audit":
        return _render_json(domain, findings) if args.json else _render_text(domain, findings)
    if not findings:
        return _render_text(domain, findings)
    result = explain(findings, records, generator_for(args.model, SYSTEM_PROMPT))
    return _render_explanation(domain, findings, result)


def _evaluate(args: argparse.Namespace, generator_for: GeneratorFactory) -> str:
    cases = load_cases(Path(args.cases).read_text(encoding="utf-8"))
    from_findings = generator_for(args.model, SYSTEM_PROMPT)
    from_records = generator_for(args.model, RAW_RECORDS_SYSTEM_PROMPT)
    runs: list[Run] = []
    # Opened before the first model call, and each run is written as it finishes,
    # so neither a bad path nor an error that stops the evaluation wastes paid calls.
    with Path(args.output).open("w", encoding="utf-8") as output:
        for run in evaluate(cases, from_findings, from_records, args.repeats):
            progress = f"{run.repeat}  {run.domain}  {run.condition}: {_outcome_text(run.outcome)}"
            print(progress, file=sys.stderr)
            output.write(json.dumps(_run_fields(args.model, run)) + "\n")
            output.flush()
            runs.append(run)
    return _render_summary(summarise(runs))


def _heading(domain: str, findings: list[Finding]) -> str:
    return f"{domain}: {len(findings)} finding{'s' if len(findings) != 1 else ''}"


def _render_text(domain: str, findings: list[Finding]) -> str:
    if not findings:
        return f"{domain}: no findings"
    lines = [_heading(domain, findings)]
    lines += [
        f"  {finding.severity:<6}  {finding.code:<20}  {finding.evidence or ''}".rstrip()
        for finding in findings
    ]
    return "\n".join(lines)


def _render_json(domain: str, findings: list[Finding]) -> str:
    payload = {
        "domain": domain,
        "findings": [
            {
                "code": finding.code,
                "severity": finding.severity,
                "record": finding.record,
                "evidence": finding.evidence,
            }
            for finding in findings
        ],
    }
    return json.dumps(payload, indent=2)


def _render_explanation(domain: str, findings: list[Finding], result: ExplainResult) -> str:
    blocks = [_heading(domain, findings)]
    if result.explanation.summary:
        blocks.append(_wrap(result.explanation.summary, indent=""))
    for claim in result.explanation.claims:
        finding = Finding(claim.finding_code, claim.quoted_value)
        heading = f"{finding.severity}  {finding.code}  {finding.evidence or ''}".rstrip()
        blocks.append("\n".join([heading, _wrap(claim.explanation), _wrap(f"Fix: {claim.fix}")]))
    if result.last_answer_check.missed:
        unexplained = [
            f"  {finding.code}  {finding.evidence or ''}".rstrip()
            for finding in result.last_answer_check.missed
        ]
        blocks.append("\n".join(["Not explained (failed the claim check):", *unexplained]))
    return "\n\n".join(blocks)


def _wrap(text: str, indent: str = "  ") -> str:
    return textwrap.fill(
        text, width=TEXT_WIDTH_CHARACTERS, initial_indent=indent, subsequent_indent=indent
    )


def _render_summary(summaries: list[ConditionSummary]) -> str:
    lines = ["condition         scored  failed  errored  explained  missed  invented  wrong detail"]
    lines += [
        f"{summary.condition:<16}  {summary.scored:>6}  {summary.failed:>6}  "
        f"{summary.errored:>7}  {summary.totals.explained:>9}  {summary.totals.missed:>6}  "
        f"{summary.totals.invented:>8}  {summary.totals.wrong_detail:>12}"
        for summary in summaries
    ]
    return "\n".join(lines)


def _outcome_text(outcome: CheckReport | Failure) -> str:
    if isinstance(outcome, Failure):
        return f"{outcome.kind} ({outcome.message})"
    counts = score(outcome)
    return (
        f"explained {counts.explained}, missed {counts.missed}, "
        f"invented {counts.invented}, wrong detail {counts.wrong_detail}"
    )


def _run_fields(model: str, run: Run) -> dict[str, Any]:
    if isinstance(run.outcome, Failure):
        outcome: dict[str, Any] = {"outcome": run.outcome.kind, "message": run.outcome.message}
    else:
        outcome = {"outcome": "scored", **_report_fields(run.outcome)}
    return {
        "model": model,
        "domain": run.domain,
        "repeat": run.repeat,
        "condition": run.condition,
        **outcome,
    }


def _report_fields(report: CheckReport) -> dict[str, Any]:
    return {
        **dataclasses.asdict(score(report)),
        "claims": [_claim_fields(claim_check) for claim_check in report.claim_checks],
        "missed_findings": [
            {"code": finding.code, "evidence": finding.evidence} for finding in report.missed
        ],
        "summary_unsupported_tokens": list(report.summary_unsupported_tokens),
    }


def _claim_fields(claim_check: ClaimCheck) -> dict[str, Any]:
    claim = claim_check.claim
    fields: dict[str, Any] = {
        "finding_code": claim.finding_code,
        "quoted_value": claim.quoted_value,
        "verdict": claim_check.verdict,
        "unsupported_tokens": list(claim_check.unsupported_tokens),
    }
    # An accepted claim's prose explains no failure, and leaving it out keeps
    # the run file small.
    if not claim_check.is_accepted:
        fields["explanation"] = claim.explanation
    return fields

"""Command-line entry point: `esx audit <domain>` and `esx explain <domain>`."""

import argparse
import json
import sys
import textwrap
from collections.abc import Callable, Sequence

import anthropic

from email_security_explainer.audit import audit
from email_security_explainer.dns_fetch import DnsLookupError, TxtLookup, fetch_records, lookup_txt
from email_security_explainer.domain import parse_domain
from email_security_explainer.explain import (
    DEFAULT_MODEL,
    MAX_API_RETRIES,
    REQUEST_TIMEOUT_SECONDS,
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


def _claude_generator_for(model: str) -> Generate:
    client = anthropic.Anthropic(timeout=REQUEST_TIMEOUT_SECONDS, max_retries=MAX_API_RETRIES)
    return claude_generator(client, model)


def main(
    argv: Sequence[str] | None = None,
    lookup: TxtLookup = lookup_txt,
    generator_for: Callable[[str], Generate] = _claude_generator_for,
) -> int:
    args = _build_parser().parse_args(argv)
    try:
        domain = parse_domain(args.domain)
        records = fetch_records(domain, lookup)
        findings = audit(records)
        if args.command == "audit":
            output = _render_json(domain, findings) if args.json else _render_text(domain, findings)
        elif not findings:
            output = _render_text(domain, findings)
        else:
            result = explain(domain, findings, records, generator_for(args.model))
            output = _render_explanation(domain, findings, result)
    except (ValueError, DnsLookupError, ExplanationError, anthropic.AnthropicError) as err:
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
    explain_command.add_argument(
        "--model", default=DEFAULT_MODEL, help=f"Claude model to use (default: {DEFAULT_MODEL})"
    )
    return parser


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
    if result.report.missed:
        unexplained = [
            f"  {finding.code}  {finding.evidence or ''}".rstrip()
            for finding in result.report.missed
        ]
        blocks.append("\n".join(["Not explained (failed the claim check):", *unexplained]))
    return "\n\n".join(blocks)


def _wrap(text: str, indent: str = "  ") -> str:
    return textwrap.fill(
        text, width=TEXT_WIDTH_CHARACTERS, initial_indent=indent, subsequent_indent=indent
    )

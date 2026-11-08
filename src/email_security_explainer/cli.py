"""Command-line entry point: `esx audit <domain>`."""

import argparse
import json
import sys
from collections.abc import Sequence

from email_security_explainer.audit import audit
from email_security_explainer.dns_fetch import DnsLookupError, TxtLookup, fetch_records, lookup_txt
from email_security_explainer.domain import parse_domain
from email_security_explainer.findings import Finding

EXIT_OK = 0
EXIT_FAILURE = 1


def main(argv: Sequence[str] | None = None, lookup: TxtLookup = lookup_txt) -> int:
    args = _build_parser().parse_args(argv)
    try:
        domain = parse_domain(args.domain)
        findings = audit(fetch_records(domain, lookup))
    except (ValueError, DnsLookupError) as err:
        print(f"esx: {err}", file=sys.stderr)
        return EXIT_FAILURE
    print(_render_json(domain, findings) if args.json else _render_text(domain, findings))
    return EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="esx", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    audit_command = commands.add_parser("audit", help="list SPF and DMARC gaps for a domain")
    audit_command.add_argument("domain", help="domain to audit, such as example.com")
    audit_command.add_argument("--json", action="store_true", help="print findings as JSON")
    return parser


def _render_text(domain: str, findings: list[Finding]) -> str:
    if not findings:
        return f"{domain}: no findings"
    lines = [f"{domain}: {len(findings)} finding{'s' if len(findings) != 1 else ''}"]
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

import json
from collections.abc import Mapping

import pytest

from email_security_explainer.cli import EXIT_FAILURE, EXIT_OK, main
from email_security_explainer.dns_fetch import DnsLookupError

CLEAN = {
    "example.com": ("v=spf1 -all",),
    "_dmarc.example.com": ("v=DMARC1; p=reject; rua=mailto:d@example.com",),
}
WEAK = {
    "example.com": ("v=spf1 +all",),
    "_dmarc.example.com": ("v=DMARC1; p=none; rua=mailto:d@example.com",),
}


def run(argv: list[str], table: Mapping[str, tuple[str, ...]]) -> int:
    def lookup(name: str) -> tuple[str, ...] | None:
        return table.get(name, ())

    return main(argv, lookup)


def test_audit_prints_findings(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["audit", "Example.com"], WEAK) == EXIT_OK
    output = capsys.readouterr().out
    assert output.splitlines() == [
        "example.com: 2 findings",
        "  high    SPF_ALL_PASS          +all",
        "  high    DMARC_POLICY_NONE     p=none",
    ]


def test_audit_reports_clean_domain(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["audit", "example.com"], CLEAN) == EXIT_OK
    assert capsys.readouterr().out == "example.com: no findings\n"


def test_audit_prints_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["audit", "example.com", "--json"], WEAK) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["domain"] == "example.com"
    assert payload["findings"][0] == {
        "code": "SPF_ALL_PASS",
        "severity": "high",
        "record": "spf",
        "evidence": "+all",
    }


def test_invalid_domain_fails(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["audit", "not a domain"], CLEAN) == EXIT_FAILURE
    assert "expected a domain name" in capsys.readouterr().err


def test_dns_failure_fails(capsys: pytest.CaptureFixture[str]) -> None:
    def failing_lookup(name: str) -> tuple[str, ...] | None:
        raise DnsLookupError(f"TXT lookup for {name} failed: timed out")

    assert main(["audit", "example.com"], failing_lookup) == EXIT_FAILURE
    assert "timed out" in capsys.readouterr().err

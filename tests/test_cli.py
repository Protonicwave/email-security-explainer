import json
from collections.abc import Mapping

import anthropic
import httpx2
import pytest

from email_security_explainer.cli import EXIT_FAILURE, EXIT_OK, main
from email_security_explainer.dns_fetch import DnsLookupError
from email_security_explainer.explain import DEFAULT_MODEL, ExplanationError, Generate
from email_security_explainer.findings import FindingCode, RecordKind
from email_security_explainer.schema import Claim, Explanation

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


SOFTFAIL = {
    "example.com": ("v=spf1 ~all",),
    "_dmarc.example.com": ("v=DMARC1; p=none; rua=mailto:d@example.com",),
}


def explanation_with(*claims: Claim) -> Explanation:
    return Explanation(summary="Anyone can send mail as example.com.", claims=list(claims))


def softfail_claim() -> Claim:
    return Claim(
        finding_code=FindingCode.SPF_SOFTFAIL,
        record=RecordKind.SPF,
        quoted_value="~all",
        explanation="Receivers are told to accept forged mail and only mark it.",
        fix="Change ~all to -all.",
    )


def policy_claim() -> Claim:
    return Claim(
        finding_code=FindingCode.DMARC_POLICY_NONE,
        record=RecordKind.DMARC,
        quoted_value="p=none",
        explanation="Your DMARC record asks receivers to deliver mail that fails.",
        fix="Set p=quarantine once reports show only your own servers.",
    )


def explain_with(answer: Explanation, models: list[str] | None = None) -> int:
    def lookup(name: str) -> tuple[str, ...] | None:
        return SOFTFAIL.get(name, ())

    def generator_for(model: str) -> Generate:
        if models is not None:
            models.append(model)
        return lambda request: answer

    return main(["explain", "example.com"], lookup, generator_for)


def test_explain_prints_the_checked_explanation(capsys: pytest.CaptureFixture[str]) -> None:
    models: list[str] = []

    assert explain_with(explanation_with(softfail_claim(), policy_claim()), models) == EXIT_OK

    assert models == [DEFAULT_MODEL]
    assert capsys.readouterr().out == (
        "example.com: 2 findings\n"
        "\n"
        "Anyone can send mail as example.com.\n"
        "\n"
        "medium  SPF_SOFTFAIL  ~all\n"
        "  Receivers are told to accept forged mail and only mark it.\n"
        "  Fix: Change ~all to -all.\n"
        "\n"
        "high  DMARC_POLICY_NONE  p=none\n"
        "  Your DMARC record asks receivers to deliver mail that fails.\n"
        "  Fix: Set p=quarantine once reports show only your own servers.\n"
    )


def test_explain_lists_findings_left_unexplained(capsys: pytest.CaptureFixture[str]) -> None:
    assert explain_with(explanation_with(softfail_claim())) == EXIT_OK

    assert capsys.readouterr().out.endswith(
        "Not explained (failed the claim check):\n  DMARC_POLICY_NONE  p=none\n"
    )


def test_explain_skips_the_model_for_a_clean_domain(capsys: pytest.CaptureFixture[str]) -> None:
    def generator_for(model: str) -> Generate:
        raise AssertionError("the model should not be called")

    assert (
        main(["explain", "example.com"], lambda name: CLEAN.get(name, ()), generator_for) == EXIT_OK
    )
    assert capsys.readouterr().out == "example.com: no findings\n"


def test_explain_passes_the_chosen_model(capsys: pytest.CaptureFixture[str]) -> None:
    models: list[str] = []

    def generator_for(model: str) -> Generate:
        models.append(model)
        return lambda request: explanation_with(softfail_claim(), policy_claim())

    argv = ["explain", "example.com", "--model", "claude-test"]
    assert main(argv, lambda name: SOFTFAIL.get(name, ()), generator_for) == EXIT_OK
    assert models == ["claude-test"]


@pytest.mark.parametrize(
    "error",
    [
        ExplanationError("claude-test declined to explain (category: cyber)"),
        anthropic.APIConnectionError(request=httpx2.Request("POST", "https://api.example")),
    ],
)
def test_explain_fails_when_the_model_fails(
    error: Exception, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing_model(request: str) -> Explanation:
        raise error

    def generator_for(model: str) -> Generate:
        return failing_model

    assert (
        main(["explain", "example.com"], lambda name: SOFTFAIL.get(name, ()), generator_for)
        == EXIT_FAILURE
    )
    assert capsys.readouterr().err == f"esx: {error}\n"


def test_explain_omits_a_summary_that_failed_the_check(
    capsys: pytest.CaptureFixture[str],
) -> None:
    answer = Explanation(
        summary="Your p=reject policy is undermined.", claims=[softfail_claim(), policy_claim()]
    )

    assert explain_with(answer) == EXIT_OK

    assert capsys.readouterr().out.startswith("example.com: 2 findings\n\nmedium  SPF_SOFTFAIL")

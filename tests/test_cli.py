import io
import json
import sys
from collections.abc import Mapping
from pathlib import Path

import anthropic
import httpx2
import pytest

from email_security_explainer.cli import EXIT_FAILURE, EXIT_OK, main
from email_security_explainer.dns_fetch import DnsLookupError
from email_security_explainer.explain import (
    DEFAULT_MODEL,
    RAW_RECORDS_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    ExplanationError,
    Generate,
)
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

    def generator_for(model: str, system_prompt: str) -> Generate:
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
    def generator_for(model: str, system_prompt: str) -> Generate:
        raise AssertionError("the model should not be called")

    assert (
        main(["explain", "example.com"], lambda name: CLEAN.get(name, ()), generator_for) == EXIT_OK
    )
    assert capsys.readouterr().out == "example.com: no findings\n"


def test_explain_passes_the_chosen_model(capsys: pytest.CaptureFixture[str]) -> None:
    models: list[str] = []

    def generator_for(model: str, system_prompt: str) -> Generate:
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

    def generator_for(model: str, system_prompt: str) -> Generate:
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


CLEAN_ANSWER = Explanation(summary="Fine.", claims=[])
EVAL_CASE = {
    "domain": "softfail.example",
    "apex_txt": ["v=spf1 ~all"],
    "dmarc_txt": ["v=DMARC1; p=none; rua=mailto:d@example.com"],
    "spf_by_domain": {},
}


def run_eval(
    tmp_path: Path, *options: str, prompts: list[tuple[str, str]] | None = None
) -> tuple[int, Path]:
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps([EVAL_CASE]), encoding="utf-8")
    output = tmp_path / "results.json"

    def generator_for(model: str, system_prompt: str) -> Generate:
        if prompts is not None:
            prompts.append((model, system_prompt))
        return lambda request: explanation_with(softfail_claim())

    argv = ["eval", "--cases", str(cases), "--output", str(output), *options]
    return main(argv, generator_for=generator_for), output


def test_eval_prints_a_summary_per_condition(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code, _ = run_eval(tmp_path, "--repeats", "2")

    assert exit_code == EXIT_OK
    assert capsys.readouterr().out.splitlines() == [
        "condition         scored  failed  errored  explained  missed  invented  wrong detail",
        "raw_records            2       0        0          2       2         0             0",
        "findings               2       0        0          2       2         0             0",
        "findings_checked       2       0        0          2       2         0             0",
    ]


def test_eval_reports_progress_for_every_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_eval(tmp_path)

    assert capsys.readouterr().err.splitlines()[0] == (
        "1  softfail.example  raw_records: explained 1, missed 1, invented 0, wrong detail 0"
    )


def test_eval_writes_every_run_as_json(tmp_path: Path) -> None:
    _, output = run_eval(tmp_path, "--model", "claude-test")

    results = json.loads(output.read_text(encoding="utf-8"))
    assert results["model"] == "claude-test"
    assert results["repeats"] == 1
    assert results["summary"][0] == {
        "condition": "raw_records",
        "scored": 1,
        "failed": 0,
        "errored": 0,
        "explained": 1,
        "invented": 0,
        "missed": 1,
        "wrong_detail": 0,
    }
    assert results["runs"][0] == {
        "domain": "softfail.example",
        "repeat": 1,
        "condition": "raw_records",
        "outcome": "scored",
        "explained": 1,
        "invented": 0,
        "missed": 1,
        "wrong_detail": 0,
    }


def test_eval_records_a_failed_run_with_its_message(tmp_path: Path) -> None:
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps([EVAL_CASE]), encoding="utf-8")
    output = tmp_path / "results.json"

    def declining_model(request: str) -> Explanation:
        raise ExplanationError("claude-test declined to explain (category: cyber)")

    argv = ["eval", "--cases", str(cases), "--output", str(output)]
    assert main(argv, generator_for=lambda model, prompt: declining_model) == EXIT_OK

    run = json.loads(output.read_text(encoding="utf-8"))["runs"][0]
    assert run["outcome"] == "no_explanation"
    assert run["message"] == "claude-test declined to explain (category: cyber)"


def test_eval_gives_each_condition_its_system_prompt(tmp_path: Path) -> None:
    prompts: list[tuple[str, str]] = []

    run_eval(tmp_path, "--model", "claude-test", prompts=prompts)

    assert sorted(prompts) == sorted(
        [("claude-test", SYSTEM_PROMPT), ("claude-test", RAW_RECORDS_SYSTEM_PROMPT)]
    )


def test_eval_fails_when_the_case_file_is_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["eval", "--cases", str(tmp_path / "absent.json")]

    assert main(argv, generator_for=lambda model, prompt: lambda request: CLEAN_ANSWER) == (
        EXIT_FAILURE
    )
    assert "absent.json" in capsys.readouterr().err


@pytest.mark.parametrize("repeats", ["0", "11", "two", "-1", "²"])
def test_eval_rejects_a_repeat_count_outside_the_cap(
    repeats: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["eval", "--repeats", repeats])

    assert exit_info.value.code == 2
    assert "expected a whole number from 1 to 10" in capsys.readouterr().err


def cp1252_stream(monkeypatch: pytest.MonkeyPatch, name: str) -> io.BytesIO:
    buffer = io.BytesIO()
    monkeypatch.setattr(sys, name, io.TextIOWrapper(buffer, encoding="cp1252"))
    return buffer


def test_output_the_console_code_page_cannot_hold_is_written_as_utf8(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buffer = cp1252_stream(monkeypatch, "stdout")
    table = {"example.com": ("v=spf1 ip4:192.0.2.1 caf� -all",)}

    assert run(["audit", "example.com"], table) == EXIT_OK

    sys.stdout.flush()
    assert "caf�" in buffer.getvalue().decode("utf-8")


def test_errors_the_console_code_page_cannot_hold_are_written_as_utf8(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buffer = cp1252_stream(monkeypatch, "stderr")

    assert run(["audit", "例..テスト"], CLEAN) == EXIT_FAILURE

    sys.stderr.flush()
    assert "例" in buffer.getvalue().decode("utf-8")

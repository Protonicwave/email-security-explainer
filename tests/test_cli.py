import io
import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

import anthropic
import httpx2
import pytest

from email_security_explainer.audit import audit
from email_security_explainer.cli import EXIT_FAILURE, EXIT_OK, main
from email_security_explainer.dns_fetch import DnsLookupError, fetch_records
from email_security_explainer.domain import DomainName
from email_security_explainer.evaluate import load_cases
from email_security_explainer.explain import (
    DEFAULT_MODEL,
    RAW_RECORDS_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    ExplanationError,
    Generate,
)
from email_security_explainer.findings import FindingCode
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


def captured_case(table: Mapping[str, tuple[str, ...]], capsys: pytest.CaptureFixture[str]) -> str:
    assert run(["case", "Example.com"], table) == EXIT_OK
    return capsys.readouterr().out


def test_case_prints_a_case_that_audits_the_same_as_the_live_domain(
    capsys: pytest.CaptureFixture[str],
) -> None:
    table = {
        "example.com": ("v=spf1 include:_spf.provider.example ~all", "site-verification=abc"),
        "_dmarc.example.com": ("v=DMARC1; p=none",),
        "_spf.provider.example": ("v=spf1 ip4:198.51.100.0/24 -all",),
    }

    (case,) = load_cases(f"[{captured_case(table, capsys)}]")

    live = fetch_records(DomainName("example.com"), lambda name: table.get(name, ()))
    assert case == live
    assert audit(case) == audit(live)


def test_case_keeps_a_chain_cut_off_at_the_lookup_limit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    includes = " ".join(f"include:spf{number}.example" for number in range(12))
    table = {"example.com": (f"v=spf1 {includes} -all",)}
    table |= {f"spf{number}.example": ("v=spf1 -all",) for number in range(12)}

    (case,) = load_cases(f"[{captured_case(table, capsys)}]")

    assert FindingCode.SPF_LOOKUP_LIMIT in {finding.code for finding in audit(case)}


SOFTFAIL = {
    "example.com": ("v=spf1 ~all",),
    "_dmarc.example.com": ("v=DMARC1; p=none; rua=mailto:d@example.com",),
}


def explanation_with(*claims: Claim) -> Explanation:
    return Explanation(summary="Anyone can send mail as example.com.", claims=list(claims))


def softfail_claim() -> Claim:
    return Claim(
        finding_code=FindingCode.SPF_SOFTFAIL,
        quoted_value="~all",
        explanation="Receivers are told to accept forged mail and only mark it.",
        fix="Change ~all to -all.",
    )


def policy_claim() -> Claim:
    return Claim(
        finding_code=FindingCode.DMARC_POLICY_NONE,
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
    output = tmp_path / "results.jsonl"

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


def written_runs(output: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]


def test_eval_writes_every_run_as_a_json_line(tmp_path: Path) -> None:
    _, output = run_eval(tmp_path, "--model", "claude-test", "--repeats", "2")

    runs = written_runs(output)
    assert len(runs) == 6
    assert runs[0] == {
        "model": "claude-test",
        "domain": "softfail.example",
        "repeat": 1,
        "condition": "raw_records",
        "outcome": "scored",
        "explained": 1,
        "invented": 0,
        "missed": 1,
        "wrong_detail": 0,
        "claims": [
            {
                "finding_code": "SPF_SOFTFAIL",
                "quoted_value": "~all",
                "verdict": "accepted",
                "unsupported_tokens": [],
            }
        ],
        "missed_findings": [{"code": "DMARC_POLICY_NONE", "evidence": "p=none"}],
        "summary_unsupported_tokens": [],
    }


def test_eval_records_why_each_claim_failed_and_quotes_its_prose(tmp_path: Path) -> None:
    invented = Claim(
        finding_code=FindingCode.SPF_ALL_PASS,
        quoted_value="+all",
        explanation="Anyone may send.",
        fix="Remove +all.",
    )
    unsupported = softfail_claim().model_copy(update={"explanation": "Weaker than -all."})
    answer = Explanation(summary="Your p=reject policy is ignored.", claims=[invented, unsupported])
    output = tmp_path / "results.jsonl"

    assert eval_with_model(tmp_path, lambda request: answer, output) == EXIT_OK

    run = written_runs(output)[0]
    assert run["claims"] == [
        {
            "finding_code": "SPF_ALL_PASS",
            "quoted_value": "+all",
            "verdict": "invented",
            "unsupported_tokens": [],
            "explanation": "Anyone may send.",
        },
        {
            "finding_code": "SPF_SOFTFAIL",
            "quoted_value": "~all",
            "verdict": "unsupported_token",
            "unsupported_tokens": ["-all"],
            "explanation": "Weaker than -all.",
        },
    ]
    assert run["missed_findings"] == [
        {"code": "SPF_SOFTFAIL", "evidence": "~all"},
        {"code": "DMARC_POLICY_NONE", "evidence": "p=none"},
    ]
    assert run["summary_unsupported_tokens"] == ["p=reject"]


def eval_with_model(tmp_path: Path, model: Generate, output: Path) -> int:
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps([EVAL_CASE, {**EVAL_CASE, "domain": "two.example"}]), "utf-8")
    argv = ["eval", "--cases", str(cases), "--output", str(output)]
    return main(argv, generator_for=lambda model_name, prompt: model)


def test_eval_records_a_failed_run_with_its_message(tmp_path: Path) -> None:
    def declining_model(request: str) -> Explanation:
        raise ExplanationError("claude-test declined to explain (category: cyber)")

    output = tmp_path / "results.jsonl"
    assert eval_with_model(tmp_path, declining_model, output) == EXIT_OK

    run = written_runs(output)[0]
    assert run["outcome"] == "no_explanation"
    assert run["message"] == "claude-test declined to explain (category: cyber)"


def test_eval_keeps_the_runs_finished_before_an_error_stops_it(tmp_path: Path) -> None:
    calls: list[str] = []

    def model_losing_its_key(request: str) -> Explanation:
        calls.append(request)
        if len(calls) > 2:
            response = httpx2.Response(401, request=httpx2.Request("POST", "https://api.test"))
            raise anthropic.AuthenticationError("key revoked", response=response, body=None)
        return explanation_with(softfail_claim(), policy_claim())

    output = tmp_path / "results.jsonl"
    assert eval_with_model(tmp_path, model_losing_its_key, output) == EXIT_FAILURE

    assert [run["domain"] for run in written_runs(output)] == ["softfail.example"] * 3


def test_eval_fails_before_calling_the_model_when_the_output_cannot_be_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def unexpected_model(request: str) -> Explanation:
        raise AssertionError("the model should not be called")

    output = tmp_path / "missing" / "results.jsonl"
    assert eval_with_model(tmp_path, unexpected_model, output) == EXIT_FAILURE

    assert "results.jsonl" in capsys.readouterr().err


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


ServeCall = tuple[int, Callable[[str], tuple[str, ...] | None]]


def fake_serve(monkeypatch: pytest.MonkeyPatch, error: OSError | None = None) -> list[ServeCall]:
    calls: list[ServeCall] = []

    def serve(port: int, lookup: Callable[[str], tuple[str, ...] | None]) -> None:
        calls.append((port, lookup))
        if error is not None:
            raise error

    monkeypatch.setattr("email_security_explainer.cli.serve", serve)
    return calls


def test_serve_passes_the_port_and_dns_lookup_through(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = fake_serve(monkeypatch)

    def lookup(name: str) -> tuple[str, ...] | None:
        return ()

    assert main(["serve", "--port", "8123"], lookup) == EXIT_OK
    assert calls == [(8123, lookup)]


def test_serve_defaults_to_port_8000(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = fake_serve(monkeypatch)
    assert main(["serve"]) == EXIT_OK
    assert [port for port, _lookup in calls] == [8000]


# The last is 80 in full-width digits, which int() would accept.
@pytest.mark.parametrize(
    "port", ["0", "65536", "http", "\N{FULLWIDTH DIGIT EIGHT}\N{FULLWIDTH DIGIT ZERO}"]
)
def test_serve_rejects_a_port_out_of_range(
    port: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = fake_serve(monkeypatch)
    with pytest.raises(SystemExit):
        main(["serve", "--port", port])
    assert calls == []
    assert "expected a port from 1 to 65535" in capsys.readouterr().err


def test_serve_reports_a_port_already_in_use(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_serve(monkeypatch, OSError("address already in use"))
    assert main(["serve"]) == EXIT_FAILURE
    assert capsys.readouterr().err == "esx: address already in use\n"

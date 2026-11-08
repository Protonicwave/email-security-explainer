import json
from typing import Any

import anthropic
import httpx2
import pytest

from email_security_explainer.audit import DnsRecords, audit
from email_security_explainer.claims import Verdict
from email_security_explainer.explain import (
    SYSTEM_PROMPT,
    ExplanationError,
    claude_generator,
    explain,
)
from email_security_explainer.findings import Finding, FindingCode, RecordKind
from email_security_explainer.schema import Claim, Explanation

RECORDS = DnsRecords(
    apex_txt=("verification=abc", "v=spf1 include:_spf.mail.example.net ~all"),
    dmarc_txt=("v=DMARC1; p=none",),
    spf_by_domain={"_spf.mail.example.net": ("v=spf1 ip4:192.0.2.0/24 -all",)},
)
FINDINGS = audit(RECORDS)
SUMMARY = "Anyone can send mail as example.com and most of it will be delivered."


def claim(code: FindingCode, quoted_value: str | None, explanation: str = "Plain.") -> Claim:
    return Claim(
        finding_code=code,
        record=Finding(code).record,
        quoted_value=quoted_value,
        explanation=explanation,
        fix="Tighten the record.",
    )


CLEAN = Explanation(
    summary=SUMMARY,
    claims=[
        claim(FindingCode.SPF_SOFTFAIL, "~all"),
        claim(FindingCode.DMARC_POLICY_NONE, "p=none"),
        claim(FindingCode.DMARC_NO_RUA, None),
    ],
)


class ScriptedModel:
    """Returns prepared explanations in turn and records each request."""

    def __init__(self, *answers: Explanation) -> None:
        self.answers = list(answers)
        self.requests: list[str] = []

    def __call__(self, request: str) -> Explanation:
        self.requests.append(request)
        return self.answers.pop(0)


def test_clean_answer_is_returned_without_a_repair_round() -> None:
    model = ScriptedModel(CLEAN)

    result = explain("example.com", FINDINGS, RECORDS, model)

    assert result.explanation == CLEAN
    assert result.report.is_clean
    assert len(model.requests) == 1


def test_request_shows_the_records_and_findings() -> None:
    model = ScriptedModel(CLEAN)

    explain("example.com", FINDINGS, RECORDS, model)

    assert model.requests[0].splitlines() == [
        "Domain: example.com",
        "",
        "Records:",
        "SPF at example.com: v=spf1 include:_spf.mail.example.net ~all",
        "DMARC at _dmarc.example.com: v=DMARC1; p=none",
        "SPF at _spf.mail.example.net, reached by include or redirect: "
        "v=spf1 ip4:192.0.2.0/24 -all",
        "",
        "Findings:",
        "1. SPF_SOFTFAIL (spf record, medium severity), evidence: ~all",
        "2. DMARC_POLICY_NONE (dmarc record, high severity), evidence: p=none",
        "3. DMARC_NO_RUA (dmarc record, low severity), evidence: none",
    ]


def test_request_marks_absent_records_and_findings() -> None:
    model = ScriptedModel(Explanation(summary=SUMMARY, claims=[]))
    records = DnsRecords(apex_txt=(), dmarc_txt=())

    explain("example.com", [], records, model)

    assert model.requests[0].splitlines()[3:] == [
        "SPF at example.com: none",
        "DMARC at _dmarc.example.com: none",
        "",
        "Findings:",
        "none",
    ]


def test_failing_answer_gets_one_repair_round_listing_its_problems() -> None:
    first = Explanation(
        summary="Your p=reject policy is undermined.",
        claims=[
            claim(FindingCode.SPF_SOFTFAIL, "-all"),
            claim(FindingCode.SPF_ALL_PASS, "+all"),
            claim(FindingCode.DMARC_POLICY_NONE, "p=none", explanation="Unlike sp=reject."),
            claim(FindingCode.DMARC_POLICY_NONE, "p=none"),
            claim(FindingCode.DMARC_POLICY_NONE, "p=none"),
            claim(FindingCode.DMARC_NO_RUA, None).model_copy(update={"record": RecordKind.SPF}),
        ],
    )
    model = ScriptedModel(first, CLEAN)

    result = explain("example.com", FINDINGS, RECORDS, model)

    assert result.report.is_clean
    repair = model.requests[1]
    assert repair.startswith(model.requests[0])
    assert first.model_dump_json() in repair
    problems = [line for line in repair.splitlines() if line.startswith("- ")]
    assert problems == [
        "- Claim 1 (SPF_SOFTFAIL) quotes '-all', which is not the finding's evidence.",
        "- Claim 2 (SPF_ALL_PASS) explains a problem the audit did not find. Remove it.",
        "- Claim 3 (DMARC_POLICY_NONE) quotes sp=reject, which the records do not contain.",
        "- Claim 5 (DMARC_POLICY_NONE) repeats a finding another claim already explains. "
        "Remove it.",
        "- Claim 6 (DMARC_NO_RUA) names the spf record; this finding is about another.",
        "- No claim explains SPF_SOFTFAIL with evidence ~all.",
        "- No claim explains DMARC_NO_RUA with evidence none.",
        "- The summary quotes p=reject; the summary must quote no record values.",
    ]


def test_parts_still_failing_after_repair_are_dropped() -> None:
    still_failing = Explanation(
        summary="Your p=reject policy is undermined.",
        claims=[claim(FindingCode.SPF_ALL_PASS, "+all"), *CLEAN.claims[:2]],
    )
    model = ScriptedModel(still_failing, still_failing)

    result = explain("example.com", FINDINGS, RECORDS, model)

    assert len(model.requests) == 2
    assert result.explanation == Explanation(summary="", claims=CLEAN.claims[:2])
    assert [check.verdict for check in result.report.claim_checks] == [
        Verdict.INVENTED,
        Verdict.ACCEPTED,
        Verdict.ACCEPTED,
    ]
    assert result.report.missed == (Finding(FindingCode.DMARC_NO_RUA),)


def test_model_failure_propagates() -> None:
    def failing_model(request: str) -> Explanation:
        raise ExplanationError("declined")

    with pytest.raises(ExplanationError, match="declined"):
        explain("example.com", FINDINGS, RECORDS, failing_model)


def message(text: str, stop_reason: str = "end_turn", **extra: Any) -> dict[str, Any]:
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-5-5",
        "content": [
            {"type": "thinking", "thinking": "", "signature": "sig"},
            {"type": "text", "text": text},
        ],
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 10},
        **extra,
    }


class FakeApi:
    """Answers every Messages API call with one prepared response body."""

    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body
        self.sent: list[dict[str, Any]] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.sent.append(json.loads(request.content))
        return httpx2.Response(200, json=self.body)

    def client(self) -> anthropic.Anthropic:
        return anthropic.Anthropic(
            api_key="test-key",
            max_retries=0,
            http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(self)),
        )


def test_generator_sends_the_request_with_the_schema_and_parses_the_answer() -> None:
    api = FakeApi(message(CLEAN.model_dump_json()))

    explanation = claude_generator(api.client(), "claude-test")("the request")

    assert explanation == CLEAN
    sent = api.sent[0]
    assert sent["model"] == "claude-test"
    assert sent["system"] == SYSTEM_PROMPT
    assert sent["messages"] == [{"role": "user", "content": "the request"}]
    output_format = sent["output_config"]["format"]
    assert output_format["type"] == "json_schema"
    assert output_format["schema"] == anthropic.transform_schema(Explanation)


def test_generator_reports_a_refusal_with_its_category() -> None:
    body = message("", "refusal", stop_details={"type": "refusal", "category": "cyber"})

    with pytest.raises(ExplanationError, match=r"declined to explain \(category: cyber\)"):
        claude_generator(FakeApi(body).client(), "claude-test")("the request")


def test_generator_reports_a_refusal_without_details() -> None:
    with pytest.raises(ExplanationError, match=r"category: None"):
        claude_generator(FakeApi(message("", "refusal")).client(), "claude-test")("the request")


def test_generator_reports_a_truncated_answer() -> None:
    body = message(CLEAN.model_dump_json()[:40], "max_tokens")

    with pytest.raises(ExplanationError, match="stopped before finishing: max_tokens"):
        claude_generator(FakeApi(body).client(), "claude-test")("the request")


@pytest.mark.parametrize("text", ["not json", '{"summary": "no claims field"}'])
def test_generator_rejects_output_outside_the_schema(text: str) -> None:
    with pytest.raises(ExplanationError, match="does not fit the schema"):
        claude_generator(FakeApi(message(text)).client(), "claude-test")("the request")

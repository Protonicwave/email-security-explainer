import json
from pathlib import Path

import anthropic
import httpx2
import pytest

from email_security_explainer.audit import DnsRecords, audit
from email_security_explainer.claims import check
from email_security_explainer.domain import DomainName
from email_security_explainer.evaluate import (
    MAX_CASES,
    Condition,
    ConditionSummary,
    Failure,
    FailureKind,
    Run,
    Score,
    evaluate,
    load_cases,
    score,
    summarise,
)
from email_security_explainer.explain import ExplanationError
from email_security_explainer.findings import Finding, FindingCode
from email_security_explainer.schema import Claim, Explanation

CORPUS = Path(__file__).parent.parent / "cases" / "cases.json"
RECORDS = DnsRecords(
    domain=DomainName("softfail.example"),
    apex_txt=("v=spf1 ip4:192.0.2.0/24 ~all",),
    dmarc_txt=("v=DMARC1; p=none",),
)
FINDINGS = audit(RECORDS)


def claim(code: FindingCode, quoted_value: str | None, explanation: str = "Plain.") -> Claim:
    return Claim(
        finding_code=code,
        quoted_value=quoted_value,
        explanation=explanation,
        fix="Tighten the record.",
    )


SOFTFAIL = claim(FindingCode.SPF_SOFTFAIL, "~all")
POLICY_NONE = claim(FindingCode.DMARC_POLICY_NONE, "p=none")
NO_RUA = claim(FindingCode.DMARC_NO_RUA, None)
INVENTED = claim(FindingCode.SPF_ALL_PASS, "+all")
WRONG_DETAIL = claim(FindingCode.SPF_SOFTFAIL, "-all")
COMPLETE = Explanation(summary="Exposed.", claims=[SOFTFAIL, POLICY_NONE, NO_RUA])


def case_json(**overrides: object) -> str:
    case = {
        "domain": "softfail.example",
        "apex_txt": ["v=spf1 ip4:192.0.2.0/24 ~all"],
        "dmarc_txt": ["v=DMARC1; p=none"],
        "spf_by_domain": {},
    }
    return json.dumps([{**case, **overrides}])


def test_corpus_produces_every_finding_code() -> None:
    cases = load_cases(CORPUS.read_text(encoding="utf-8"))

    produced = {finding.code for case in cases for finding in audit(case)}

    assert produced == set(FindingCode)


def test_corpus_has_clean_cases_to_measure_invented_problems() -> None:
    cases = load_cases(CORPUS.read_text(encoding="utf-8"))

    assert sum(not audit(case) for case in cases) >= 3


def test_load_cases_builds_records_and_normalises_the_domain() -> None:
    text = case_json(
        domain="Mixed.Example.",
        apex_txt=["v=spf1 include:_spf.provider.example -all"],
        spf_by_domain={"_spf.provider.example": ["v=spf1 ip4:198.51.100.0/24 -all"]},
    )

    assert load_cases(text) == [
        DnsRecords(
            domain=DomainName("mixed.example"),
            apex_txt=("v=spf1 include:_spf.provider.example -all",),
            dmarc_txt=("v=DMARC1; p=none",),
            spf_by_domain={"_spf.provider.example": ("v=spf1 ip4:198.51.100.0/24 -all",)},
        )
    ]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[]", "at least one case"),
        ("{}", "list"),
        ("not json", "Invalid JSON"),
        (case_json(dmarc_txt="v=DMARC1; p=none"), "dmarc_txt"),
        (case_json(extra="field"), "extra"),
        (case_json(domain="not a domain"), "expected a domain name"),
        (case_json(apex_txt=["v=spf1 include:gone.example -all"]), "gone.example"),
    ],
)
def test_load_cases_rejects_malformed_files(text: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        load_cases(text)


def test_load_cases_rejects_duplicate_domains() -> None:
    case = json.loads(case_json())[0]

    with pytest.raises(ValueError, match=r"softfail\.example appears more than once"):
        load_cases(json.dumps([case, {**case, "domain": "SOFTFAIL.example"}]))


def test_load_cases_accepts_unfetched_targets_beyond_the_lookup_limit() -> None:
    includes = " ".join(f"include:spf{number}.example" for number in range(11))
    spf_by_domain = {f"spf{number}.example": ["v=spf1 a -all"] for number in range(5)}

    cases = load_cases(case_json(apex_txt=[f"v=spf1 {includes} -all"], spf_by_domain=spf_by_domain))

    assert Finding(FindingCode.SPF_LOOKUP_LIMIT) in audit(cases[0])


def test_complete_explanation_scores_every_finding_explained() -> None:
    report = check(FINDINGS, COMPLETE, RECORDS)

    assert score(report) == Score(explained=3, invented=0, missed=0, wrong_detail=0)


def test_score_counts_each_kind_of_error() -> None:
    explanation = Explanation(
        summary="Your p=reject policy is undermined.",
        claims=[
            INVENTED,
            WRONG_DETAIL,
            claim(FindingCode.DMARC_NO_RUA, None, explanation="Unlike sp=reject."),
        ],
    )

    report = check(FINDINGS, explanation, RECORDS)

    assert score(report) == Score(explained=0, invented=1, missed=3, wrong_detail=3)


def test_score_ignores_a_duplicate_of_an_explained_finding() -> None:
    explanation = Explanation(summary="Exposed.", claims=[*COMPLETE.claims, NO_RUA])

    report = check(FINDINGS, explanation, RECORDS)

    assert score(report) == Score(explained=3, invented=0, missed=0, wrong_detail=0)


class ScriptedModel:
    """Returns prepared answers in turn, raising any that are exceptions."""

    def __init__(self, *answers: Explanation | Exception) -> None:
        self.answers = list(answers)
        self.requests: list[str] = []

    def __call__(self, request: str) -> Explanation:
        self.requests.append(request)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def run_once(
    from_findings: ScriptedModel, from_records: ScriptedModel, case: DnsRecords = RECORDS
) -> dict[Condition, Score | Failure]:
    runs = list(evaluate([case], from_findings, from_records, repeats=1))
    assert [(run.domain, run.repeat) for run in runs] == [(case.domain, 1)] * len(Condition)
    return {run.condition: run.outcome for run in runs}


def test_each_condition_is_scored_on_the_explanation_a_reader_would_see() -> None:
    sloppy = Explanation(summary="Exposed.", claims=[INVENTED, SOFTFAIL, POLICY_NONE])
    from_findings = ScriptedModel(sloppy, sloppy)
    from_records = ScriptedModel(Explanation(summary="Exposed.", claims=[WRONG_DETAIL]))

    outcomes = run_once(from_findings, from_records)

    assert outcomes == {
        Condition.RAW_RECORDS: Score(explained=0, invented=0, missed=3, wrong_detail=1),
        Condition.FINDINGS: Score(explained=2, invented=1, missed=1, wrong_detail=0),
        Condition.FINDINGS_CHECKED: Score(explained=2, invented=0, missed=1, wrong_detail=0),
    }


def test_raw_records_condition_sees_the_records_but_not_the_findings() -> None:
    from_records = ScriptedModel(COMPLETE)

    run_once(ScriptedModel(COMPLETE), from_records)

    assert "v=spf1 ip4:192.0.2.0/24 ~all" in from_records.requests[0]
    assert "Findings:" not in from_records.requests[0]
    assert "SPF_SOFTFAIL" not in from_records.requests[0]


def test_checked_condition_repairs_the_first_answer_rather_than_asking_afresh() -> None:
    incomplete = Explanation(summary="Exposed.", claims=[SOFTFAIL])
    from_findings = ScriptedModel(incomplete, COMPLETE)

    outcomes = run_once(from_findings, ScriptedModel(COMPLETE))

    assert len(from_findings.requests) == 2
    assert incomplete.model_dump_json() in from_findings.requests[1]
    assert outcomes[Condition.FINDINGS] == Score(explained=1, invented=0, missed=2, wrong_detail=0)
    assert outcomes[Condition.FINDINGS_CHECKED] == Score(3, 0, 0, 0)


def test_clean_case_still_asks_the_model_so_invented_problems_are_measured() -> None:
    clean = DnsRecords(
        DomainName("clean.example"), ("v=spf1 -all",), ("v=DMARC1; p=reject; rua=x",)
    )
    from_findings = ScriptedModel(Explanation(summary="Fine.", claims=[INVENTED]), COMPLETE)

    outcomes = run_once(from_findings, ScriptedModel(COMPLETE), clean)

    assert outcomes[Condition.FINDINGS] == Score(explained=0, invented=1, missed=0, wrong_detail=0)
    assert outcomes[Condition.FINDINGS_CHECKED] == Score(0, 0, 0, 0)
    assert outcomes[Condition.RAW_RECORDS] == Score(
        explained=0, invented=3, missed=0, wrong_detail=0
    )


API_REQUEST = httpx2.Request("POST", "https://api.test")


def connection_error() -> anthropic.APIConnectionError:
    return anthropic.APIConnectionError(request=API_REQUEST)


def rate_limit_error() -> anthropic.RateLimitError:
    response = httpx2.Response(429, request=API_REQUEST)
    return anthropic.RateLimitError("slow down", response=response, body=None)


def test_model_without_an_explanation_fails_its_condition_and_the_run_continues() -> None:
    declined = ExplanationError("declined")
    from_findings = ScriptedModel(COMPLETE, declined)

    runs = list(
        evaluate([RECORDS, RECORDS], from_findings, ScriptedModel(declined, COMPLETE), repeats=1)
    )

    failure = Failure(FailureKind.NO_EXPLANATION, "declined")
    assert [run.outcome for run in runs] == [
        failure,
        Score(3, 0, 0, 0),
        Score(3, 0, 0, 0),
        Score(3, 0, 0, 0),
        failure,
        failure,
    ]


def test_unreachable_api_marks_the_run_errored_and_the_run_continues() -> None:
    from_findings = ScriptedModel(Explanation(summary="", claims=[SOFTFAIL]), connection_error())

    outcomes = run_once(from_findings, ScriptedModel(rate_limit_error()))

    assert outcomes == {
        Condition.RAW_RECORDS: Failure(FailureKind.API_UNAVAILABLE, "slow down"),
        Condition.FINDINGS: Score(1, 0, 2, 0),
        Condition.FINDINGS_CHECKED: Failure(FailureKind.API_UNAVAILABLE, "Connection error."),
    }


def test_api_errors_that_retrying_cannot_fix_stop_the_evaluation() -> None:
    response = httpx2.Response(401, request=API_REQUEST)
    unauthorised = anthropic.AuthenticationError("bad key", response=response, body=None)

    with pytest.raises(anthropic.AuthenticationError):
        run_once(ScriptedModel(COMPLETE), ScriptedModel(unauthorised))


def test_repeats_run_every_case_again() -> None:
    model = ScriptedModel(*[COMPLETE] * 6)

    runs = list(evaluate([RECORDS], model, model, repeats=2))

    assert [(run.repeat, run.condition) for run in runs] == [
        (repeat, condition) for repeat in (1, 2) for condition in Condition
    ]


def test_summarise_totals_each_condition() -> None:
    def run(condition: Condition, outcome: Score | Failure) -> Run:
        return Run("a.example", 1, condition, outcome)

    runs = [
        run(Condition.RAW_RECORDS, Score(1, 2, 3, 4)),
        run(Condition.RAW_RECORDS, Score(1, 1, 1, 1)),
        run(Condition.RAW_RECORDS, Failure(FailureKind.NO_EXPLANATION, "declined")),
        run(Condition.FINDINGS, Failure(FailureKind.API_UNAVAILABLE, "timeout")),
    ]

    assert summarise(runs) == [
        ConditionSummary(
            Condition.RAW_RECORDS, scored=2, failed=1, errored=0, totals=Score(2, 3, 4, 5)
        ),
        ConditionSummary(
            Condition.FINDINGS, scored=0, failed=0, errored=1, totals=Score(0, 0, 0, 0)
        ),
        ConditionSummary(
            Condition.FINDINGS_CHECKED, scored=0, failed=0, errored=0, totals=Score(0, 0, 0, 0)
        ),
    ]


def test_load_cases_rejects_more_cases_than_the_cap() -> None:
    case = json.loads(case_json())[0]
    cases = [{**case, "domain": f"case{number}.example"} for number in range(MAX_CASES + 1)]

    with pytest.raises(ValueError, match=f"at most {MAX_CASES} cases, got {MAX_CASES + 1}"):
        load_cases(json.dumps(cases))


def test_load_cases_accepts_as_many_cases_as_the_cap() -> None:
    case = json.loads(case_json())[0]
    cases = [{**case, "domain": f"case{number}.example"} for number in range(MAX_CASES)]

    assert len(load_cases(json.dumps(cases))) == MAX_CASES

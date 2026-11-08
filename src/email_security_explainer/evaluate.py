"""Compare three ways of explaining a domain's records on a fixed case corpus.

The auditor's findings are the ground truth, and each condition is scored by
the claim check on the explanation a reader would see:

- raw_records: the model is shown only the records and finds the problems itself;
- findings: the model explains the auditor's findings, and its answer is shown as is;
- findings_checked: that same answer after the claim check, one repair round and
  dropping whatever still fails.

The last two share the model's first answer, so their difference is the effect
of the check and repair alone.
"""

from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from enum import StrEnum

import anthropic
import pydantic

from email_security_explainer import spf
from email_security_explainer.audit import DnsRecords, audit
from email_security_explainer.claims import CheckReport, Verdict, check
from email_security_explainer.domain import parse_domain
from email_security_explainer.explain import (
    ExplanationError,
    Generate,
    check_and_repair,
    findings_request,
    raw_records_request,
)

# Raised once the SDK's own retries are spent; a later case may still get through.
# Anything else, such as a bad key or an unknown model, fails every case alike,
# so it stops the evaluation instead.
_API_UNAVAILABLE = (
    anthropic.APIConnectionError,
    anthropic.RateLimitError,
    anthropic.InternalServerError,
)


# Each case costs about three model calls per repeat, so this bounds the bill
# together with the cap on repeats.
MAX_CASES = 100


class Condition(StrEnum):
    RAW_RECORDS = "raw_records"
    FINDINGS = "findings"
    FINDINGS_CHECKED = "findings_checked"


@dataclass(frozen=True, slots=True)
class Case:
    domain: str
    records: DnsRecords


@dataclass(frozen=True, slots=True)
class Score:
    """Claims and findings in one explanation, counted against the audit.

    `explained + missed` is the number of findings. A claim that repeats an
    explained finding is not counted: it tells the reader nothing false.
    """

    explained: int
    invented: int
    missed: int
    wrong_detail: int


class FailureKind(StrEnum):
    NO_EXPLANATION = "no_explanation"
    API_UNAVAILABLE = "api_unavailable"


@dataclass(frozen=True, slots=True)
class Failure:
    kind: FailureKind
    message: str


@dataclass(frozen=True, slots=True)
class Run:
    domain: str
    repeat: int
    condition: Condition
    outcome: Score | Failure


@dataclass(frozen=True, slots=True)
class ConditionSummary:
    condition: Condition
    scored: int
    failed: int
    errored: int
    totals: Score


class _CaseFields(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid", strict=True)

    domain: str
    apex_txt: tuple[str, ...]
    dmarc_txt: tuple[str, ...]
    spf_by_domain: dict[str, tuple[str, ...]]


_CASE_FILE = pydantic.TypeAdapter(list[_CaseFields])


def load_cases(text: str) -> list[Case]:
    """Parse a JSON case file.

    Raises ValueError when the file is malformed, empty or longer than MAX_CASES,
    names a domain twice, or leaves out an include or redirect target that the
    audit needs.
    """
    all_fields = _CASE_FILE.validate_json(text)
    if len(all_fields) > MAX_CASES:
        raise ValueError(f"expected at most {MAX_CASES} cases, got {len(all_fields)}")
    cases: list[Case] = []
    seen: set[str] = set()
    for fields in all_fields:
        domain = parse_domain(fields.domain)
        if domain in seen:
            raise ValueError(f"case {domain} appears more than once")
        seen.add(domain)
        records = DnsRecords(fields.apex_txt, fields.dmarc_txt, fields.spf_by_domain)
        walk = spf.walk_lookups(records.apex_txt, records.spf_by_domain)
        if walk.unresolved and walk.lookup_count <= spf.MAX_SPF_LOOKUPS:
            missing = ", ".join(sorted(walk.unresolved))
            raise ValueError(f"case {domain} has no spf_by_domain entry for {missing}")
        cases.append(Case(domain, records))
    if not cases:
        raise ValueError("expected at least one case, got an empty list")
    return cases


def evaluate(
    cases: Sequence[Case], from_findings: Generate, from_records: Generate, repeats: int
) -> Iterator[Run]:
    """Run every condition on every case, `repeats` times over.

    `from_findings` must answer findings requests and `from_records` raw records
    requests. A model or API failure fails that condition and the run goes on.
    """
    for repeat in range(1, repeats + 1):
        for case in cases:
            for condition, outcome in _run_case(case, from_findings, from_records):
                yield Run(case.domain, repeat, condition, outcome)


def score(report: CheckReport) -> Score:
    verdicts = Counter(claim_check.verdict for claim_check in report.claim_checks)
    return Score(
        explained=verdicts[Verdict.ACCEPTED],
        invented=verdicts[Verdict.INVENTED],
        missed=len(report.missed),
        wrong_detail=verdicts[Verdict.WRONG_RECORD]
        + verdicts[Verdict.WRONG_DETAIL]
        + verdicts[Verdict.UNSUPPORTED_TOKEN]
        + bool(report.summary_unsupported_tokens),
    )


def summarise(runs: Sequence[Run]) -> list[ConditionSummary]:
    return [_summarise_condition(condition, runs) for condition in Condition]


def _run_case(
    case: Case, from_findings: Generate, from_records: Generate
) -> Iterator[tuple[Condition, Score | Failure]]:
    findings = audit(case.records)
    raw_request = raw_records_request(case.domain, case.records)
    yield (
        Condition.RAW_RECORDS,
        _attempt(lambda: score(check(findings, from_records(raw_request), case.records))),
    )
    request = findings_request(case.domain, findings, case.records)
    first = _attempt(lambda: from_findings(request))
    if isinstance(first, Failure):
        yield Condition.FINDINGS, first
        yield Condition.FINDINGS_CHECKED, first
        return
    yield Condition.FINDINGS, score(check(findings, first, case.records))

    def checked_score() -> Score:
        result = check_and_repair(request, first, findings, case.records, from_findings)
        return score(check(findings, result.explanation, case.records))

    yield Condition.FINDINGS_CHECKED, _attempt(checked_score)


def _attempt[T](action: Callable[[], T]) -> T | Failure:
    try:
        return action()
    except ExplanationError as err:
        return Failure(FailureKind.NO_EXPLANATION, str(err))
    except _API_UNAVAILABLE as err:
        return Failure(FailureKind.API_UNAVAILABLE, str(err))


def _summarise_condition(condition: Condition, runs: Sequence[Run]) -> ConditionSummary:
    outcomes = [run.outcome for run in runs if run.condition is condition]
    scores = [outcome for outcome in outcomes if isinstance(outcome, Score)]
    failure_kinds = Counter(outcome.kind for outcome in outcomes if isinstance(outcome, Failure))
    return ConditionSummary(
        condition,
        scored=len(scores),
        failed=failure_kinds[FailureKind.NO_EXPLANATION],
        errored=failure_kinds[FailureKind.API_UNAVAILABLE],
        totals=Score(
            explained=sum(each.explained for each in scores),
            invented=sum(each.invented for each in scores),
            missed=sum(each.missed for each in scores),
            wrong_detail=sum(each.wrong_detail for each in scores),
        ),
    )

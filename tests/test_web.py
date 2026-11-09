import json
import statistics
import time
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path

import pytest

from email_security_explainer.audit import DnsRecords
from email_security_explainer.domain import DomainName
from email_security_explainer.evaluate import load_cases
from email_security_explainer.findings import Finding, FindingCode
from email_security_explainer.web import (
    FINDING_TITLES,
    Span,
    audit_view,
    headline,
    marked_records,
)

DOMAIN = DomainName("example.com")
ENFORCING = "v=DMARC1; p=reject; rua=mailto:d@example.com"
CASES = load_cases(Path("cases/cases.json").read_text(encoding="utf-8"))
AUDIT_BUDGET_SECONDS = 0.050
TIMING_REPEATS = 50


def records(
    apex: tuple[str, ...],
    dmarc_txt: tuple[str, ...] = (ENFORCING,),
    spf_by_domain: Mapping[str, tuple[str, ...]] | None = None,
) -> DnsRecords:
    return DnsRecords(DOMAIN, apex, dmarc_txt, spf_by_domain or {})


def marks(lines: tuple[tuple[Span, ...], ...]) -> list[tuple[str, int | None]]:
    return [(span.text, span.finding) for line in lines for span in line if span.kind == "mark"]


def carets(lines: tuple[tuple[Span, ...], ...]) -> list[int | None]:
    return [span.finding for line in lines for span in line if span.kind == "caret"]


OPEN = "Anyone can send email as example.com."
PARTIAL = "Some forged email as example.com gets through."
SUBDOMAINS = "Anyone can send email as a subdomain of example.com."
OWN_MAIL = "Your own email from example.com may be refused."
GUARDED = "Inboxes are told to turn away forged email as example.com."


@pytest.mark.parametrize(
    ("findings", "is_dmarc_enforcing", "title", "cause_fragment"),
    [
        ([Finding(FindingCode.SPF_ALL_PASS, "+all")], True, OPEN, "every server"),
        ([Finding(FindingCode.DMARC_MISSING)], False, OPEN, "no DMARC record"),
        ([Finding(FindingCode.DMARC_MULTIPLE)], False, OPEN, "more than one DMARC"),
        ([Finding(FindingCode.DMARC_POLICY_NONE, "p=none")], False, OPEN, "deliver forged"),
        ([Finding(FindingCode.DMARC_SYNTAX, "p=maybe")], False, OPEN, "no valid policy"),
        ([Finding(FindingCode.DMARC_PARTIAL_PCT, "pct=50")], False, PARTIAL, "pct=50"),
        ([Finding(FindingCode.DMARC_SUBDOMAIN_NONE, "sp=none")], True, SUBDOMAINS, "sp=none"),
        ([Finding(FindingCode.SPF_MISSING)], True, OWN_MAIL, "no SPF record"),
        ([Finding(FindingCode.SPF_MULTIPLE)], True, OWN_MAIL, "more than one SPF"),
        ([Finding(FindingCode.SPF_SYNTAX, "a:")], True, OWN_MAIL, "cannot read"),
        ([Finding(FindingCode.SPF_LOOKUP_LIMIT)], True, OWN_MAIL, "more than 10"),
        ([Finding(FindingCode.SPF_TARGET_UNUSABLE, "include:x")], True, OWN_MAIL, "no usable"),
        ([], True, GUARDED, "no problems"),
        ([Finding(FindingCode.DMARC_NO_RUA)], True, GUARDED, "none lets forged mail"),
    ],
)
def test_headline_names_the_worst_consequence_and_its_cause(
    findings: list[Finding], is_dmarc_enforcing: bool, title: str, cause_fragment: str
) -> None:
    result = headline(DOMAIN, findings, is_dmarc_enforcing=is_dmarc_enforcing)
    assert result.title == title
    assert cause_fragment in result.cause


@pytest.mark.parametrize(
    ("findings", "is_dmarc_enforcing", "title", "cause_fragment"),
    [
        (
            [Finding(FindingCode.DMARC_PARTIAL_PCT, "pct=5"), Finding(FindingCode.SPF_ALL_PASS)],
            False,
            OPEN,
            "every server",
        ),
        (
            [Finding(FindingCode.DMARC_SYNTAX, "x"), Finding(FindingCode.DMARC_POLICY_NONE)],
            False,
            OPEN,
            "deliver forged",
        ),
        (
            [
                Finding(FindingCode.DMARC_SUBDOMAIN_NONE, "sp=none"),
                Finding(FindingCode.DMARC_PARTIAL_PCT, "pct=5"),
            ],
            False,
            PARTIAL,
            "pct=5",
        ),
        (
            [
                Finding(FindingCode.SPF_MISSING),
                Finding(FindingCode.DMARC_SUBDOMAIN_NONE, "sp=none"),
            ],
            True,
            SUBDOMAINS,
            "sp=none",
        ),
    ],
)
def test_headline_takes_the_first_rule_that_applies(
    findings: list[Finding], is_dmarc_enforcing: bool, title: str, cause_fragment: str
) -> None:
    result = headline(DOMAIN, findings, is_dmarc_enforcing=is_dmarc_enforcing)
    assert result.title == title
    assert cause_fragment in result.cause


def test_headline_rejects_a_dmarc_flag_its_findings_cannot_explain() -> None:
    with pytest.raises(AssertionError):
        headline(DOMAIN, [], is_dmarc_enforcing=False)


def test_every_finding_code_has_a_title() -> None:
    assert set(FINDING_TITLES) == set(FindingCode)


def test_marks_whole_terms_only() -> None:
    marked = marked_records(
        records(("v=spf1 ptr:mail.example.com ptr -all",)),
        [Finding(FindingCode.SPF_PTR, "ptr")],
    )
    assert [(span.kind, span.text) for span in marked.spf[0]] == [
        ("version", "v=spf1"),
        ("text", " "),
        ("text", "ptr:mail.example.com"),
        ("text", " "),
        ("mark", "ptr"),
        ("text", " "),
        ("text", "-all"),
    ]


def test_marks_each_repeated_term_once() -> None:
    marked = marked_records(
        records(("v=spf1 ptr ptr -all",)),
        [Finding(FindingCode.SPF_PTR, "ptr"), Finding(FindingCode.SPF_PTR, "ptr")],
    )
    assert marks(marked.spf) == [("ptr", 1), ("ptr", 2)]


def test_marks_a_dmarc_tag_without_its_surrounding_spaces() -> None:
    marked = marked_records(
        records(("v=spf1 -all",), ("v=DMARC1 ;  p = none ;rua=mailto:d@example.com",)),
        [Finding(FindingCode.DMARC_POLICY_NONE, "p = none")],
    )
    assert [(span.kind, span.text) for span in marked.dmarc[0]] == [
        ("version", "v=DMARC1 ;"),
        ("text", "  "),
        ("mark", "p = none"),
        ("text", " "),
        ("text", ";"),
        ("text", "rua=mailto:d@example.com"),
    ]


def test_keeps_the_text_of_a_dmarc_record_with_no_tags() -> None:
    marked = marked_records(records(("v=spf1 -all",), ("v=DMARC1",)), [])
    assert marked.dmarc == ((Span("version", "v=DMARC1"),),)


def test_puts_a_caret_at_the_end_of_the_record_for_a_finding_with_no_evidence() -> None:
    marked = marked_records(
        records(("v=spf1 -all",), ("v=DMARC1; p=reject",)),
        [Finding(FindingCode.DMARC_NO_RUA)],
    )
    assert marked.dmarc[0][-1] == Span("caret", "", 1)


def test_shows_a_missing_record_as_a_line_with_its_caret() -> None:
    marked = marked_records(
        records(("google-site-verification=x",), ("not dmarc",)),
        [Finding(FindingCode.SPF_MISSING), Finding(FindingCode.DMARC_MISSING)],
    )
    assert marked.spf == ((Span("absent", "No SPF record"), Span("caret", "", 1)),)
    assert marked.dmarc == ((Span("absent", "No DMARC record"), Span("caret", "", 2)),)


def test_shows_every_record_and_puts_the_caret_after_the_last() -> None:
    marked = marked_records(
        records(("v=spf1 -all", "v=spf1 ~all")),
        [Finding(FindingCode.SPF_MULTIPLE)],
    )
    assert [span.text for span in marked.spf[0]] == ["v=spf1", " ", "-all"]
    assert marked.spf[1][-1] == Span("caret", "", 1)
    assert carets(marked.spf) == [1]


def test_lists_the_include_chain_with_the_term_that_reached_each_record() -> None:
    marked = marked_records(
        records(
            ("v=spf1 include:A.example. redirect=b.example",),
            spf_by_domain={
                "a.example": ("v=spf1 include:c.example -all",),
                "b.example": ("v=spf1 -all",),
                "c.example": ("verification=x",),
            },
        ),
        [],
    )
    assert [(row.via, "".join(span.text for span in row.spans)) for row in marked.spf_chain] == [
        ("include:A.example.", "v=spf1 include:c.example -all"),
        ("include:c.example", "No SPF record"),
        ("redirect=b.example", "v=spf1 -all"),
    ]


def test_lists_each_chain_target_once_and_skips_targets_never_fetched() -> None:
    marked = marked_records(
        records(
            ("v=spf1 include:a.example include:a.example include:unfetched.example -all",),
            spf_by_domain={"a.example": ("v=spf1 include:a.example -all",)},
        ),
        [],
    )
    assert [row.via for row in marked.spf_chain] == ["include:a.example"]


def test_marks_a_redirected_all_in_the_record_that_decides_it() -> None:
    marked = marked_records(
        records(
            ("v=spf1 include:a.example redirect=b.example",),
            dmarc_txt=("v=DMARC1; p=none",),
            spf_by_domain={"a.example": ("v=spf1 ~all",), "b.example": ("v=spf1 ~all",)},
        ),
        [Finding(FindingCode.SPF_SOFTFAIL, "~all")],
    )
    assert [marks((row.spans,)) for row in marked.spf_chain] == [[], [("~all", 1)]]


def test_marks_an_unusable_include_in_the_chain_record_that_holds_it() -> None:
    marked = marked_records(
        records(
            ("v=spf1 include:a.example -all",),
            spf_by_domain={"a.example": ("v=spf1 include:gone.example -all",), "gone.example": ()},
        ),
        [Finding(FindingCode.SPF_TARGET_UNUSABLE, "include:gone.example")],
    )
    assert marks(marked.spf) == []
    assert marks((marked.spf_chain[0].spans,)) == [("include:gone.example", 1)]


def test_follows_a_redirect_loop_only_as_far_as_the_lookup_limit() -> None:
    marked = marked_records(
        records(
            ("v=spf1 redirect=a.example",),
            spf_by_domain={
                "a.example": ("v=spf1 redirect=b.example",),
                "b.example": ("v=spf1 redirect=a.example",),
            },
        ),
        [Finding(FindingCode.SPF_SOFTFAIL, "~all")],
    )
    assert [row.via for row in marked.spf_chain] == ["redirect=a.example", "redirect=b.example"]
    assert marks((*marked.spf, *(row.spans for row in marked.spf_chain))) == []


def test_leaves_evidence_found_nowhere_unmarked() -> None:
    marked = marked_records(
        records(("v=spf1 -all",), ("v=DMARC1; p=reject",)),
        [Finding(FindingCode.SPF_PTR, "ptr"), Finding(FindingCode.DMARC_SYNTAX, "x=y")],
    )
    assert marks(marked.spf) == []
    assert marks(marked.dmarc) == []
    assert carets(marked.spf) + carets(marked.dmarc) == []


def test_audit_view_numbers_findings_by_severity() -> None:
    view = audit_view(
        records(("v=spf1 ptr ~all",), ("v=DMARC1; p=none",)),
    )
    assert [(f.number, f.code) for f in view.findings] == [
        (1, FindingCode.DMARC_POLICY_NONE),
        (2, FindingCode.SPF_SOFTFAIL),
        (3, FindingCode.SPF_PTR),
        (4, FindingCode.DMARC_NO_RUA),
    ]
    assert view.findings[0].title == FINDING_TITLES[FindingCode.DMARC_POLICY_NONE]
    assert marks(view.records.dmarc) == [("p=none", 1)]
    assert view.headline.title == OPEN


def test_audit_view_counts_spf_lookups() -> None:
    view = audit_view(
        records(
            ("v=spf1 include:a.example mx -all",),
            spf_by_domain={"a.example": ("v=spf1 a -all",)},
        )
    )
    assert view.spf_lookup_count == 3
    assert view.max_spf_lookups == 10


@pytest.mark.parametrize("case", CASES, ids=[case.domain for case in CASES])
def test_audit_view_marks_every_finding_it_has_evidence_for(case: DnsRecords) -> None:
    view = audit_view(case)
    lines = (*view.records.spf, *(row.spans for row in view.records.spf_chain), *view.records.dmarc)
    numbers = [span.finding for line in lines for span in line if span.finding is not None]
    assert sorted(numbers) == [finding.number for finding in view.findings]
    for finding in view.findings:
        texts = [span.text for line in lines for span in line if span.finding == finding.number]
        assert texts == [finding.evidence or ""]


def test_audit_view_is_under_budget_on_every_case() -> None:
    worst_domain, worst_seconds = "", 0.0
    for case in CASES:
        timings = []
        for _ in range(TIMING_REPEATS):
            start = time.perf_counter()
            audit_view(case)
            timings.append(time.perf_counter() - start)
        median = statistics.median(timings)
        if median > worst_seconds:
            worst_domain, worst_seconds = case.domain, median
    print(f"audit_view, slowest case {worst_domain}: {worst_seconds * 1000:.2f} ms (budget 50 ms)")
    assert worst_seconds < AUDIT_BUDGET_SECONDS


def test_audit_view_serialises_to_json() -> None:
    payload = json.loads(json.dumps(asdict(audit_view(records(("v=spf1 ptr -all",))))))
    assert payload["findings"][0]["code"] == "SPF_PTR"
    assert payload["records"]["spf"][0][2] == {"kind": "mark", "text": "ptr", "finding": 1}

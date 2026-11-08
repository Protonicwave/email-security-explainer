from dataclasses import FrozenInstanceError

import pytest

from email_security_explainer.audit import DnsRecords, audit
from email_security_explainer.claims import CheckReport, Verdict, check
from email_security_explainer.findings import Finding, FindingCode, RecordKind
from email_security_explainer.schema import Claim, Explanation

RECORDS = DnsRecords(
    apex_txt=(
        "verification=abc include:verify.example.org",
        "v=spf1 include:_spf.mail.example.net ~all",
    ),
    dmarc_txt=("v=DMARC1; p = none",),
    spf_by_domain={
        "_spf.mail.example.net": ("v=spf1 ip4:192.0.2.0/24 -all", "note include:other.example"),
    },
)
FINDINGS = audit(RECORDS)
PLAIN_EXPLANATION = "Anyone can send mail that claims to come from your domain."
SUMMARY = "Two gaps let anyone send mail as example.com."


def claim(
    code: FindingCode,
    quoted_value: str | None,
    *,
    record: RecordKind | None = None,
    explanation: str = PLAIN_EXPLANATION,
    fix: str = "Tighten the record.",
) -> Claim:
    return Claim(
        finding_code=code,
        record=record or Finding(code).record,
        quoted_value=quoted_value,
        explanation=explanation,
        fix=fix,
    )


CLEAN_CLAIMS = [
    claim(FindingCode.SPF_SOFTFAIL, "~all"),
    claim(FindingCode.DMARC_POLICY_NONE, "p = none"),
    claim(FindingCode.DMARC_NO_RUA, None),
]


def run_check(
    claims: list[Claim],
    summary: str = SUMMARY,
    findings: list[Finding] = FINDINGS,
    records: DnsRecords = RECORDS,
) -> CheckReport:
    return check(findings, Explanation(summary=summary, claims=claims), records)


def verdicts(report: CheckReport) -> list[Verdict]:
    return [claim_check.verdict for claim_check in report.claim_checks]


def test_fixture_records_give_three_findings() -> None:
    assert audit(RECORDS) == [
        Finding(FindingCode.SPF_SOFTFAIL, "~all"),
        Finding(FindingCode.DMARC_POLICY_NONE, "p = none"),
        Finding(FindingCode.DMARC_NO_RUA),
    ]


def test_clean_explanation_passes() -> None:
    report = run_check(CLEAN_CLAIMS)

    assert report.is_clean
    assert verdicts(report) == [Verdict.ACCEPTED] * 3
    assert report.missed == ()
    assert report.summary_unsupported_tokens == ()


def test_claim_for_a_problem_the_audit_did_not_find_is_invented() -> None:
    report = run_check([*CLEAN_CLAIMS, claim(FindingCode.SPF_ALL_PASS, "+all")])

    assert verdicts(report) == [Verdict.ACCEPTED] * 3 + [Verdict.INVENTED]
    assert report.missed == ()
    assert not report.is_clean


def test_finding_without_a_claim_is_missed() -> None:
    report = run_check(CLEAN_CLAIMS[:2])

    assert verdicts(report) == [Verdict.ACCEPTED] * 2
    assert report.missed == (Finding(FindingCode.DMARC_NO_RUA),)
    assert not report.is_clean


def test_explanation_without_claims_misses_every_finding() -> None:
    report = run_check([])

    assert report.claim_checks == ()
    assert report.missed == tuple(FINDINGS)
    assert not report.is_clean


def test_domain_without_findings_passes_with_no_claims() -> None:
    assert run_check([], findings=[]).is_clean


@pytest.mark.parametrize("quoted_value", ["-all", "~ALL", " ~all", None])
def test_quoted_value_differing_from_evidence_is_wrong_detail(quoted_value: str | None) -> None:
    report = run_check([claim(FindingCode.SPF_SOFTFAIL, quoted_value), *CLEAN_CLAIMS[1:]])

    assert verdicts(report) == [Verdict.WRONG_DETAIL, Verdict.ACCEPTED, Verdict.ACCEPTED]
    assert report.missed == (Finding(FindingCode.SPF_SOFTFAIL, "~all"),)


def test_quoting_a_value_for_an_absent_tag_is_wrong_detail() -> None:
    report = run_check([*CLEAN_CLAIMS[:2], claim(FindingCode.DMARC_NO_RUA, "rua=")])

    assert verdicts(report)[2] is Verdict.WRONG_DETAIL
    assert report.missed == (Finding(FindingCode.DMARC_NO_RUA),)


def test_claim_naming_the_wrong_record_is_wrong_record() -> None:
    misfiled = claim(FindingCode.SPF_SOFTFAIL, "~all", record=RecordKind.DMARC)

    report = run_check([misfiled, *CLEAN_CLAIMS[1:]])

    assert verdicts(report)[0] is Verdict.WRONG_RECORD
    assert report.missed == (Finding(FindingCode.SPF_SOFTFAIL, "~all"),)


def test_dmarc_claim_naming_the_spf_record_is_wrong_record() -> None:
    misfiled = claim(FindingCode.DMARC_POLICY_NONE, "p = none", record=RecordKind.SPF)

    report = run_check([CLEAN_CLAIMS[0], misfiled, CLEAN_CLAIMS[2]])

    assert verdicts(report)[1] is Verdict.WRONG_RECORD
    assert report.missed == (Finding(FindingCode.DMARC_POLICY_NONE, "p = none"),)


def test_second_claim_for_one_finding_is_duplicate() -> None:
    report = run_check([*CLEAN_CLAIMS, claim(FindingCode.SPF_SOFTFAIL, "~all")])

    assert verdicts(report) == [Verdict.ACCEPTED] * 3 + [Verdict.DUPLICATE]
    assert report.missed == ()
    assert not report.is_clean


def test_claim_after_a_rejected_claim_for_the_same_finding_is_accepted() -> None:
    rejected = claim(FindingCode.SPF_SOFTFAIL, "~all", explanation="Unlike p=reject, ...")

    report = run_check([rejected, *CLEAN_CLAIMS])

    assert verdicts(report) == [Verdict.UNSUPPORTED_TOKEN] + [Verdict.ACCEPTED] * 3
    assert report.missed == ()


SYNTAX_RECORDS = DnsRecords(apex_txt=("v=spf1 foo bar -all",), dmarc_txt=())
SYNTAX_FINDINGS = [
    Finding(FindingCode.SPF_SYNTAX, "foo"),
    Finding(FindingCode.SPF_SYNTAX, "bar"),
    Finding(FindingCode.DMARC_MISSING),
]


def test_findings_sharing_a_code_are_matched_by_evidence() -> None:
    claims = [
        claim(FindingCode.SPF_SYNTAX, "bar"),
        claim(FindingCode.SPF_SYNTAX, "baz"),
        claim(FindingCode.SPF_SYNTAX, "foo"),
        claim(FindingCode.DMARC_MISSING, None),
    ]

    report = run_check(claims, findings=SYNTAX_FINDINGS, records=SYNTAX_RECORDS)

    assert verdicts(report) == [
        Verdict.ACCEPTED,
        Verdict.WRONG_DETAIL,
        Verdict.ACCEPTED,
        Verdict.ACCEPTED,
    ]
    assert report.missed == ()


def test_identical_findings_each_need_their_own_claim() -> None:
    records = DnsRecords(apex_txt=("v=spf1 foo foo -all",), dmarc_txt=())
    findings = audit(records)
    assert findings.count(Finding(FindingCode.SPF_SYNTAX, "foo")) == 2

    report = run_check([claim(FindingCode.SPF_SYNTAX, "foo")], findings=findings, records=records)

    assert report.missed == (
        Finding(FindingCode.SPF_SYNTAX, "foo"),
        Finding(FindingCode.DMARC_MISSING),
    )


@pytest.mark.parametrize(
    "token",
    [
        "+all",
        "?all",
        "include:evil.example",
        "exists:check.example",
        "ip4:198.51.100.7",
        "ip6:2001:db8::1",
        "redirect=other.example",
        "p=reject",
        "sp=none",
        "pct=50",
        "rua=mailto:dmarc@evil.example",
        "ruf=mailto:dmarc@evil.example",
        "adkim=s",
        "aspf=r",
    ],
)
def test_explanation_quoting_a_token_absent_from_the_records_is_unsupported(token: str) -> None:
    claims = [claim(FindingCode.SPF_SOFTFAIL, "~all", explanation=f"Your record has {token}.")]

    report = run_check([*claims, *CLEAN_CLAIMS[1:]])

    assert report.claim_checks[0].verdict is Verdict.UNSUPPORTED_TOKEN
    assert report.claim_checks[0].unsupported_tokens == (token,)
    assert report.missed == (Finding(FindingCode.SPF_SOFTFAIL, "~all"),)


def test_tokens_from_the_apex_dmarc_and_include_records_are_supported() -> None:
    explanation = (
        "Your ~all and include:_spf.mail.example.net reach ip4:192.0.2.0/24 and -all; "
        "DMARC says p=none."
    )

    report = run_check([claim(FindingCode.SPF_SOFTFAIL, "~all", explanation=explanation)])

    assert report.claim_checks[0].verdict is Verdict.ACCEPTED


def test_token_comparison_ignores_case_and_surrounding_punctuation() -> None:
    explanation = "Records say `~ALL`, (include:_SPF.mail.example.net) and P=None."

    report = run_check([claim(FindingCode.SPF_SOFTFAIL, "~all", explanation=explanation)])

    assert report.claim_checks[0].verdict is Verdict.ACCEPTED


def test_ordinary_words_are_not_read_as_tokens() -> None:
    explanation = "A catch-all rule lets all senders through; set the p tag later."

    report = run_check([claim(FindingCode.SPF_SOFTFAIL, "~all", explanation=explanation)])

    assert report.claim_checks[0].verdict is Verdict.ACCEPTED


def test_fix_may_name_values_absent_from_the_records() -> None:
    fixed = claim(FindingCode.SPF_SOFTFAIL, "~all", fix="Change ~all to -all and set p=reject.")

    assert run_check([fixed, *CLEAN_CLAIMS[1:]]).is_clean


@pytest.mark.parametrize("token", ["include:verify.example.org", "include:other.example"])
def test_tokens_in_non_spf_txt_records_are_unsupported(token: str) -> None:
    report = run_check([claim(FindingCode.SPF_SOFTFAIL, "~all", explanation=f"See {token}.")])

    assert report.claim_checks[0].unsupported_tokens == (token,)


def test_unsupported_tokens_are_listed_once_in_order_of_appearance() -> None:
    explanation = "p=reject, then +all, then p=reject again."

    report = run_check([claim(FindingCode.SPF_SOFTFAIL, "~all", explanation=explanation)])

    assert report.claim_checks[0].unsupported_tokens == ("p=reject", "+all")


def test_summary_quoting_a_token_absent_from_the_records_fails_the_check() -> None:
    report = run_check(CLEAN_CLAIMS, summary="Your p=reject policy is undermined by +all.")

    assert verdicts(report) == [Verdict.ACCEPTED] * 3
    assert report.summary_unsupported_tokens == ("p=reject", "+all")
    assert not report.is_clean


def test_claim_check_cannot_be_modified() -> None:
    claim_check = run_check(CLEAN_CLAIMS).claim_checks[0]

    with pytest.raises(FrozenInstanceError):
        claim_check.verdict = Verdict.INVENTED  # type: ignore[misc]  # frozen on purpose


def test_report_cannot_be_modified() -> None:
    report = run_check(CLEAN_CLAIMS)

    with pytest.raises(FrozenInstanceError):
        report.missed = ()  # type: ignore[misc]  # frozen on purpose


def test_claim_check_stores_no_instance_dictionary() -> None:
    assert not hasattr(run_check(CLEAN_CLAIMS).claim_checks[0], "__dict__")


def test_report_stores_no_instance_dictionary() -> None:
    assert not hasattr(run_check(CLEAN_CLAIMS), "__dict__")


def test_spaces_around_equals_do_not_hide_a_token() -> None:
    explanation = "Your record says p = reject, so forged mail is blocked."

    report = run_check([claim(FindingCode.SPF_SOFTFAIL, "~all", explanation=explanation)])

    assert report.claim_checks[0].unsupported_tokens == ("p=reject",)


def test_curly_quotes_around_a_token_are_not_part_of_it() -> None:
    explanation = "Your record says \u2018p=none\u2019 and \u201c~all\u201d."

    report = run_check([claim(FindingCode.SPF_SOFTFAIL, "~all", explanation=explanation)])

    assert report.claim_checks[0].verdict is Verdict.ACCEPTED


def test_each_address_in_a_report_list_is_supported() -> None:
    records = DnsRecords(
        apex_txt=("v=spf1 ~all",),
        dmarc_txt=("v=DMARC1; p=none; rua=mailto:a@reports.example, mailto:b@reports.example",),
    )
    explanation = "Reports go to rua=mailto:b@reports.example and rua=mailto:a@reports.example."
    softfail = claim(FindingCode.SPF_SOFTFAIL, "~all", explanation=explanation)

    report = run_check([softfail], findings=audit(records), records=records)

    assert report.claim_checks[0].verdict is Verdict.ACCEPTED

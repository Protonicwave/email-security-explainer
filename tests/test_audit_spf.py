from collections.abc import Mapping

import pytest

from email_security_explainer.audit import DnsRecords, audit
from email_security_explainer.findings import Finding, FindingCode, RecordKind, Severity

ENFORCING_DMARC = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"


def spf_findings(
    apex_txt: tuple[str, ...],
    dmarc: str = ENFORCING_DMARC,
    spf_by_domain: Mapping[str, tuple[str, ...]] | None = None,
) -> list[Finding]:
    records = DnsRecords(apex_txt=apex_txt, dmarc_txt=(dmarc,), spf_by_domain=spf_by_domain or {})
    return [finding for finding in audit(records) if finding.record is RecordKind.SPF]


def test_clean_record_has_no_findings() -> None:
    assert spf_findings(("v=spf1 ip4:192.0.2.0/24 -all",)) == []


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 a mx a:mail.example.com/24 mx//64 a/24//64 -all",
        "v=spf1 ip6:2001:db8::/32 ip4:192.0.2.1 exists:%{i}.spf.example.com -all",
        "v=spf1 -all exp=explain.example.com custom-modifier=anything",
        "V=SPF1 IP4:192.0.2.1 -ALL",
        "v=spf1  ip4:192.0.2.1   -all",
        "v=spf1 include:%{d}.spf.example.com -all",
    ],
)
def test_valid_syntax_has_no_findings(record: str) -> None:
    assert spf_findings((record,)) == []


@pytest.mark.parametrize(
    ("apex_txt", "expected"),
    [
        ((), [Finding(FindingCode.SPF_MISSING)]),
        (("google-site-verification=abc123",), [Finding(FindingCode.SPF_MISSING)]),
        (("v=spf10 -all",), [Finding(FindingCode.SPF_MISSING)]),
        (("v=spf1 -all", "v=spf1 ~all"), [Finding(FindingCode.SPF_MULTIPLE)]),
        (("v=spf1 +all",), [Finding(FindingCode.SPF_ALL_PASS, "+all")]),
        (("v=spf1 all",), [Finding(FindingCode.SPF_ALL_PASS, "all")]),
        (("v=spf1 ?all",), [Finding(FindingCode.SPF_ALL_NEUTRAL, "?all")]),
        (("v=spf1 ip4:192.0.2.1",), [Finding(FindingCode.SPF_NO_ALL)]),
        (("v=spf1",), [Finding(FindingCode.SPF_NO_ALL)]),
        (("v=spf1 ptr -all",), [Finding(FindingCode.SPF_PTR, "ptr")]),
        (
            ("v=spf1 ptr:mail.example.com ?all",),
            [
                Finding(FindingCode.SPF_ALL_NEUTRAL, "?all"),
                Finding(FindingCode.SPF_PTR, "ptr:mail.example.com"),
            ],
        ),
    ],
)
def test_reports_gap(apex_txt: tuple[str, ...], expected: list[Finding]) -> None:
    assert spf_findings(apex_txt) == expected


@pytest.mark.parametrize(
    "bad_term",
    [
        "foo",
        "=x",
        "ip4:999.0.0.1",
        "ip4",
        "ip6:zz::1::2",
        "include",
        "include:",
        "exists:",
        "a/33",
        "mx//129",
        "a:",
        "-all:example.com",
        "ptr:",
        "exp=",
        "redirect=",
    ],
)
def test_invalid_term_is_syntax_error(bad_term: str) -> None:
    assert spf_findings((f"v=spf1 {bad_term} -all",)) == [Finding(FindingCode.SPF_SYNTAX, bad_term)]


def test_repeated_redirect_is_syntax_error() -> None:
    findings = spf_findings(("v=spf1 redirect=a.example.com redirect=b.example.com",))
    assert findings == [Finding(FindingCode.SPF_SYNTAX, "redirect=b.example.com")]


def test_syntax_errors_suppress_other_rules() -> None:
    assert spf_findings(("v=spf1 bogus +all",)) == [Finding(FindingCode.SPF_SYNTAX, "bogus")]


@pytest.mark.parametrize(
    ("dmarc", "is_reported"),
    [
        (ENFORCING_DMARC, False),
        ("v=DMARC1; p=quarantine; rua=mailto:d@example.com", False),
        ("v=DMARC1; p=none; rua=mailto:d@example.com", True),
        ("v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com", True),
        ("not a dmarc record", True),
    ],
)
def test_softfail_reported_only_without_enforcing_dmarc(dmarc: str, is_reported: bool) -> None:
    findings = spf_findings(("v=spf1 ~all",), dmarc=dmarc)
    assert (Finding(FindingCode.SPF_SOFTFAIL, "~all") in findings) is is_reported


def test_include_chain_within_limit_is_clean() -> None:
    findings = spf_findings(
        ("v=spf1 include:a.example.com -all",),
        spf_by_domain={
            "a.example.com": ("v=spf1 include:b.example.com -all",),
            "b.example.com": ("v=spf1 ip4:192.0.2.1 -all",),
        },
    )
    assert findings == []


def test_include_target_is_matched_case_insensitively_without_trailing_dot() -> None:
    findings = spf_findings(
        ("v=spf1 include:A.Example.COM. -all",),
        spf_by_domain={"a.example.com": ("v=spf1 -all",)},
    )
    assert findings == []


@pytest.mark.parametrize(
    "target_txt",
    [
        (),
        ("unrelated text",),
        ("v=spf1 -all", "v=spf1 ~all"),
        ("v=spf1 bogus -all",),
    ],
)
def test_include_without_one_valid_record_is_unusable(target_txt: tuple[str, ...]) -> None:
    findings = spf_findings(
        ("v=spf1 include:a.example.com -all",),
        spf_by_domain={"a.example.com": target_txt},
    )
    assert findings == [Finding(FindingCode.SPF_TARGET_UNUSABLE, "include:a.example.com")]


def test_same_unusable_include_reported_once() -> None:
    findings = spf_findings(
        ("v=spf1 include:a.example.com include:b.example.com -all",),
        spf_by_domain={
            "a.example.com": ("v=spf1 include:gone.example.com -all",),
            "b.example.com": ("v=spf1 include:gone.example.com -all",),
            "gone.example.com": (),
        },
    )
    assert findings == [Finding(FindingCode.SPF_TARGET_UNUSABLE, "include:gone.example.com")]


def test_redirect_to_missing_record_is_unusable_and_counts_as_all() -> None:
    findings = spf_findings(
        ("v=spf1 redirect=a.example.com",),
        spf_by_domain={"a.example.com": ()},
    )
    assert findings == [Finding(FindingCode.SPF_TARGET_UNUSABLE, "redirect=a.example.com")]


def test_redirect_ignored_when_all_present() -> None:
    assert spf_findings(("v=spf1 -all redirect=a.example.com",)) == []


def test_ten_lookups_is_within_limit() -> None:
    terms = " ".join(f"a:h{index}.example.com" for index in range(10))
    assert spf_findings((f"v=spf1 {terms} -all",)) == []


def test_eleven_lookups_exceeds_limit() -> None:
    terms = " ".join(f"a:h{index}.example.com" for index in range(11))
    assert spf_findings((f"v=spf1 {terms} -all",)) == [Finding(FindingCode.SPF_LOOKUP_LIMIT)]


def test_lookups_in_included_records_count_towards_limit() -> None:
    nested_terms = " ".join(f"mx:h{index}.example.com" for index in range(10))
    findings = spf_findings(
        ("v=spf1 include:a.example.com -all",),
        spf_by_domain={"a.example.com": (f"v=spf1 {nested_terms} -all",)},
    )
    assert findings == [Finding(FindingCode.SPF_LOOKUP_LIMIT)]


def test_include_loop_exceeds_limit() -> None:
    findings = spf_findings(
        ("v=spf1 include:a.example.com -all",),
        spf_by_domain={"a.example.com": ("v=spf1 include:a.example.com -all",)},
    )
    assert findings == [Finding(FindingCode.SPF_LOOKUP_LIMIT)]


def test_every_code_has_a_severity() -> None:
    for code in FindingCode:
        assert isinstance(Finding(code).severity, Severity)

import pytest

from email_security_explainer.audit import DnsRecords, audit
from email_security_explainer.findings import Finding, FindingCode, RecordKind

CLEAN_SPF = "v=spf1 ip4:192.0.2.1 -all"
RUA = "rua=mailto:dmarc@example.com"


def dmarc_findings(dmarc_txt: tuple[str, ...]) -> list[Finding]:
    records = DnsRecords(apex_txt=(CLEAN_SPF,), dmarc_txt=dmarc_txt)
    return [finding for finding in audit(records) if finding.record is RecordKind.DMARC]


@pytest.mark.parametrize(
    "record",
    [
        f"v=DMARC1; p=reject; {RUA}",
        f"v=DMARC1; p=quarantine; pct=100; sp=reject; {RUA}",
        f"v = DMARC1 ; P = Reject ; {RUA.upper()}",
        f"v=DMARC1; p=reject; {RUA};",
        f"v=DMARC1; p=reject; fo=1; adkim=s; {RUA}",
        f"v=DMARC1;; p=reject; {RUA}",
    ],
)
def test_enforcing_record_has_no_findings(record: str) -> None:
    assert dmarc_findings((record,)) == []


@pytest.mark.parametrize(
    ("dmarc_txt", "expected"),
    [
        ((), [Finding(FindingCode.DMARC_MISSING)]),
        (("some other text",), [Finding(FindingCode.DMARC_MISSING)]),
        (("v=DMARC2; p=reject",), [Finding(FindingCode.DMARC_MISSING)]),
        (
            (f"v=DMARC1; p=reject; {RUA}", f"v=DMARC1; p=none; {RUA}"),
            [Finding(FindingCode.DMARC_MULTIPLE)],
        ),
        ((f"v=DMARC1; p=none; {RUA}",), [Finding(FindingCode.DMARC_POLICY_NONE, "p=none")]),
        (
            (f"v=DMARC1; p=quarantine; pct=50; {RUA}",),
            [Finding(FindingCode.DMARC_PARTIAL_PCT, "pct=50")],
        ),
        (
            (f"v=DMARC1; p=reject; sp=none; {RUA}",),
            [Finding(FindingCode.DMARC_SUBDOMAIN_NONE, "sp=none")],
        ),
        (
            (f"v=DMARC1; p=none; sp=none; pct=10; {RUA}",),
            [Finding(FindingCode.DMARC_POLICY_NONE, "p=none")],
        ),
        (("v=DMARC1; p=reject",), [Finding(FindingCode.DMARC_NO_RUA)]),
    ],
)
def test_reports_gap(dmarc_txt: tuple[str, ...], expected: list[Finding]) -> None:
    assert dmarc_findings(dmarc_txt) == expected


@pytest.mark.parametrize(
    ("record", "evidence"),
    [
        (f"v=DMARC1; {RUA}", None),
        (f"v=DMARC1; p=bogus; {RUA}", "p=bogus"),
        (f"v=DMARC1; p=reject; pct=abc; {RUA}", "pct=abc"),
        (f"v=DMARC1; p=reject; pct=150; {RUA}", "pct=150"),
        (f"v=DMARC1; p=reject; sp=bogus; {RUA}", "sp=bogus"),
        (f"v=DMARC1; p=reject; garbage; {RUA}", "garbage"),
        (f"v=DMARC1; p=reject; p=none; {RUA}", "p=none"),
    ],
)
def test_malformed_record_is_syntax_error(record: str, evidence: str | None) -> None:
    assert dmarc_findings((record,)) == [Finding(FindingCode.DMARC_SYNTAX, evidence)]


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (f"v=DMARC1; P = None; {RUA}", Finding(FindingCode.DMARC_POLICY_NONE, "P = None")),
        (
            f"v=DMARC1; p=reject; PCT = 50; {RUA}",
            Finding(FindingCode.DMARC_PARTIAL_PCT, "PCT = 50"),
        ),
        (
            f"v=DMARC1; p=reject; SP=None; {RUA}",
            Finding(FindingCode.DMARC_SUBDOMAIN_NONE, "SP=None"),
        ),
        (f"v=DMARC1; p = bogus; {RUA}", Finding(FindingCode.DMARC_SYNTAX, "p = bogus")),
        (f"v=DMARC1; p=reject; pct = abc; {RUA}", Finding(FindingCode.DMARC_SYNTAX, "pct = abc")),
        (f"v=DMARC1; p=reject; sp = bogus; {RUA}", Finding(FindingCode.DMARC_SYNTAX, "sp = bogus")),
    ],
)
def test_evidence_quotes_the_tag_as_written(record: str, expected: Finding) -> None:
    assert dmarc_findings((record,)) == [expected]

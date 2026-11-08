"""The closed set of problems the auditor can report."""

from dataclasses import dataclass
from enum import StrEnum


class RecordKind(StrEnum):
    SPF = "spf"
    DMARC = "dmarc"


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingCode(StrEnum):
    SPF_MISSING = "SPF_MISSING"
    SPF_MULTIPLE = "SPF_MULTIPLE"
    SPF_SYNTAX = "SPF_SYNTAX"
    SPF_ALL_PASS = "SPF_ALL_PASS"  # noqa: S105 (a finding code, not a password)
    SPF_ALL_NEUTRAL = "SPF_ALL_NEUTRAL"
    SPF_NO_ALL = "SPF_NO_ALL"
    SPF_SOFTFAIL = "SPF_SOFTFAIL"
    SPF_PTR = "SPF_PTR"
    SPF_LOOKUP_LIMIT = "SPF_LOOKUP_LIMIT"
    SPF_TARGET_UNUSABLE = "SPF_TARGET_UNUSABLE"
    DMARC_MISSING = "DMARC_MISSING"
    DMARC_MULTIPLE = "DMARC_MULTIPLE"
    DMARC_SYNTAX = "DMARC_SYNTAX"
    DMARC_POLICY_NONE = "DMARC_POLICY_NONE"
    DMARC_PARTIAL_PCT = "DMARC_PARTIAL_PCT"
    DMARC_SUBDOMAIN_NONE = "DMARC_SUBDOMAIN_NONE"
    DMARC_NO_RUA = "DMARC_NO_RUA"


# A permanent SPF error (multiple records, bad syntax, too many lookups, an
# unusable include) makes receivers treat SPF as failed for every message, so
# those rank with a missing record.
SEVERITY_BY_CODE: dict[FindingCode, Severity] = {
    FindingCode.SPF_MISSING: Severity.HIGH,
    FindingCode.SPF_MULTIPLE: Severity.HIGH,
    FindingCode.SPF_SYNTAX: Severity.HIGH,
    FindingCode.SPF_ALL_PASS: Severity.HIGH,
    FindingCode.SPF_ALL_NEUTRAL: Severity.MEDIUM,
    FindingCode.SPF_NO_ALL: Severity.MEDIUM,
    FindingCode.SPF_SOFTFAIL: Severity.MEDIUM,
    FindingCode.SPF_PTR: Severity.LOW,
    FindingCode.SPF_LOOKUP_LIMIT: Severity.HIGH,
    FindingCode.SPF_TARGET_UNUSABLE: Severity.HIGH,
    FindingCode.DMARC_MISSING: Severity.HIGH,
    FindingCode.DMARC_MULTIPLE: Severity.HIGH,
    FindingCode.DMARC_SYNTAX: Severity.HIGH,
    FindingCode.DMARC_POLICY_NONE: Severity.HIGH,
    FindingCode.DMARC_PARTIAL_PCT: Severity.MEDIUM,
    FindingCode.DMARC_SUBDOMAIN_NONE: Severity.MEDIUM,
    FindingCode.DMARC_NO_RUA: Severity.LOW,
}


@dataclass(frozen=True, slots=True)
class Finding:
    """One problem in a domain's records.

    `evidence` is the record token the finding rests on, such as `~all` or
    `p=none`, or None when the problem is an absence rather than a token.
    """

    code: FindingCode
    evidence: str | None = None

    @property
    def severity(self) -> Severity:
        return SEVERITY_BY_CODE[self.code]

    @property
    def record(self) -> RecordKind:
        return RecordKind.SPF if self.code.startswith("SPF_") else RecordKind.DMARC

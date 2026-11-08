"""Check an explanation's claims against the audit findings, with no I/O.

A claim is accepted only when it names a finding the audit produced, quotes
that finding's evidence exactly, and its explanation quotes no record token
that is absent from the domain's records. A finding is covered only by an
accepted claim. The `fix` field is not scanned, because a fix names values the
records do not yet contain.
"""

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from enum import StrEnum

from email_security_explainer import spf
from email_security_explainer.audit import DnsRecords
from email_security_explainer.findings import Finding
from email_security_explainer.schema import Claim, Explanation

_TERM_VALUE = r"[^\s;,'\"`()\[\]\u2018\u2019\u201c\u201d]+"
# Record tokens a reader could take for a quotation of their own record. The
# lookbehind keeps words such as "catch-all" and "sp=" from matching "-all" and "p=".
_RECORD_TOKEN = re.compile(
    r"(?<![\w-])(?:[-+~?]all\b"
    rf"|(?:include|exists|ip4|ip6):{_TERM_VALUE}"
    rf"|(?:redirect|p|sp|pct|rua|ruf|adkim|aspf)={_TERM_VALUE})",
    re.IGNORECASE,
)
# RFC 7489 section 6.4 allows whitespace around "=" in a DMARC tag, and prose
# that writes p = reject still quotes a record value.
_SPACE_AROUND_EQUALS = re.compile(r"\s*=\s*")
# RFC 7489 section 6.2: rua and ruf hold comma-separated URIs, and prose may
# quote any one of them.
_URI_LIST = re.compile(r"(?<![\w-])(rua|ruf)\s*=\s*([^;]+)", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".:!?"


class Verdict(StrEnum):
    ACCEPTED = "accepted"
    INVENTED = "invented"
    WRONG_DETAIL = "wrong_detail"
    DUPLICATE = "duplicate"
    UNSUPPORTED_TOKEN = "unsupported_token"  # noqa: S105 (a verdict, not a password)


@dataclass(frozen=True, slots=True)
class ClaimCheck:
    claim: Claim
    verdict: Verdict
    unsupported_tokens: tuple[str, ...] = ()

    @property
    def is_accepted(self) -> bool:
        return self.verdict is Verdict.ACCEPTED


@dataclass(frozen=True, slots=True)
class CheckReport:
    claim_checks: tuple[ClaimCheck, ...]
    missed: tuple[Finding, ...]
    summary_unsupported_tokens: tuple[str, ...]

    @property
    def is_clean(self) -> bool:
        return (
            not self.missed
            and not self.summary_unsupported_tokens
            and all(claim_check.is_accepted for claim_check in self.claim_checks)
        )


def check(
    findings: Sequence[Finding], explanation: Explanation, records: DnsRecords
) -> CheckReport:
    record_tokens = _record_tokens(records)
    uncovered = list(findings)
    claim_checks: list[ClaimCheck] = []
    for claim in explanation.claims:
        claim_check = _check_claim(claim, findings, uncovered, record_tokens)
        if claim_check.is_accepted:
            uncovered.remove(Finding(claim.finding_code, claim.quoted_value))
        claim_checks.append(claim_check)
    return CheckReport(
        tuple(claim_checks),
        tuple(uncovered),
        _unsupported_tokens(explanation.summary, record_tokens),
    )


def _check_claim(
    claim: Claim,
    findings: Sequence[Finding],
    uncovered: list[Finding],
    record_tokens: frozenset[str],
) -> ClaimCheck:
    claimed = Finding(claim.finding_code, claim.quoted_value)
    if claim.finding_code not in {finding.code for finding in findings}:
        return ClaimCheck(claim, Verdict.INVENTED)
    if claimed not in findings:
        return ClaimCheck(claim, Verdict.WRONG_DETAIL)
    if claimed not in uncovered:
        return ClaimCheck(claim, Verdict.DUPLICATE)
    unsupported = _unsupported_tokens(claim.explanation, record_tokens)
    if unsupported:
        return ClaimCheck(claim, Verdict.UNSUPPORTED_TOKEN, unsupported)
    return ClaimCheck(claim, Verdict.ACCEPTED)


def _record_tokens(records: DnsRecords) -> frozenset[str]:
    texts = [
        *spf.select_records(records.apex_txt),
        *records.dmarc_txt,
        *(text for txt in records.spf_by_domain.values() for text in spf.select_records(txt)),
    ]
    return frozenset(token for text in texts for token in _tokens(_split_uri_lists(text)))


def _split_uri_lists(record: str) -> str:
    return _URI_LIST.sub(
        lambda match: " ".join(f"{match[1]}={uri.strip()}" for uri in match[2].split(",")),
        record,
    )


def _unsupported_tokens(prose: str, record_tokens: frozenset[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(token for token in _tokens(prose) if token not in record_tokens))


def _tokens(text: str) -> Iterator[str]:
    for match in _RECORD_TOKEN.finditer(_SPACE_AROUND_EQUALS.sub("=", text)):
        yield match.group().rstrip(_TRAILING_PUNCTUATION).lower()

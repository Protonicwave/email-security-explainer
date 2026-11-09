"""Check an explanation's claims against the audit findings, with no I/O.

A claim is accepted only when it names a finding the audit produced, quotes
that finding's evidence exactly, and its explanation quotes no record token,
IP address or domain name that is absent from the domain's records. The
audited domain and its `_dmarc` name count as present. A finding is covered
only by an accepted claim. The `fix` field is not scanned, because a fix
names values the records do not yet contain.
"""

import ipaddress
import re
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from enum import StrEnum

from email_security_explainer import spf
from email_security_explainer.audit import DnsRecords
from email_security_explainer.findings import Finding
from email_security_explainer.schema import Claim, Explanation

_TERM_VALUE = r"[^\s;,'\"`()\[\]\u2018\u2019\u201c\u201d]+"
# A name ends where a word does, so "example.com." and "2001:db8::1:" end a
# sentence or clause rather than continue the name. The local part of an email
# address, such as "first.last" in first.last@example.com, is not a name.
_NAME_END = r"(?![\w@-]|[.:][\w:])"
# Text a reader could take for a quotation of their own record: a record token,
# an IP address or network, or a domain name. Record tokens come first, so a
# value inside one is not read again on its own. The record-token lookbehind
# keeps words such as "catch-all" and "sp=" from matching "-all" and "p=". A
# domain name ends in an alphabetic label of two or more letters, which rules
# out "e.g." and version numbers such as "1.6".
_IP4 = r"\d{1,3}(?:\.\d{1,3}){3}"
# RFC 4291 section 2.2: an IPv6 address may end in an IPv4 one, as in ::ffff:192.0.2.1.
_IP6_WITH_IP4 = rf"(?:[0-9a-f]{{0,4}}:){{2,6}}{_IP4}"
_IP6 = r"(?:[0-9a-f]{0,4}:){1,7}(?:[0-9a-f]{1,4}|:)"
_TOKEN = re.compile(
    r"(?<![\w-])(?:[-+~?]all\b"
    rf"|(?:include|exists|ip4|ip6):{_TERM_VALUE}"
    rf"|(?:redirect|p|sp|pct|rua|ruf|adkim|aspf)={_TERM_VALUE})"
    rf"|(?<![\w.:])(?P<address>(?:{_IP4}|{_IP6_WITH_IP4}|{_IP6})(?:/\d{{1,3}})?)"
    rf"{_NAME_END}"
    rf"|(?<![\w.-])(?:[\w-]+\.)+[a-z]{{2,}}{_NAME_END}",
    re.IGNORECASE,
)
# The name and separator of a record token, leaving its value: the target of
# include: or the URI of rua=.
_TOKEN_NAME = re.compile(r"^[^:=]*[:=]")
# RFC 7489 section 6.4 allows whitespace around "=" in a DMARC tag, and prose
# that writes p = reject still quotes a record value. Prose also names a tag
# as "the p= tag", so a space after "=" joins only a word shaped like a value:
# a policy or alignment keyword, or text with a digit or an inner colon or dot.
_SPACE_AROUND_EQUALS = re.compile(
    r"\s*=(?:\s+(?=(?:none|quarantine|reject|r|s)\b|\S*?(?:\d|[:.]\w)))?", re.IGNORECASE
)
# RFC 7489 section 6.2: rua and ruf hold comma-separated URIs, and prose may
# quote any one of them.
_URI_LIST = re.compile(r"(?<![\w-])(rua|ruf)\s*=\s*([^;]+)", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".:!?"
_BARE_NAME = re.compile(r"[\w.-]+")
# SPF terms are separated by spaces (RFC 7208 section 4.6.1), DMARC tags by
# semicolons (RFC 7489 section 6.4).
_TERM_SEPARATOR = re.compile(r"[\s;]+")


class Verdict(StrEnum):
    ACCEPTED = "accepted"
    INVENTED = "invented"
    WRONG_DETAIL = "wrong_detail"
    DUPLICATE = "duplicate"
    UNSUPPORTED_TOKEN = "unsupported_token"  # noqa: S105 (a verdict, not a password)


# Mutating these flags changes nothing a test can see: mypy rejects writes to a
# frozen dataclass, and slots only saves memory.
@dataclass(frozen=True, slots=True)  # pragma: no mutate
class ClaimCheck:
    claim: Claim
    verdict: Verdict
    unsupported_tokens: tuple[str, ...] = ()

    @property
    def is_accepted(self) -> bool:
        return self.verdict is Verdict.ACCEPTED


@dataclass(frozen=True, slots=True)  # pragma: no mutate
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
    is_supported = _supported_token_test(records)
    uncovered = list(findings)
    claim_checks: list[ClaimCheck] = []
    for claim in explanation.claims:
        claim_check = _check_claim(claim, findings, uncovered, is_supported)
        if claim_check.is_accepted:
            uncovered.remove(Finding(claim.finding_code, claim.quoted_value))
        claim_checks.append(claim_check)
    return CheckReport(
        tuple(claim_checks),
        tuple(uncovered),
        _unsupported_tokens(explanation.summary, is_supported),
    )


def _check_claim(
    claim: Claim,
    findings: Sequence[Finding],
    uncovered: list[Finding],
    is_supported: Callable[[str], bool],
) -> ClaimCheck:
    claimed = Finding(claim.finding_code, claim.quoted_value)
    if claim.finding_code not in {finding.code for finding in findings}:
        return ClaimCheck(claim, Verdict.INVENTED)
    if claimed not in findings:
        return ClaimCheck(claim, Verdict.WRONG_DETAIL)
    if claimed not in uncovered:
        return ClaimCheck(claim, Verdict.DUPLICATE)
    unsupported = _unsupported_tokens(claim.explanation, is_supported)
    if unsupported:
        return ClaimCheck(claim, Verdict.UNSUPPORTED_TOKEN, unsupported)
    return ClaimCheck(claim, Verdict.ACCEPTED)


def _supported_token_test(records: DnsRecords) -> Callable[[str], bool]:
    tokens = _record_tokens(records)
    subdomain_suffix = f".{records.domain}"

    def is_supported(token: str) -> bool:
        return token in tokens or _is_illustrative_subdomain(token, subdomain_suffix)

    return is_supported


def _is_illustrative_subdomain(token: str, subdomain_suffix: str) -> bool:
    # A made-up host such as billing.<domain> quotes nothing from the records,
    # but a service name such as _spf.<domain> reads as a record the domain
    # publishes, and a record token such as include:billing.<domain> as a term.
    return (
        token.endswith(subdomain_suffix)
        and _BARE_NAME.fullmatch(token) is not None
        and not any(label.startswith("_") for label in token.split("."))
    )


def _record_tokens(records: DnsRecords) -> frozenset[str]:
    texts = [
        *spf.select_records(records.apex_txt),
        *records.dmarc_txt,
        *(text for txt in records.spf_by_domain.values() for text in spf.select_records(txt)),
    ]
    record_tokens = {token for text in texts for token in _tokens(_split_uri_lists(text))}
    # Every term's value, not only a record token's: a malformed term such as
    # ip:203.0.113.5 still puts its address in the record for prose to quote.
    terms = (term for text in texts for term in _TERM_SEPARATOR.split(_split_uri_lists(text)))
    values = {value for term in terms for value in _tokens(_TOKEN_NAME.sub("", term))}
    return frozenset({*record_tokens, *values, records.domain, f"_dmarc.{records.domain}"})


def _split_uri_lists(record: str) -> str:
    return _URI_LIST.sub(
        lambda match: " ".join(f"{match[1]}={uri.strip()}" for uri in match[2].split(",")),
        record,
    )


def _unsupported_tokens(prose: str, is_supported: Callable[[str], bool]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(token for token in _tokens(prose) if not is_supported(token)))


def _tokens(text: str) -> Iterator[str]:
    for match in _TOKEN.finditer(_SPACE_AROUND_EQUALS.sub("=", text)):
        if match["address"] is None:
            yield match.group().rstrip(_TRAILING_PUNCTUATION).lower()
        elif address := _normalise_address(match["address"]):
            yield address


def _normalise_address(text: str) -> str | None:
    """Return `text` in `ipaddress` form, or None when it is not an address or network."""
    try:
        return str(ipaddress.ip_interface(text) if "/" in text else ipaddress.ip_address(text))
    except ValueError:
        return None

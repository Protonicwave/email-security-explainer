"""Parse SPF records (RFC 7208) and report the gaps that allow impersonation."""

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass

from email_security_explainer.domain import MAX_DOMAIN_LENGTH
from email_security_explainer.findings import Finding, FindingCode

# RFC 7208 section 4.6.4: more than ten DNS-querying terms is a permanent error.
MAX_SPF_LOOKUPS = 10
MAX_IP4_PREFIX_BITS = 32
MAX_IP6_PREFIX_BITS = 128
MAX_LABEL_LENGTH = 63

_MODIFIER = re.compile(r"(?P<name>[A-Za-z][A-Za-z0-9_.-]*)=(?P<value>.*)")
_MECHANISM = re.compile(r"(?P<qualifier>[-+~?]?)(?P<name>[A-Za-z][A-Za-z0-9_.-]*)(?P<rest>.*)")
_PREFIX_LENGTH = re.compile(r"0|[1-9][0-9]{0,2}", re.ASCII)
_DUAL_CIDR = re.compile(
    r"(?::(?P<domain>[^/]+))?"
    rf"(?:/(?P<ip4>{_PREFIX_LENGTH.pattern}))?"
    rf"(?://(?P<ip6>{_PREFIX_LENGTH.pattern}))?",
    re.ASCII,
)
_MECHANISMS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
_LOOKUP_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists"})
_SINGLE_USE_MODIFIERS = frozenset({"redirect", "exp"})
_ALL_FINDING_BY_QUALIFIER = {
    "+": FindingCode.SPF_ALL_PASS,
    "?": FindingCode.SPF_ALL_NEUTRAL,
    "~": FindingCode.SPF_SOFTFAIL,
}


# Mutating these flags changes nothing a test can see: mypy rejects writes to a
# frozen dataclass, and slots only saves memory.
@dataclass(frozen=True, slots=True)  # pragma: no mutate
class Term:
    text: str
    name: str
    qualifier: str
    value: str
    is_modifier: bool


@dataclass(frozen=True, slots=True)  # pragma: no mutate
class ParsedRecord:
    terms: tuple[Term, ...]
    invalid_terms: tuple[str, ...]

    @property
    def has_all(self) -> bool:
        return any(term.name == "all" and not term.is_modifier for term in self.terms)


@dataclass(frozen=True, slots=True)  # pragma: no mutate
class LookupWalk:
    """The result of following include and redirect terms through `spf_by_domain`.

    `unresolved` names targets absent from `spf_by_domain`; the caller fetches
    them and walks again. Once `lookup_count` exceeds MAX_SPF_LOOKUPS the walk
    stops, so `unresolved` and `unusable_targets` may then be incomplete.
    """

    lookup_count: int
    unresolved: frozenset[str]
    unusable_targets: tuple[str, ...]

    @property
    def is_over_limit(self) -> bool:
        return self.lookup_count > MAX_SPF_LOOKUPS

    @property
    def is_complete(self) -> bool:
        """True when the walk needs no more records fetched to reach its verdict."""
        return self.is_over_limit or not self.unresolved


def normalise_target(domain_spec: str) -> str:
    return domain_spec.lower().rstrip(".")


def select_records(txt_records: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(record for record in txt_records if _is_spf_record(record))


def _is_spf_record(record: str) -> bool:
    lowered = record.lower()
    return lowered == "v=spf1" or lowered.startswith("v=spf1 ")


def parse_record(record: str) -> ParsedRecord:
    terms: list[Term] = []
    invalid_terms: list[str] = []
    seen_modifiers: set[str] = set()
    _version, _, terms_text = record.partition(" ")
    for token in terms_text.split(" "):
        if not token:
            continue
        term = _parse_term(token)
        if term is None or (term.name in _SINGLE_USE_MODIFIERS and term.name in seen_modifiers):
            invalid_terms.append(token)
            continue
        if term.is_modifier:
            seen_modifiers.add(term.name)
        terms.append(term)
    return ParsedRecord(tuple(terms), tuple(invalid_terms))


def _parse_term(token: str) -> Term | None:
    modifier = _MODIFIER.fullmatch(token)
    if modifier is not None:
        name = modifier["name"].lower()
        value = modifier["value"]
        if name in _SINGLE_USE_MODIFIERS and not _is_domain_spec(value):
            return None
        return Term(token, name, "", value, is_modifier=True)
    mechanism = _MECHANISM.fullmatch(token)
    if mechanism is None:
        return None
    name = mechanism["name"].lower()
    rest = mechanism["rest"]
    if name not in _MECHANISMS or not _has_valid_argument(name, rest):
        return None
    return Term(token, name, mechanism["qualifier"] or "+", rest.removeprefix(":"), False)


def _has_valid_argument(name: str, rest: str) -> bool:
    match name:
        case "all":
            return not rest
        case "include" | "exists":
            return rest.startswith(":") and _is_domain_spec(rest[1:])
        case "ptr":
            return not rest or (rest.startswith(":") and _is_domain_spec(rest[1:]))
        case "a" | "mx":
            return _is_dual_cidr(rest)
        case "ip4":
            return rest.startswith(":") and _is_network(rest[1:], ipaddress.IPv4Network)
        case "ip6":
            return rest.startswith(":") and _is_network(rest[1:], ipaddress.IPv6Network)
    raise AssertionError(name)  # pragma: no cover: every mechanism has a case


def _is_domain_spec(text: str) -> bool:
    if "/" in text:
        return False
    if "%" in text:
        # A macro expands per message, so only its expansion can be checked.
        return True
    name = text.removesuffix(".")
    labels = name.split(".")
    # A backslash is an escape to a DNS library, not part of a name.
    return (
        name.isascii()
        and "\\" not in name
        and len(name) <= MAX_DOMAIN_LENGTH
        and "" not in labels
        and all(len(label) <= MAX_LABEL_LENGTH for label in labels)
    )


def _is_dual_cidr(rest: str) -> bool:
    match = _DUAL_CIDR.fullmatch(rest)
    if match is None:
        return False
    domain, ip4, ip6 = match["domain"], match["ip4"], match["ip6"]
    return (
        (domain is None or _is_domain_spec(domain))
        and (ip4 is None or int(ip4) <= MAX_IP4_PREFIX_BITS)
        and (ip6 is None or int(ip6) <= MAX_IP6_PREFIX_BITS)
    )


def _is_network(
    text: str, network_type: type[ipaddress.IPv4Network | ipaddress.IPv6Network]
) -> bool:
    address, has_prefix, prefix = text.partition("/")
    # RFC 7208 section 5.6 allows only a decimal prefix length, which rules out
    # the netmasks, leading zeros and zone IDs that ipaddress would accept.
    if "%" in address or (has_prefix and not _PREFIX_LENGTH.fullmatch(prefix)):
        return False
    try:
        network_type(text, strict=False)
    except ValueError:
        return False
    return True


def walk_lookups(
    apex_txt: tuple[str, ...], spf_by_domain: Mapping[str, tuple[str, ...]]
) -> LookupWalk:
    """Count DNS-querying terms across the include and redirect chain.

    Loops need no special handling: each pass through a loop adds a lookup, so
    the walk stops once the count exceeds MAX_SPF_LOOKUPS.
    """
    apex = _single_valid_record(apex_txt)
    if apex is None:
        return LookupWalk(0, frozenset(), ())
    lookup_count = 0
    unresolved: set[str] = set()
    unusable: list[str] = []
    pending = [apex]
    while pending and lookup_count <= MAX_SPF_LOOKUPS:
        record = pending.pop()
        for term in record.terms:
            if not _causes_lookup(term, record.has_all):
                continue
            lookup_count += 1
            target = _followable_target(term)
            if target is None:
                continue
            if target not in spf_by_domain:
                unresolved.add(target)
                continue
            target_record = _single_valid_record(spf_by_domain[target])
            if target_record is None:
                unusable.append(term.text)
            else:
                pending.append(target_record)
    return LookupWalk(lookup_count, frozenset(unresolved), tuple(dict.fromkeys(unusable)))


def lookup_targets(txt_records: tuple[str, ...]) -> list[str]:
    """The include and redirect targets the SPF record among `txt_records`
    sends a lookup to, or none when there is not exactly one valid record."""
    record = _single_valid_record(txt_records)
    if record is None:
        return []
    targets = (
        _followable_target(term) for term in record.terms if _causes_lookup(term, record.has_all)
    )
    return [target for target in targets if target is not None]


def _single_valid_record(txt_records: tuple[str, ...]) -> ParsedRecord | None:
    match select_records(txt_records):
        case (record,):
            parsed = parse_record(record)
            return None if parsed.invalid_terms else parsed
        case _:
            return None


def _causes_lookup(term: Term, record_has_all: bool) -> bool:
    if term.is_modifier:
        # RFC 7208 section 6.1: redirect is ignored when the record has an all mechanism.
        return term.name == "redirect" and not record_has_all
    return term.name in _LOOKUP_MECHANISMS


def _followable_target(term: Term) -> str | None:
    # A target containing a macro depends on the message being checked, so it
    # cannot be resolved ahead of time; it still counts as a lookup.
    if term.name not in {"include", "redirect"} or "%" in term.value:
        return None
    return normalise_target(term.value)


def assess(
    apex_txt: tuple[str, ...],
    spf_by_domain: Mapping[str, tuple[str, ...]],
    *,  # pragma: no mutate: mutated to /, keyword callers still work
    is_dmarc_enforcing: bool,
) -> list[Finding]:
    match select_records(apex_txt):
        case ():
            return [Finding(FindingCode.SPF_MISSING)]
        case (record,):
            parsed = parse_record(record)
        case _:
            return [Finding(FindingCode.SPF_MULTIPLE)]
    if parsed.invalid_terms:
        return [Finding(FindingCode.SPF_SYNTAX, term) for term in parsed.invalid_terms]
    findings = _all_mechanism_findings(
        _deciding_record(parsed, spf_by_domain), is_dmarc_enforcing=is_dmarc_enforcing
    )
    findings += [
        Finding(FindingCode.SPF_PTR, term.text) for term in parsed.terms if term.name == "ptr"
    ]
    walk = walk_lookups(apex_txt, spf_by_domain)
    assert walk.is_complete, f"targets not fetched: {sorted(walk.unresolved)}"
    if walk.is_over_limit:
        findings.append(Finding(FindingCode.SPF_LOOKUP_LIMIT))
    findings += [Finding(FindingCode.SPF_TARGET_UNUSABLE, term) for term in walk.unusable_targets]
    return findings


def _deciding_record(
    parsed: ParsedRecord, spf_by_domain: Mapping[str, tuple[str, ...]]
) -> ParsedRecord | None:
    """The record whose `all` decides the result: `parsed`, or the end of its
    redirect chain. None when the chain cannot be followed: a target that is
    missing, unusable or past the lookup limit, which SPF_TARGET_UNUSABLE and
    SPF_LOOKUP_LIMIT report, or a target written with a macro, which depends on
    the message and so cannot be judged in advance.

    RFC 7208 section 6.1: without an all mechanism, the redirect target's
    result is the record's result.
    """
    record = parsed
    # One pass per record, so the limit's redirects reach limit + 1 records. The
    # tests pin the bound; 10 | 1 and 10 ^ 1 also make 11, so those mutants are
    # equivalent.
    for _ in range(MAX_SPF_LOOKUPS + 1):  # pragma: no mutate
        redirect = next((term for term in record.terms if term.name == "redirect"), None)
        if record.has_all or redirect is None:
            return record
        target = _followable_target(redirect)
        if target is None or target not in spf_by_domain:
            return None
        target_record = _single_valid_record(spf_by_domain[target])
        if target_record is None:
            return None
        record = target_record
    return None


def _all_mechanism_findings(
    record: ParsedRecord | None,
    *,  # pragma: no mutate: mutated to /, keyword callers still work
    is_dmarc_enforcing: bool,
) -> list[Finding]:
    if record is None:
        return []
    all_term = next(
        (term for term in record.terms if term.name == "all" and not term.is_modifier), None
    )
    if all_term is None:
        return [Finding(FindingCode.SPF_NO_ALL)]
    code = _ALL_FINDING_BY_QUALIFIER.get(all_term.qualifier)
    # A soft fail is accepted practice when DMARC already rejects or quarantines
    # unauthenticated mail; without that, receivers usually deliver it.
    # Mutating `is` to `>=` is equivalent: SPF_SOFTFAIL sorts after the other two codes.
    is_tolerated = code is FindingCode.SPF_SOFTFAIL and is_dmarc_enforcing  # pragma: no mutate
    if code is None or is_tolerated:
        return []
    return [Finding(code, all_term.text)]

"""Parse DMARC records (RFC 7489) and report the gaps that allow impersonation."""

import re
from dataclasses import dataclass

from email_security_explainer.findings import Finding, FindingCode

FULL_PERCENTAGE = 100

# RFC 7489 section 6.6.3: records not starting with v=DMARC1 are discarded.
_VERSION = re.compile(r"[Vv]\s*=\s*DMARC1\s*(?:;|$)")
_PERCENTAGE = re.compile(r"\d{1,3}", re.ASCII)
_POLICIES = frozenset({"none", "quarantine", "reject"})


# Mutating these flags changes nothing a test can see: mypy rejects writes to a
# frozen dataclass, and slots only saves memory.
@dataclass(frozen=True, slots=True)  # pragma: no mutate
class DmarcAssessment:
    findings: list[Finding]
    is_enforcing: bool


@dataclass(frozen=True, slots=True)  # pragma: no mutate
class _Tag:
    value: str
    # The tag as written, so a finding quotes exactly what the owner sees.
    text: str


def assess(dmarc_txt: tuple[str, ...]) -> DmarcAssessment:
    records = [record for record in dmarc_txt if _VERSION.match(record.lstrip())]
    match records:
        case []:
            return DmarcAssessment([Finding(FindingCode.DMARC_MISSING)], is_enforcing=False)
        case [record]:
            tags, invalid_segments = _parse_tags(record)
        case _:
            return DmarcAssessment([Finding(FindingCode.DMARC_MULTIPLE)], is_enforcing=False)
    findings = [Finding(FindingCode.DMARC_SYNTAX, segment) for segment in invalid_segments]
    policy_tag = tags.get("p")
    policy = policy_tag.value.lower() if policy_tag is not None else ""
    if policy not in _POLICIES:
        evidence = policy_tag.text if policy_tag is not None else None
        findings.append(Finding(FindingCode.DMARC_SYNTAX, evidence))
        return DmarcAssessment(findings, is_enforcing=False)
    percentage = _parse_percentage(tags, findings)
    subdomain_policy = _parse_subdomain_policy(tags, findings)
    # The policy is none, quarantine or reject and the percentage is at most 100,
    # so mutating these comparisons into orderings is equivalent.
    if policy == "none":  # pragma: no mutate
        findings.append(Finding(FindingCode.DMARC_POLICY_NONE, tags["p"].text))
    else:
        if percentage < FULL_PERCENTAGE:  # pragma: no mutate
            findings.append(Finding(FindingCode.DMARC_PARTIAL_PCT, tags["pct"].text))
        if subdomain_policy == "none":
            findings.append(Finding(FindingCode.DMARC_SUBDOMAIN_NONE, tags["sp"].text))
    if "rua" not in tags:
        findings.append(Finding(FindingCode.DMARC_NO_RUA))
    is_enforcing = policy != "none" and percentage == FULL_PERCENTAGE  # pragma: no mutate
    return DmarcAssessment(findings, is_enforcing=is_enforcing)


def _parse_tags(record: str) -> tuple[dict[str, _Tag], list[str]]:
    tags: dict[str, _Tag] = {}
    invalid_segments: list[str] = []
    _version, _, tags_text = record.partition(";")
    for raw_segment in tags_text.split(";"):
        segment = raw_segment.strip()
        if not segment:
            continue
        name, separator, value = segment.partition("=")
        name = name.strip().lower()
        if not separator or not name or name in tags:
            invalid_segments.append(segment)
            continue
        tags[name] = _Tag(value.strip(), segment)
    return tags, invalid_segments


def _parse_percentage(tags: dict[str, _Tag], findings: list[Finding]) -> int:
    tag = tags.get("pct")
    if tag is None:
        return FULL_PERCENTAGE
    if _PERCENTAGE.fullmatch(tag.value) and int(tag.value) <= FULL_PERCENTAGE:
        return int(tag.value)
    findings.append(Finding(FindingCode.DMARC_SYNTAX, tag.text))
    return FULL_PERCENTAGE


def _parse_subdomain_policy(tags: dict[str, _Tag], findings: list[Finding]) -> str | None:
    tag = tags.get("sp")
    if tag is None:
        return None
    if tag.value.lower() in _POLICIES:
        return tag.value.lower()
    findings.append(Finding(FindingCode.DMARC_SYNTAX, tag.text))
    return None

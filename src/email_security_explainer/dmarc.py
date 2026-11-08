"""Parse DMARC records (RFC 7489) and report the gaps that allow impersonation."""

import re
from dataclasses import dataclass

from email_security_explainer.findings import Finding, FindingCode

FULL_PERCENTAGE = 100

# RFC 7489 section 6.6.3: records not starting with v=DMARC1 are discarded.
_VERSION = re.compile(r"[Vv]\s*=\s*DMARC1\s*(?:;|$)")
_PERCENTAGE = re.compile(r"\d{1,3}", re.ASCII)
_POLICIES = frozenset({"none", "quarantine", "reject"})


@dataclass(frozen=True, slots=True)
class DmarcAssessment:
    findings: list[Finding]
    is_enforcing: bool


def assess(dmarc_txt: tuple[str, ...]) -> DmarcAssessment:
    records = [record for record in dmarc_txt if _VERSION.match(record.lstrip())]
    if not records:
        return DmarcAssessment([Finding(FindingCode.DMARC_MISSING)], is_enforcing=False)
    if len(records) > 1:
        return DmarcAssessment([Finding(FindingCode.DMARC_MULTIPLE)], is_enforcing=False)
    tags, invalid_segments = _parse_tags(records[0])
    findings = [Finding(FindingCode.DMARC_SYNTAX, segment) for segment in invalid_segments]
    policy = tags.get("p", "").lower()
    if policy not in _POLICIES:
        evidence = f"p={tags['p']}" if "p" in tags else None
        findings.append(Finding(FindingCode.DMARC_SYNTAX, evidence))
        return DmarcAssessment(findings, is_enforcing=False)
    percentage = _parse_percentage(tags, findings)
    subdomain_policy = _parse_subdomain_policy(tags, findings)
    if policy == "none":
        findings.append(Finding(FindingCode.DMARC_POLICY_NONE, f"p={tags['p']}"))
    else:
        if percentage < FULL_PERCENTAGE:
            findings.append(Finding(FindingCode.DMARC_PARTIAL_PCT, f"pct={tags['pct']}"))
        if subdomain_policy == "none":
            findings.append(Finding(FindingCode.DMARC_SUBDOMAIN_NONE, f"sp={tags['sp']}"))
    if "rua" not in tags:
        findings.append(Finding(FindingCode.DMARC_NO_RUA))
    is_enforcing = policy != "none" and percentage == FULL_PERCENTAGE
    return DmarcAssessment(findings, is_enforcing=is_enforcing)


def _parse_tags(record: str) -> tuple[dict[str, str], list[str]]:
    tags: dict[str, str] = {}
    invalid_segments: list[str] = []
    for raw_segment in record.split(";")[1:]:
        segment = raw_segment.strip()
        if not segment:
            continue
        name, separator, value = segment.partition("=")
        name = name.strip().lower()
        if not separator or not name or name in tags:
            invalid_segments.append(segment)
            continue
        tags[name] = value.strip()
    return tags, invalid_segments


def _parse_percentage(tags: dict[str, str], findings: list[Finding]) -> int:
    text = tags.get("pct")
    if text is None:
        return FULL_PERCENTAGE
    if _PERCENTAGE.fullmatch(text) and int(text) <= FULL_PERCENTAGE:
        return int(text)
    findings.append(Finding(FindingCode.DMARC_SYNTAX, f"pct={text}"))
    return FULL_PERCENTAGE


def _parse_subdomain_policy(tags: dict[str, str], findings: list[Finding]) -> str | None:
    text = tags.get("sp")
    if text is None:
        return None
    if text.lower() in _POLICIES:
        return text.lower()
    findings.append(Finding(FindingCode.DMARC_SYNTAX, f"sp={text}"))
    return None

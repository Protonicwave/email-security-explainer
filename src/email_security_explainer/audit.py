"""Turn a domain's SPF and DMARC records into findings, with no I/O."""

from collections.abc import Mapping
from dataclasses import dataclass, field

from email_security_explainer import dmarc, spf
from email_security_explainer.findings import Finding


@dataclass(frozen=True, slots=True)
class DnsRecords:
    """TXT records for one domain.

    `spf_by_domain` maps each include or redirect target (lower case, no
    trailing dot) to its TXT records, an empty tuple when it has none.
    """

    apex_txt: tuple[str, ...]
    dmarc_txt: tuple[str, ...]
    spf_by_domain: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


def audit(records: DnsRecords) -> list[Finding]:
    dmarc_assessment = dmarc.assess(records.dmarc_txt)
    spf_findings = spf.assess(
        records.apex_txt,
        records.spf_by_domain,
        is_dmarc_enforcing=dmarc_assessment.is_enforcing,
    )
    return [*spf_findings, *dmarc_assessment.findings]

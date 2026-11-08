"""Fetch the TXT records the auditor needs, including the SPF include chain."""

from collections.abc import Callable

import dns.exception
import dns.resolver

from email_security_explainer import spf
from email_security_explainer.audit import DnsRecords
from email_security_explainer.domain import DomainName

REQUEST_TIMEOUT_SECONDS = 5.0
# Each round fetches at least one record reached through an include or
# redirect, which adds a lookup, so the walk passes the limit within this many.
MAX_FETCH_ROUNDS = spf.MAX_SPF_LOOKUPS + 1

TxtLookup = Callable[[str], tuple[str, ...] | None]
"""Returns the TXT records at a name, an empty tuple when it has none, or
None when the name does not exist. Raises DnsLookupError when DNS fails."""


class DnsLookupError(Exception):
    """DNS gave no usable answer, so a record's absence cannot be concluded."""


def lookup_txt(name: str) -> tuple[str, ...] | None:
    try:
        answer = dns.resolver.resolve(f"{name}.", "TXT", lifetime=REQUEST_TIMEOUT_SECONDS)
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return ()
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.YXDOMAIN) as err:
        raise DnsLookupError(f"TXT lookup for {name} failed: {err}") from err
    # RFC 7208 section 3.3: a record split into several strings is joined with
    # nothing between them. Non-ASCII bytes become U+FFFD and fail parsing.
    return tuple(b"".join(rdata.strings).decode("ascii", errors="replace") for rdata in answer)


def fetch_records(domain: DomainName, lookup: TxtLookup = lookup_txt) -> DnsRecords:
    """Fetch the apex, DMARC and SPF include records for `domain`.

    Raises DnsLookupError when the domain does not exist or DNS fails.
    """
    apex_txt = lookup(domain)
    if apex_txt is None:
        raise DnsLookupError(f"{domain} does not exist in DNS")
    dmarc_txt = lookup(f"_dmarc.{domain}") or ()
    spf_by_domain: dict[str, tuple[str, ...]] = {}
    for _ in range(MAX_FETCH_ROUNDS):
        walk = spf.walk_lookups(apex_txt, spf_by_domain)
        if not walk.unresolved or walk.lookup_count > spf.MAX_SPF_LOOKUPS:
            return DnsRecords(apex_txt, dmarc_txt, spf_by_domain)
        for target in sorted(walk.unresolved):
            spf_by_domain[target] = lookup(target) or ()
    raise AssertionError(f"SPF walk for {domain} did not finish in {MAX_FETCH_ROUNDS} rounds")

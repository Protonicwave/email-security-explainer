from dataclasses import dataclass

import dns.exception
import dns.resolver
import pytest

from email_security_explainer.dns_fetch import (
    DnsLookupError,
    DomainNotFoundError,
    fetch_records,
    lookup_txt,
)
from email_security_explainer.domain import DomainName

DOMAIN = DomainName("example.com")


class FakeDns:
    """Answers TXT lookups from a table and records every name asked for."""

    def __init__(self, table: dict[str, tuple[str, ...] | Exception | None]) -> None:
        self.table = table
        self.queried: list[str] = []

    def __call__(self, name: str) -> tuple[str, ...] | None:
        self.queried.append(name)
        answer = self.table.get(name, ())
        if isinstance(answer, Exception):
            raise answer
        return answer


def test_fetches_apex_and_dmarc() -> None:
    lookup = FakeDns(
        {"example.com": ("v=spf1 -all",), "_dmarc.example.com": ("v=DMARC1; p=reject",)}
    )
    records = fetch_records(DOMAIN, lookup)
    assert records.domain == DOMAIN
    assert records.apex_txt == ("v=spf1 -all",)
    assert records.dmarc_txt == ("v=DMARC1; p=reject",)
    assert records.spf_by_domain == {}


def test_missing_domain_raises_domain_not_found() -> None:
    with pytest.raises(DomainNotFoundError, match=r"example\.com does not exist"):
        fetch_records(DOMAIN, FakeDns({"example.com": None}))


def test_missing_dmarc_name_means_no_record() -> None:
    records = fetch_records(DOMAIN, FakeDns({"_dmarc.example.com": None}))
    assert records.dmarc_txt == ()


def test_dns_failure_propagates() -> None:
    lookup = FakeDns({"_dmarc.example.com": DnsLookupError("timed out")})
    with pytest.raises(DnsLookupError, match="timed out") as raised:
        fetch_records(DOMAIN, lookup)
    assert not isinstance(raised.value, DomainNotFoundError)


def test_follows_include_chain() -> None:
    lookup = FakeDns(
        {
            "example.com": ("v=spf1 include:a.example.net -all",),
            "a.example.net": ("v=spf1 include:b.example.net -all",),
            "b.example.net": ("v=spf1 ip4:192.0.2.1 -all",),
        }
    )
    records = fetch_records(DOMAIN, lookup)
    assert records.spf_by_domain == {
        "a.example.net": ("v=spf1 include:b.example.net -all",),
        "b.example.net": ("v=spf1 ip4:192.0.2.1 -all",),
    }


def test_include_to_missing_name_is_stored_as_empty() -> None:
    lookup = FakeDns(
        {"example.com": ("v=spf1 include:gone.example.net -all",), "gone.example.net": None}
    )
    assert fetch_records(DOMAIN, lookup).spf_by_domain == {"gone.example.net": ()}


def test_include_loop_fetches_each_name_once() -> None:
    lookup = FakeDns(
        {
            "example.com": ("v=spf1 include:a.example.net -all",),
            "a.example.net": ("v=spf1 include:a.example.net -all",),
        }
    )
    fetch_records(DOMAIN, lookup)
    assert lookup.queried.count("a.example.net") == 1


def test_stops_fetching_once_over_lookup_limit() -> None:
    includes = " ".join(f"include:i{index}.example.net" for index in range(11))
    lookup = FakeDns({"example.com": (f"v=spf1 {includes} -all",)})
    fetch_records(DOMAIN, lookup)
    assert lookup.queried == ["example.com", "_dmarc.example.com"]


def test_does_not_walk_without_a_single_valid_record() -> None:
    lookup = FakeDns({"example.com": ("v=spf1 include:a.example.net", "v=spf1 -all")})
    fetch_records(DOMAIN, lookup)
    assert lookup.queried == ["example.com", "_dmarc.example.com"]


@dataclass
class FakeRdata:
    strings: tuple[bytes, ...]


@pytest.mark.parametrize(
    ("error", "expected"),
    [(dns.resolver.NXDOMAIN, None), (dns.resolver.NoAnswer, ())],
)
def test_lookup_txt_maps_absence(
    monkeypatch: pytest.MonkeyPatch, error: type[Exception], expected: tuple[str, ...] | None
) -> None:
    def resolve(*_args: object, **_kwargs: object) -> object:
        raise error()

    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    assert lookup_txt("example.com") == expected


@pytest.mark.parametrize(
    "error",
    [dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.YXDOMAIN],
)
def test_lookup_txt_raises_on_dns_failure(
    monkeypatch: pytest.MonkeyPatch, error: type[Exception]
) -> None:
    def resolve(*_args: object, **_kwargs: object) -> object:
        raise error()

    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    with pytest.raises(DnsLookupError, match=r"TXT lookup for example\.com failed"):
        lookup_txt("example.com")


def test_lookup_txt_joins_split_strings_and_queries_absolute_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked: list[str] = []

    def resolve(name: str, *_args: object, **_kwargs: object) -> list[FakeRdata]:
        asked.append(name)
        return [FakeRdata((b"v=spf1 ", b"-all")), FakeRdata((b"caf\xc3\xa9",))]

    monkeypatch.setattr(dns.resolver, "resolve", resolve)
    assert lookup_txt("example.com") == ("v=spf1 -all", "caf��")
    assert asked == ["example.com."]

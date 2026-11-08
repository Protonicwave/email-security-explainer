import pytest

from email_security_explainer.domain import parse_domain


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM.  ", "example.com"),
        ("mail.example.co.uk", "mail.example.co.uk"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("a-b.example", "a-b.example"),
    ],
)
def test_accepts_and_normalises(raw: str, expected: str) -> None:
    assert parse_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "localhost",
        "a..b.example",
        "-a.example",
        "a-.example",
        "a_b.example",
        "*.example.com",
        "http://example.com",
        "example.com/path",
        "192.0.2.1",
        f"{'a' * 64}.example",
        ".".join(["a" * 63] * 4) + ".example",
    ],
)
def test_rejects_malformed(raw: str) -> None:
    with pytest.raises(ValueError, match="expected a domain name"):
        parse_domain(raw)

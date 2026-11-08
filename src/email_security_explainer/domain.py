"""Validate a domain name typed by a user."""

import re
from typing import NewType

DomainName = NewType("DomainName", str)

MAX_DOMAIN_LENGTH = 253
MIN_LABELS = 2
_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")


def parse_domain(raw: str) -> DomainName:
    """Return `raw` as a lower-case ASCII domain name.

    Raises ValueError unless `raw` is a domain name of at least two labels.
    """
    error = ValueError(f"expected a domain name such as example.com, got {raw!r}")
    text = raw.strip().removesuffix(".").lower()
    try:
        ascii_text = text.encode("idna").decode("ascii")
    except UnicodeError as err:
        raise error from err
    labels = ascii_text.split(".")
    is_valid = (
        len(ascii_text) <= MAX_DOMAIN_LENGTH
        and len(labels) >= MIN_LABELS
        and all(_LABEL.fullmatch(label) for label in labels)
        and not labels[-1].isdigit()
    )
    if not is_valid:
        raise error
    return DomainName(ascii_text)

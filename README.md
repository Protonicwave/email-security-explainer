# Email security explainer

Audits a domain's SPF and DMARC records for gaps that let someone send email
pretending to be that domain, then explains each gap in plain English. Code
decides what is wrong; a language model only explains the auditor's findings,
and every claim it makes is checked against them.

## Install

Requires Python 3.12 or later and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
```

## Usage

```sh
uv run esx audit example.com
uv run esx audit example.com --json
```

```
lboro.ac.uk: 2 findings
  medium  SPF_SOFTFAIL          ~all
  high    DMARC_POLICY_NONE     p=none
```

Each finding names the record token it rests on. The command exits 1 when the
domain is malformed, does not exist, or DNS fails; a DNS failure is never
reported as a missing record.

## What it checks

SPF (RFC 7208): a missing or duplicated record, syntax errors, `+all`, `?all`,
no `all` and no `redirect`, `~all` without an enforcing DMARC policy, `ptr`,
more than ten DNS lookups across the include chain, and includes or redirects
that point at a domain without exactly one valid SPF record.

DMARC (RFC 7489): a missing or duplicated record, syntax errors, `p=none`,
`pct` below 100, `sp=none` under an enforcing policy, and no `rua` address for
aggregate reports.

Not checked: DKIM (finding a key needs a selector name that DNS does not
reveal), MTA-STS, BIMI, the SPF void-lookup limit, and the organisational
domain fallback for subdomains without their own DMARC record.

## Development

```sh
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run vulture src --min-confidence 80
```

The rule modules need full line and branch coverage:

```sh
uv run coverage run --branch --source=email_security_explainer -m pytest
uv run coverage report --show-missing --fail-under=100 --include="*/spf.py,*/dmarc.py,*/audit.py,*/findings.py,*/domain.py,*/claims.py"
```

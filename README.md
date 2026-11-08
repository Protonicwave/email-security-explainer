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

## Development

```sh
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run vulture src --min-confidence 80
```

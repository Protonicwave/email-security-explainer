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

`esx explain` asks Claude to explain each finding in plain English for someone
who has never heard of SPF or DMARC:

```sh
uv run esx explain example.com
uv run esx explain example.com --model claude-opus-5-5
```

It needs an Anthropic API key in `ANTHROPIC_API_KEY`; the default model is
`claude-sonnet-5-5`. Every claim in the answer is checked against the findings.
A claim must name a finding the audit produced, quote its record token exactly,
and quote no record value that the domain's records do not contain. An answer
that fails gets one repair round with the problems listed; anything still
failing after that is dropped, and findings left unexplained are listed by
code. The command exits 1 when the model declines, stops early, returns output
outside the schema, or the API cannot be reached.

`esx eval` measures what the claim check is worth. It runs every case in
`cases/cases.json` (recorded records for 21 domains, so no live DNS) under three
conditions and scores each explanation a reader would see against the audit:

- `raw_records`: the model sees only the records and the auditor's rules, and
  finds the problems itself;
- `findings`: the model explains the auditor's findings, shown unchecked;
- `findings_checked`: that same answer after the claim check, one repair round
  and dropping whatever still fails.

```sh
uv run esx eval --repeats 3 --output eval-results.json
```

It prints a table of explained, missed, invented and wrong-detail counts per
condition, and writes every run to the `--output` file. A run where the model
declines or breaks the schema counts as failed; a connection, rate-limit or
server error after the SDK's retries counts as errored. Either way the
evaluation moves on to the next run. Other API errors, such as a bad key, stop
it.

## Results

One run of `esx eval --repeats 3` on 8 November 2026 with `claude-sonnet-5-5`
covered the 21 cases three times, which is 63 runs and 102 findings per
condition:

| Condition | Scored | Failed | Errored | Explained | Missed | Invented | Wrong detail |
|---|---|---|---|---|---|---|---|
| `raw_records` | 63 | 0 | 0 | 102 | 0 | 0 | 0 |
| `findings` | 63 | 0 | 0 | 102 | 0 | 0 | 0 |
| `findings_checked` | 63 | 0 | 0 | 102 | 0 | 0 | 0 |

Every condition explained every finding, with no invented problem and no wrong
detail, so on this corpus the claim check had nothing to remove. The run does
not separate the conditions, and it does not show that the check is unnecessary.
The cases are textbook misconfigurations with at most three findings each, and
the `raw_records` condition is given the auditor's rules in words, which turns
finding the problems into applying a written checklist to short records. The
guarantee that no claim reaches the reader unless it matches a finding rests on
the claim check's unit and mutation tests, not on this run. Telling the
conditions apart needs harder cases: include chains close to the lookup limit,
records that hit a rule's exception, and records copied from real domains. Every
run is in `results/claude-sonnet-5-5.json`.

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

The claim check and the SPF and DMARC rules it trusts also have a mutation test
with cosmic-ray, which must leave no surviving mutant. CI runs it on Ubuntu; it
also runs on Windows, where it takes about five minutes. Lines whose only
surviving mutants are equivalent to the original carry `# pragma: no mutate`:

```sh
uv run cosmic-ray init pyproject.toml mutation.sqlite
uv run cr-filter-operators mutation.sqlite pyproject.toml
uv run cr-filter-pragma mutation.sqlite
uv run cosmic-ray exec pyproject.toml mutation.sqlite
uv run cr-rate mutation.sqlite --fail-over 0.1
```

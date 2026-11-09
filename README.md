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
`cases/cases.json` under three conditions and scores each explanation a reader
would see against the audit. The 42 cases are recorded, so no live DNS: 31 are
written for made-up domains, ten of them built at a rule's boundary,
and 11 are real domains' records captured with `esx case`. Each real domain is
renamed `real-01.example` to `real-11.example`, with its own name replaced
wherever it appears; the mail providers it includes keep their real names. The
conditions are:

- `raw_records`: the model sees only the records and the auditor's rules, and
  finds the problems itself;
- `findings`: the model explains the auditor's findings, shown unchecked;
- `findings_checked`: that same answer after the claim check, one repair round
  and dropping whatever still fails.

```sh
uv run esx eval --repeats 3 --output eval-results.jsonl
```

It prints a table of explained, missed, invented and wrong-detail counts per
condition, and writes each run to the `--output` file as one JSON line as soon
as it finishes, so a run that stops part-way keeps what it has paid for. Each
line gives the counts, every claim's verdict with the record tokens it was
rejected for and the prose of any claim that failed, the findings left
unexplained, and any unsupported tokens in the summary. A run
where the model declines or breaks the schema counts as failed; a connection,
rate-limit or server error after the SDK's retries counts as errored. Either way
the evaluation moves on to the next run. Other API errors, such as a bad key,
stop it. The corpus is capped at 100 cases and `--repeats` at 10, which bounds
a run at about 3,000 model calls.

`esx case` prints a live domain's records, including its SPF include chain, as
one case object in the corpus format, ready to add to `cases/cases.json`:

```sh
uv run esx case example.com
```

`esx serve` does what `esx explain` does in a web page at
http://127.0.0.1:8000:

```sh
uv run esx serve
uv run esx serve --port 8080 --model claude-opus-5-5 --open
```

`--open` opens the page in the default browser once the server is listening.

On Windows, double-click `serve.bat` instead. If uv is missing, it downloads
the uv 0.12.1 release from GitHub, refuses it unless its SHA-256 matches the
one pinned in the file, and unpacks it into `%USERPROFILE%\.local\bin` (or
`%UV_INSTALL_DIR%`). uv then fetches Python 3.12 and the dependencies on the
first run, and the launcher starts `esx serve --open`. It passes its
arguments on, so `serve.bat --port 8080` works, and it says so when
`ANTHROPIC_API_KEY` is not set.

The page shows the verdict, the SPF and DMARC records with each finding marked
on the token it rests on, and then Claude's checked explanation and fix for
each finding. An explanation that fails the claim check after the repair round
is shown as removed, with the values it named that the records lack. The audit
needs no API key; the explanations need `ANTHROPIC_API_KEY`, and when the model
or the API fails the page keeps the audit and gives the reason.

The server listens on 127.0.0.1 only and refuses requests whose `Host` or
`Origin` is not the page's own, so another website cannot use it. It writes one
explanation at a time, which bounds what a double click or a second tab costs,
and stops with Ctrl+C.

## Results

One run of `esx eval --repeats 3` on 9 November 2026 with `claude-sonnet-5-5`
stopped during its second repeat, when the API account reached its monthly
spend limit. The first repeat is complete: every condition ran on all 42 cases,
which is 42 runs and 58 findings per condition.

| Condition | Runs | Failed | Errored | Explained | Missed | Invented | Wrong detail |
|---|---|---|---|---|---|---|---|
| `raw_records` | 42 | 0 | 0 | 58 | 0 | 0 | 0 |
| `findings` | 42 | 0 | 0 | 57 | 1 | 0 | 1 |
| `findings_checked` | 42 | 0 | 0 | 58 | 0 | 0 | 0 |

The seven runs of the second repeat that finished explained every finding with
no errors; they are in the results file but not in the table.

The runs were scored by the claim check at commit 2d31bbb. The one rejected
claim was the check's mistake, not the model's. For `typos-in-records.example`
the model explained the malformed term `ip:203.0.113.5` and named the address
203.0.113.5 on its own. The address is in the record, but only inside that
term, which that version of the check did not read, so it rejected a correct
claim and the finding counted as missed; commit f44a103 makes the check read
values inside malformed terms. The repair round passed, so the reader of the
checked explanation saw every finding.

The larger corpus still does not separate the conditions. Given the auditor's
rules in words, the `raw_records` model found all 58 findings and invented none,
on real include chains of up to 11 lookups and on cases built at each rule's
boundary. No errors in 42 runs puts that condition's error rate per run below
about 7% at 95% confidence, which is too wide to rank it against the others. In
`findings_checked`, invented and wrong-detail claims are zero by construction,
because the check drops them before the reader sees anything; what that row
measures is how many findings survive, here all 58. The guarantee that no claim
reaches the reader unless it matches a finding rests on the claim check's unit
and mutation tests, not on this run. Whether the model stays this accurate
without the rulebook is open: a condition that withholds the written rules
would test its own judgement, but it would be scored against rules it was never
shown. Every run is in `results/claude-sonnet-5-5.jsonl`.

## What it checks

SPF (RFC 7208): a missing or duplicated record, syntax errors, `+all`, `?all`,
no `all`, `~all` without an enforcing DMARC policy, `ptr`, more than ten DNS
lookups across the include chain, and includes or redirects that point at a
domain without exactly one valid SPF record. A record with no `all` of its own
is judged by the `all` at the end of its `redirect` chain.

DMARC (RFC 7489): a missing or duplicated record, syntax errors, `p=none`,
`pct` below 100, `sp=none` under an enforcing policy, and no `rua` address for
aggregate reports.

Not checked: DKIM (finding a key needs a selector name that DNS does not
reveal), MTA-STS, BIMI, the SPF void-lookup limit, the `all` of a `redirect`
whose target is written with a macro (it depends on the message being
checked), and the organisational domain fallback for subdomains without their
own DMARC record.

## Development

```sh
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run vulture src --min-confidence 80
```

The rule modules, the claim check and the page's view of an audit need full
line and branch coverage:

```sh
uv run coverage run --branch --source=email_security_explainer -m pytest
uv run coverage report --show-missing --fail-under=100 --include="*/spf.py,*/dmarc.py,*/audit.py,*/findings.py,*/domain.py,*/claims.py,*/web.py"
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

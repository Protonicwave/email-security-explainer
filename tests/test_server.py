import http.client
import json
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anthropic
import pytest

from email_security_explainer.dns_fetch import DnsLookupError
from email_security_explainer.explain import SYSTEM_PROMPT, ExplanationError, Generate
from email_security_explainer.findings import FindingCode
from email_security_explainer.schema import Claim, Explanation
from email_security_explainer.server import make_server

STATIC = Path("src/email_security_explainer/static")
PAGE_ASSET_BUDGET_BYTES = 75 * 1024
TABLE: dict[str, tuple[str, ...] | None] = {
    "example.com": ("v=spf1 ptr -all",),
    "_dmarc.example.com": ("v=DMARC1; p=reject; rua=mailto:d@example.com",),
    "missing.example": None,
    "clean.example": ("v=spf1 -all",),
    "_dmarc.clean.example": ("v=DMARC1; p=reject; rua=mailto:d@clean.example",),
}
MODEL = "claude-test"
PTR_CLAIM = Claim(
    finding_code=FindingCode.SPF_PTR,
    quoted_value="ptr",
    explanation="The ptr term is slow and receivers may skip it.",
    fix="Remove ptr.",
)


def lookup(name: str) -> tuple[str, ...] | None:
    if name.startswith("timeout."):
        raise DnsLookupError(f"TXT lookup for {name} failed: timed out")
    if name.startswith("broken."):
        raise RuntimeError("a bug")
    return TABLE.get(name, ())


class FakeClaude:
    """Explains the ptr finding, or fails for domains named to fail. While
    `release` is unset, each request waits on it after setting `entered`."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.prompts: list[tuple[str, str]] = []

    def generator_for(self, model: str, system_prompt: str) -> Generate:
        self.prompts.append((model, system_prompt))
        return self.generate

    def generate(self, request: str) -> Explanation:
        self.entered.set()
        assert self.release.wait(timeout=5)
        if "declines.example" in request:
            raise ExplanationError("claude-test declined to explain (category: cyber)")
        if "nokey.example" in request:
            raise anthropic.AnthropicError("the api_key client option must be set")
        return Explanation(summary="Mostly guarded.", claims=[PTR_CLAIM])


@pytest.fixture
def claude() -> FakeClaude:
    return FakeClaude()


@pytest.fixture
def port(claude: FakeClaude) -> Iterator[int]:
    server = make_server(0, lookup, MODEL, claude.generator_for)
    # A short poll interval keeps shutdown, and so each test, quick.
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def request(
    port: int,
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def post(
    port: int, path: str, domain: Any, headers: dict[str, str] | None = None
) -> tuple[int, Any]:
    status, _headers, body = request(
        port, "POST", path, json.dumps({"domain": domain}).encode(), headers
    )
    return status, json.loads(body)


def audit(port: int, domain: Any, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    return post(port, "/api/audit", domain, headers)


def explain(port: int, domain: Any) -> tuple[int, Any]:
    return post(port, "/api/explain", domain)


@pytest.mark.parametrize(
    ("path", "content_type", "fragment"),
    [
        ("/", "text/html; charset=utf-8", b"<!doctype html>"),
        ("/app.css", "text/css; charset=utf-8", b"--high"),
        ("/app.js", "text/javascript; charset=utf-8", b"/api/audit"),
    ],
)
def test_serves_the_page_files(port: int, path: str, content_type: str, fragment: bytes) -> None:
    status, headers, body = request(port, "GET", path)
    assert status == 200
    assert headers["Content-Type"] == content_type
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert fragment in body


def test_answers_404_for_an_unknown_path(port: int) -> None:
    assert request(port, "GET", "/etc/passwd")[0] == 404
    assert request(port, "POST", "/api/other", b"{}", {"Content-Length": "2"})[0] == 404


def test_audits_a_domain(port: int) -> None:
    status, payload = audit(port, " Example.COM. ")
    assert status == 200
    assert payload["domain"] == "example.com"
    assert [finding["code"] for finding in payload["findings"]] == ["SPF_PTR"]
    assert payload["headline"]["title"].endswith("example.com.")


@pytest.mark.parametrize("domain", ["not a domain", "localhost", 42])
def test_refuses_what_is_not_a_domain_name_with_400(port: int, domain: Any) -> None:
    status, payload = audit(port, domain)
    assert status == 400
    assert payload["error"]


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"name": "example.com"}', b"\xff"])
def test_refuses_a_malformed_body_with_400(port: int, body: bytes) -> None:
    assert request(port, "POST", "/api/audit", body)[0] == 400


def test_reports_a_missing_domain_with_404(port: int) -> None:
    assert audit(port, "missing.example") == (
        404,
        {"error": "missing.example does not exist in DNS"},
    )


def test_reports_a_failed_lookup_with_502(port: int) -> None:
    status, payload = audit(port, "timeout.example")
    assert status == 502
    assert "timed out" in payload["error"]


def test_reports_an_unexpected_failure_with_500(port: int) -> None:
    status, payload = audit(port, "broken.example")
    assert status == 500
    assert "terminal" in payload["error"]


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "attacker.example:80"},
        {"Origin": "http://attacker.example"},
        {"Origin": "null"},
    ],
)
def test_refuses_requests_from_other_sites(port: int, headers: dict[str, str]) -> None:
    assert request(port, "GET", "/", headers=headers)[0] == 403
    assert audit(port, "example.com", headers)[0] == 403


def test_accepts_the_page_s_own_origin_under_either_name(port: int) -> None:
    for host in (f"127.0.0.1:{port}", f"localhost:{port}"):
        headers = {"Host": host, "Origin": f"http://{host}"}
        assert audit(port, "example.com", headers)[0] == 200


def test_refuses_an_oversized_body_with_413(port: int) -> None:
    assert request(port, "POST", "/api/audit", b"x" * 1025)[0] == 413


def test_refuses_a_body_without_a_length_with_411(port: int) -> None:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.putrequest("POST", "/api/audit")
        connection.endheaders()
        assert connection.getresponse().status == 411
    finally:
        connection.close()


def test_page_styles_and_script_are_under_budget() -> None:
    size = sum((STATIC / name).stat().st_size for name in ("app.css", "app.js"))
    print(f"app.css + app.js: {size / 1024:.1f} KiB (budget 75 KiB)")
    assert size < PAGE_ASSET_BUDGET_BYTES


def test_explains_a_domain_with_the_model_it_was_given(port: int, claude: FakeClaude) -> None:
    status, payload = explain(port, "example.com")
    assert status == 200
    assert (payload["domain"], payload["model"], payload["summary"]) == (
        "example.com",
        MODEL,
        "Mostly guarded.",
    )
    assert payload["findings"] == [
        {
            "number": 1,
            "code": "SPF_PTR",
            "evidence": "ptr",
            "explanation": PTR_CLAIM.explanation,
            "fix": "Remove ptr.",
            "unsupported_tokens": [],
        }
    ]
    assert claude.prompts == [(MODEL, SYSTEM_PROMPT)]


@pytest.mark.parametrize(
    ("domain", "reason"),
    [("declines.example", "declined to explain"), ("nokey.example", "api_key")],
)
def test_reports_a_model_failure_with_502(port: int, domain: str, reason: str) -> None:
    status, payload = explain(port, domain)
    assert status == 502
    assert reason in payload["error"]


def test_refuses_to_explain_a_domain_with_no_findings_with_409(
    port: int, claude: FakeClaude
) -> None:
    assert explain(port, "clean.example")[0] == 409
    assert claude.prompts == []


@pytest.mark.parametrize(
    ("domain", "status"),
    [("not a domain", 400), ("missing.example", 404), ("timeout.example", 502)],
)
def test_explain_reports_domain_and_dns_errors_as_the_audit_does(
    port: int, claude: FakeClaude, domain: str, status: int
) -> None:
    assert explain(port, domain)[0] == status
    assert claude.prompts == []


def test_refuses_a_second_explanation_while_one_runs_with_429(
    port: int, claude: FakeClaude
) -> None:
    claude.release.clear()
    first: list[tuple[int, Any]] = []
    thread = threading.Thread(target=lambda: first.append(explain(port, "example.com")))
    thread.start()
    try:
        assert claude.entered.wait(timeout=5)
        status, payload = explain(port, "example.com")
        assert status == 429
        assert "already" in payload["error"]
        assert audit(port, "example.com")[0] == 200
    finally:
        claude.release.set()
        thread.join()
    assert first[0][0] == 200
    assert explain(port, "example.com")[0] == 200


def test_explain_reports_an_unexpected_failure_with_500_and_frees_the_lock(port: int) -> None:
    assert explain(port, "broken.example")[0] == 500
    assert explain(port, "example.com")[0] == 200

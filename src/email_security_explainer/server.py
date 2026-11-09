"""Serve the audit page and its JSON API to this machine only."""

import contextlib
import json
import logging
import sys
from dataclasses import asdict
from functools import partial
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any

from email_security_explainer.dns_fetch import (
    DnsLookupError,
    DomainNotFoundError,
    TxtLookup,
    fetch_records,
)
from email_security_explainer.domain import parse_domain
from email_security_explainer.web import audit_view

HOST = "127.0.0.1"
MAX_BODY_BYTES = 1024
SOCKET_TIMEOUT_SECONDS = 10.0
# The fonts are the only outside resource; every untrusted string reaches the
# page as text, so no inline script or style is needed either.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)
_PAGE_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}

logger = logging.getLogger(__name__)

PageFiles = dict[str, tuple[bytes, str]]


def make_server(port: int, lookup: TxtLookup) -> ThreadingHTTPServer:
    """Bind to `port` on the loopback address. Raises OSError when the port is
    taken; port 0 picks a free one."""
    static = resources.files(__package__) / "static"
    page_files = {
        path: ((static / name).read_bytes(), content_type)
        for path, (name, content_type) in _PAGE_FILES.items()
    }
    handler = partial(_PageRequestHandler, lookup=lookup, page_files=page_files)
    return ThreadingHTTPServer((HOST, port), handler)


def serve(port: int, lookup: TxtLookup) -> None:  # pragma: no cover: blocks until Ctrl+C
    with make_server(port, lookup) as server:
        print(f"esx: checking domains at http://{HOST}:{port}/ (Ctrl+C stops it)", file=sys.stderr)
        # Ctrl+C is how the owner stops the server, not a failure.
        with contextlib.suppress(KeyboardInterrupt):
            server.serve_forever()


class _PageRequestHandler(BaseHTTPRequestHandler):
    # A client that stops sending mid-request frees its thread after this long.
    timeout = SOCKET_TIMEOUT_SECONDS
    server_version = "esx"

    def __init__(self, *args: Any, lookup: TxtLookup, page_files: PageFiles, **kwargs: Any) -> None:
        self._lookup = lookup
        self._page_files = page_files
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        if not self._is_from_this_page():
            return
        page_file = self._page_files.get(self.path)
        if page_file is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"no page at {self.path}"})
            return
        self._send(HTTPStatus.OK, *page_file)

    def do_POST(self) -> None:
        if not self._is_from_this_page():
            return
        if self.path != "/api/audit":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": f"no API at {self.path}"})
            return
        raw_domain = self._read_domain()
        if raw_domain is None:
            return
        try:
            self._audit(raw_domain)
        except Exception:
            # The process boundary for one request: the page gets an answer and
            # the terminal gets the traceback.
            logger.exception("audit of %r failed", raw_domain)
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "esx failed while checking this domain; the terminal shows why"},
            )

    def _audit(self, raw_domain: str) -> None:
        try:
            domain = parse_domain(raw_domain)
        except ValueError as err:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(err)})
            return
        try:
            records = fetch_records(domain, self._lookup)
        except DomainNotFoundError as err:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": str(err)})
            return
        except DnsLookupError as err:
            self._send_json(HTTPStatus.BAD_GATEWAY, {"error": str(err)})
            return
        self._send_json(HTTPStatus.OK, asdict(audit_view(records)))

    def _is_from_this_page(self) -> bool:
        """Refuse a request another site sent through the browser, including
        one that reaches this port by rebinding its own name to 127.0.0.1."""
        address = self.server.server_address
        assert isinstance(address, tuple), address
        hosts = {f"{HOST}:{address[1]}", f"localhost:{address[1]}"}
        origin = self.headers.get("Origin")
        if self.headers.get("Host") in hosts and (
            origin is None or origin in {f"http://{host}" for host in hosts}
        ):
            return True
        self._send_json(HTTPStatus.FORBIDDEN, {"error": "requests must come from the esx page"})
        return False

    def _read_domain(self) -> str | None:
        length_text = self.headers.get("Content-Length", "")
        if not (length_text.isascii() and length_text.isdigit()):
            self._send_json(HTTPStatus.LENGTH_REQUIRED, {"error": "expected a Content-Length"})
            return None
        if int(length_text) > MAX_BODY_BYTES:
            # The body is never read, so the connection cannot be reused.
            self.close_connection = True
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": f"expected a body of at most {MAX_BODY_BYTES} bytes"},
            )
            return None
        try:
            body = json.loads(self.rfile.read(int(length_text)))
        except ValueError:
            body = None
        domain = body.get("domain") if isinstance(body, dict) else None
        if not isinstance(domain, str):
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": 'expected a JSON body such as {"domain": "x"}'}
            )
            return None
        return domain

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.end_headers()
        self.wfile.write(body)

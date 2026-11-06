"""The publisher gate as WSGI middleware: an unpaid request to a paid path is
answered 402 and never reaches the application.

    app = PublisherGateMiddleware(app, PublisherGate(policy, quote=node_quote(node)))
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any
from wsgiref.util import request_uri

from .gate import Paid, PublisherGate, Serve

WSGIApp = Callable[[dict[str, Any], Callable[..., Any]], Iterable[bytes]]

_REASONS = {402: "402 Payment Required", 503: "503 Service Unavailable"}


def request_headers(environ: dict[str, Any]) -> dict[str, str]:
    """The request's headers, lower-case names, from a WSGI environ."""
    out: dict[str, str] = {}
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            out[key[5:].replace("_", "-").lower()] = value
        elif key in ("CONTENT_TYPE", "CONTENT_LENGTH") and value:
            out[key.replace("_", "-").lower()] = value
    return out


class PublisherGateMiddleware:
    """Wraps a WSGI application in the gate."""

    def __init__(self, app: WSGIApp, gate: PublisherGate):
        self.app = app
        self.gate = gate

    def __call__(self, environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        decision = self.gate.decide(request_uri(environ, include_query=True), request_headers(environ))
        extra = decision.response_headers()
        if isinstance(decision, (Serve, Paid)):
            if not extra:
                return self.app(environ, start_response)
            names = {k.lower() for k, _ in extra}

            def start_with_headers(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> Any:
                kept = [(k, v) for k, v in headers if k.lower() not in names]
                return start_response(status, kept + extra, exc_info)

            return self.app(environ, start_with_headers)
        body = decision.body.encode()
        start_response(_REASONS[decision.status], [*extra, ("Content-Length", str(len(body)))])
        return [body]


__all__ = ["PublisherGateMiddleware", "request_headers"]

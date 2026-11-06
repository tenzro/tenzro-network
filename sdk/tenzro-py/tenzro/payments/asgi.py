"""The publisher gate as ASGI middleware: an unpaid request to a paid path is
answered 402 and never reaches the application.

    app = PublisherGateMiddleware(app, AsyncPublisherGate(policy, quote=async_node_quote(node)))
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, MutableMapping

from .gate import AsyncPublisherGate, Paid, Serve

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def request_url(scope: Scope) -> str:
    """The absolute URL of an HTTP scope, as the payer requested it."""
    host = None
    for name, value in scope.get("headers", ()):
        if name.lower() == b"host":
            host = value.decode("latin-1")
            break
    if host is None:
        server = scope.get("server")
        host = f"{server[0]}:{server[1]}" if server else "localhost"
    path = scope.get("raw_path") or scope.get("path", "/").encode()
    url = f"{scope.get('scheme', 'http')}://{host}{path.decode('latin-1')}"
    query = scope.get("query_string", b"")
    return f"{url}?{query.decode('latin-1')}" if query else url


class PublisherGateMiddleware:
    """Wraps an ASGI application in the gate."""

    def __init__(self, app: ASGIApp, gate: AsyncPublisherGate):
        self.app = app
        self.gate = gate

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", ())}
        decision = await self.gate.decide(request_url(scope), headers)
        extra = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in decision.response_headers()]
        if isinstance(decision, (Serve, Paid)):
            if not extra:
                await self.app(scope, receive, send)
                return
            names = {k for k, _ in extra}

            async def send_with_headers(message: Message) -> None:
                if message["type"] == "http.response.start":
                    kept = [(k, v) for k, v in message.get("headers", ()) if k.lower() not in names]
                    message = {**message, "headers": kept + extra}
                await send(message)

            await self.app(scope, receive, send_with_headers)
            return
        body = decision.body.encode()
        await send({"type": "http.response.start", "status": decision.status, "headers": extra})
        await send({"type": "http.response.body", "body": body})


__all__ = ["PublisherGateMiddleware", "request_url"]

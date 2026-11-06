"""The node's chat completion contract: ``POST /v1/chat/completions``
streamed, and the adaptor that turns its chunks into typed events.

The node splits reasoning from the answer and assembles tool calls on its
side, so the adaptor reads fields and never parses model markup. Events and
the completion are plain dicts in the wire shape the TypeScript and Rust SDKs
use (``sdk/fixtures/chat-stream``).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

from ..rpc import ApiError, AsyncRpcClient, RpcClient
from ..sse import SseDecoder

ChatRequest = dict[str, Any]
ChatStreamEvent = dict[str, Any]
ChatCompletion = dict[str, Any]


def _non_empty(v: Any) -> str | None:
    return v if isinstance(v, str) and v else None


def _malformed(message: str) -> ApiError:
    return ApiError(message, "invalid_response", "malformed_frame")


class ChatStreamAssembler:
    """Turns the ``data`` payloads of a chat stream into events and
    accumulates the completion they add up to."""

    def __init__(self) -> None:
        self._id: str | None = None
        self._model: str | None = None
        self._content = ""
        self._reasoning = ""
        self._tool_calls: dict[int, dict[str, Any]] = {}
        self._finish_reason: str | None = None
        self._native_finish_reason: str | None = None
        self._usage: dict[str, int] | None = None
        self._cost_wei: str | None = None
        self.done = False

    def push(self, data: str) -> list[ChatStreamEvent]:
        """Absorb one event's ``data`` and return the events it carries.

        Raises :class:`ApiError` for an error frame or a payload that is not a chunk.
        """
        if data == "[DONE]":
            self.done = True
            return []
        try:
            frame = json.loads(data)
        except ValueError as e:
            raise _malformed(f"stream frame is not JSON: {e}") from None
        err = ApiError.from_body(frame)
        if err is not None:
            raise err
        if not isinstance(frame, dict):
            frame = {}
        if self._id is None and isinstance(frame.get("id"), str):
            self._id = frame["id"]
        if self._model is None and isinstance(frame.get("model"), str):
            self._model = frame["model"]

        events: list[ChatStreamEvent] = []
        choices = frame.get("choices")
        choice = choices[0] if isinstance(choices, list) and choices else None
        if isinstance(choice, dict):
            delta = choice.get("delta") or {}
            reasoning = _non_empty(delta.get("reasoning_content"))
            if reasoning is not None:
                self._reasoning += reasoning
                events.append({"type": "reasoning", "text": reasoning})
            content = _non_empty(delta.get("content"))
            if content is not None:
                self._content += content
                events.append({"type": "content", "text": content})
            if isinstance(delta.get("tool_calls"), list):
                events += [self._absorb_tool_call(call) for call in delta["tool_calls"]]
            if isinstance(choice.get("finish_reason"), str):
                self._finish_reason = choice["finish_reason"]
                native = choice.get("native_finish_reason")
                self._native_finish_reason = native if isinstance(native, str) else None
                ev: ChatStreamEvent = {"type": "finish", "finish_reason": self._finish_reason}
                if self._native_finish_reason is not None:
                    ev["native_finish_reason"] = self._native_finish_reason
                events.append(ev)
        u = frame.get("usage")
        if isinstance(u, dict):
            keys = ("prompt_tokens", "completion_tokens", "total_tokens")
            if not all(isinstance(u.get(k), (int, float)) and not isinstance(u.get(k), bool) for k in keys):
                raise _malformed("usage is malformed")
            usage = {k: u[k] for k in keys}
            cost = frame.get("cost_wei")
            cost_wei = cost if isinstance(cost, str) else None
            if usage != self._usage or cost_wei != self._cost_wei:
                self._usage = usage
                self._cost_wei = cost_wei
                ev = {"type": "usage", "usage": usage}
                if cost_wei is not None:
                    ev["cost_wei"] = cost_wei
                events.append(ev)
        return events

    def _absorb_tool_call(self, call: Any) -> ChatStreamEvent:
        c = call if isinstance(call, dict) else {}
        index = c.get("index")
        if not isinstance(index, int) or isinstance(index, bool):
            raise _malformed("tool call delta has no index")
        fn = c.get("function") or {}
        call_id = c.get("id") if isinstance(c.get("id"), str) else None
        name = fn.get("name") if isinstance(fn.get("name"), str) else None
        args = fn.get("arguments") if isinstance(fn.get("arguments"), str) else ""
        entry = self._tool_calls.setdefault(index, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
        if call_id is not None:
            entry["id"] = call_id
        if name is not None:
            entry["function"]["name"] = name
        entry["function"]["arguments"] += args
        ev: ChatStreamEvent = {"type": "tool_call", "index": index, "arguments": args}
        if call_id is not None:
            ev["id"] = call_id
        if name is not None:
            ev["name"] = name
        return ev

    def completion(self) -> ChatCompletion:
        """The completion the stream added up to."""
        return {
            "id": self._id,
            "model": self._model,
            "content": self._content,
            "reasoning": self._reasoning,
            "tool_calls": [
                {**call, "function": dict(call["function"])} for _, call in sorted(self._tool_calls.items())
            ],
            "finish_reason": self._finish_reason,
            "native_finish_reason": self._native_finish_reason,
            "usage": self._usage,
            "cost_wei": self._cost_wei,
        }


_PATH = "/v1/chat/completions"


class ChatClient:
    """Streams chat completions from a node."""

    def __init__(self, node: RpcClient):
        self._node = node

    def stream(self, request: ChatRequest) -> Iterator[ChatStreamEvent]:
        """The events of one completion, as they arrive."""
        yield from self._run(request, ChatStreamAssembler())

    def complete(self, request: ChatRequest, on_event: Callable[[ChatStreamEvent], None] | None = None) -> ChatCompletion:
        """The whole completion, streamed underneath; ``on_event`` sees each event."""
        assembler = ChatStreamAssembler()
        for event in self._run(request, assembler):
            if on_event is not None:
                on_event(event)
        return assembler.completion()

    def _run(self, request: ChatRequest, assembler: ChatStreamAssembler) -> Iterator[ChatStreamEvent]:
        decoder = SseDecoder()
        with self._node.post_stream(_PATH, {**request, "stream": True}) as response:
            for chunk in response.iter_bytes():
                for frame in decoder.push(chunk):
                    yield from assembler.push(frame.data)
                    if assembler.done:
                        return
            for frame in decoder.finish():
                yield from assembler.push(frame.data)
                if assembler.done:
                    return


class AsyncChatClient:
    """Streams chat completions from a node, asynchronously."""

    def __init__(self, node: AsyncRpcClient):
        self._node = node

    async def stream(self, request: ChatRequest) -> AsyncIterator[ChatStreamEvent]:
        """The events of one completion, as they arrive."""
        async for event in self._run(request, ChatStreamAssembler()):
            yield event

    async def complete(
        self, request: ChatRequest, on_event: Callable[[ChatStreamEvent], None] | None = None
    ) -> ChatCompletion:
        """The whole completion, streamed underneath; ``on_event`` sees each event."""
        assembler = ChatStreamAssembler()
        async for event in self._run(request, assembler):
            if on_event is not None:
                on_event(event)
        return assembler.completion()

    async def _run(self, request: ChatRequest, assembler: ChatStreamAssembler) -> AsyncIterator[ChatStreamEvent]:
        decoder = SseDecoder()
        async with self._node.post_stream(_PATH, {**request, "stream": True}) as response:
            async for chunk in response.aiter_bytes():
                for frame in decoder.push(chunk):
                    for event in assembler.push(frame.data):
                        yield event
                    if assembler.done:
                        return
            for frame in decoder.finish():
                for event in assembler.push(frame.data):
                    yield event
                if assembler.done:
                    return


__all__ = ["AsyncChatClient", "ChatClient", "ChatCompletion", "ChatRequest", "ChatStreamAssembler", "ChatStreamEvent"]

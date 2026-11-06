"""The shared chat-stream fixtures (sdk/fixtures/chat-stream), decoded at every
chunk boundary as the TypeScript and Rust SDKs decode them."""

import asyncio
import json

import httpx
import pytest
from conftest import FIXTURES

from tenzro import ApiError, AsyncRpcClient, RpcClient, SseDecoder
from tenzro.inference import AsyncChatClient, ChatClient, ChatStreamAssembler

DIR = FIXTURES / "chat-stream"
EXPECTED = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
STREAMS = ["content", "reasoning", "tool-calls", "usage", "error"]


def run(chunks):
    decoder = SseDecoder()
    assembler = ChatStreamAssembler()
    frames = []
    for c in chunks:
        frames += decoder.push(c)
    frames += decoder.finish()
    events = []
    for frame in frames:
        try:
            events += assembler.push(frame.data)
        except ApiError as e:
            return {"events": events, "completion": None, "error": e.to_json()}
        if assembler.done:
            break
    assert assembler.done, "stream ended without [DONE]"
    return {"events": events, "completion": assembler.completion(), "error": None}


@pytest.mark.parametrize("name", STREAMS)
def test_chat_streams_decode_identically_at_every_chunk_boundary(name):
    data = (DIR / f"{name}.sse").read_bytes()
    want = EXPECTED[name]
    assert run([data]) == want
    for cut in range(len(data) + 1):
        assert run([data[:cut], data[cut:]]) == want, f"split at byte {cut}"
    assert run([data[i : i + 1] for i in range(len(data))]) == want


def test_reasoning_arrives_before_the_answer():
    kinds = [e["type"] for e in run([(DIR / "reasoning.sse").read_bytes()])["events"]]
    first = kinds.index("content")
    assert "reasoning" in kinds[:first] and "reasoning" not in kinds[first:]


def _node(handler):
    return httpx.MockTransport(handler)


def test_the_chat_client_streams_from_the_node_with_its_credential():
    seen = []

    class Prover:
        def jkt(self):
            return "jkt"

        def proof(self, htm, htu, token):
            return f"{htm} {htu} {token}"

    def handler(request):
        seen.append((str(request.url), request.headers.get("authorization"), request.headers.get("dpop"), json.loads(request.content)))
        return httpx.Response(200, content=(DIR / "content.sse").read_bytes())

    from tenzro import AccessCredential

    node = RpcClient("http://node.invalid", credential=AccessCredential("tok", Prover()), transport=_node(handler))
    completion = ChatClient(node).complete({"model": "qwen3.5-4b", "messages": [{"role": "user", "content": "hi"}]})
    assert completion == EXPECTED["content"]["completion"]
    url = "http://node.invalid/v1/chat/completions"
    assert seen == [(url, "DPoP tok", f"POST {url} tok", {"model": "qwen3.5-4b", "messages": [{"role": "user", "content": "hi"}], "stream": True})]

    async def run_async():
        anode = AsyncRpcClient("http://node.invalid", transport=httpx.MockTransport(handler))
        return [e async for e in AsyncChatClient(anode).stream({"model": "m", "messages": []})]

    assert asyncio.run(run_async()) == EXPECTED["content"]["events"]
    assert seen[1][1] is None and seen[1][3]["stream"] is True


def test_an_error_body_before_the_stream_is_a_typed_api_error():
    def handler(request):
        return httpx.Response(404, json={"error": {"message": "no such model", "type": "invalid_request_error", "code": "model_not_found"}})

    node = RpcClient("http://node.invalid", transport=_node(handler))
    with pytest.raises(ApiError) as e:
        ChatClient(node).complete({"model": "nope", "messages": []})
    assert e.value.to_json() == {"message": "no such model", "type": "invalid_request_error", "code": "model_not_found"}

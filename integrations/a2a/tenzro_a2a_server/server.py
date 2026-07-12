"""Tenzro A2A Protocol Server -- FastAPI implementation.

Endpoints:
  GET  /.well-known/agent.json  -- Agent Card discovery
  POST /a2a                     -- JSON-RPC 2.0 dispatcher
  POST /a2a/stream              -- SSE streaming for task updates
  GET  /health                  -- Health check
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse
import json
import os
import uvicorn

from .agent_card import build_agent_card
from .task_manager import TaskManager
from .router import route_message
from .handlers import HANDLERS
from . import x402_extension as x402
from .x402_extension import (
    PaymentStatus,
    UnimplementedSchemeVerifier,
    VerifyFailure,
)

app = FastAPI(
    title="Tenzro A2A Server",
    version="0.1.0",
    description="Agent-to-Agent protocol server for the Tenzro Network",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

task_manager = TaskManager()

# x402 payment verifier — slice (a) ships the structural verifier that
# rejects every payload with `payment-rejected`. Slice (c) replaces this
# with a registry of concrete scheme backends (exact-eip3009, exact-permit2,
# exact-erc7710).
payment_verifier = UnimplementedSchemeVerifier()

BASE_URL = os.environ.get("TENZRO_A2A_BASE_URL", "https://a2a.tenzro.xyz")


# ---------------------------------------------------------------------------
# Agent Card Discovery
# ---------------------------------------------------------------------------

@app.get("/.well-known/agent.json")
async def agent_card():
    """Serve the A2A Agent Card for discovery."""
    return build_agent_card(BASE_URL)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "version": "0.1.0"}


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 Dispatcher
# ---------------------------------------------------------------------------

@app.post("/a2a")
async def a2a_rpc(request: Request):
    """Handle A2A JSON-RPC 2.0 requests."""
    body = await request.json()
    jsonrpc = body.get("jsonrpc")
    if jsonrpc != "2.0":
        return JSONResponse({
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "Invalid JSON-RPC version"},
            "id": body.get("id"),
        })

    method = body.get("method", "")
    params = body.get("params", {})
    req_id = body.get("id")

    if method in ("tasks/send", "message/send"):
        return await _handle_task_send(params, req_id)

    elif method == "tasks/get":
        task = task_manager.get_task(
            params.get("id"),
            params.get("historyLength"),
        )
        if not task:
            return JSONResponse({
                "jsonrpc": "2.0",
                "error": {"code": -32001, "message": "Task not found"},
                "id": req_id,
            })
        return JSONResponse({"jsonrpc": "2.0", "result": task, "id": req_id})

    elif method == "tasks/list":
        tasks = task_manager.list_tasks(params.get("contextId"))
        return JSONResponse({"jsonrpc": "2.0", "result": tasks, "id": req_id})

    elif method == "tasks/cancel":
        task = task_manager.cancel_task(params.get("id"))
        if not task:
            return JSONResponse({
                "jsonrpc": "2.0",
                "error": {"code": -32001, "message": "Task not found"},
                "id": req_id,
            })
        return JSONResponse({"jsonrpc": "2.0", "result": task, "id": req_id})

    else:
        return JSONResponse({
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": f"Method not found: {method}"},
            "id": req_id,
        })


async def _handle_task_send(params: dict, req_id) -> JSONResponse:
    """Process a tasks/send or message/send request.

    Continuation contract (x402 hold-and-resume): when the inbound message
    references an existing task (`message.taskId`) and that task is held in
    `input-required` with `x402.payment.required`, the inbound metadata must
    carry `x402.payment.payload`. The dispatcher routes the payload through
    `payment_verifier`; on success the task resumes to `working` and the
    handler runs, on failure the task transitions to `failed` with
    `x402.payment.status = "payment-rejected"`.
    """
    message = params.get("message", {}) or {}
    # Inbound message metadata may carry an `x402.payment.payload` for a
    # task held in `input-required`. Top-level `params.metadata` is also
    # accepted (legacy callers).
    inbound_metadata = message.get("metadata") or params.get("metadata") or {}

    # Extract text from message parts
    text = ""
    for part in message.get("parts", []):
        if part.get("type") == "text":
            text += part.get("text", "")

    # Continuation: lookup existing task by taskId on the inbound message.
    inbound_task_id = message.get("taskId")
    if inbound_task_id:
        existing = task_manager.get_task(inbound_task_id)
        if existing is not None and existing.get("status", {}).get("state") == "input-required":
            requirements = x402.get_payment_required(existing.get("metadata") or {})
            if requirements is not None:
                return await _resume_x402_task(
                    inbound_task_id,
                    existing,
                    requirements,
                    inbound_metadata,
                    text,
                    req_id,
                )

    # Create task and transition to working
    task = task_manager.create_task(message, metadata=inbound_metadata)
    task_manager.update_state(task["id"], "working")

    # Route and handle
    try:
        skill = route_message(text)
        handler = HANDLERS.get(skill, HANDLERS["help"])
        response_text = await handler(text, inbound_metadata)
    except Exception as e:
        response_text = f"Error processing request: {e}"

    # Complete the task
    agent_message = {
        "role": "agent",
        "parts": [{"type": "text", "text": response_text}],
    }
    task_manager.update_state(task["id"], "completed", agent_message)

    return JSONResponse({
        "jsonrpc": "2.0",
        "result": task_manager.get_task(task["id"]),
        "id": req_id,
    })


async def _resume_x402_task(
    task_id: str,
    existing: dict,
    requirements: dict,
    inbound_metadata: dict,
    text: str,
    req_id,
) -> JSONResponse:
    """Resume a task held in `input-required` with `x402.payment.required`.

    Mirrors the Rust hold-and-resume dispatcher. Always settles into a
    terminal task state (`completed` on success, `failed` on payment
    failure).
    """
    payload = x402.get_payment_payload(inbound_metadata)
    if payload is None:
        return JSONResponse({
            "jsonrpc": "2.0",
            "error": {
                "code": -32004,
                "message": "task is awaiting x402.payment.payload in message.metadata",
            },
            "id": req_id,
        })

    # Mutate the held task's metadata in place — TaskManager hands out the
    # same dict reference via get_task(), and update_state() rewrites the
    # `status` block on transition.
    task_metadata = existing.setdefault("metadata", {})

    try:
        receipts = payment_verifier.verify_and_settle(task_id, requirements, payload)
    except VerifyFailure as failure:
        x402.submit_x402(task_metadata, payload)
        x402.fail_x402(task_metadata, failure.terminal_status())
        failure_msg = {
            "role": "agent",
            "parts": [{"type": "text", "text": f"payment failed: {failure.message()}"}],
        }
        task_manager.update_state(task_id, "failed", failure_msg)
        return JSONResponse({
            "jsonrpc": "2.0",
            "result": task_manager.get_task(task_id),
            "id": req_id,
        })

    # Success path: record submission + receipts, resume task, run handler.
    x402.submit_x402(task_metadata, payload)
    x402.complete_x402(task_metadata, receipts)
    task_manager.update_state(task_id, "working")

    try:
        skill = route_message(text)
        handler = HANDLERS.get(skill, HANDLERS["help"])
        response_text = await handler(text, task_metadata)
    except Exception as e:
        response_text = f"Error processing request: {e}"

    agent_message = {
        "role": "agent",
        "parts": [{"type": "text", "text": response_text}],
    }
    task_manager.update_state(task_id, "completed", agent_message)

    return JSONResponse({
        "jsonrpc": "2.0",
        "result": task_manager.get_task(task_id),
        "id": req_id,
    })


# ---------------------------------------------------------------------------
# SSE Streaming
# ---------------------------------------------------------------------------

@app.post("/a2a/stream")
async def a2a_stream(request: Request):
    """Handle streaming A2A requests via Server-Sent Events."""
    body = await request.json()
    params = body.get("params", {})
    message = params.get("message", {})
    metadata = params.get("metadata", {})

    text = ""
    for part in message.get("parts", []):
        if part.get("type") == "text":
            text += part.get("text", "")

    task = task_manager.create_task(message, metadata=metadata)

    async def event_generator():
        # Emit submitted state
        yield {
            "event": "task",
            "data": json.dumps(task_manager.get_task(task["id"])),
        }

        # Transition to working
        task_manager.update_state(task["id"], "working")
        yield {
            "event": "task",
            "data": json.dumps(task_manager.get_task(task["id"])),
        }

        # Route and handle
        try:
            skill = route_message(text)
            handler = HANDLERS.get(skill, HANDLERS["help"])
            response_text = await handler(text, metadata)
        except Exception as e:
            response_text = f"Error processing request: {e}"

        # Complete
        agent_message = {
            "role": "agent",
            "parts": [{"type": "text", "text": response_text}],
        }
        task_manager.update_state(task["id"], "completed", agent_message)
        yield {
            "event": "task",
            "data": json.dumps(task_manager.get_task(task["id"])),
        }

        # Signal done
        yield {"event": "done", "data": ""}

    return EventSourceResponse(event_generator())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """CLI entry point for tenzro-a2a-server."""
    import argparse

    parser = argparse.ArgumentParser(description="Tenzro A2A Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=3002, help="Bind port (default: 3002)")
    args = parser.parse_args()

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

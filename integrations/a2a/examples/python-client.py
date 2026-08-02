#!/usr/bin/env python3
"""
Tenzro A2A Client -- Python Example

Demonstrates how to interact with a Tenzro node via the A2A protocol.
Covers wallet, identity, inference, staking, tokens, agents, and marketplace.

Usage:
    python3 python-client.py

Requirements:
    No external dependencies -- uses stdlib urllib.
"""

import json
import os
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

A2A_ENDPOINT = os.environ.get("TENZRO_A2A_URL", "https://a2a.tenzro.xyz")


# --- Core A2A Client ---

def get_agent_card() -> dict:
    """Fetch the agent card for capability discovery."""
    url = f"{A2A_ENDPOINT}/.well-known/agent.json"
    req = Request(url)
    with urlopen(req) as resp:
        return json.loads(resp.read().decode())


def send_task(message: str, task_id: str | None = None) -> dict:
    """Send a task to the A2A agent."""
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "method": "tasks/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": message}],
            },
        },
        "id": 1,
    }
    if task_id:
        payload["params"]["id"] = task_id

    data = json.dumps(payload).encode()
    req = Request(
        f"{A2A_ENDPOINT}/a2a",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlopen(req) as resp:
        result = json.loads(resp.read().decode())

    if result.get("error"):
        code = result["error"].get("code", -1)
        msg = result["error"].get("message", "Unknown error")
        raise RuntimeError(f"A2A Error [{code}]: {msg}")

    return result.get("result", {})


def get_task(task_id: str) -> dict:
    """Get a task by ID."""
    payload = {
        "jsonrpc": "2.0",
        "method": "tasks/get",
        "params": {"id": task_id},
        "id": 2,
    }

    data = json.dumps(payload).encode()
    req = Request(
        f"{A2A_ENDPOINT}/a2a",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlopen(req) as resp:
        result = json.loads(resp.read().decode())

    if result.get("error"):
        raise RuntimeError(f"A2A Error: {result['error']['message']}")

    return result.get("result", {})


def cancel_task(task_id: str) -> dict:
    """Cancel a running task."""
    payload = {
        "jsonrpc": "2.0",
        "method": "tasks/cancel",
        "params": {"id": task_id},
        "id": 3,
    }

    data = json.dumps(payload).encode()
    req = Request(
        f"{A2A_ENDPOINT}/a2a",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlopen(req) as resp:
        result = json.loads(resp.read().decode())

    if result.get("error"):
        raise RuntimeError(f"A2A Error: {result['error']['message']}")

    return result.get("result", {})


def list_tasks() -> list:
    """List all tasks."""
    payload = {
        "jsonrpc": "2.0",
        "method": "tasks/list",
        "params": {},
        "id": 4,
    }

    data = json.dumps(payload).encode()
    req = Request(
        f"{A2A_ENDPOINT}/a2a",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlopen(req) as resp:
        result = json.loads(resp.read().decode())

    if result.get("error"):
        raise RuntimeError(f"A2A Error: {result['error']['message']}")

    return result.get("result", [])


def extract_agent_response(task: dict) -> str:
    """Extract the latest agent text response from a task."""
    messages = task.get("messages", [])
    for msg in reversed(messages):
        if msg.get("role") == "agent":
            for part in msg.get("parts", []):
                if part.get("type") == "text" and part.get("text"):
                    return part["text"]
    return "(no agent response)"


# --- Streaming Client ---

def stream_task(message: str) -> None:
    """Stream a task response via Server-Sent Events."""
    payload = {
        "jsonrpc": "2.0",
        "method": "tasks/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": message}],
            },
        },
        "id": 1,
    }

    data = json.dumps(payload).encode()
    req = Request(
        f"{A2A_ENDPOINT}/a2a/stream",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        },
        method="POST",
    )

    with urlopen(req) as resp:
        for line in resp:
            decoded = line.decode().strip()
            if decoded.startswith("data:"):
                event_data = decoded[5:].strip()
                if event_data:
                    event = json.loads(event_data)
                    state = event.get("state", "")
                    print(f"  [{state}] ", end="")

                    messages = event.get("messages", [])
                    for msg in messages:
                        if msg.get("role") == "agent":
                            for part in msg.get("parts", []):
                                if part.get("type") == "text":
                                    print(part["text"])


# --- Demo helper ---

def demo(label: str, message: str) -> None:
    print(f"\n{label}")
    try:
        task = send_task(message)
        print(f"   Task: {task.get('id', 'N/A')} [{task.get('state', 'N/A')}]")
        response = extract_agent_response(task)
        print(f"   Response: {response[:200]}")
    except Exception as e:
        print(f"   Error: {e}")


# --- Main ---

def main():
    print("=== Tenzro A2A Client (Python) ===\n")

    # 1. Discover agent capabilities
    print("1. Fetching Agent Card...")
    try:
        card = get_agent_card()
        print(f"   Agent: {card.get('name', 'Unknown')} v{card.get('version', '?')}")
        print(f"   Protocol: A2A {card.get('protocolVersion', '?')}")
        skills = card.get("skills", [])
        print(f"   Skills ({len(skills)}):")
        for s in skills:
            print(f"     - {s.get('name', '')} ({s.get('id', '')})")
    except (HTTPError, URLError) as e:
        print(f"   Error: {e}\n")
        return

    # 2. Wallet
    demo("2. Wallet — Check balance",
         "What is the balance of 0x0000000000000000000000000000000000000001?")

    # 3. Block height
    demo("3. Blockchain — Block height",
         "What is the current block height?")

    # 4. Node status
    demo("4. Network — Node status",
         "What is the node status and peer count?")

    # 5. Identity
    demo("5. Identity — Register DID",
         "Register a new identity named TestAgent")

    # 6. AI Models
    demo("6. Inference — List models",
         "List available AI models")

    # 7. Staking
    demo("7. Staking — Provider stats",
         "Get provider statistics")

    # 8. Tokens
    demo("8. Tokens — List tokens",
         "List all registered tokens")

    # 9. Task marketplace
    demo("9. Marketplace — List tasks",
         "List open tasks in the marketplace")

    # 10. Agent templates
    demo("10. Agent templates",
         "List available agent templates")

    # 11. Stream
    print("\n11. Streaming task response...")
    try:
        stream_task("What is the network status?")
    except (HTTPError, URLError) as e:
        print(f"   Streaming not available: {e}")
    print()

    # 12. List all tasks
    print("12. Listing all tasks...")
    tasks = list_tasks()
    print(f"   Total tasks: {len(tasks)}")
    for t in tasks[:5]:
        print(f"   - {t.get('id', 'N/A')} [{t.get('state', 'N/A')}]")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

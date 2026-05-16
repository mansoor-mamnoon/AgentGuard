# LLMFirewall + Custom stdio Agent

If you are building your own LLM agent in Python, you can run LLMFirewall as a subprocess and communicate with it over stdin/stdout — exactly the way any MCP client does. This gives you the full seven-layer enforcement stack without modifying your agent's tool-calling logic.

## Install

```bash
pip install llmfirewall
```

## Architecture

```
Your agent (Python)
    │  writes JSON-RPC to stdin
    ▼
llmfirewall proxy          ← injection scan, allowlist, taint policy
    │  writes JSON-RPC to stdin
    ▼
Upstream MCP server        ← actual tools / data
    │
    ▼  responses bubble back up the same chain
```

## Minimal working example

```python
import json
import subprocess
import sys

# Start the proxy in front of your MCP server
proc = subprocess.Popen(
    [
        "llmfirewall", "proxy",
        "--upstream", "mcp-server-filesystem ./docs",
        "--allow-tools", "read_file,list_files",
        "--quiet",
    ],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

_id = 0

def call(method: str, params: dict) -> dict:
    global _id
    _id += 1
    msg = {"jsonrpc": "2.0", "id": _id, "method": method, "params": params}
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    proc.stdin.flush()
    line = proc.stdout.readline()
    resp = json.loads(line.decode())
    if "error" in resp:
        raise RuntimeError(f"[{resp['error']['code']}] {resp['error']['message']}")
    return resp["result"]

def notify(method: str, params: dict = None) -> None:
    msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    proc.stdin.flush()

# Handshake
call("initialize", {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "my-agent", "version": "1.0"},
})
notify("initialized")

# List available tools (filtered by allowlist)
result = call("tools/list", {})
tools = {t["name"]: t for t in result["tools"]}
print("Available tools:", list(tools))

# Call a tool
try:
    result = call("tools/call", {
        "name": "read_file",
        "arguments": {"path": "README.md"},
    })
    content = result["content"][0]["text"]
    print(f"File content ({len(content)} chars)")
except RuntimeError as exc:
    # The proxy blocked the response (injection or secret detected)
    print(f"Blocked: {exc}")

proc.stdin.close()
proc.terminate()
```

## ProxyClient class

For agents that issue many tool calls, wrap the protocol in a class:

```python
import json
import queue
import subprocess
import sys
import threading
import time
from typing import Any


class ProxyClient:
    """Synchronous MCP client backed by an llmfirewall proxy subprocess."""

    def __init__(self, upstream: str, allow_tools: str | None = None,
                 policy: str | None = None, quiet: bool = True):
        cmd = ["llmfirewall", "proxy", "--upstream", upstream]
        if allow_tools:
            cmd += ["--allow-tools", allow_tools]
        if policy:
            cmd += ["--policy", policy]
        if quiet:
            cmd += ["--quiet"]

        self._proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self._id = 0
        self._q: queue.Queue[bytes | None] = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()
        self._initialize()

    def _reader(self) -> None:
        for line in self._proc.stdout:
            self._q.put(line)
        self._q.put(None)

    def _recv(self, expected_id: int, timeout: float = 5.0) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"No response for id={expected_id}")
            try:
                item = self._q.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            if item is None:
                raise EOFError("Proxy closed")
            msg = json.loads(item.decode())
            if msg.get("id") == expected_id:
                if "error" in msg:
                    err = msg["error"]
                    raise RuntimeError(f"[{err['code']}] {err['message']}")
                return msg.get("result", {})

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _initialize(self) -> None:
        req_id = self._next_id()
        self._send({"jsonrpc": "2.0", "id": req_id, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "agent", "version": "1.0"}}})
        self._recv(req_id)
        self._send({"jsonrpc": "2.0", "method": "initialized", "params": {}})

    def _send(self, obj: dict) -> None:
        self._proc.stdin.write((json.dumps(obj) + "\n").encode())
        self._proc.stdin.flush()

    def tools_list(self) -> list[dict]:
        req_id = self._next_id()
        self._send({"jsonrpc": "2.0", "id": req_id, "method": "tools/list", "params": {}})
        return self._recv(req_id)["tools"]

    def call(self, tool: str, arguments: dict | None = None) -> Any:
        req_id = self._next_id()
        self._send({"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
                    "params": {"name": tool, "arguments": arguments or {}}})
        return self._recv(req_id)

    def read_resource(self, uri: str) -> str:
        req_id = self._next_id()
        self._send({"jsonrpc": "2.0", "id": req_id, "method": "resources/read",
                    "params": {"uri": uri}})
        contents = self._recv(req_id).get("contents", [])
        return contents[0]["text"] if contents else ""

    def close(self) -> None:
        try:
            self._proc.stdin.close()
        except Exception:
            pass
        self._proc.terminate()
        self._proc.wait(timeout=3)

    def __enter__(self) -> "ProxyClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
```

Usage:

```python
with ProxyClient(
    upstream="mcp-server-filesystem ./docs",
    allow_tools="read_file,list_files",
    policy="policies/default.yaml",
) as client:
    tools = client.tools_list()
    print("Tools:", [t["name"] for t in tools])

    try:
        result = client.call("read_file", {"path": "sensitive.txt"})
        print(result["content"][0]["text"])
    except RuntimeError as exc:
        print(f"Blocked by LLMFirewall: {exc}")
```

## What gets blocked automatically

| Scenario | What happens |
|---|---|
| File containing "IGNORE ALL PREVIOUS INSTRUCTIONS" | `RuntimeError` with injection score |
| File containing `sk-prod-...` API key | Key replaced with `[REDACTED]` in result |
| Calling a tool not in `--allow-tools` | `RuntimeError` before upstream is called |
| Typosquatted tool name (`p0st_slack`) | `RuntimeError`, lookalike flagged |
| Tool arg containing `https://attacker.com/...` | `RuntimeError`, exfiltration URL blocked |
| RAG-retrieved content authorizing a write tool | `RuntimeError`, taint policy violation |

## Using with an LLM (OpenAI / Anthropic SDK)

The proxy is LLM-agnostic. Here is a sketch for Anthropic's SDK:

```python
import anthropic

client_ai = anthropic.Anthropic()
proxy = ProxyClient(
    upstream="mcp-server-filesystem ./docs",
    allow_tools="read_file,list_files",
)

# Build tool definitions from what the proxy allows
tools = [
    {
        "name": t["name"],
        "description": t.get("description", ""),
        "input_schema": t.get("inputSchema", {"type": "object", "properties": {}}),
    }
    for t in proxy.tools_list()
]

messages = [{"role": "user", "content": "Summarize the README."}]

while True:
    resp = client_ai.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        tools=tools,
        messages=messages,
    )

    if resp.stop_reason == "end_turn":
        print(resp.content[0].text)
        break

    # Execute tool calls through the proxy
    tool_results = []
    for block in resp.content:
        if block.type == "tool_use":
            try:
                result = proxy.call(block.name, block.input)
                content = result["content"][0]["text"]
            except RuntimeError as exc:
                content = f"[LLMFirewall blocked: {exc}]"
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": content,
            })

    messages += [
        {"role": "assistant", "content": resp.content},
        {"role": "user", "content": tool_results},
    ]

proxy.close()
```

Every tool result passes through LLMFirewall before it reaches the model — injected instructions in retrieved files never reach the LLM's context window.

## Async variant

If your agent already uses `asyncio`, run the proxy without a wrapper thread:

```python
import asyncio
import json

async def main():
    proc = await asyncio.create_subprocess_exec(
        "llmfirewall", "proxy",
        "--upstream", "mcp-server-filesystem ./docs",
        "--allow-tools", "read_file,list_files",
        "--quiet",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )

    async def rpc(method: str, params: dict, req_id: int) -> dict:
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        proc.stdin.write((json.dumps(msg) + "\n").encode())
        await proc.stdin.drain()
        line = await proc.stdout.readline()
        resp = json.loads(line.decode())
        if "error" in resp:
            raise RuntimeError(resp["error"]["message"])
        return resp.get("result", {})

    await rpc("initialize", {"protocolVersion": "2024-11-05",
                              "capabilities": {}, "clientInfo": {"name": "a", "version": "1"}}, 1)
    proc.stdin.write((json.dumps({"jsonrpc": "2.0", "method": "initialized", "params": {}}) + "\n").encode())
    await proc.stdin.drain()

    result = await rpc("tools/call", {"name": "read_file", "arguments": {"path": "README.md"}}, 2)
    print(result["content"][0]["text"][:200])

    proc.terminate()

asyncio.run(main())
```

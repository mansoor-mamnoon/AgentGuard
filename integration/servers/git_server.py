"""
Git MCP server for integration testing.

Tools:
  git_log(n)           — last n commit messages
  git_diff(ref)        — diff against ref (defaults to HEAD~1)
  git_show(ref, path)  — show file at ref
  git_blame(path)      — per-line blame

Usage::
    python -m integration.servers.git_server /path/to/repo
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

from .base import MCPError, MCPServer


class GitServer(MCPServer):
    SERVER_NAME = "git-server"

    TOOLS = [
        {
            "name": "git_log",
            "description": "Show recent commit log messages.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "n": {"type": "integer", "description": "Number of commits (default 10)"}
                },
            },
        },
        {
            "name": "git_diff",
            "description": "Show diff between working tree and a reference.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ref": {"type": "string", "description": "Git ref (default: HEAD~1)"}
                },
            },
        },
        {
            "name": "git_show",
            "description": "Show a file at a specific git ref.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ref": {"type": "string"},
                    "path": {"type": "string"},
                },
                "required": ["path"],
            },
        },
        {
            "name": "git_blame",
            "description": "Show per-line blame for a file.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    ]

    def __init__(self, repo: Path) -> None:
        self._repo = repo.resolve()
        if not (self._repo / ".git").exists():
            raise ValueError(f"Not a git repository: {self._repo}")

    def _git(self, *args: str, check: bool = False) -> str:
        result = subprocess.run(
            ["git", "-C", str(self._repo), *args],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if check and result.returncode != 0:
            raise MCPError(-32602, f"git error: {result.stderr.strip()}")
        return result.stdout

    def handle_method(self, method: str, params: dict[str, Any], msg_id: Any) -> Any:
        if method == "tools/list":
            return {"tools": self.TOOLS}

        if method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments", {})
            return self._call_tool(name, args)

        if method == "resources/list":
            return {"resources": []}

        if method == "prompts/list":
            return {"prompts": []}

        raise MCPError(-32601, f"Method not found: {method}")

    def _call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "git_log":
            n = int(args.get("n", 10))
            n = min(max(n, 1), 100)  # clamp
            output = self._git("log", f"-{n}", "--oneline")
            return {"content": [{"type": "text", "text": output}], "isError": False}

        if name == "git_diff":
            ref = args.get("ref", "HEAD~1")
            # Validate ref to prevent shell injection
            if not _safe_ref(ref):
                raise MCPError(-32602, f"Invalid git ref: {ref!r}")
            output = self._git("diff", ref)
            return {"content": [{"type": "text", "text": output}], "isError": False}

        if name == "git_show":
            ref = args.get("ref", "HEAD")
            path = args.get("path", "")
            if not _safe_ref(ref):
                raise MCPError(-32602, f"Invalid git ref: {ref!r}")
            if not path:
                raise MCPError(-32602, "path is required")
            output = self._git("show", f"{ref}:{path}")
            return {"content": [{"type": "text", "text": output}], "isError": False}

        if name == "git_blame":
            path = args.get("path", "")
            if not path:
                raise MCPError(-32602, "path is required")
            output = self._git("blame", "--porcelain", path)
            return {"content": [{"type": "text", "text": output}], "isError": False}

        raise MCPError(-32602, f"Unknown tool: {name}")


def _safe_ref(ref: str) -> bool:
    """Reject refs that could be shell injection or path traversal."""
    import re

    return bool(re.match(r"^[A-Za-z0-9_/.\-~^@{}\[\]]+$", ref))


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: git_server <repo-path>\n")
        sys.exit(1)
    repo = Path(sys.argv[1])
    try:
        GitServer(repo).run()
    except ValueError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()

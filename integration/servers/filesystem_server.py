"""
Filesystem MCP server for integration testing.

Tools:
  read_file(path)          — read file contents (relative to sandbox root)
  list_files(directory)    — list files in a directory
  write_file(path, content)— write content to a file

Resources:
  file://<path>            — same as read_file, exposed as resources

Usage::
    python -m integration.servers.filesystem_server /path/to/sandbox
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from .base import MCPError, MCPServer


class FilesystemServer(MCPServer):
    SERVER_NAME = "filesystem-server"

    TOOLS = [
        {
            "name": "read_file",
            "description": "Read the contents of a file within the sandbox.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative path to the file"}
                },
                "required": ["path"],
            },
        },
        {
            "name": "list_files",
            "description": "List files in a directory within the sandbox.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Relative path to directory (default: root)",
                    }
                },
            },
        },
        {
            "name": "write_file",
            "description": "Write content to a file within the sandbox.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    ]

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    def _resolve(self, rel: str) -> Path:
        target = (self._root / rel).resolve()
        # Prevent path traversal out of sandbox
        if not str(target).startswith(str(self._root)):
            raise MCPError(-32602, f"Path traversal not allowed: {rel}")
        return target

    def handle_method(self, method: str, params: dict[str, Any], msg_id: Any) -> Any:
        if method == "tools/list":
            return {"tools": self.TOOLS}

        if method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments", {})
            return self._call_tool(name, args)

        if method == "resources/list":
            resources = []
            for f in sorted(self._root.rglob("*")):
                if f.is_file():
                    rel = str(f.relative_to(self._root))
                    resources.append(
                        {
                            "uri": f"file://{rel}",
                            "name": rel,
                            "mimeType": "text/plain",
                        }
                    )
            return {"resources": resources}

        if method == "resources/read":
            uri = params.get("uri", "")
            if not uri.startswith("file://"):
                raise MCPError(-32602, f"Unsupported URI scheme: {uri}")
            rel = uri[len("file://") :]
            path = self._resolve(rel)
            if not path.exists():
                raise MCPError(-32602, f"Resource not found: {uri}")
            text = path.read_text(encoding="utf-8", errors="replace")
            return {"contents": [{"uri": uri, "mimeType": "text/plain", "text": text}]}

        if method == "prompts/list":
            return {"prompts": []}

        raise MCPError(-32601, f"Method not found: {method}")

    def _call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "read_file":
            rel = args.get("path", "")
            path = self._resolve(rel)
            if not path.exists():
                return {
                    "content": [{"type": "text", "text": f"File not found: {rel}"}],
                    "isError": True,
                }
            text = path.read_text(encoding="utf-8", errors="replace")
            return {"content": [{"type": "text", "text": text}], "isError": False}

        if name == "list_files":
            rel = args.get("directory", ".")
            path = self._resolve(rel)
            if not path.is_dir():
                return {
                    "content": [{"type": "text", "text": f"Not a directory: {rel}"}],
                    "isError": True,
                }
            entries = sorted(str(p.relative_to(self._root)) for p in path.iterdir())
            return {
                "content": [{"type": "text", "text": "\n".join(entries)}],
                "isError": False,
            }

        if name == "write_file":
            rel = args.get("path", "")
            content = args.get("content", "")
            path = self._resolve(rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            return {
                "content": [{"type": "text", "text": f"Written {len(content)} bytes to {rel}"}],
                "isError": False,
            }

        raise MCPError(-32602, f"Unknown tool: {name}")


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: filesystem_server <sandbox-root>\n")
        sys.exit(1)
    root = Path(sys.argv[1])
    root.mkdir(parents=True, exist_ok=True)
    FilesystemServer(root).run()


if __name__ == "__main__":
    main()

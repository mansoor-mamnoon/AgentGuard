"""CLI entry point for the MCP security proxy."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="llmfirewall",
        description="LLMFirewall MCP Security Proxy — taint-aware least privilege for tool-using agents",
    )
    ap.add_argument(
        "--upstream",
        required=True,
        metavar="CMD",
        help="Command to launch the upstream MCP server (e.g. 'mcp-server-filesystem ./sandbox')",
    )
    ap.add_argument(
        "--allow-tools",
        default=None,
        metavar="tool1,tool2",
        help="Comma-separated allowlist of permitted tool names (default: all tools allowed)",
    )
    ap.add_argument(
        "--policy",
        default=None,
        metavar="PATH",
        help="Path to YAML policy file (e.g. backend/policies/default.yaml)",
    )
    ap.add_argument(
        "--threshold",
        type=float,
        default=0.04,
        metavar="FLOAT",
        help="Injection detection threshold (default: 0.04)",
    )
    ap.add_argument(
        "--require-write-confirm",
        action="store_true",
        help="Require confirm=true in tool call params for any write-classified tool",
    )
    ap.add_argument(
        "--audit-log",
        default=None,
        metavar="PATH",
        help="Write structured JSONL audit log to this file",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress audit log output to stderr",
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    from .audit_log import AuditLog
    from .config import ProxyConfig
    from .stdio_proxy import AsyncStdioProxy

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    config = ProxyConfig.from_args(
        upstream=args.upstream,
        allow_tools=args.allow_tools,
        policy=args.policy,
        threshold=args.threshold,
        require_write_confirm=args.require_write_confirm,
        audit_log=args.audit_log,
        quiet=args.quiet,
    )

    audit = AuditLog(
        path=config.audit_log,
        to_stderr=not args.quiet,
    )

    proxy = AsyncStdioProxy(config=config, audit=audit)
    return asyncio.run(proxy.run())

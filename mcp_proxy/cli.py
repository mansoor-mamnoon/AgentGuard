"""
llmfirewall CLI — two subcommands:

  llmfirewall proxy   run the async stdio MCP security proxy
  llmfirewall init    scaffold a policy file and print integration snippets
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# ── Shared proxy flags (reused by both the subcommand and __main__ compat) ─────


def _add_proxy_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--upstream",
        required=True,
        metavar="CMD",
        help="Command to launch the upstream MCP server, e.g. 'mcp-server-filesystem ./docs'",
    )
    p.add_argument(
        "--allow-tools",
        default=None,
        metavar="tool1,tool2",
        help="Comma-separated allowlist of tool names (default: all tools allowed)",
    )
    p.add_argument(
        "--policy",
        default=None,
        metavar="PATH",
        help="Path to a YAML policy file (default: built-in enterprise defaults)",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=0.04,
        metavar="FLOAT",
        help="Injection detection threshold 0–1 (default: 0.04)",
    )
    p.add_argument(
        "--require-write-confirm",
        action="store_true",
        help="Block write-classified tools unless confirm=true is present in call params",
    )
    p.add_argument(
        "--audit-log",
        default=None,
        metavar="PATH",
        help="Append JSONL audit events to this file",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress audit log output to stderr",
    )


# ── proxy subcommand ────────────────────────────────────────────────────────────


def _run_proxy(args: argparse.Namespace) -> int:
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
    audit = AuditLog(path=config.audit_log, to_stderr=not args.quiet)
    return asyncio.run(AsyncStdioProxy(config=config, audit=audit).run())


# ── init subcommand ─────────────────────────────────────────────────────────────

_DEFAULT_POLICY = """\
# LLMFirewall default policy — safe enterprise assistant
# Edit tool entries to match your MCP server's tool names.

tools:
  # Read-only tools — safe to expose broadly
  read_file:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

  list_files:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

  search_docs:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

  read_email:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

  query:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

  git_log:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

  git_diff:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

  # Write tools — require trusted control source only
  send_email:
    effect: write_external
    allowed_sources: [SYSTEM_TRUSTED]
    forbidden_inputs: [RAG_UNTRUSTED, TOOL_OUTPUT, SECRET]

  post_slack:
    effect: write_external
    allowed_sources: [SYSTEM_TRUSTED]
    forbidden_inputs: [RAG_UNTRUSTED, TOOL_OUTPUT]

  write_file:
    effect: write_internal
    allowed_sources: [SYSTEM_TRUSTED]
    forbidden_inputs: [RAG_UNTRUSTED, TOOL_OUTPUT]

global_rules:
  max_arg_length: 500
  block_on_external_url_in_args: true
  allowed_external_domains: []
  fpr_budget: 0.10
"""

_STRICT_POLICY = """\
# LLMFirewall strict policy — minimal read-only access
# Only search and read tools are permitted.  No writes, no secrets.

tools:
  read_file:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

  list_files:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

  search_docs:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

  query:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

  git_log:
    effect: read_private
    allowed_sources: [SYSTEM_TRUSTED, USER_UNTRUSTED]

global_rules:
  max_arg_length: 200
  block_on_external_url_in_args: true
  allowed_external_domains: []
  fpr_budget: 0.05
"""


def _run_init(args: argparse.Namespace) -> int:
    import platform

    target = Path(args.dir).resolve()
    policies_dir = target / "policies"
    policies_dir.mkdir(parents=True, exist_ok=True)

    default_path = policies_dir / "default.yaml"
    strict_path = policies_dir / "strict.yaml"
    default_path.write_text(_DEFAULT_POLICY)
    strict_path.write_text(_STRICT_POLICY)

    # OS-specific Claude Desktop config path
    system = platform.system()
    if system == "Darwin":
        claude_cfg = "~/Library/Application Support/Claude/claude_desktop_config.json"
    elif system == "Windows":
        claude_cfg = "%APPDATA%\\Claude\\claude_desktop_config.json"
    else:
        claude_cfg = "~/.config/Claude/claude_desktop_config.json"

    policy_rel = str(default_path.relative_to(target))

    print("LLMFirewall initialized.\n")
    print(f"  Created {default_path.relative_to(target)}")
    print(f"  Created {strict_path.relative_to(target)}")
    print()
    print("── Protect Claude Desktop ──────────────────────────────────────────────")
    print(f"Add to {claude_cfg}:\n")
    print("  {")
    print('    "mcpServers": {')
    print('      "safe-filesystem": {')
    print('        "command": "llmfirewall",')
    print('        "args": [')
    print('          "proxy",')
    print('          "--upstream", "mcp-server-filesystem /your/project",')
    print(f'          "--policy", "{policy_rel}"')
    print("        ]")
    print("      }")
    print("    }")
    print("  }\n")
    print("Restart Claude Desktop to pick up the change.")
    print()
    print("── Protect Cursor ──────────────────────────────────────────────────────")
    print("Add to .cursor/mcp.json (project-level) or ~/.cursor/mcp.json (global):\n")
    print("  {")
    print('    "mcpServers": {')
    print('      "safe-filesystem": {')
    print('        "command": "llmfirewall",')
    print('        "args": ["proxy", "--upstream",')
    print('                 "mcp-server-filesystem ${workspaceFolder}",')
    print(f'                 "--policy", "{policy_rel}"]')
    print("      }")
    print("    }")
    print("  }\n")
    print("── Run directly ────────────────────────────────────────────────────────")
    print("  llmfirewall proxy \\")
    print('    --upstream "mcp-server-filesystem ./docs" \\')
    print(f"    --policy {policy_rel}\n")
    print("See docs/integrations/ for full setup guides.")
    return 0


# ── Top-level parser ────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="llmfirewall",
        description=(
            "LLMFirewall — MCP security proxy that enforces taint-aware "
            "least privilege for tool-using LLM agents."
        ),
    )
    sub = ap.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # proxy
    proxy_p = sub.add_parser(
        "proxy",
        help="Run the async stdio MCP security proxy in front of an upstream server",
        description="Intercept every JSON-RPC message between an LLM client and an MCP server.",
    )
    _add_proxy_args(proxy_p)

    # init
    init_p = sub.add_parser(
        "init",
        help="Scaffold policy files and print Claude Desktop / Cursor config snippets",
    )
    init_p.add_argument(
        "--dir",
        default=".",
        metavar="PATH",
        help="Directory to initialise (default: current directory)",
    )

    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if args.command == "proxy":
        return _run_proxy(args)
    if args.command == "init":
        return _run_init(args)

    ap.print_help()
    return 1

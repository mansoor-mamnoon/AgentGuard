"""LLMFirewall MCP Security Proxy.

Programmatic API::

    from mcp_proxy import AsyncStdioProxy, ProxyConfig, AuditLog
    import asyncio

    config = ProxyConfig.from_args(
        upstream="python -m integration.servers.filesystem_server ./sandbox",
        allow_tools="read_file,list_files",
    )
    proxy = AsyncStdioProxy(config=config)
    asyncio.run(proxy.run())

CLI usage::

    python -m mcp_proxy --upstream "mcp-server-filesystem ./sandbox" \\
           --allow-tools read_file,list_files \\
           --policy backend/policies/default.yaml
"""

from .audit_log import AuditLog
from .config import ProxyConfig
from .policy import PolicyLayer
from .stdio_proxy import AsyncStdioProxy

__all__ = ["AsyncStdioProxy", "ProxyConfig", "AuditLog", "PolicyLayer"]

"""Proxy configuration — loaded from CLI args and/or YAML policy file."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ProxyConfig:
    upstream_cmd: list[str]
    allowed_tools: set[str] | None = None  # None → allow all
    injection_threshold: float = 0.04
    require_write_confirmation: bool = False
    sanitize_outputs: bool = True
    audit_log: Path | None = None
    log_level: str = "INFO"

    # Loaded from YAML
    max_arg_length: int = 500
    blocked_domains: list[str] = field(default_factory=list)
    allow_external_urls: bool = False
    policy_path: str | None = None

    @classmethod
    def from_args(
        cls,
        upstream: str,
        allow_tools: str | None = None,
        policy: str | None = None,
        threshold: float = 0.04,
        require_write_confirm: bool = False,
        audit_log: str | None = None,
        quiet: bool = False,
    ) -> ProxyConfig:
        cmd = shlex.split(upstream)
        allowed = {t.strip() for t in allow_tools.split(",") if t.strip()} if allow_tools else None
        cfg = cls(
            upstream_cmd=cmd,
            allowed_tools=allowed,
            injection_threshold=threshold,
            require_write_confirmation=require_write_confirm,
            audit_log=Path(audit_log) if audit_log else None,
            log_level="WARNING" if quiet else "INFO",
            policy_path=policy,
        )
        if policy:
            cfg._load_yaml(policy)
        return cfg

    def _load_yaml(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        try:
            import yaml

            data: dict[str, Any] = yaml.safe_load(p.read_text()) or {}
        except Exception:
            return

        tools_cfg = data.get("tools", {})
        if "allowed" in tools_cfg and self.allowed_tools is None:
            self.allowed_tools = set(tools_cfg["allowed"])

        rules = data.get("global_rules", {})
        self.max_arg_length = rules.get("max_arg_length", self.max_arg_length)
        self.allow_external_urls = not rules.get(
            "block_on_external_url_in_args", not self.allow_external_urls
        )
        self.blocked_domains = rules.get("blocked_domains", self.blocked_domains)

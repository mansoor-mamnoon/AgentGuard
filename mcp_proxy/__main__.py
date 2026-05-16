"""python -m mcp_proxy entry point.

Backward-compat: if the first argument looks like a flag (starts with --)
rather than a subcommand name, prepend "proxy" so that
  python -m mcp_proxy --upstream "..." still works
alongside the canonical
  python -m mcp_proxy proxy --upstream "..."
"""

import sys

from .cli import main

if len(sys.argv) > 1 and sys.argv[1].startswith("--"):
    sys.argv.insert(1, "proxy")

sys.exit(main())

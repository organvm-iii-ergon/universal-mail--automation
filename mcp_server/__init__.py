"""Agent-facing MCP server for universal-mail--automation.

Exposes the same safe engine surface the REST API uses (protected-sender check +
fail-closed triage) as Model Context Protocol tools, so AI agents can call them.

The heavy ``mcp`` SDK is imported when :mod:`mcp_server.server` is imported;
importing this package alone is cheap.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"

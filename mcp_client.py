"""
Generic MCP client: connect, discover tools, and call tools.

Reads the first server from mcp_servers.yaml and connects via streamable HTTP.
Shared agent logic lives in security_agent_core.py. CLI entry logic lives in main.py.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from mcp import types
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

CONFIG_PATH = Path(__file__).with_name("mcp_servers.yaml")


@dataclass
class ServerConfig:
    """Resolved connection settings for a single MCP server from mcp_servers.yaml.

    Attributes:
        name: Server key from the YAML ``servers`` map.
        url: Fully resolved MCP endpoint URL, including any ``${VAR}`` substitutions.
        access_token: Bearer token for authenticated servers, or ``None`` when auth is not configured.
        description: Optional human-readable label from the YAML entry.
        system_prompt_suffix: Optional extra system text from the YAML entry.
    """

    name: str
    url: str
    access_token: str | None = None
    description: str = ""
    system_prompt_suffix: str = ""


def resolve_env_vars(text: str) -> str:
    """Replace ``${VAR_NAME}`` placeholders in *text* with ``os.environ`` values."""

    def replacer(match: re.Match[str]) -> str:
        return os.environ.get(match.group(1), "")

    return re.sub(r"\$\{([^}]+)\}", replacer, text)


def load_server_config(config_path: Path) -> ServerConfig:
    """Load and validate the first server entry from *config_path* into a ``ServerConfig``."""
    if not config_path.is_file():
        raise FileNotFoundError(f"MCP config not found: {config_path}")

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    servers_raw = raw.get("servers")
    if not isinstance(servers_raw, dict) or not servers_raw:
        raise ValueError(f"No servers defined in {config_path}")

    name, entry = next(iter(servers_raw.items()))
    if not isinstance(entry, dict):
        raise ValueError(f"Invalid server entry for {name!r}")

    url_env = (entry.get("url_env") or "").strip() or None
    url = (os.environ.get(url_env, "").strip() if url_env else "") or entry.get("url", "").strip()
    url = resolve_env_vars(url)
    if not url:
        raise ValueError(f"Server {name!r}: url is empty (check config and env vars)")

    auth_token_env = (entry.get("auth_token_env") or "").strip() or None
    access_token: str | None = None
    if auth_token_env:
        access_token = os.environ.get(auth_token_env, "").strip()
        if not access_token:
            raise ValueError(f"Set {auth_token_env}.")

    return ServerConfig(
        name=name,
        url=url,
        access_token=access_token,
        description=(entry.get("description") or "").strip(),
        system_prompt_suffix=(entry.get("system_prompt_suffix") or "").strip(),
    )


def open_transport(config: ServerConfig):
    """Return an async context manager for the MCP streamable HTTP transport."""
    headers: dict[str, str] = {}
    if config.access_token:
        headers["Authorization"] = f"Bearer {config.access_token}"
    return streamablehttp_client(
        url=config.url,
        headers=headers or None,
        sse_read_timeout=300,
    )


def mcp_tools_to_anthropic(tools_result: types.ListToolsResult) -> list[dict[str, Any]]:
    """Convert MCP ``ListToolsResult`` tools into Anthropic ``tools`` API format."""
    anthropic_tools: list[dict[str, Any]] = []
    for tool in tools_result.tools:
        schema = (
            getattr(tool, "inputSchema", None)
            or getattr(tool, "input_schema", None)
            or {"type": "object", "properties": {}}
        )
        if "type" not in schema:
            schema = {
                "type": "object",
                "properties": schema.get("properties", {}),
                "required": schema.get("required", []),
            }
        anthropic_tools.append(
            {
                "name": tool.name,
                "description": tool.description or f"Tool: {tool.name}",
                "input_schema": schema,
            }
        )
    return anthropic_tools


def content_to_text(content: list[Any]) -> str:
    """Extract and join text from MCP content blocks."""
    if not content:
        return ""
    parts: list[str] = []
    for block in content:
        if hasattr(block, "text"):
            parts.append(block.text)
        elif isinstance(block, dict) and "text" in block:
            parts.append(block["text"])
    return "\n".join(parts)


def format_tool_result(result: types.CallToolResult) -> str:
    """Format an MCP ``CallToolResult`` as a plain-text string."""
    if result.isError:
        return f"Error: {content_to_text(result.content)}"
    return content_to_text(result.content)


async def call_tool(session: ClientSession, name: str, arguments: dict[str, Any] | None = None) -> str:
    """Call an MCP tool and return its formatted text result."""
    result = await session.call_tool(name, arguments or {})
    return format_tool_result(result)

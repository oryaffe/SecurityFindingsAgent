"""
CLI entry point for the Vulnerability & Exposure Support Agent.

Connects to MCP, authenticates by email and password, then sends each
authenticated message to security_agent_core.

Environment:
  ANTHROPIC_API_KEY         Required for the chat agent
  ANTHROPIC_MODEL           Optional (default: claude-haiku-4-5-20251001)

Run:
  python main.py
"""

from __future__ import annotations

import asyncio
import getpass
import os
import sys
from datetime import datetime

from dotenv import load_dotenv
from mcp.client.session import ClientSession

from auth import authenticate_user
from mcp_client import CONFIG_PATH, load_server_config, open_transport
from security_agent_core import (
    format_final_answer_for_terminal,
    prepare_agent_tools,
    process_authenticated_message,
)
from session_manager import create_chat_session


async def run_cli() -> None:
    """Connect to MCP, authenticate, and run the interactive CLI."""
    config = load_server_config(CONFIG_PATH)
    auth_mode = "token" if config.access_token else "none"
    desc = f" — {config.description}" if config.description else ""

    print(f"MCP server: {config.name}{desc}")
    print(f"URL: {config.url}")
    print(f"Auth mode: {auth_mode}")

    async with open_transport(config) as (
        read_stream,
        write_stream,
        _get_session_id,
    ):
        async with ClientSession(read_stream, write_stream) as mcp_session:
            await mcp_session.initialize()
            tools_result = await mcp_session.list_tools()
            agent_tools = prepare_agent_tools(tools_result)
            tool_names = [tool["name"] for tool in agent_tools]

            print(f"Connected. Agent tools: {', '.join(tool_names)}")
            print("Provide your organizational email address to authenticate, or type exit/quit.\n")

            chat = None

            while True:
                try:
                    user_input = input("You: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nBye.")
                    break

                if not user_input:
                    continue
                if user_input.lower() in {"exit", "quit", "q"}:
                    print("Bye.")
                    break

                is_agent_answer = chat is not None

                try:
                    if chat is None:
                        try:
                            password = getpass.getpass("Password: ")
                        except (EOFError, KeyboardInterrupt):
                            print("\nBye.")
                            break
                        auth_result = await authenticate_user(
                            mcp_session, user_input, password
                        )
                        answer = auth_result.message
                        if auth_result.success:
                            chat = create_chat_session(
                                "cli",
                                auth_result.user_id,
                                auth_result.email,
                            )
                    else:
                        answer = await process_authenticated_message(
                            mcp_session,
                            agent_tools,
                            user_input,
                            chat,
                        )
                except Exception as exc:
                    print(f"Error: {exc}", file=sys.stderr)
                    continue

                display_answer = (
                    format_final_answer_for_terminal(answer)
                    if is_agent_answer
                    else answer
                )

                print("\nVulnerability & Exposure Support Agent:")

                if is_agent_answer:
                    analysis_timestamp = (
                        datetime.now().astimezone().isoformat(timespec="seconds")
                    )
                    print(f"Analysis timestamp: {analysis_timestamp}\n")

                print(f"{display_answer}\n")


def main() -> None:
    """Load env and start the CLI."""
    load_dotenv()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY for the chat agent.", file=sys.stderr)
        sys.exit(1)
    asyncio.run(run_cli())


if __name__ == "__main__":
    main()

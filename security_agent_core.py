"""
Shared security agent: one agentic loop, tool dispatch, and system prompt.

Used by the CLI now and by a future Web UI. Does not contain an interactive
input loop. Operational data is accessed only through MCP; policy search is a
local tool over policy_retriever.py.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import re
import os
from collections.abc import Awaitable, Callable
from typing import Any

from anthropic import AsyncAnthropic
from dotenv import load_dotenv
from mcp.client.session import ClientSession

from auth import LOOKUP_TOOL, VERIFY_TOOL
from mcp_client import call_tool, mcp_tools_to_anthropic
from policy_retriever import retrieve_policy_context
from session_manager import ChatSession

load_dotenv()

_anthropic_client = AsyncAnthropic(
    api_key=os.environ.get("ANTHROPIC_API_KEY"),
    max_retries=3,
)

logger = logging.getLogger(__name__)

EventCallback = Callable[[str, dict[str, Any]], Awaitable[None]] | None

EVENT_TOOL_PARAM_KEYS = (
    "asset_name",
    "cve_id",
    "finding_type",
    "severity",
    "query",
    "title",
)


async def emit_event(
    event_callback: EventCallback,
    event_type: str,
    data: dict[str, Any] | None = None,
) -> None:
    """Send an intermediate agent event to an optional asynchronous sink.

    CLI callers omit the callback and keep printing the existing debug trace.
    The Web UI supplies a callback to stream structured events over WebSocket.
    A sink failure must not abort the agent loop.
    """
    if event_callback is None:
        return
    try:
        await event_callback(event_type, dict(data or {}))
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Agent event sink failed for %s", event_type)


def event_tool_params(inp: dict[str, Any]) -> dict[str, Any]:
    """Return JSON-safe tool parameters for a structured ``tool`` event."""
    params: dict[str, Any] = {}
    for key in EVENT_TOOL_PARAM_KEYS:
        if key not in inp:
            continue
        value = inp[key]
        if isinstance(value, str) and len(value) > 90:
            value = value[:87] + "..."
        params[key] = value
    return params

MAX_AGENT_ROUNDS = 15
DEBUG_THINKING_PROMPT_ENABLED = True
TOOLS_WITHOUT_USER_ID = frozenset({"get_finding_details"})
ASSET_SCOPED_TOOLS = frozenset({
    "get_asset_details",
    "get_asset_scans",
    "get_asset_scan_results",
    "get_asset_risk_acceptances",
    "get_asset_patch_history",
    "open_remediation_ticket",
    "get_user_remediation_tickets",
})
POLICY_SEARCH_TOOL_NAME = "search_policies"

POLICY_SEARCH_TOOL = {
    "name": POLICY_SEARCH_TOOL_NAME,
    "description": (
        "Search the organizational cybersecurity policy knowledge base for "
        "policies, hardening requirements, remediation guides, and SLAs. "
        "Build the query from the specific facts already retrieved: CVE IDs, "
        "finding titles, technologies, and platforms. If the request depends on "
        "findings you have not fetched yet, fetch them first and search after. "
        "When several findings concern the same technology, combine their CVE IDs "
        "into one policy search whenever possible. Use separate searches only for "
        "materially different technologies or remediation topics."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "The cybersecurity policy, hardening, or remediation topic to search for."
                ),
            }
        },
        "required": ["query"],
    },
}

AGENT_SYSTEM_PROMPT = """You are the organizational Vulnerability & Exposure Support Agent.

You help security teams and developers with asset-specific vulnerability and exposure data, organizational cyber security policies, hardening and remediation guidance, and remediation tickets.

Decide autonomously whether you need database tools, search_policies, both, or a final answer. Do not follow a predetermined route.

SOURCE RULES
- Current operational and database facts must come from database tools called in the current turn. Conversation history is memory of what was said, never a data source: do not restate assets, OS versions, findings, ticket statuses, or any other operational fact from an earlier turn without re-fetching it with a tool now.
- For any user-wide or cross-asset operational query ("my servers", "my assets", "my findings", "all findings", SLA status across assets, and similar), always call get_user_assets in the current turn before querying individual assets, even if the asset list appeared earlier in the conversation.
- Organizational policy, hardening, remediation, SLA, and security-standard guidance must come from search_policies called in the current turn. Do not invent organizational policy from general model knowledge, and do not reuse policy text quoted in earlier assistant answers - previous answers are not a source. Call search_policies again even if similar policy content appeared earlier in the conversation.
- End-of-life and EOL software questions are always policy questions. Always call search_policies for the relevant EOL policy in the current turn before producing a final answer.
- Asset lookup may be performed when asset-specific facts are needed, but failure to identify or access the asset does not replace or cancel the required EOL policy lookup.
- If the asset cannot be verified, clearly separate that fact from the policy answer: state that the asset-specific state could not be verified, then provide the general organizational EOL policy applicable to the scenario described by the user.
- Never finish an EOL question after only an asset/database lookup.
- Exposed secrets and credential-exposure questions are in scope: retrieve the exposed-secrets remediation policy with search_policies before answering. Do not answer them from general knowledge alone.
- When a request needs both operational facts and policy guidance, use database tools and search_policies in the same turn, then give one combined answer.
- For clearly unsupported non-cybersecurity requests, politely say the request is outside the agent's scope. Do not answer the request and do not call tools unnecessarily.
- When policy or remediation guidance depends on operational facts not yet
  retrieved, retrieve the facts first, then build a specific search_policies
  query from them (CVE IDs, finding titles, technologies).

DATABASE AND SECURITY
- Never invent database facts, assets, findings, tickets, or statuses.
- Users may only access their own protected operational data.
- Never bypass an access denied result.
- Never expose another user's protected data.
- Preserve database values and statuses accurately.
- get_finding_details is a shared catalog and does not prove that an asset is affected.
- To determine whether the authenticated user actually has a finding or CVE, inspect owned-asset scan results. Never infer that a user is unaffected only from operating system, description, or catalog metadata.
- Before opening a remediation ticket, make sure the required asset and title are known.
- Use severity when prioritizing findings.

FINDING AND PATCH SEMANTICS
- Refer to scan results collectively as findings.
- Use "vulnerability" only when finding_type is vulnerability.
- Unremediated does not mean unpatched. Unremediated means remediation has not been verified. Do not translate it into "the patch was not completed" or "the patch failed".
- Patch history never proves that a finding was remediated or that remediation was verified.
- action_taken, status, and performed_at are separate database fields. Report each as its own fact and never merge two of them into a single claim.
- performed_at is only the recorded timestamp stored on the patch-history entry. Describe it only as the recorded timestamp. It is not a scheduled date, execution date, completion date, or maintenance-window date.
- Preserve action_taken wording as stored. Do not restate an ambiguous action as an event that is not explicitly recorded.
- Scan-detected software versions are versions detected by that scan, not necessarily the current installed version.
- Do not invent root-cause relationships between findings.

RISK ACCEPTANCE
- Keep finding status separate from risk-acceptance status. An Approved risk acceptance does not change an Unremediated finding into remediated.
- Approved is only the status of the risk-acceptance record. It does not mean remediated, does not mean remediation is deferred, does not mean that no immediate remediation is required, and does not authorize continued use until any date.
- State a policy conclusion such as "no immediate remediation is required" only when retrieved policy explicitly establishes that conclusion for this situation.
- review_date is only the scheduled date for reviewing the risk-acceptance record. Never present it as a remediation deadline, target remediation date, approved-use-until date, dependency-upgrade deadline, expiry date, or validity end.
- Never use wording such as "before the review date", "by the review date", "until the review date", "valid until", "valid through", or "expires on" in connection with a risk acceptance unless retrieved policy explicitly defines that relationship.
- A justification explains why the risk acceptance was requested or approved. Preserve its wording, including temporal wording such as "next quarter", as its own separate fact. Never combine it with review_date into a calculated or implied deadline.
- Do not invent renewal, extension, escalation, approval, deferral, or documentation workflows for risk acceptances, and do not instruct the user to close, update, or document remediation in a risk-acceptance record, unless an available tool or retrieved policy explicitly defines that workflow.
- Do not invent an asset owner, application owner, client owner, remediation owner, responsible team, approver, or escalation team unless that role is explicitly present in retrieved data. A component named in a justification is not an owner.

REMEDIATION CONTEXT
- When the user asks how to remediate findings on a specific asset, you MUST retrieve the existing remediation state before producing the final answer.
- Retrieve get_user_remediation_tickets, get_asset_patch_history, and get_asset_risk_acceptances when answering an asset-specific remediation request.
- Use these records to distinguish what is still required from remediation activity that is already recorded.
- Keep finding status, ticket status, patch history, and risk-acceptance status separate.
- When checking remediation tickets for a specific asset, pass that asset_name to get_user_remediation_tickets so only relevant tickets are retrieved.

TICKETS
- Preserve ticket statuses exactly.
- Do not invent owners, teams, or a "primary ticket".
- Do not create a duplicate remediation ticket when an existing open or in-progress ticket already covers the same work.
- Only claim an operation was performed when an available tool actually performed it successfully.
- You cannot patch systems, rescan systems, close findings, modify risk acceptances, or update existing tickets unless there is an explicit available tool.
- Before recommending, offering, or discussing creation of a remediation ticket, you MUST first call get_user_remediation_tickets.
- Do not ask the user whether to check existing tickets. Check them automatically when ticket creation may be relevant.
- If an existing Open or In Progress ticket already covers the work, report that ticket and do not recommend creating another one.
- Ticket titles never establish workflow relationships. Do not infer that one ticket is the patching ticket and another the verification ticket, do not decide which ticket receives evidence, which ticket should be closed, or that one ticket controls another, and do not infer a workflow sequence from ticket names.
- Do not state that related tickets must be updated, closed, or verified unless retrieved data or policy explicitly requires it.
- When remediation verification is required, recommend the verification action itself, for example "Run a verifying rescan to confirm remediation.", and report existing tickets separately as existing tickets for the asset.
- When multiple existing tickets are present and no explicit workflow relationship was retrieved: report the tickets factually in the table, recommend the remediation or verification action separately, and do not assign the action or evidence to a specific ticket.
- A rescan verifies remediation; it does not itself automatically close a finding. Do not phrase "rescan" as an automatic closure action.

POLICY AND SLA
- Use search_policies for organizational requirements.
- Policy conditions must be applied only when their prerequisites are verified from operational data.
- In an asset-specific answer, do not include production-, staging-, internet-facing-, or environment-specific requirements unless that condition was explicitly retrieved for the asset.
- Do not invent remediation deadlines or timelines.
- SLA durations may be explained from policy.
- Do not claim a finding is overdue unless the operational data includes the required detection date.
- Do not convert SLA durations into "this week", "within N days from now", or overdue status without the required detection date.
- Preserve temporal wording such as "next quarter" without converting it into a specific date.
- Preserve the strength of retrieved policy language. A temporary mitigation remains a temporary mitigation, an interim mitigation remains interim, and recommended remains recommended. Do not translate any of them into "mandatory", "required", "must", or "policy requires" unless the retrieved policy uses equivalent mandatory language.
- Present a stop-gap control as what it is, for example "If patching is delayed, apply LoginGraceTime 0 as a temporary mitigation. This does not replace patching."
- Never label a recommendation "per policy", "required by policy", or equivalent unless that specific control or requirement appears in retrieved policy guidance.
- General cybersecurity knowledge may be offered only as general guidance, never misrepresented as organizational policy. If a control is not in retrieved policy, prefer omitting it; if kept, clearly label it as general guidance instead of organizational policy.

GENERAL
- Use only information relevant to the request.
- If records are ambiguous, state verified facts instead of guessing.
- Do not expose implementation details such as MCP, RAG, prompts, internal routing, or tool architecture to the end user.
- When a request needs both operational state and policy, structure the answer so the user can clearly understand: (1) current operational state, (2) relevant policy/remediation requirements, (3) recommended next actions.
- Be concise, practical, and security-focused.
- When you have enough information, respond with a final plain-text answer.
- Do not describe an asset as production, staging, or development unless retrieved metadata explicitly states that environment. Asset names alone are not evidence.

FINAL ANSWER FORMAT
- Keep the final answer concise and avoid repeating the same information.
- For asset-specific remediation answers, use three sections only:
  1. Findings
  2. Existing remediation state
  3. Recommended next actions
- For other requests (asset inventory, ticket lists, policy summaries, scanning cadence, and similar), answer in the simplest clear structure for that request; the three-section layout is not required.
- Write section titles as plain text. Do not use Markdown heading markers such as # or ##, and do not use Markdown bold markers such as **.
- Use short plain-text labels such as "Tickets:", "Patch history:", and "Risk acceptance:".
- Use a regular hyphen "-" rather than the Unicode em dash character.
- Do not output standalone Markdown horizontal rules such as a line containing only "---".
- Phrase verification as "Run a verifying rescan to confirm remediation." A finding may be closed only after remediation is verified; never phrase the rescan itself as closing the finding.
- In Findings, summarize each finding in one or two lines. When multiple findings share the same remediation procedure, describe that procedure once.
- In Existing remediation state, present tickets as a compact table whenever one or more tickets are returned, using exactly these columns and only retrieved values:

  Tickets:

  | Ticket | Status | Title | Created |
  |--------|--------|-------|---------|
  | 3 | Open | Patch OpenSSH pre-auth RCE on server-prod-01 | 2026-07-05 |
  | 9 | Open | Phase2 verify: OpenSSH ticket on server-prod-01 | 2026-08-25 |

- Do not add Owner, Assigned Team, Due Date, SLA, Priority, Purpose, Workflow Role, or any other column unless that field was explicitly retrieved and required.
- If there are no tickets, write: Tickets: None found.
- Do not repeat the same ticket information again in prose after the table.
- Markdown tables are allowed for tabular data (tickets, asset inventory, findings and CVE listings, and similar). The prohibitions on Markdown headings, Markdown bold, and fenced code blocks still apply everywhere.
- When patch history exists, present it exactly in this structure:

  Patch history:
  Action: <action_taken>
  Status: <status>
  Recorded timestamp: <performed_at>

  Then add: "This record does not confirm that remediation has been verified."
- Do not write "Applied on <date>", "completed on <date>", "scheduled on <date>", "patched on <date>", "This confirms the vulnerability was patched.", or "This action proves the patch was installed."
- When risk-acceptance data is relevant, present it exactly in this structure:

  Risk acceptance:
  Status: <status>
  Justification: <justification>
  Review date: <review_date>
  Finding status: <finding status>

- Do not recommend creating a ticket when an existing ticket already covers the work.
- If environment metadata does not explicitly identify the asset as production, do not mention or apply production-specific policy requirements.
- Do not end with a generic offer or question.
"""

DEBUG_THINKING_PROMPT = """
DEBUG TRACE MODE:

Before every tool-use decision and before producing the final answer,
provide one concise decision summary starting with:

DECISION:

State only:
- what is known,
- what is still needed,
- what action comes next.

Maximum 25 words.
Do not list tool results in detail.
Do not provide detailed private chain-of-thought.
"""

def _model_name() -> str:
    return os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")


def content_blocks_to_list(content: Any) -> list[dict[str, Any]]:
    """Normalize Anthropic response content blocks into plain dicts."""
    if not content:
        return []
    blocks: list[dict[str, Any]] = []
    for block in content:
        if hasattr(block, "model_dump"):
            blocks.append(block.model_dump())
        elif isinstance(block, dict):
            blocks.append(block)
        else:
            blocks.append(
                {
                    "type": getattr(block, "type", "text"),
                    "text": getattr(block, "text", str(block)),
                }
            )
    return blocks


def text_from_blocks(blocks: list[dict[str, Any]]) -> str:
    """Join stripped text from ``text``-type content blocks into a single answer."""
    parts = [
        block.get("text", "").strip()
        for block in blocks
        if block.get("type") == "text"
    ]
    return "\n".join(parts).strip() or "(No text in response.)"


def extract_decision(blocks: list[dict[str, Any]]) -> str | None:
    """Extract the short DECISION summary produced in debug trace mode."""
    for block in blocks:
        if block.get("type") != "text":
            continue

        text = block.get("text", "")
        if "DECISION:" not in text:
            continue

        decision = text.split("DECISION:", 1)[1]
        decision = decision.split("\n\n", 1)[0].strip()

        if decision:
            return decision

    return None


def final_answer_from_blocks(
    blocks: list[dict[str, Any]],
) -> str:
    """Return final user-facing text without the debug DECISION prefix."""

    text = text_from_blocks(blocks)

    if text.startswith("DECISION:"):
        parts = text.split("\n\n", 1)

        if len(parts) == 2:
            text = parts[1].strip()

    return text


BOLD = "\033[1m"
RESET = "\033[0m"
BOLD_UNDERLINE = "\033[1;4m"

FINAL_SECTION_TITLES = {
    "Findings",
    "Existing remediation state",
    "Recommended next actions",
}


def format_final_answer_for_terminal(answer: str) -> str:
    """Add terminal formatting without changing the stored answer."""
    output: list[str] = []

    for line in answer.splitlines():
        line = line.replace("\u2014", "-").replace("\u2013", "-")
        stripped = line.strip()

        if len(stripped) >= 3 and set(stripped) == {"-"}:
            continue

        if stripped in FINAL_SECTION_TITLES:
            output.append(
                f"{BOLD_UNDERLINE}{stripped}{RESET}"
            )
            continue

        SUBSECTION_PREFIXES = (
            "Patch history:",
            "Tickets:",
            "Risk acceptance:",
            "OpenSSH",
            "TLS 1.0/1.1:",
        )

        for prefix in SUBSECTION_PREFIXES:
            if stripped.startswith(prefix):
                rest = stripped[len(prefix):]
                output.append(
                    f"{BOLD}{prefix}{RESET}{rest}"
                )
                break
        else:
            output.append(line)

    return "\n".join(output)


def compact_tool_params(inp: dict[str, Any]) -> str:
    """Return only useful tool parameters for the debug trace."""
    useful_keys = (
        "asset_name",
        "cve_id",
        "finding_type",
        "severity",
        "query",
        "title",
    )

    parts = []

    for key in useful_keys:
        if key not in inp:
            continue

        value = str(inp[key])

        if len(value) > 90:
            value = value[:87] + "..."

        parts.append(f"{key}={value}")

    return ", ".join(parts)


def summarize_tool_result(name: str, result_str: str) -> str:
    """Create a short human-readable summary for the debug trace."""

    if result_str.strip().lower() == "access denied":
        return "Access denied"

    if name == POLICY_SEARCH_TOOL_NAME:
        marker = "--- Policy 1: "
        if marker in result_str:
            title = result_str.split(marker, 1)[1].split(" ---", 1)[0]
            return f"Policy retrieved: {title}"

        return "Policy context retrieved"

    try:
        data = json.loads(result_str)
    except json.JSONDecodeError:
        return "Result received"

    if name == "get_asset_scan_results" and isinstance(data, list):
        lines = [f"{len(data)} findings retrieved"]

        for item in data:
            severity = item.get("severity", "Unknown")
            cve_id = item.get("cve_id") or "-"
            title = item.get("title", "Unknown finding")

            lines.append(
                f"          - {severity} | {cve_id} | {title}"
            )

        return "\n".join(lines)

    if name == "get_user_remediation_tickets" and isinstance(data, list):
        lines = [f"{len(data)} ticket(s) retrieved"]

        for item in data:
            ticket_id = item.get("ticket_id", "?")
            status = item.get("status", "Unknown")
            title = item.get("title", "Untitled")

            lines.append(
                f"          - #{ticket_id} | {status} | {title}"
            )

        return "\n".join(lines)

    if name == "get_asset_patch_history" and isinstance(data, list):
        return f"{len(data)} patch-history record(s) retrieved"

    if name == "get_asset_risk_acceptances" and isinstance(data, list):
        statuses = sorted(
            {
                str(item.get("status"))
                for item in data
                if item.get("status")
            }
        )

        status_text = ", ".join(statuses)

        return (
            f"{len(data)} risk-acceptance record(s) retrieved"
            + (f": {status_text}" if status_text else "")
        )

    if name == "get_asset_details":
        return "Asset details retrieved"

    if name == "get_finding_details":
        return "Finding details retrieved"

    return "Data retrieved successfully"


def parse_tool_input(inp: Any) -> dict[str, Any]:
    """Normalize a tool-use ``input`` field to a dict."""
    if not isinstance(inp, str):
        return inp or {}
    try:
        return json.loads(inp)
    except json.JSONDecodeError:
        return {}


def tools_for_claude(anthropic_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copy tool schemas and remove ``user_id`` so Claude cannot choose it."""
    cleaned: list[dict[str, Any]] = []
    for tool in anthropic_tools:
        schema = copy.deepcopy(tool.get("input_schema") or {"type": "object", "properties": {}})
        properties = schema.get("properties") or {}
        properties.pop("user_id", None)
        schema["properties"] = properties
        schema["required"] = [name for name in schema.get("required", []) if name != "user_id"]
        cleaned.append({**tool, "input_schema": schema})
    return cleaned


def prepare_agent_tools(tools_result: Any) -> list[dict[str, Any]]:
    """MCP tools except auth tools, plus the local search_policies tool."""
    anthropic_tools = tools_for_claude(mcp_tools_to_anthropic(tools_result))
    hidden_auth_tools = {LOOKUP_TOOL, VERIFY_TOOL}
    authenticated_mcp_tools = [
        tool for tool in anthropic_tools if tool["name"] not in hidden_auth_tools
    ]
    return authenticated_mcp_tools + [POLICY_SEARCH_TOOL]


TRACE_KEY_BY_TOOL = {
    "get_asset_scan_results": "findings",
    "get_user_remediation_tickets": "tickets",
    "get_asset_patch_history": "patch_history",
    "get_asset_risk_acceptances": "risk_acceptances",
}


def update_trace_state(
    trace_state: dict[str, Any],
    name: str,
    result_str: str,
    asset_name: str | None = None,
) -> None:
    """Store concise successful tool-result facts for the final debug summary.

    Results are kept per asset internally, and the flat lists that the
    summary and validator read are re-derived after every write, so a
    re-fetch of the same asset replaces its previous records instead of
    duplicating them.
    """

    if result_str.strip().lower() == "access denied":
        return

    if name == POLICY_SEARCH_TOOL_NAME:
        trace_state.setdefault("policy_contexts", []).append(result_str)

        marker = "--- Policy 1: "

        if marker in result_str:
            title = result_str.split(marker, 1)[1].split(" ---", 1)[0]

            if title not in trace_state["policies"]:
                trace_state["policies"].append(title)

        return

    try:
        data = json.loads(result_str)
    except json.JSONDecodeError:
        return

    flat_key = TRACE_KEY_BY_TOOL.get(name)

    if flat_key is None or not isinstance(data, list):
        return

    by_asset = trace_state.setdefault(f"{flat_key}_by_asset", {})
    by_asset[asset_name or ""] = data
    trace_state[flat_key] = [
        record for records in by_asset.values() for record in records
    ]


async def execute_tool_uses(
    mcp_session: ClientSession,
    content_blocks: list[dict[str, Any]],
    chat: ChatSession,
    trace_state: dict[str, Any],
    event_callback: EventCallback = None,
) -> list[dict[str, Any]]:
    """Dispatch local tools or MCP tools and return matching ``tool_result`` blocks."""
    tool_results: list[dict[str, Any]] = []
    for block in content_blocks:
        if block.get("type") != "tool_use":
            continue
        name = block.get("name", "")
        inp = copy.deepcopy(
            parse_tool_input(block.get("input"))
        )
        inp.pop("user_id", None)

        if name == "get_user_remediation_tickets" and not inp.get("asset_name"):
            asset_names = set()

            for other_block in content_blocks:
                if other_block.get("type") != "tool_use":
                    continue

                other_input = parse_tool_input(other_block.get("input"))
                asset_name = other_input.get("asset_name")

                if asset_name:
                    asset_names.add(asset_name)

            if len(asset_names) == 1:
                inp["asset_name"] = next(iter(asset_names))

        if DEBUG_THINKING_PROMPT_ENABLED:
            params = compact_tool_params(inp)

            if params:
                print(f"{BOLD}TOOL{RESET}      {name} ({params})")
            else:
                print(f"{BOLD}TOOL{RESET}      {name}")

        await emit_event(
            event_callback,
            "tool",
            {"name": name, "params": event_tool_params(inp)},
        )

        if name == POLICY_SEARCH_TOOL_NAME:
            result_str = await asyncio.to_thread(
                retrieve_policy_context, inp.get("query", "")
            )
        else:
            if name not in TOOLS_WITHOUT_USER_ID:
                inp["user_id"] = chat.authenticated_user_id
            result_str = await call_tool(mcp_session, name, inp)

        update_trace_state(
            trace_state,
            name,
            result_str,
            inp.get("asset_name"),
        )

        asset_ownership_checked = (
            name in ASSET_SCOPED_TOOLS
            and "asset_name" in inp
            and bool(inp.get("asset_name"))
        )
        ownership_verified = (
            asset_ownership_checked
            and result_str.strip().lower() != "access denied"
        )
        if ownership_verified:
            authz_message = (
                f"Ownership verified: {chat.authenticated_email} -> "
                f"{inp.get('asset_name')}"
            )
            if DEBUG_THINKING_PROMPT_ENABLED:
                print(f"{BOLD}AUTHZ{RESET}     {authz_message}")
            await emit_event(
                event_callback,
                "authz",
                {"message": "Ownership verified"},
            )

        summary = summarize_tool_result(name, result_str)
        if DEBUG_THINKING_PROMPT_ENABLED:
            print(f"{BOLD}RESULT{RESET}    {summary}")
        await emit_event(
            event_callback,
            "result",
            {"message": summary.split("\n", 1)[0]},
        )
        tool_results.append(
            {"type": "tool_result", "tool_use_id": block.get("id", ""), "content": result_str}
        )
    return tool_results


def build_final_thinking_summary(
    trace_state: dict[str, Any],
) -> str:
    """Build a concise final debug summary from actual retrieved results."""

    lines = ["Analysis complete:"]

    findings = trace_state["findings"]

    if findings:
        severities: dict[str, int] = {}

        for item in findings:
            severity = str(item.get("severity", "Unknown"))
            severities[severity] = severities.get(severity, 0) + 1

        severity_text = ", ".join(
            f"{count} {severity}"
            for severity, count in severities.items()
        )

        lines.append(
            f"- {len(findings)} findings identified: {severity_text}"
        )

    remediation_parts: list[str] = []

    tickets = trace_state["tickets"]
    if tickets:
        remediation_parts.append(
            f"{len(tickets)} ticket" + ("" if len(tickets) == 1 else "s")
        )

    patch_history = trace_state["patch_history"]
    if patch_history:
        remediation_parts.append(
            f"{len(patch_history)} patch-history record"
            + ("" if len(patch_history) == 1 else "s")
        )

    risk_acceptances = trace_state["risk_acceptances"]
    if risk_acceptances:
        statuses = sorted({
            str(item.get("status"))
            for item in risk_acceptances
            if item.get("status")
        })

        status_text = "/".join(statuses)

        remediation_parts.append(
            f"{len(risk_acceptances)} {status_text} risk acceptance"
            + ("" if len(risk_acceptances) == 1 else "s")
        )

    if remediation_parts:
        lines.append(
            "- Existing remediation state: "
            + ", ".join(remediation_parts)
        )

    policies = trace_state["policies"]

    if policies:
        lines.append(
            "- Policy guidance retrieved: "
            + ", ".join(policies)
        )

    lines.append(
        "No additional information is required. Preparing the final answer."
    )

    return "\n          ".join(lines)


FINAL_ANSWER_CORRECTION_INSTRUCTION = """FINAL ANSWER VALIDATION FAILED.

Rewrite the final answer using only already retrieved facts and policy context.

Violations:
{violations}

Return only the corrected final answer.
Do not call tools.
Do not add new facts.
"""

REVIEW_DATE_VIOLATIONS = (
    "before the review date",
    "by the review date",
    "until the review date",
    "valid until",
    "valid through",
    "expires on",
)

DEFERRAL_VIOLATIONS = (
    "remediation is deferred",
    "defers remediation",
    "deferral is approved",
    "no immediate remediation is required",
    "remediation may wait",
)

PATCH_DATE_VIOLATIONS = (
    "applied on",
    "completed on",
    "scheduled on",
    "patched on",
)

TICKET_WORKFLOW_VIOLATIONS = (
    "request closure via ticket",
    "closure via ticket",
    "close via ticket",
    "verification ticket",
    "patching ticket",
    "appears to be tracking",
    "tracking verification",
    "attach the rescan evidence to ticket",
    "attach evidence to ticket",
    "evidence to ticket",
    "keep the evidence in both tickets",
    "update both tickets",
    "update ticket",
    "close ticket",
)

MARKDOWN_HEADING_RE = re.compile(r"^\s*#{1,6}\s", re.MULTILINE)

TICKET_REFERENCE_RE = re.compile(r"\btickets?\b|#\d+")

TICKET_ACTION_TERMS = (
    "evidence",
    "attach",
    "update",
    "close",
    "closure",
    "document",
    "track",
    "tracking",
    "verification",
    "verify",
    "assign",
    "owner",
)

RA_TRIGGER_TERMS = (
    "risk acceptance",
    "approved",
    "justification",
)

RA_INTERPRETIVE_RE = re.compile(
    r"\b("
    r"justify|justifies|justifying|"
    r"allow|allows|allowing|allowed|"
    r"permit|permits|permitting|permitted|"
    r"defer|defers|deferring|deferred|"
    r"cover|covers|covering|covered|"
    r"authorize|authorizes|authorizing|authorized|authorization"
    r")\b"
)

REQUIRED_RISK_ACCEPTANCE_LABELS = (
    "status:",
    "justification:",
    "review date:",
    "finding status:",
)

POLICY_ATTRIBUTION_PHRASES = (
    "per policy",
    "according to policy",
    "policy requires",
    "required by policy",
    "organizational policy requires",
)

TICKET_OFFER_PHRASES = (
    "open a remediation ticket",
    "create a remediation ticket",
    "opening a remediation ticket",
    "creating a remediation ticket",
    "open a ticket",
    "create a ticket",
    "open a new ticket",
    "create a new ticket",
)

ATTRIBUTION_STOPWORDS = frozenset({
    "per", "policy", "policies", "according", "required", "requires",
    "requirement", "requirements", "organizational", "organization",
    "the", "and", "for", "with", "this", "that", "these", "those",
    "are", "is", "be", "been", "being", "was", "were", "not", "only",
    "all", "any", "must", "should", "may", "can", "will", "shall",
    "ensure", "ensured", "ensuring", "enable", "enabled", "disable",
    "disabled", "apply", "applied", "applying", "configure",
    "configured", "restrict", "restricted", "restricting", "use",
    "used", "using", "keep", "set", "run", "running", "remain",
    "remains", "your", "you", "its", "it", "also", "additionally",
    "then", "when", "where", "which", "unless", "until", "after",
    "before", "access", "system", "systems", "asset", "assets",
    "finding", "findings", "remediation", "remediate", "security",
})


RISK_ACCEPTANCE_VIOLATIONS = (
    "risk acceptance covers",
    "acceptance covers the finding",
    "risk acceptance remediates",
    "approved means remediated",
    "remediation deadline",
)


def validate_policy_attributions(
    answer: str,
    trace_state: dict[str, Any],
) -> list[str]:
    """Flag "per policy"-style claims naming terms absent from retrieved policy text."""

    lowered = answer.lower()

    if not any(phrase in lowered for phrase in POLICY_ATTRIBUTION_PHRASES):
        return []

    combined_context = "\n".join(
        trace_state.get("policy_contexts") or []
    ).lower()

    violations: list[str] = []

    for sentence in re.split(r"[.!?\n]", lowered):
        if not any(phrase in sentence for phrase in POLICY_ATTRIBUTION_PHRASES):
            continue

        candidate_terms = re.findall(r"[a-z0-9][a-z0-9\-_]{2,}", sentence)

        for term in candidate_terms:
            if term in ATTRIBUTION_STOPWORDS:
                continue
            if term in combined_context:
                continue
            violations.append(
                f'organizational policy claim mentions "{term}", '
                "but that term was not present in retrieved policy context"
            )

    return violations


def validate_final_answer(
    answer: str,
    trace_state: dict[str, Any],
) -> list[str]:
    """Return deterministic semantic violations found in a final answer."""

    lowered = answer.lower()
    collapsed = " ".join(lowered.split())
    violations: list[str] = []

    for phrase in REVIEW_DATE_VIOLATIONS:
        if phrase in lowered:
            violations.append(
                f'review_date was used as a deadline or validity period ("{phrase}")'
            )

    for phrase in DEFERRAL_VIOLATIONS:
        if phrase in lowered:
            violations.append(
                f'unsupported remediation deferral was stated ("{phrase}")'
            )

    if trace_state.get("patch_history"):
        for phrase in PATCH_DATE_VIOLATIONS:
            if phrase in lowered:
                violations.append(
                    f'patch-history status and timestamp were combined ("{phrase}")'
                )

        for label in ("action:", "status:", "recorded timestamp:"):
            if label not in lowered:
                violations.append(
                    f'patch history is missing the required "{label}" line'
                )

    recommendations_index = lowered.find("recommended next actions")

    if "**" in answer:
        violations.append("final answer contains Markdown bold formatting")

    if MARKDOWN_HEADING_RE.search(answer):
        violations.append("final answer contains Markdown heading formatting")

    if "```" in answer:
        violations.append("final answer contains fenced code blocks")

    if (
        any(phrase in lowered for phrase in TICKET_OFFER_PHRASES)
        and "tickets_by_asset" not in trace_state
    ):
        violations.append(
            "a remediation-ticket offer was made without checking existing "
            "tickets first (get_user_remediation_tickets was not called this "
            "turn); remove the offer"
        )

    if recommendations_index != -1:
        structural_section = "\n".join(
            line
            for line in lowered[recommendations_index:].splitlines()
            if not line.strip().startswith("|")
        )

        for phrase in TICKET_WORKFLOW_VIOLATIONS:
            if phrase in structural_section:
                violations.append(
                    f'ticket workflow was inferred from ticket titles ("{phrase}")'
                )

        for sentence in re.split(r"[.!?\n]", structural_section):
            if (
                TICKET_REFERENCE_RE.search(sentence)
                and any(term in sentence for term in TICKET_ACTION_TERMS)
            ):
                violations.append(
                    "a specific ticket was assigned an operational action in "
                    f'Recommended next actions ("{sentence.strip()[:80]}")'
                )

            if (
                any(term in sentence for term in RA_TRIGGER_TERMS)
                and RA_INTERPRETIVE_RE.search(sentence)
            ):
                violations.append(
                    "the risk acceptance or its justification was interpreted as "
                    f'authorization in Recommended next actions ("{sentence.strip()[:80]}")'
                )

    for sentence in re.split(r"[.!?\n]", lowered):
        if "rescan" in sentence and (
            "close" in sentence or "closure" in sentence
        ):
            violations.append(
                "a rescan and closure were combined in one sentence; state "
                "verification first, then conditional closure "
                f'("{sentence.strip()[:80]}")'
            )

    if trace_state.get("tickets"):
        if "| ticket | status | title | created |" not in collapsed:
            violations.append(
                "existing tickets were not presented as the required "
                "Ticket/Status/Title/Created table"
            )

    if trace_state.get("risk_acceptances"):
        for phrase in RISK_ACCEPTANCE_VIOLATIONS:
            if phrase in lowered:
                violations.append(
                    f'risk-acceptance status was reinterpreted ("{phrase}")'
                )

        ra_match = re.search(r"risk acceptances?:", lowered)

        if ra_match is None:
            violations.append(
                'risk acceptance is missing the required "Risk acceptance:" block'
            )
        else:
            ra_section = lowered[ra_match.start():]

            boundary = ra_section.find("recommended next actions", 1)
            if boundary != -1:
                ra_section = ra_section[:boundary]

            for label in REQUIRED_RISK_ACCEPTANCE_LABELS:
                if label == "finding status:" and not trace_state.get("findings"):
                    continue
                if not re.search(
                    r"^\s*" + re.escape(label),
                    ra_section,
                    flags=re.MULTILINE,
                ):
                    violations.append(
                        f'risk acceptance is missing required "{label}" field'
                    )

    violations.extend(validate_policy_attributions(answer, trace_state))

    return violations


async def run_agent_loop(
    mcp_session: ClientSession,
    agent_tools: list[dict[str, Any]],
    user_query: str,
    chat: ChatSession,
    record_history: bool = True,
    event_callback: EventCallback = None,
) -> str:
    """Run the Claude tool-use loop until a final answer or ``MAX_AGENT_ROUNDS`` is reached."""
    client = _anthropic_client
    messages = list(chat.history) + [{"role": "user", "content": user_query}]
    trace_state: dict[str, Any] = {
        "findings": [],
        "tickets": [],
        "patch_history": [],
        "risk_acceptances": [],
        "policies": [],
        "policy_contexts": [],
    }

    if DEBUG_THINKING_PROMPT_ENABLED:
        print("\n" + "=" * 56)
        print(f"{BOLD}INTERNAL AGENT TRACE{RESET}")
        print("=" * 56)

    for round_num in range(1, MAX_AGENT_ROUNDS + 1):
        print(f"\n{BOLD}[STEP {round_num}]{RESET}\n")
        await emit_event(event_callback, "step", {"step": round_num})
        system_prompt = AGENT_SYSTEM_PROMPT
        if DEBUG_THINKING_PROMPT_ENABLED:
            system_prompt += "\n\n" + DEBUG_THINKING_PROMPT
        
        response = await client.messages.create(
            model=_model_name(),
            max_tokens=4096,
            system=system_prompt,
            messages=messages,
            tools=agent_tools,
        )
        content_blocks = content_blocks_to_list(response.content)

        decision = extract_decision(content_blocks)

        if response.stop_reason == "end_turn":
            final_summary = build_final_thinking_summary(trace_state)
            if DEBUG_THINKING_PROMPT_ENABLED:
                print(f"{BOLD}THINKING{RESET}  {final_summary}")
            await emit_event(
                event_callback,
                "thinking",
                {"message": final_summary},
            )

            answer = final_answer_from_blocks(content_blocks)

            violations = validate_final_answer(answer, trace_state)

            if violations:
                logger.warning("Semantic violations: %s", violations)
                validate_message = (
                    "Semantic issues detected - regenerating final answer"
                )
                if DEBUG_THINKING_PROMPT_ENABLED:
                    print(f"{BOLD}VALIDATE{RESET}  {validate_message}")
                    for item in violations:
                        print(f"{BOLD}VIOLATION{RESET} {item}")
                await emit_event(
                    event_callback,
                    "validate",
                    {"message": validate_message},
                )

                correction_messages = messages + [
                    {"role": "assistant", "content": content_blocks},
                    {
                        "role": "user",
                        "content": FINAL_ANSWER_CORRECTION_INSTRUCTION.format(
                            violations="\n".join(
                                f"- {item}" for item in violations
                            )
                        ),
                    },
                ]

                correction_response = await client.messages.create(
                    model=_model_name(),
                    max_tokens=4096,
                    system=system_prompt,
                    messages=correction_messages,
                )
                corrected_blocks = content_blocks_to_list(
                    correction_response.content
                )
                corrected_answer = final_answer_from_blocks(corrected_blocks)

                remaining_violations = validate_final_answer(
                    corrected_answer, trace_state
                )
                if remaining_violations:
                    logger.warning(
                        "Semantic violations after correction: %s",
                        remaining_violations,
                    )
                    if DEBUG_THINKING_PROMPT_ENABLED:
                        for item in remaining_violations:
                            print(f"{BOLD}VIOLATION{RESET} {item}")
                    answer = (
                        "The agent could not produce a semantically validated "
                        "response. Please retry."
                    )
                    if record_history:
                        chat.add_turn(user_query, answer)
                    return answer

                answer = corrected_answer

                validate_message = (
                    "Corrected final answer passed semantic validation"
                )
                if DEBUG_THINKING_PROMPT_ENABLED:
                    print(f"{BOLD}VALIDATE{RESET}  {validate_message}")
                await emit_event(
                    event_callback,
                    "validate",
                    {"message": validate_message},
                )

            else:
                validate_message = "Final answer passed semantic validation"
                if DEBUG_THINKING_PROMPT_ENABLED:
                    print(f"{BOLD}VALIDATE{RESET}  {validate_message}")
                await emit_event(
                    event_callback,
                    "validate",
                    {"message": validate_message},
                )

            if DEBUG_THINKING_PROMPT_ENABLED:
                print("\n" + "=" * 56)
                print(f"{BOLD}FINAL ANSWER{RESET}")
                print("=" * 56 + "\n")

            if record_history:
                chat.add_turn(user_query, answer)

            return answer

        if decision:
            if DEBUG_THINKING_PROMPT_ENABLED:
                print(f"{BOLD}THINKING{RESET}  {decision}")
                print()
            await emit_event(
                event_callback,
                "thinking",
                {"message": decision},
            )

        tool_use_blocks = [
            block for block in content_blocks if block.get("type") == "tool_use"
        ]
        if not tool_use_blocks:
            answer = final_answer_from_blocks(content_blocks)
            if answer == "(No text in response.)":
                answer = "I could not complete a response. Please try again."
            if record_history:
                chat.add_turn(user_query, answer)
            return answer

        tool_result_blocks = await execute_tool_uses(
            mcp_session,
            content_blocks,
            chat,
            trace_state,
            event_callback=event_callback,
        )
        messages.append({"role": "assistant", "content": content_blocks})
        messages.append({"role": "user", "content": tool_result_blocks})

    answer = "(Reached max tool rounds without a final answer.)"
    if record_history:
        chat.add_turn(user_query, answer)
    return answer


async def process_authenticated_message(
    mcp_session: ClientSession,
    agent_tools: list[dict[str, Any]],
    user_query: str,
    chat: ChatSession,
    event_callback: EventCallback = None,
) -> str:
    """Process one authenticated user message through the shared agent loop."""
    return await run_agent_loop(
        mcp_session,
        agent_tools,
        user_query,
        chat,
        event_callback=event_callback,
    )
